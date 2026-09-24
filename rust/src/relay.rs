//! Write-only audit relay.
//!
//! The relay is a separate process. It holds a copy of the audit MAC key,
//! re-verifies every record against its own chain head, including the chain
//! already on disk at startup, and stores a byte-identical copy. A sequence
//! gap, a contradictory redelivery, an oversized frame, or a bad handshake
//! fails the store closed. A clean
//! disconnect does not: a host crash must not poison the store.
//!
//! The shared MAC key is a prototype stand-in. A production verifier would
//! be enrolled with its own verification key.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::audit::GENESIS;
use crate::canonical::{Json, canonical_bytes, json_number, loads_strict, new_id, sha256_hex};
use crate::keys::KeyRing;

type HmacSha256 = Hmac<Sha256>;
type ViolationHandler = Arc<dyn Fn(String) + Send + Sync>;

pub const RELAY_PROTOCOL: &str = "voss.relay.1";
pub const MAX_FRAME: usize = 1 << 22;
const IDLE_CLOSE_AFTER: u32 = 8;

#[derive(Debug)]
pub enum RelayFail {
    Violation(String),
    Closed(String),
    Timeout,
    Io(String),
}

impl std::fmt::Display for RelayFail {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Violation(reason) => formatter.write_str(reason),
            Self::Closed(reason) => formatter.write_str(reason),
            Self::Timeout => formatter.write_str("timeout"),
            Self::Io(reason) => formatter.write_str(reason),
        }
    }
}

impl RelayFail {
    fn violation(self) -> Self {
        match self {
            Self::Io(reason) => Self::Violation(format!("malformed_frame:{reason}")),
            other => other,
        }
    }
}

pub fn sign_hello(transfer_key: &[u8], nonce: &str, challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(RELAY_PROTOCOL.as_bytes());
    mac.update(b":");
    mac.update(challenge.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn sign_challenge(transfer_key: &[u8], challenge: &str) -> String {
    // Binds the server's per-process challenge frame to transfer-key
    // possession, so an observer cannot substitute a challenge: every hello
    // must MAC over the challenge THIS process issued.
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(RELAY_PROTOCOL.as_bytes());
    mac.update(b":challenge:");
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn challenge_frame(transfer_key: &[u8], challenge: &str) -> Json {
    Json::object([
        ("type", Json::string("challenge")),
        ("challenge", Json::string(challenge)),
        ("mac", Json::string(sign_challenge(transfer_key, challenge))),
    ])
}

pub fn frame_signed(protocol: &str, transfer_key: &[u8], seq: i64, message: &Json) -> Result<Json, String> {
    let body = insert_field(message, "seq", Json::Int(seq))?;
    let mac = frame_mac(protocol, transfer_key, seq, &body)?;
    insert_field(&body, "mac", Json::string(mac))
}

pub fn frame_is_authed(message: &Json, protocol: &str, transfer_key: &[u8]) -> bool {
    let Some(seq) = json_i64(message.get("seq")) else {
        return false;
    };
    if seq < 0 {
        return false;
    }
    let Some(mac) = message.get("mac").and_then(Json::as_str) else {
        return false;
    };
    let Some(mut map) = message.as_object().cloned() else {
        return false;
    };
    map.remove("mac");
    let Ok(expected) = frame_mac(protocol, transfer_key, seq, &Json::Object(map)) else {
        return false;
    };
    constant_time_eq(&expected, mac)
}

fn frame_mac(protocol: &str, transfer_key: &[u8], seq: i64, body: &Json) -> Result<String, String> {
    let canonical = canonical_bytes(body).map_err(|error| error.message().to_string())?;
    let mut mac = HmacSha256::new_from_slice(transfer_key).map_err(|error| error.to_string())?;
    mac.update(protocol.as_bytes());
    mac.update(b":");
    mac.update(seq.to_string().as_bytes());
    mac.update(b":");
    mac.update(&canonical);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn insert_field(message: &Json, key: &str, value: Json) -> Result<Json, String> {
    let mut map = message
        .as_object()
        .cloned()
        .ok_or_else(|| "frame must be an object".to_string())?;
    map.insert(key.to_string(), value);
    Ok(Json::Object(map))
}

pub fn frame(message: &Json) -> Result<Vec<u8>, RelayFail> {
    let body = canonical_bytes(message).map_err(|error| RelayFail::Violation(error.message().to_string()))?;
    if body.len() > MAX_FRAME {
        return Err(RelayFail::Violation("oversize_frame".to_string()));
    }
    let mut bytes = (body.len() as u32).to_be_bytes().to_vec();
    bytes.extend(body);
    Ok(bytes)
}

pub fn read_frame(stream: &mut TcpStream) -> Result<Json, RelayFail> {
    let mut header = [0u8; 4];
    read_exact(stream, &mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(RelayFail::Violation("oversize_frame".to_string()));
    }
    let mut body = vec![0u8; length];
    read_exact(stream, &mut body)?;
    let text = String::from_utf8(body).map_err(|error| RelayFail::Violation(format!("malformed_frame:{error}")))?;
    let value = loads_strict(&text).map_err(|error| RelayFail::Violation(format!("malformed_frame:{}", error.message())))?;
    if !matches!(value, Json::Object(_)) {
        return Err(RelayFail::Violation("malformed_frame".to_string()));
    }
    Ok(value)
}

struct ServerState {
    head: String,
    ids: BTreeMap<String, Json>,
    stored_count: i64,
    compromised: bool,
    stale: bool,
    // Hello nonces this process has accepted. Not written to disk.
    seen_nonces: HashSet<String>,
}

struct ServerInner {
    store_path: PathBuf,
    control_path: PathBuf,
    keyring: KeyRing,
    transfer_key: Vec<u8>,
    // Fresh per-process challenge: restarting the server mints a new one, so
    // a hello that echoed an earlier process's challenge (same transfer key)
    // can never open a session on this process. The single-use nonce set only
    // rejects replays within one process lifetime.
    challenge: String,
    timeout: Duration,
        stop: AtomicBool,
        active: AtomicBool,
        state: Mutex<ServerState>,
        listener: TcpListener,
    }

pub struct AuditRelayServer {
    inner: Arc<ServerInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl AuditRelayServer {
    pub fn bind(
        store_dir: impl AsRef<Path>,
        keyring: KeyRing,
        transfer_key: Vec<u8>,
        timeout: Duration,
    ) -> Result<Self, RelayFail> {
        if transfer_key.len() < 16 {
            return Err(RelayFail::Io("transfer key must be at least 16 bytes".to_string()));
        }
        let store_dir = store_dir.as_ref();
        fs::create_dir_all(store_dir).map_err(|error| RelayFail::Io(error.to_string()))?;
        let store_dir = fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
        let store_path = store_dir.join("relay-audit.jsonl");
        let control_path = store_dir.join("relay-control.jsonl");
        let mut state = ServerState {
            head: GENESIS.to_string(),
            ids: BTreeMap::new(),
            stored_count: 0,
            compromised: false,
            stale: false,
            seen_nonces: HashSet::new(),
        };
        load_store(&store_path, &mut state, &keyring);
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| RelayFail::Io(error.to_string()))?;
        listener.set_nonblocking(true).map_err(|error| RelayFail::Io(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(ServerInner {
                store_path,
                control_path,
                keyring,
                transfer_key,
                challenge: new_id("challenge-"),
                timeout,
                stop: AtomicBool::new(false),
                active: AtomicBool::new(false),
                state: Mutex::new(state),
                listener,
            }),
            thread: Mutex::new(None),
        })
    }

    pub fn port(&self) -> u16 {
        self.inner.listener.local_addr().map(|addr| addr.port()).unwrap_or(0)
    }

    pub fn compromised(&self) -> bool {
        self.inner.state.lock().expect("relay state").compromised
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("relay thread");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *slot = Some(thread::spawn(move || serve_loop(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("relay thread").take() {
            let _ = handle.join();
        }
    }
}

fn serve_loop(inner: Arc<ServerInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        match inner.listener.accept() {
            Ok((stream, _)) => dispatch(&inner, stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn dispatch(inner: &ServerInner, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    if inner.active.swap(true, Ordering::SeqCst) {
        reply(&mut stream, &Json::object([
            ("type", Json::string("busy")),
        ]));
        write_control(&inner.control_path, "relay_busy", "another host is connected");
        return;
    }
    handle_connection(inner, stream);
    inner.active.store(false, Ordering::SeqCst);
}

fn handle_connection(inner: &ServerInner, mut stream: TcpStream) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(inner.timeout));
    let _ = stream.set_write_timeout(Some(inner.timeout));
    // Speak first with this process's challenge; a valid hello must MAC over it.
    reply(&mut stream, &challenge_frame(&inner.transfer_key, &inner.challenge));
    if inner.state.lock().expect("relay state").compromised {
        reply(&mut stream, &Json::object([
            ("type", Json::string("refused")),
            ("reason", Json::string("relay_compromised")),
        ]));
        graceful_close(stream);
        return;
    }
    let mut idle = 0u32;
    let mut phase = "hello";
    let mut expected_seq = 0i64;
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            break;
        }
        if inner.state.lock().expect("relay state").compromised {
            reply(&mut stream, &Json::object([
                ("type", Json::string("refused")),
                ("reason", Json::string("relay_compromised")),
            ]));
            break;
        }
        let message = match read_frame(&mut stream) {
            Ok(message) => message,
            Err(RelayFail::Timeout) => {
                idle += 1;
                let mut state = inner.state.lock().expect("relay state");
                if !state.stale {
                    state.stale = true;
                    drop(state);
                    write_control(&inner.control_path, "relay_stale", "no records within timeout");
                }
                if idle >= IDLE_CLOSE_AFTER {
                    write_control(&inner.control_path, "relay_idle_closed", "connection closed after idle timeout");
                    break;
                }
                continue;
            }
            Err(RelayFail::Closed(_)) => {
                write_control(&inner.control_path, "relay_stream_closed", "host stream ended");
                break;
            }
            Err(error) => {
                violate(inner, &mut stream, &error.violation().to_string());
                break;
            }
        };
        idle = 0;
        {
            let mut state = inner.state.lock().expect("relay state");
            if state.stale {
                state.stale = false;
                drop(state);
                write_control(&inner.control_path, "relay_recovered", "records resumed after idle");
            }
        }
        if phase == "hello" {
            if let Some(reason) = claim_hello(inner, &message) {
                write_control(&inner.control_path, "relay_denied_hello", reason);
                reply(&mut stream, &Json::object([
                    ("type", Json::string("violation")),
                    ("reason", Json::string("denied_hello_auth")),
                ]));
                break;
            }
            let nonce = message.get("nonce").and_then(Json::as_str).unwrap_or("");
            write_control(&inner.control_path, "relay_accepted_hello", "authenticated host connected");
            reply(&mut stream, &Json::object([
                ("type", Json::string("hello_ok")),
                ("nonce", Json::string(nonce)),
            ]));
            phase = "stream_begin";
        } else if phase == "stream_begin" {
            if message.get("type").and_then(Json::as_str) != Some("stream_begin") {
                violate(inner, &mut stream, "expected_stream_begin");
                break;
            }
            if !frame_is_authed(&message, RELAY_PROTOCOL, &inner.transfer_key) {
                violate(inner, &mut stream, "stream_begin_auth");
                break;
            }
            if json_i64(message.get("seq")) != Some(1) {
                violate(inner, &mut stream, "sequence_gap expected 1");
                break;
            }
            let state = inner.state.lock().expect("relay state");
            let ready = Json::object([
                ("type", Json::string("stream_ready")),
                ("chain_len", Json::Int(state.stored_count)),
                ("head", Json::string(&state.head)),
            ]);
            drop(state);
            reply(&mut stream, &ready);
            expected_seq = 0;
            phase = "records";
        } else {
            if !frame_is_authed(&message, RELAY_PROTOCOL, &inner.transfer_key) {
                violate(inner, &mut stream, "record_auth");
                break;
            }
            expected_seq += 1;
            let got = json_i64(message.get("seq"));
            if got != Some(expected_seq) {
                let shown = got.map(|value| value.to_string()).unwrap_or_else(|| "null".to_string());
                violate(inner, &mut stream, &format!("sequence_gap expected {expected_seq} got {shown}"));
                break;
            }
            if !ingest_record(inner, &mut stream, &message) {
                break;
            }
        }
    }
    graceful_close(stream);
}

fn ingest_record(inner: &ServerInner, stream: &mut TcpStream, message: &Json) -> bool {
    let Some(record) = message.get("record").filter(|value| matches!(value, Json::Object(_))).cloned() else {
        violate(inner, stream, "record_missing_payload");
        return false;
    };
    let Some(event_id) = record.get("event_id").and_then(Json::as_str).map(str::to_string) else {
        violate(inner, stream, "record_missing_id");
        return false;
    };
    let seq = json_i64(message.get("seq")).unwrap_or(0);
    {
        let state = inner.state.lock().expect("relay state");
        if let Some(existing) = state.ids.get(&event_id) {
            if existing != &record {
                drop(state);
                violate(inner, stream, &format!("duplicate_contradiction:{event_id}"));
                return false;
            }
            let chain_len = state.stored_count;
            drop(state);
            reply(stream, &ack(seq, true, chain_len));
            return true;
        }
    }
    let (mac, chain) = match verify_record(&record, &inner.state.lock().expect("relay state").head, &inner.keyring) {
        Ok(value) => value,
        Err(error) => {
            violate(inner, stream, &error.to_string());
            return false;
        }
    };
    let line = Json::object([
        ("chain_prev", Json::string(&inner.state.lock().expect("relay state").head)),
        ("chain_mac", Json::string(&mac)),
        ("chain_hash", Json::string(&chain)),
        ("record", record.clone()),
    ]);
    let Ok(mut encoded) = canonical_bytes(&line) else {
        violate(inner, stream, "record_encode");
        return false;
    };
    encoded.push(b'\n');
    let chain_len = {
        let mut state = inner.state.lock().expect("relay state");
        if let Some(existing) = state.ids.get(&event_id) {
            if existing != &record {
                drop(state);
                violate(inner, stream, &format!("duplicate_contradiction:{event_id}"));
                return false;
            }
            let chain_len = state.stored_count;
            drop(state);
            reply(stream, &ack(seq, true, chain_len));
            return true;
        }
        state.ids.insert(event_id, record);
        state.head = chain.clone();
        state.stored_count += 1;
        let count = state.stored_count;
        if let Err(error) = append_bytes(&inner.store_path, &encoded) {
            state.compromised = true;
            drop(state);
            violate(inner, stream, &error);
            return false;
        }
        count
    };
    reply(stream, &ack(seq, false, chain_len));
    true
}

fn verify_record(record: &Json, previous: &str, keyring: &KeyRing) -> Result<(String, String), RelayFail> {
    let payload_bytes = canonical_bytes(record).map_err(|error| RelayFail::Violation(error.message().to_string()))?;
    let mut mac_input = previous.as_bytes().to_vec();
    mac_input.extend_from_slice(&payload_bytes);
    let mac = keyring.mac_audit(&mac_input);
    let record_text = String::from_utf8(payload_bytes).map_err(|error| RelayFail::Violation(error.to_string()))?;
    let chain = sha256_hex(&Json::object([
        ("prev", Json::string(previous)),
        ("record", Json::string(record_text)),
    ]))
    .map_err(|error| RelayFail::Violation(error.message().to_string()))?;
    Ok((mac, chain))
}

fn ack(seq: i64, dup: bool, chain_len: i64) -> Json {
    Json::object([
        ("type", Json::string("ack")),
        ("seq", Json::Int(seq)),
        ("dup", Json::Bool(dup)),
        ("chain_len", Json::Int(chain_len)),
    ])
}

fn claim_hello(inner: &ServerInner, message: &Json) -> Option<&'static str> {
    if !valid_hello(&inner.transfer_key, &inner.challenge, message) {
        return Some("denied_hello_auth");
    }
    let nonce = message.get("nonce").and_then(Json::as_str).unwrap_or("");
    let mut state = inner.state.lock().expect("relay state");
    if !state.seen_nonces.insert(nonce.to_string()) {
        return Some("replayed_hello_nonce");
    }
    None
}

fn valid_hello(transfer_key: &[u8], challenge: &str, message: &Json) -> bool {
    if message.get("type").and_then(Json::as_str) != Some("hello") {
        return false;
    }
    if message.get("version").and_then(Json::as_str) != Some(RELAY_PROTOCOL) {
        return false;
    }
    if message.get("challenge").and_then(Json::as_str) != Some(challenge) {
        return false;
    }
    let Some(nonce) = message.get("nonce").and_then(Json::as_str) else {
        return false;
    };
    let Some(mac) = message.get("mac").and_then(Json::as_str) else {
        return false;
    };
    constant_time_eq(&sign_hello(transfer_key, nonce, challenge), mac)
}

fn violate(inner: &ServerInner, stream: &mut TcpStream, reason: &str) {
    inner.state.lock().expect("relay state").compromised = true;
    write_control(&inner.control_path, "relay_violation", reason);
    reply(stream, &Json::object([
        ("type", Json::string("violation")),
        ("reason", Json::string(reason)),
    ]));
}

fn reply(stream: &mut TcpStream, message: &Json) {
    if let Ok(bytes) = frame(message) {
        let _ = stream.write_all(&bytes);
        let _ = stream.flush();
    }
}

fn graceful_close(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let mut buffer = [0u8; 65536];
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    let _ = stream.shutdown(Shutdown::Write);
}

struct ClientState {
    cursor: u64,
    connected: bool,
    last_error: String,
    violation: String,
    records_relayed: i64,
    dup_redeliveries: i64,
}

struct ClientInner {
    audit_path: PathBuf,
    host: String,
    port: u16,
    transfer_key: Vec<u8>,
    timeout: Duration,
    tick: Duration,
    stop: AtomicBool,
    state: Mutex<ClientState>,
    on_violation: Mutex<Option<ViolationHandler>>,
}

pub struct AuditRelayClient {
    inner: Arc<ClientInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl AuditRelayClient {
    pub fn new(audit_path: impl AsRef<Path>, host: impl Into<String>, port: u16, transfer_key: Vec<u8>) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                audit_path: audit_path.as_ref().to_path_buf(),
                host: host.into(),
                port,
                transfer_key,
                timeout: Duration::from_secs(5),
                tick: Duration::from_millis(50),
                stop: AtomicBool::new(false),
                state: Mutex::new(ClientState {
                    cursor: 0,
                    connected: false,
                    last_error: String::new(),
                    violation: String::new(),
                    records_relayed: 0,
                    dup_redeliveries: 0,
                }),
                on_violation: Mutex::new(None),
            }),
            thread: Mutex::new(None),
        }
    }

    pub fn set_on_violation<F>(&self, handler: F)
    where
        F: Fn(String) + Send + Sync + 'static,
    {
        *self.inner.on_violation.lock().expect("relay violation") = Some(Arc::new(handler));
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("relay client");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *slot = Some(thread::spawn(move || client_loop(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("relay client").take() {
            let _ = handle.join();
        }
        let already = !self.inner.state.lock().expect("relay client").violation.is_empty();
        if !already && let Err(error) = session(&self.inner, true) {
            let mut state = self.inner.state.lock().expect("relay client");
            if state.violation.is_empty() {
                state.last_error = format!("stop-drain: {error}");
            }
        }
    }

    pub fn health(&self) -> Json {
        let state = self.inner.state.lock().expect("relay client");
        Json::object([
            ("ok", Json::Bool(state.violation.is_empty() && state.last_error.is_empty())),
            ("connected", Json::Bool(state.connected)),
            ("violation", optional_text(&state.violation)),
            ("error", optional_text(&state.last_error)),
            ("records_relayed", Json::Int(state.records_relayed)),
            ("dup_redeliveries", Json::Int(state.dup_redeliveries)),
        ])
    }
}

fn client_loop(inner: Arc<ClientInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        if let Err(error) = session(&inner, false) {
            let callback = {
                let mut state = inner.state.lock().expect("relay client");
                state.connected = false;
                state.last_error = error.to_string();
                if matches!(error, RelayFail::Violation(_)) && state.violation.is_empty() {
                    state.violation = error.to_string();
                    inner.on_violation.lock().expect("relay violation").clone()
                } else {
                    None
                }
            };
            if let Some(callback) = callback {
                callback(error.to_string());
            }
        }
        let start = Instant::now();
        while !inner.stop.load(Ordering::SeqCst) && start.elapsed() < inner.tick {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn session(inner: &ClientInner, one_pass: bool) -> Result<(), RelayFail> {
    let address = format!("{}:{}", inner.host, inner.port);
    let mut stream = TcpStream::connect_timeout(&address.parse().map_err(|error: std::net::AddrParseError| RelayFail::Io(error.to_string()))?, inner.timeout)
        .map_err(|error| RelayFail::Io(error.to_string()))?;
    stream.set_nodelay(true).map_err(|error| RelayFail::Io(error.to_string()))?;
    stream.set_read_timeout(Some(inner.timeout)).map_err(|error| RelayFail::Io(error.to_string()))?;
    stream.set_write_timeout(Some(inner.timeout)).map_err(|error| RelayFail::Io(error.to_string()))?;
    let challenge = read_frame(&mut stream)?;
    let Some(challenge_value) = challenge.get("challenge").and_then(Json::as_str) else {
        return Err(RelayFail::Violation(format!("no challenge: {challenge:?}")));
    };
    if challenge.get("type").and_then(Json::as_str) != Some("challenge") {
        return Err(RelayFail::Violation(format!("no challenge: {challenge:?}")));
    }
    if challenge.get("mac").and_then(Json::as_str) != Some(&sign_challenge(&inner.transfer_key, challenge_value)) {
        return Err(RelayFail::Violation("challenge failed authentication".to_string()));
    }
    let nonce = new_id("relay-");
    let hello = Json::object([
        ("type", Json::string("hello")),
        ("version", Json::string(RELAY_PROTOCOL)),
        ("challenge", Json::string(challenge_value)),
        ("nonce", Json::string(&nonce)),
        ("mac", Json::string(sign_hello(&inner.transfer_key, &nonce, challenge_value))),
    ]);
    write_frame(&mut stream, &hello)?;
    let reply = read_frame(&mut stream)?;
    if reply.get("type").and_then(Json::as_str) != Some("hello_ok") {
        return Err(RelayFail::Violation(format!("hello rejected: {reply:?}")));
    }
    let begin = frame_signed(RELAY_PROTOCOL, &inner.transfer_key, 1, &Json::object([
        ("type", Json::string("stream_begin")),
    ]))
    .map_err(RelayFail::Violation)?;
    write_frame(&mut stream, &begin)?;
    let ready = read_frame(&mut stream)?;
    if ready.get("type").and_then(Json::as_str) != Some("stream_ready") {
        return Err(RelayFail::Violation(format!("stream rejected: {ready:?}")));
    }
    {
        let mut state = inner.state.lock().expect("relay client");
        state.cursor = 0;
        state.connected = true;
        state.last_error.clear();
    }
    let mut seq = 0i64;
    loop {
        for line in tail_once(inner)? {
            seq += 1;
            let parsed = loads_strict(&line).map_err(|error| RelayFail::Violation(error.message().to_string()))?;
            let Some(record) = parsed.get("record").cloned() else {
                return Err(RelayFail::Violation("record_missing_payload".to_string()));
            };
            let signed = frame_signed(
                RELAY_PROTOCOL,
                &inner.transfer_key,
                seq,
                &Json::object([
                    ("type", Json::string("record")),
                    ("record", record),
                ]),
            )
            .map_err(RelayFail::Violation)?;
            write_frame(&mut stream, &signed)?;
            let ack = read_frame(&mut stream)?;
            if ack.get("type").and_then(Json::as_str) == Some("violation") {
                let reason = ack.get("reason").and_then(Json::as_str).unwrap_or("");
                return Err(RelayFail::Violation(format!("relay: {reason}")));
            }
            if ack.get("type").and_then(Json::as_str) != Some("ack") {
                return Err(RelayFail::Violation(format!("unexpected relay reply: {ack:?}")));
            }
            let mut state = inner.state.lock().expect("relay client");
            if ack.get("dup").and_then(Json::as_bool) == Some(true) {
                state.dup_redeliveries += 1;
            } else {
                state.records_relayed += 1;
            }
        }
        if one_pass || inner.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        thread::sleep(inner.tick);
    }
}

fn tail_once(inner: &ClientInner) -> Result<Vec<String>, RelayFail> {
    let mut file = match fs::File::open(&inner.audit_path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(RelayFail::Io(error.to_string())),
    };
    let cursor = inner.state.lock().expect("relay client").cursor;
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(cursor)).map_err(|error| RelayFail::Io(error.to_string()))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).map_err(|error| RelayFail::Io(error.to_string()))?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&data);
    let complete_end = if text.ends_with('\n') {
        text.len()
    } else {
        text.rfind('\n').map(|index| index + 1).unwrap_or(0)
    };
    let complete = &text[..complete_end];
    inner.state.lock().expect("relay client").cursor = cursor + complete_end as u64;
    Ok(complete.lines().filter(|line| !line.trim().is_empty()).map(str::to_string).collect())
}

fn write_frame(stream: &mut TcpStream, message: &Json) -> Result<(), RelayFail> {
    let bytes = frame(message)?;
    stream.write_all(&bytes).map_err(|error| RelayFail::Io(error.to_string()))?;
    stream.flush().map_err(|error| RelayFail::Io(error.to_string()))
}

fn load_store(path: &Path, state: &mut ServerState, keyring: &KeyRing) {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(_) => {
            state.compromised = true;
            return;
        }
    };
    let mut head = GENESIS.to_string();
    let mut ids = BTreeMap::new();
    let mut count = 0i64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(stored) = loads_strict(line) else {
            state.compromised = true;
            return;
        };
        let Some(payload) = stored.get("record").cloned() else {
            state.compromised = true;
            return;
        };
        let Some(chain_prev) = stored.get("chain_prev").and_then(Json::as_str) else {
            state.compromised = true;
            return;
        };
        let Some(chain_mac) = stored.get("chain_mac").and_then(Json::as_str) else {
            state.compromised = true;
            return;
        };
        let Some(chain_hash) = stored.get("chain_hash").and_then(Json::as_str) else {
            state.compromised = true;
            return;
        };
        if !constant_time_eq(chain_prev, &head) {
            state.compromised = true;
            return;
        }
        let Ok((mac, chain)) = verify_record(&payload, &head, keyring) else {
            state.compromised = true;
            return;
        };
        if !constant_time_eq(&mac, chain_mac) || !constant_time_eq(&chain, chain_hash) {
            state.compromised = true;
            return;
        }
        let Some(event_id) = payload.get("event_id").and_then(Json::as_str) else {
            state.compromised = true;
            return;
        };
        if event_id.is_empty() {
            state.compromised = true;
            return;
        }
        if let Some(existing) = ids.get(event_id)
            && existing != &payload
        {
            state.compromised = true;
            return;
        }
        ids.insert(event_id.to_string(), payload);
        head = chain;
        count += 1;
    }
    state.head = head;
    state.ids = ids;
    state.stored_count = count;
}

fn append_bytes(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.flush().map_err(|error| error.to_string())?;
    Ok(())
}

fn write_control(path: &Path, event: &str, detail: &str) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    let line = Json::object([
        ("detail", Json::string(detail)),
        ("event", Json::string(event)),
        ("ts", json_number(seconds)),
    ]);
    if let Ok(mut bytes) = canonical_bytes(&line) {
        bytes.push(b'\n');
        let _ = append_bytes(path, &bytes);
    }
}

fn read_exact(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<(), RelayFail> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(RelayFail::Closed("peer closed".to_string())),
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if is_timeout(&error) => return Err(RelayFail::Timeout),
            Err(error)
                if error.kind() == std::io::ErrorKind::ConnectionReset
                    || error.kind() == std::io::ErrorKind::ConnectionAborted =>
            {
                return Err(RelayFail::Closed(format!("connection_lost: {error}")));
            }
            Err(error) => return Err(RelayFail::Io(error.to_string())),
        }
    }
    Ok(())
}

fn is_timeout(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::TimedOut
        || error.kind() == std::io::ErrorKind::WouldBlock
        || error.raw_os_error() == Some(10060)
}

fn json_i64(value: Option<&Json>) -> Option<i64> {
    match value {
        Some(Json::Int(number)) => Some(*number),
        Some(Json::Uint(number)) if *number <= i64::MAX as u64 => Some(*number as i64),
        _ => None,
    }
}

fn optional_text(value: &str) -> Json {
    if value.is_empty() {
        Json::Null
    } else {
        Json::string(value)
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}
