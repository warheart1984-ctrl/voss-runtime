//! External-action transport with its own accounting process.
//!
//! `external.send_mock` can be handed to a separate process. The host keeps
//! no copy of the event. A delivery counts only when that process returns a
//! receipt. The same idempotency key is delivered once. A dropped
//! acknowledgement leaves the host outcome unknown; the service ledger is
//! the record of what happened. Refusal, or a service that cannot be
//! reached, fails the effect closed. `--drop-ack` and `--refuse` are dev
//! stand-ins for a lost reply and an outage.

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

use crate::canonical::{Json, canonical_bytes, json_number, loads_strict, new_id};
use crate::relay::{self, RelayFail};

type HmacSha256 = Hmac<Sha256>;

pub const OUTBOX_PROTOCOL: &str = "voss.outbox.1";
const MAX_DIGEST_CHARS: usize = 128;

pub fn sign_outbox_hello(transfer_key: &[u8], nonce: &str, challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(OUTBOX_PROTOCOL.as_bytes());
    mac.update(b":");
    mac.update(challenge.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn sign_outbox_challenge(transfer_key: &[u8], challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(OUTBOX_PROTOCOL.as_bytes());
    mac.update(b":challenge:");
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn outbox_challenge_frame(transfer_key: &[u8], challenge: &str) -> Json {
    Json::object([
        ("mac", Json::string(sign_outbox_challenge(transfer_key, challenge))),
        ("challenge", Json::string(challenge)),
        ("type", Json::string("challenge")),
    ])
}

struct DeliveryFields {
    delivery_id: String,
    service: String,
    recipient: String,
    payload_digest: String,
    idempotency_key: String,
}

struct Store {
    receipts: BTreeMap<String, Json>,
    refuse: bool,
    seen_nonces: HashSet<String>, // this process only; not persisted
    auth_seq: i64,
    reply_seq: i64,
    frame_key: Vec<u8>,
}

struct ServerInner {
    control_path: PathBuf,
    ledger_path: PathBuf,
    delivered_dir: PathBuf,
    transfer_key: Vec<u8>,
    // Fresh per-process challenge: restarting the server mints a new one, so a
    // hello that echoed an earlier process's challenge (same transfer key) can
    // never open a session on this process.
    challenge: String,
    drop_ack: bool,
    store: Mutex<Store>,
    stop: AtomicBool,
    active: AtomicBool,
    listener: TcpListener,
}

pub struct OutboxServer {
    inner: Arc<ServerInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl OutboxServer {
    pub fn bind(
        store_dir: impl AsRef<Path>,
        transfer_key: Vec<u8>,
        drop_ack: bool,
        refuse: bool,
        port: u16,
    ) -> Result<Self, String> {
        if transfer_key.len() < 16 {
            return Err("transfer key must be at least 16 bytes".to_string());
        }
        let store_dir = store_dir.as_ref();
        fs::create_dir_all(store_dir).map_err(|error| error.to_string())?;
        let store_dir = fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
        let delivered_dir = store_dir.join("delivered");
        fs::create_dir_all(&delivered_dir).map_err(|error| error.to_string())?;
        let ledger_path = store_dir.join("outbox-receipts.jsonl");
        let receipts = load_receipts(&ledger_path, &delivered_dir)?;
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).map_err(|error| error.to_string())?;
        listener.set_nonblocking(true).map_err(|error| error.to_string())?;
        let inner = Arc::new(ServerInner {
            control_path: store_dir.join("outbox-control.jsonl"),
            ledger_path,
            delivered_dir,
            transfer_key,
            challenge: new_id("challenge-"),
            drop_ack,
            store: Mutex::new(Store {
                receipts,
                refuse,
                seen_nonces: HashSet::new(),
                auth_seq: 0,
                reply_seq: 0,
                frame_key: Vec::new(),
            }),
            stop: AtomicBool::new(false),
            active: AtomicBool::new(false),
            listener,
        });
        Ok(Self {
            inner,
            thread: Mutex::new(None),
        })
    }

    pub fn port(&self) -> u16 {
        self.inner.listener.local_addr().map(|addr| addr.port()).unwrap_or(0)
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("outbox thread");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        write_control(&inner.control_path, "outbox_started", &format!("pid={}", std::process::id()));
        *slot = Some(thread::spawn(move || serve_loop(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("outbox thread").take() {
            let _ = handle.join();
        }
    }
}

fn serve_loop(inner: Arc<ServerInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        match inner.listener.accept() {
            Ok((stream, _)) => dispatch(Arc::clone(&inner), stream),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn dispatch(inner: Arc<ServerInner>, stream: TcpStream) {
    if inner.active.swap(true, Ordering::SeqCst) {
        let mut stream = stream;
        prepare(&mut stream, Duration::from_secs(5));
        reply(&mut stream, &Json::object([("type", Json::string("busy"))]));
        write_control(&inner.control_path, "outbox_busy", "another host is connected");
        graceful_close(stream);
        return;
    }
    thread::spawn(move || {
        let stream = handle_connection(Arc::clone(&inner), stream);
        inner.active.store(false, Ordering::SeqCst);
        graceful_close(stream);
    });
}

fn handle_connection(inner: Arc<ServerInner>, mut stream: TcpStream) -> TcpStream {
    prepare(&mut stream, Duration::from_secs(120));
    // Speak first with this process's challenge; a valid hello must MAC over it.
    reply(&mut stream, &outbox_challenge_frame(&inner.transfer_key, &inner.challenge));
    let hello = match relay::read_frame(&mut stream) {
        Ok(message) => message,
        Err(_) => {
            write_control(&inner.control_path, "outbox_stream_closed", "before hello");
            return stream;
        }
    };
    if let Some(reason) = claim_hello(&inner, &hello) {
        write_control(
            &inner.control_path,
            "outbox_denied_hello",
            &format!("{reason}:{}", clip(&preview(&hello))),
        );
        reply(&mut stream, &ack_error("denied_outbox_auth"));
        return stream;
    }
    let nonce = hello.get("nonce").and_then(Json::as_str).unwrap_or("");
    let frame_key = relay::derive_session_key(
        OUTBOX_PROTOCOL,
        &inner.transfer_key,
        &inner.challenge,
        nonce,
    );
    {
        let mut store = inner.store.lock().expect("outbox store");
        store.auth_seq = 0;
        store.reply_seq = 0;
        store.frame_key = frame_key;
    }
    write_control(&inner.control_path, "outbox_accepted_hello", "host");
    if !reply_signed(&inner, &mut stream, &Json::object([("type", Json::string("hello_ok"))])) {
        return stream;
    }
    while !inner.stop.load(Ordering::SeqCst) {
        let message = match relay::read_frame(&mut stream) {
            Ok(message) => message,
            Err(RelayFail::Timeout) => continue,
            Err(RelayFail::Closed(_)) => return stream,
            Err(error) => {
                write_control(&inner.control_path, "outbox_stream_closed", &clip(&error.to_string()));
                return stream;
            }
        };
        if !relay::frame_is_authed(&message, OUTBOX_PROTOCOL, &inner.store.lock().expect("outbox store").frame_key) {
            write_control(&inner.control_path, "outbox_anomaly", "unauthenticated frame");
            return stream;
        }
        let expected = {
            let mut store = inner.store.lock().expect("outbox store");
            store.auth_seq += 1;
            store.auth_seq
        };
        if message.get("seq").and_then(Json::as_i64) != Some(expected) {
            write_control(
                &inner.control_path,
                "outbox_anomaly",
                &format!("sequence expected {expected}"),
            );
            return stream;
        }
        if message.get("type").and_then(Json::as_str) != Some("deliver") {
            let kind = message.get("type").and_then(Json::as_str);
            write_control(&inner.control_path, "outbox_anomaly", &format!("unknown frame {kind:?}"));
            return stream;
        }
        let fields = match check_deliver(&message) {
            Ok(fields) => fields,
            Err(error) => {
                write_control(&inner.control_path, "outbox_anomaly", &error);
                return stream;
            }
        };
        let (ack, dropped) = match accept_delivery(&inner, &fields) {
            Ok(value) => value,
            Err(_) => return stream,
        };
        if dropped {
            return stream;
        }
        if !reply_signed(&inner, &mut stream, &ack) {
            return stream;
        }
    }
    stream
}

fn claim_hello(inner: &ServerInner, message: &Json) -> Option<&'static str> {
    if !valid_hello(&inner.transfer_key, &inner.challenge, message) {
        return Some("denied_outbox_auth");
    }
    let nonce = message.get("nonce").and_then(Json::as_str).unwrap_or("");
    let mut store = inner.store.lock().expect("outbox store");
    if !store.seen_nonces.insert(nonce.to_string()) {
        return Some("replayed_hello_nonce");
    }
    None
}

fn reply_signed(inner: &ServerInner, stream: &mut TcpStream, message: &Json) -> bool {
    let seq = {
        let mut store = inner.store.lock().expect("outbox store");
        store.reply_seq += 1;
        store.reply_seq
    };
    let key = inner.store.lock().expect("outbox store").frame_key.clone();
    let Ok(signed) = relay::frame_signed(OUTBOX_PROTOCOL, &key, seq, message) else {
        return false;
    };
    reply(stream, &signed);
    true
}

fn accept_delivery(inner: &ServerInner, fields: &DeliveryFields) -> Result<(Json, bool), String> {
    let mut store = inner.store.lock().expect("outbox store");
    if let Some(prior) = store.receipts.get(&fields.idempotency_key).cloned() {
        if prior.get("service").and_then(Json::as_str) != Some(fields.service.as_str())
            || prior.get("recipient").and_then(Json::as_str) != Some(fields.recipient.as_str())
            || prior.get("payload_digest").and_then(Json::as_str) != Some(fields.payload_digest.as_str())
        {
            write_control(&inner.control_path, "outbox_idempotency_conflict", &fields.idempotency_key);
            return Ok((
                Json::object([
                    ("delivery_id", Json::string(&fields.delivery_id)),
                    ("reason", Json::string("idempotency key reused for different request")),
                    ("status", Json::string("refused")),
                    ("type", Json::string("delivered")),
                ]),
                false,
            ));
        }
        if let Err(error) = recover_delivery_file(&inner.delivered_dir, &prior) {
            store.refuse = true;
            write_control(&inner.control_path, "outbox_storage_failure", &clip(&error));
            return Ok((uncertain_reply(fields, &prior), false));
        }
        write_control(&inner.control_path, "outbox_duplicate", &fields.idempotency_key);
        return Ok((
            Json::object([
                ("delivered_at", prior.get("delivered_at").cloned().unwrap_or(Json::Null)),
                ("delivery_id", Json::string(&fields.delivery_id)),
                ("receipt_id", Json::string(prior.get("receipt_id").and_then(Json::as_str).unwrap_or(""))),
                ("status", Json::string("duplicate")),
                ("type", Json::string("delivered")),
            ]),
            false,
        ));
    }
    if store.refuse {
        write_control(&inner.control_path, "outbox_refused", &fields.idempotency_key);
        return Ok((
            Json::object([
                ("delivery_id", Json::string(&fields.delivery_id)),
                ("reason", Json::string("service refusing all deliveries")),
                ("status", Json::string("refused")),
                ("type", Json::string("delivered")),
            ]),
            false,
        ));
    }
    let receipt_id = new_id("rcpt-");
    let delivered_at = wall_now();
    let stamp = json_number(delivered_at);
    let record = Json::object([
        ("delivered_at", stamp.clone()),
        ("delivery_id", Json::string(&fields.delivery_id)),
        ("idempotency_key", Json::string(&fields.idempotency_key)),
        ("payload_digest", Json::string(&fields.payload_digest)),
        ("receipt_id", Json::string(&receipt_id)),
        ("recipient", Json::string(&fields.recipient)),
        ("service", Json::string(&fields.service)),
        ("status", Json::string("delivered")),
        ("ts", stamp),
    ]);
    if let Err(error) = append_ledger(&inner.ledger_path, &record) {
        store.refuse = true;
        write_control(&inner.control_path, "outbox_storage_failure", &clip(&error));
        return Err(error);
    }
    store.receipts.insert(fields.idempotency_key.clone(), record.clone());
    if let Err(error) = write_delivered(&inner.delivered_dir, &record) {
        store.refuse = true;
        write_control(&inner.control_path, "outbox_storage_failure", &clip(&error));
        return Ok((uncertain_reply(fields, &record), false));
    }
    write_control(
        &inner.control_path,
        "outbox_delivered",
        &format!("{receipt_id} key={}", fields.idempotency_key),
    );
    let ack = Json::object([
        ("delivered_at", json_number(delivered_at)),
        ("delivery_id", Json::string(&fields.delivery_id)),
        ("receipt_id", Json::string(&receipt_id)),
        ("status", Json::string("delivered")),
        ("type", Json::string("delivered")),
    ]);
    if inner.drop_ack {
        write_control(&inner.control_path, "outbox_dropped_ack", &fields.idempotency_key);
        return Ok((ack, true));
    }
    Ok((ack, false))
}

fn uncertain_reply(fields: &DeliveryFields, record: &Json) -> Json {
    Json::object([
        ("delivered_at", record.get("delivered_at").cloned().unwrap_or(Json::Null)),
        ("delivery_id", Json::string(&fields.delivery_id)),
        ("reason", Json::string("delivery recorded, response uncertain")),
        ("receipt_id", Json::string(record.get("receipt_id").and_then(Json::as_str).unwrap_or(""))),
        ("status", Json::string("uncertain")),
        ("type", Json::string("delivered")),
    ])
}

fn load_receipts(ledger_path: &Path, delivered_dir: &Path) -> Result<BTreeMap<String, Json>, String> {
    let text = match fs::read_to_string(ledger_path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(_) => return Err("cannot read outbox receipt ledger".to_string()),
    };
    let mut receipts = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line.is_empty() {
            return Err(format!("invalid outbox ledger at line {line_number}"));
        }
        let record = loads_strict(line).map_err(|_| format!("invalid outbox ledger at line {line_number}"))?;
        let Json::Object(_) = &record else {
            return Err(format!("invalid outbox ledger at line {line_number}"));
        };
        let idem = record.get("idempotency_key").and_then(Json::as_str).unwrap_or("");
        let receipt_id = record.get("receipt_id").and_then(Json::as_str).unwrap_or("");
        if idem.is_empty()
            || receipt_id.is_empty()
            || record.get("status").and_then(Json::as_str) != Some("delivered")
        {
            return Err(format!("invalid outbox ledger at line {line_number}"));
        }
        if receipts.contains_key(idem) {
            return Err(format!("duplicate idempotency key in outbox ledger at line {line_number}"));
        }
        for field in ["service", "recipient", "payload_digest", "delivery_id", "delivered_at"] {
            if record.get(field).is_none() {
                return Err(format!("incomplete outbox ledger at line {line_number}"));
            }
        }
        recover_delivery_file(delivered_dir, &record)?;
        receipts.insert(idem.to_string(), record);
    }
    Ok(receipts)
}

fn recover_delivery_file(delivered_dir: &Path, record: &Json) -> Result<(), String> {
    let receipt_id = record.get("receipt_id").and_then(Json::as_str).unwrap_or("");
    let path = delivered_dir.join(format!("{receipt_id}.json"));
    if path.exists() {
        let text = fs::read_to_string(&path).map_err(|_| "cannot verify outbox effect file".to_string())?;
        let existing = loads_strict(&text).map_err(|_| "cannot verify outbox effect file".to_string())?;
        if existing != *record {
            return Err("outbox effect disagrees with receipt ledger".to_string());
        }
        return Ok(());
    }
    write_delivered(delivered_dir, record)
}

fn append_ledger(path: &Path, record: &Json) -> Result<(), String> {
    let mut bytes = canonical_bytes(record).map_err(|error| error.message().to_string())?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().create(true).append(true).open(path).map_err(|error| error.to_string())?;
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    Ok(())
}

fn write_delivered(delivered_dir: &Path, record: &Json) -> Result<(), String> {
    let receipt_id = record.get("receipt_id").and_then(Json::as_str).unwrap_or("");
    let path = delivered_dir.join(format!("{receipt_id}.json"));
    let temp = PathBuf::from(format!("{}.tmp", path.display()));
    let bytes = canonical_bytes(record).map_err(|error| error.message().to_string())?;
    let _ = fs::remove_file(&temp);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| {
            let _ = fs::remove_file(&temp);
            error.to_string()
        })?;
        file.sync_all().map_err(|error| error.to_string())?;
    }
    let _ = bytes;
    fs::rename(&temp, &path).map_err(|error| {
        let _ = fs::remove_file(&temp);
        error.to_string()
    })
}

fn check_deliver(message: &Json) -> Result<DeliveryFields, String> {
    let field = |name: &str| -> Result<String, String> {
        match message.get(name).and_then(Json::as_str) {
            Some(value) if !value.is_empty() => Ok(value.to_string()),
            _ => Err(format!("missing or invalid field {name:?}")),
        }
    };
    let fields = DeliveryFields {
        delivery_id: field("delivery_id")?,
        service: field("service")?,
        recipient: field("recipient")?,
        payload_digest: field("payload_digest")?,
        idempotency_key: field("idempotency_key")?,
    };
    if fields.service != "mail" {
        return Err("unsupported external service".to_string());
    }
    if fields.payload_digest.chars().count() > MAX_DIGEST_CHARS {
        return Err("oversize payload_digest".to_string());
    }
    Ok(fields)
}

fn valid_hello(transfer_key: &[u8], challenge: &str, message: &Json) -> bool {
    if message.get("type").and_then(Json::as_str) != Some("hello") {
        return false;
    }
    if message.get("version").and_then(Json::as_str) != Some(OUTBOX_PROTOCOL) {
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
    constant_time_eq(&sign_outbox_hello(transfer_key, nonce, challenge), mac)
}

#[derive(Debug)]
pub enum OutboxError {
    Unavailable(String),
    Uncertain(String),
}

impl OutboxError {
    pub fn message(&self) -> &str {
        match self {
            Self::Unavailable(message) | Self::Uncertain(message) => message,
        }
    }
}

pub struct DeliveryReceipt {
    pub receipt_id: String,
    pub status: String,
    pub delivered_at: Option<f64>,
}

pub struct OutboxHealth {
    pub ok: bool,
    pub connected: bool,
    pub failed: bool,
    pub error: String,
}

struct LinkState {
    stream: Option<TcpStream>,
    connected: bool,
    ever_connected: bool,
    failed: bool,
    last_error: String,
    send_seq: i64,
    expect_seq: i64,
    frame_key: Vec<u8>,
}

struct LinkInner {
    host: String,
    port: u16,
    transfer_key: Vec<u8>,
    timeout: Duration,
    stop: AtomicBool,
    state: Mutex<LinkState>,
}

pub struct OutboxLink {
    inner: Arc<LinkInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl OutboxLink {
    pub fn new(host: impl Into<String>, port: u16, transfer_key: Vec<u8>) -> Self {
        Self::with_timeout(host, port, transfer_key, Duration::from_secs(2))
    }

    pub fn with_timeout(host: impl Into<String>, port: u16, transfer_key: Vec<u8>, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(LinkInner {
                host: host.into(),
                port,
                transfer_key,
                timeout,
                stop: AtomicBool::new(false),
                state: Mutex::new(LinkState {
                    stream: None,
                    connected: false,
                    ever_connected: false,
                    failed: false,
                    last_error: String::new(),
                    send_seq: 0,
                    expect_seq: 0,
                    frame_key: Vec::new(),
                }),
            }),
            thread: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("outbox link");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *slot = Some(thread::spawn(move || run_link(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("outbox link").take() {
            let _ = handle.join();
        }
        if let Some(stream) = self.inner.state.lock().expect("outbox link").stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    pub fn health(&self) -> OutboxHealth {
        let state = self.inner.state.lock().expect("outbox link");
        OutboxHealth {
            ok: state.connected && !state.failed && !self.inner.stop.load(Ordering::SeqCst),
            connected: state.connected,
            failed: state.failed,
            error: state.last_error.clone(),
        }
    }

    pub fn health_json(&self) -> Json {
        let health = self.health();
        Json::object([
            ("connected", Json::Bool(health.connected)),
            ("error", if health.error.is_empty() { Json::Null } else { Json::string(health.error) }),
            ("failed", Json::Bool(health.failed)),
            ("ok", Json::Bool(health.ok)),
        ])
    }

    pub fn deliver(
        &self,
        delivery_id: &str,
        service: &str,
        recipient: &str,
        payload_digest: &str,
        idempotency_key: &str,
    ) -> Result<DeliveryReceipt, OutboxError> {
        let mut state = self.inner.state.lock().expect("outbox link");
        if state.stream.is_none() {
            return Err(OutboxError::Unavailable("outbox accounting service unreachable".to_string()));
        }
        state.send_seq += 1;
        let send_seq = state.send_seq;
        let message = match relay::frame_signed(
            OUTBOX_PROTOCOL,
            &state.frame_key,
            send_seq,
            &Json::object([
                ("delivery_id", Json::string(delivery_id)),
                ("idempotency_key", Json::string(idempotency_key)),
                ("payload_digest", Json::string(payload_digest)),
                ("recipient", Json::string(recipient)),
                ("service", Json::string(service)),
                ("type", Json::string("deliver")),
            ]),
        ) {
            Ok(message) => message,
            Err(error) => return Err(OutboxError::Unavailable(error)),
        };
        let expect = state.expect_seq + 1;
        let stream = state.stream.as_mut().expect("stream checked");
        let _ = stream.set_read_timeout(Some(self.inner.timeout));
        let _ = stream.set_write_timeout(Some(self.inner.timeout));
        let reply = match write_frame(stream, &message).and_then(|_| relay::read_frame(stream).map_err(|error| error.to_string())) {
            Ok(reply) => reply,
            Err(error) => {
                state.connected = false;
                state.last_error = format!("outbox link lost: {error}");
                if let Some(stream) = state.stream.take() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                if state.ever_connected && !state.failed {
                    state.failed = true;
                }
                return Err(OutboxError::Uncertain(state.last_error.clone()));
            }
        };
        if !relay::frame_is_authed(&reply, OUTBOX_PROTOCOL, &state.frame_key) {
            return Err(OutboxError::Uncertain("reply failed authentication".to_string()));
        }
        if reply.get("type").and_then(Json::as_str) != Some("delivered") {
            return Err(OutboxError::Uncertain(format!("unexpected reply {reply:?}")));
        }
        if reply.get("seq").and_then(Json::as_i64) != Some(expect) {
            return Err(OutboxError::Uncertain(format!(
                "reply sequence expected {expect} got {:?}",
                reply.get("seq")
            )));
        }
        state.expect_seq = expect;
        let status = reply.get("status").and_then(Json::as_str).unwrap_or("");
        if status == "uncertain" {
            let reason = reply
                .get("reason")
                .and_then(Json::as_str)
                .unwrap_or("delivery recorded, response uncertain");
            return Err(OutboxError::Uncertain(reason.to_string()));
        }
        if status == "delivered" || status == "duplicate" {
            return Ok(DeliveryReceipt {
                receipt_id: reply.get("receipt_id").and_then(Json::as_str).unwrap_or("").to_string(),
                status: status.to_string(),
                delivered_at: reply.get("delivered_at").and_then(Json::as_f64),
            });
        }
        Err(OutboxError::Unavailable(format!("outbox refused delivery: {reply:?}")))
    }
}

fn run_link(inner: Arc<LinkInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        {
            let mut state = inner.state.lock().expect("outbox link");
            if state.stream.is_none()
                && !state.failed
                && !inner.stop.load(Ordering::SeqCst)
                && let Err(error) = open_session(&inner, &mut state)
            {
                state.connected = false;
                state.last_error = format!("outbox connect failed: {error}");
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn open_session(inner: &LinkInner, state: &mut LinkState) -> Result<(), String> {
    let address = format!("{}:{}", inner.host, inner.port);
    let mut stream = TcpStream::connect_timeout(
        &address.parse().map_err(|error: std::net::AddrParseError| error.to_string())?,
        inner.timeout,
    )
    .map_err(|error| error.to_string())?;
    stream.set_nodelay(true).map_err(|error| error.to_string())?;
    stream.set_nonblocking(false).map_err(|error| error.to_string())?;
    stream.set_read_timeout(Some(inner.timeout)).map_err(|error| error.to_string())?;
    stream.set_write_timeout(Some(inner.timeout)).map_err(|error| error.to_string())?;
    let challenge = relay::read_frame(&mut stream).map_err(|error| error.to_string())?;
    if challenge.get("type").and_then(Json::as_str) != Some("challenge") {
        return Err(format!("no challenge: {challenge:?}"));
    }
    let Some(challenge_value) = challenge.get("challenge").and_then(Json::as_str) else {
        return Err(format!("no challenge: {challenge:?}"));
    };
    if challenge.get("mac").and_then(Json::as_str) != Some(&sign_outbox_challenge(&inner.transfer_key, challenge_value)) {
        return Err("challenge failed authentication".to_string());
    }
    let nonce = new_id("ob-");
    let session_key = relay::derive_session_key(
        OUTBOX_PROTOCOL,
        &inner.transfer_key,
        challenge_value,
        &nonce,
    );
    let hello = Json::object([
        ("challenge", Json::string(challenge_value)),
        ("mac", Json::string(sign_outbox_hello(&inner.transfer_key, &nonce, challenge_value))),
        ("nonce", Json::string(nonce)),
        ("type", Json::string("hello")),
        ("version", Json::string(OUTBOX_PROTOCOL)),
    ]);
    if let Err(error) = write_frame(&mut stream, &hello).and_then(|_| {
        let reply = relay::read_frame(&mut stream).map_err(|error| error.to_string())?;
        if reply.get("type").and_then(Json::as_str) != Some("hello_ok") {
            return Err(format!("hello refused: {reply:?}"));
        }
        if !relay::frame_is_authed(&reply, OUTBOX_PROTOCOL, &session_key) {
            return Err("hello_ok failed authentication".to_string());
        }
        if reply.get("seq").and_then(Json::as_i64) != Some(1) {
            return Err(format!("unexpected hello_ok seq {:?}", reply.get("seq")));
        }
        Ok(())
    }) {
        let _ = stream.shutdown(Shutdown::Both);
        return Err(error);
    }
        state.send_seq = 0;
        state.expect_seq = 1;
        state.frame_key = session_key;
    state.stream = Some(stream);
    state.connected = true;
    state.ever_connected = true;
    state.last_error.clear();
    Ok(())
}

fn prepare(stream: &mut TcpStream, timeout: Duration) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
}

fn ack_error(reason: &str) -> Json {
    Json::object([
        ("reason", Json::string(reason)),
        ("status", Json::string("error")),
        ("type", Json::string("ack")),
    ])
}

fn reply(stream: &mut TcpStream, message: &Json) {
    let _ = write_frame(stream, message);
}

fn write_frame(stream: &mut TcpStream, message: &Json) -> Result<(), String> {
    let bytes = relay::frame(message).map_err(|error| error.to_string())?;
    stream.write_all(&bytes).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    Ok(())
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

fn write_control(path: &Path, event: &str, detail: &str) {
    let seconds = wall_now();
    let line = Json::object([
        ("detail", Json::string(detail)),
        ("event", Json::string(event)),
        ("ts", json_number(seconds)),
    ]);
    if let Ok(mut bytes) = canonical_bytes(&line) {
        bytes.push(b'\n');
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(&bytes);
            let _ = file.flush();
        }
    }
}

fn preview(message: &Json) -> String {
    canonical_bytes(message)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
}

fn clip(value: &str) -> String {
    value.chars().take(120).collect()
}

fn wall_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
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
