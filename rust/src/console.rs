//! Operator approval console outside the trusted host.
//!
//! The human gesture lives in its own process. The host publishes approval
//! views over an authenticated socket and receives votes and the kill switch
//! on that same socket. The console holds no keys and cannot grant anything
//! by itself: every vote still round-trips the runtime.
//!
//! If the console is not live, consequential approvals are denied. They are
//! never queued and never auto-granted. `--auto` is a dev stand-in for the
//! gesture.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::canonical::{Json, canonical_bytes, json_number, new_id};
use crate::relay::{self, RelayFail};

type HmacSha256 = Hmac<Sha256>;
type VoteHandler = Arc<dyn Fn(String, String, String) + Send + Sync>;
type TextHandler = Arc<dyn Fn(String) + Send + Sync>;

pub const CONSOLE_PROTOCOL: &str = "voss.console.1";

pub fn sign_console_hello(transfer_key: &[u8], nonce: &str, challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(CONSOLE_PROTOCOL.as_bytes());
    mac.update(b":");
    mac.update(challenge.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn sign_console_challenge(transfer_key: &[u8], challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(CONSOLE_PROTOCOL.as_bytes());
    mac.update(b":challenge:");
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn console_challenge_frame(transfer_key: &[u8], challenge: &str) -> Json {
    Json::object([
        ("mac", Json::string(sign_console_challenge(transfer_key, challenge))),
        ("challenge", Json::string(challenge)),
        ("type", Json::string("challenge")),
    ])
}

struct ServerInner {
    control_path: PathBuf,
    transcript_path: PathBuf,
    transfer_key: Vec<u8>,
    // Fresh per-process challenge: restarting the server mints a new one, so a
    // hello that echoed an earlier process's challenge (same transfer key) can
    // never open a session on this process.
    challenge: String,
    auto: Option<String>,
    delay: Duration,
    approver_ref: String,
    stop: AtomicBool,
    active: AtomicBool,
    listener: TcpListener,
    conn: Mutex<Option<TcpStream>>,
    send: Mutex<()>,
    auth: Mutex<ConsoleAuth>,
}

struct ConsoleAuth {
    seen: HashSet<String>, // hello nonces, this process only
    auth_seq: i64,
    send_seq: i64,
}

pub struct ConsoleServer {
    inner: Arc<ServerInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ConsoleServer {
    pub fn bind(
        store_dir: impl AsRef<Path>,
        transfer_key: Vec<u8>,
        auto: Option<String>,
        delay: Duration,
        port: u16,
    ) -> Result<Self, String> {
        if transfer_key.len() < 16 {
            return Err("transfer key must be at least 16 bytes".to_string());
        }
        if let Some(auto) = &auto
            && auto != "approve"
            && auto != "deny"
            && auto != "cancel"
        {
            return Err("--auto must be approve|deny|cancel".to_string());
        }
        let store_dir = store_dir.as_ref();
        fs::create_dir_all(store_dir).map_err(|error| error.to_string())?;
        let store_dir = fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
        let listener = TcpListener::bind(format!("127.0.0.1:{port}")).map_err(|error| error.to_string())?;
        listener.set_nonblocking(true).map_err(|error| error.to_string())?;
        let inner = Arc::new(ServerInner {
            control_path: store_dir.join("console-control.jsonl"),
            transcript_path: store_dir.join("console-transcript.jsonl"),
            transfer_key,
            challenge: new_id("challenge-"),
            auto,
            delay,
            approver_ref: format!("operator@console:{}", std::process::id()),
            stop: AtomicBool::new(false),
            active: AtomicBool::new(false),
            listener,
            conn: Mutex::new(None),
            send: Mutex::new(()),
            auth: Mutex::new(ConsoleAuth {
                seen: HashSet::new(),
                auth_seq: 0,
                send_seq: 0,
            }),
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
        let mut slot = self.thread.lock().expect("console thread");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        let auto_label = inner.auto.clone().unwrap_or_else(|| "interactive".to_string());
        write_control(
            &inner.control_path,
            "console_started",
            &format!("pid={} auto={auto_label}", std::process::id()),
        );
        *slot = Some(thread::spawn(move || serve_loop(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("console thread").take() {
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
        write_control(&inner.control_path, "console_busy", "another host is connected");
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
    prepare(&mut stream, Duration::from_secs(60));
    // Speak first with this process's challenge; a valid hello must MAC over it.
    reply(&mut stream, &console_challenge_frame(&inner.transfer_key, &inner.challenge));
    let hello = match relay::read_frame(&mut stream) {
        Ok(message) => message,
        Err(_) => {
            write_control(&inner.control_path, "console_stream_closed", "before hello");
            return stream;
        }
    };
    if let Some(reason) = claim_hello(&inner, &hello) {
        write_control(
            &inner.control_path,
            "console_denied_hello",
            &format!("{reason}:{}", clip(&preview(&hello))),
        );
        reply(&mut stream, &ack_error("denied_console_auth"));
        return stream;
    }
    write_control(&inner.control_path, "console_accepted_hello", "host");
    reply(&mut stream, &Json::object([("type", Json::string("hello_ok"))]));
    {
        let mut auth = inner.auth.lock().expect("console auth");
        auth.auth_seq = 0;
        auth.send_seq = 0;
    }
    {
        let mut slot = inner.conn.lock().expect("console socket");
        *slot = stream.try_clone().ok();
    }
    if inner.auto.is_none() {
        let commands = Arc::clone(&inner);
        thread::spawn(move || command_loop(commands));
    }
    while !inner.stop.load(Ordering::SeqCst) {
        let message = match relay::read_frame(&mut stream) {
            Ok(message) => message,
            Err(RelayFail::Timeout) => continue,
            Err(RelayFail::Closed(_)) => break,
            Err(error) => {
                write_control(&inner.control_path, "console_stream_closed", &clip(&error.to_string()));
                break;
            }
        };
        if !relay::frame_is_authed(&message, CONSOLE_PROTOCOL, &inner.transfer_key) {
            write_control(&inner.control_path, "console_anomaly", "unauthenticated frame");
            break;
        }
        let expected = {
            let mut auth = inner.auth.lock().expect("console auth");
            auth.auth_seq += 1;
            auth.auth_seq
        };
        if message.get("seq").and_then(Json::as_i64) != Some(expected) {
            write_control(
                &inner.control_path,
                "console_anomaly",
                &format!("sequence_error expected {expected}"),
            );
            break;
        }
        match message.get("type").and_then(Json::as_str) {
            Some("approval_view") => {
                let flow_id = message.get("flow_id").and_then(Json::as_str).unwrap_or("").to_string();
                record_view(&inner, &flow_id, message.get("view"));
                write_control(&inner.control_path, "console_view", &format!("flow={flow_id}"));
                println!("[approval] flow={flow_id} -> type approve|deny|cancel or 'kill <reason>'");
                let _ = io::stdout().flush();
                if inner.auto.is_some() {
                    let flow_id = flow_id.clone();
                    let voter = Arc::clone(&inner);
                    thread::spawn(move || {
                        thread::sleep(voter.delay);
                        let decision = voter.auto.clone().unwrap_or_default().to_ascii_uppercase();
                        vote(&voter, &flow_id, &decision);
                    });
                }
            }
            Some("approval_result") => {
                let flow_id = text_field(&message, "flow_id");
                let decision = text_field(&message, "decision");
                let approver = text_field(&message, "approver_ref");
                append_transcript(&inner.transcript_path, "result", &[
                    ("approver_ref", Json::string(&approver)),
                    ("decision", Json::string(&decision)),
                    ("flow_id", Json::string(&flow_id)),
                ]);
                write_control(
                    &inner.control_path,
                    "console_result",
                    &format!("flow={flow_id} decision={decision}"),
                );
            }
            Some(kind) => {
                write_control(&inner.control_path, "console_anomaly", &format!("unknown frame {kind:?}"));
                break;
            }
            None => {
                write_control(&inner.control_path, "console_anomaly", "unknown frame None");
                break;
            }
        }
    }
    *inner.conn.lock().expect("console socket") = None;
    stream
}

fn command_loop(inner: Arc<ServerInner>) {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            break;
        };
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let mut parts = line.split_whitespace();
        let Some(head) = parts.next() else {
            continue;
        };
        if head.eq_ignore_ascii_case("kill") {
            let reason = parts.next().unwrap_or("operator").to_string();
            send_conn(&inner, &Json::object([
                ("reason", Json::string(&reason)),
                ("type", Json::string("terminate")),
            ]));
            write_control(&inner.control_path, "console_terminate_directive", &reason);
            append_transcript(&inner.transcript_path, "terminate", &[("reason", Json::string(&reason))]);
            continue;
        }
        let Some(gesture) = parts.next() else {
            continue;
        };
        if parts.next().is_some() {
            continue;
        }
        let gesture = gesture.to_ascii_lowercase();
        if gesture != "approve" && gesture != "deny" && gesture != "cancel" {
            continue;
        }
        vote(&inner, head, &gesture.to_ascii_uppercase());
    }
}

fn vote(inner: &ServerInner, flow_id: &str, decision: &str) {
    send_conn(inner, &Json::object([
        ("approver_ref", Json::string(&inner.approver_ref)),
        ("decision", Json::string(decision)),
        ("flow_id", Json::string(flow_id)),
        ("type", Json::string("vote")),
    ]));
    write_control(&inner.control_path, "console_vote", &format!("flow={flow_id} decision={decision}"));
    append_transcript(&inner.transcript_path, "vote", &[
        ("approver_ref", Json::string(&inner.approver_ref)),
        ("decision", Json::string(decision)),
        ("flow_id", Json::string(flow_id)),
    ]);
}

fn send_conn(inner: &ServerInner, message: &Json) {
    let _guard = inner.send.lock().expect("console send");
    let seq = {
        let mut auth = inner.auth.lock().expect("console auth");
        auth.send_seq += 1;
        auth.send_seq
    };
    let Ok(signed) = relay::frame_signed(CONSOLE_PROTOCOL, &inner.transfer_key, seq, message) else {
        return;
    };
    let mut slot = inner.conn.lock().expect("console socket");
    let Some(stream) = slot.as_mut() else {
        return;
    };
    if let Ok(bytes) = relay::frame(&signed) {
        let _ = stream.write_all(&bytes);
        let _ = stream.flush();
    }
}

fn record_view(inner: &ServerInner, flow_id: &str, view: Option<&Json>) {
    let field = |key: &str| view.and_then(|view| view.get(key)).cloned().unwrap_or(Json::Null);
    append_transcript(&inner.transcript_path, "view", &[
        ("action", field("action")),
        ("consequences", field("consequences")),
        ("expires_in_seconds", field("expires_in_seconds")),
        ("flow_id", Json::string(flow_id)),
        ("payload_digest", field("payload_digest")),
        ("resource", field("resource")),
        ("reversible", field("reversible")),
        ("risk_class", field("risk_class")),
    ]);
}

pub struct ConsoleHealth {
    pub ok: bool,
    pub connected: bool,
    pub failed: bool,
    pub error: String,
}

struct ClientState {
    connected: bool,
    ever_connected: bool,
    failed: bool,
    last_error: String,
    send_seq: i64,
    expect_seq: i64,
}

struct ClientInner {
    host: String,
    port: u16,
    transfer_key: Vec<u8>,
    timeout: Duration,
    stop: AtomicBool,
    state: Mutex<ClientState>,
    writer: Mutex<Option<TcpStream>>,
    on_vote: Mutex<Option<VoteHandler>>,
    on_terminate: Mutex<Option<TextHandler>>,
    on_failure: Mutex<Option<TextHandler>>,
}

pub struct ConsoleClient {
    inner: Arc<ClientInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl ConsoleClient {
    pub fn new(host: impl Into<String>, port: u16, transfer_key: Vec<u8>) -> Self {
        Self::with_timeout(host, port, transfer_key, Duration::from_secs(2))
    }

    pub fn with_timeout(host: impl Into<String>, port: u16, transfer_key: Vec<u8>, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(ClientInner {
                host: host.into(),
                port,
                transfer_key,
                timeout,
                stop: AtomicBool::new(false),
                state: Mutex::new(ClientState {
                    connected: false,
                    ever_connected: false,
                    failed: false,
                    last_error: String::new(),
                    send_seq: 0,
                    expect_seq: 0,
                }),
                writer: Mutex::new(None),
                on_vote: Mutex::new(None),
                on_terminate: Mutex::new(None),
                on_failure: Mutex::new(None),
            }),
            thread: Mutex::new(None),
        }
    }

    pub fn set_on_vote(&self, callback: impl Fn(String, String, String) + Send + Sync + 'static) {
        *self.inner.on_vote.lock().expect("console vote") = Some(Arc::new(callback));
    }

    pub fn set_on_terminate(&self, callback: impl Fn(String) + Send + Sync + 'static) {
        *self.inner.on_terminate.lock().expect("console terminate") = Some(Arc::new(callback));
    }

    pub fn set_on_failure(&self, callback: impl Fn(String) + Send + Sync + 'static) {
        *self.inner.on_failure.lock().expect("console failure") = Some(Arc::new(callback));
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("console client");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *slot = Some(thread::spawn(move || run_client(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(stream) = self.inner.writer.lock().expect("console writer").take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.thread.lock().expect("console client").take() {
            let _ = handle.join();
        }
    }

    pub fn health(&self) -> ConsoleHealth {
        let state = self.inner.state.lock().expect("console client");
        ConsoleHealth {
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

    pub fn publish_view(&self, flow_id: &str, view: &Json) {
        self.send_best_effort(&Json::object([
            ("flow_id", Json::string(flow_id)),
            ("type", Json::string("approval_view")),
            ("view", view.clone()),
        ]));
    }

    pub fn publish_result(&self, flow_id: &str, decision: &str, approver_ref: &str) {
        self.send_best_effort(&Json::object([
            ("approver_ref", Json::string(approver_ref)),
            ("decision", Json::string(decision)),
            ("flow_id", Json::string(flow_id)),
            ("type", Json::string("approval_result")),
        ]));
    }

    fn send_best_effort(&self, message: &Json) {
        let seq = {
            let mut state = self.inner.state.lock().expect("console client");
            state.send_seq += 1;
            state.send_seq
        };
        let Ok(signed) = relay::frame_signed(CONSOLE_PROTOCOL, &self.inner.transfer_key, seq, message) else {
            return;
        };
        let mut slot = self.inner.writer.lock().expect("console writer");
        let Some(stream) = slot.as_mut() else {
            return;
        };
        if let Err(error) = write_frame(stream, &signed) {
            drop(slot);
            record_error(&self.inner, format!("console link lost: {error}"));
        }
    }
}

fn run_client(inner: Arc<ClientInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        if inner.state.lock().expect("console client").failed {
            return;
        }
        if let Err(error) = session(&inner) {
            if inner.stop.load(Ordering::SeqCst) {
                return;
            }
            record_error(&inner, format!("console session failed: {error}"));
        }
        if inner.stop.load(Ordering::SeqCst) || inner.state.lock().expect("console client").failed {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn session(inner: &ClientInner) -> Result<(), String> {
    {
        let mut state = inner.state.lock().expect("console client");
        state.send_seq = 0;
        state.expect_seq = 0;
    }
    let stream = connect_hello(inner)?;
    let mut reader = stream.try_clone().map_err(|error| error.to_string())?;
    *inner.writer.lock().expect("console writer") = Some(stream);
    let result = read_votes(inner, &mut reader);
    let _ = inner.writer.lock().expect("console writer").take();
    inner.state.lock().expect("console client").connected = false;
    result
}

fn connect_hello(inner: &ClientInner) -> Result<TcpStream, String> {
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
    if challenge.get("mac").and_then(Json::as_str) != Some(&sign_console_challenge(&inner.transfer_key, challenge_value)) {
        return Err("challenge failed authentication".to_string());
    }
    let nonce = new_id("console-");
    write_frame(&mut stream, &Json::object([
        ("challenge", Json::string(challenge_value)),
        ("mac", Json::string(sign_console_hello(&inner.transfer_key, &nonce, challenge_value))),
        ("nonce", Json::string(nonce)),
        ("type", Json::string("hello")),
        ("version", Json::string(CONSOLE_PROTOCOL)),
    ]))?;
    let reply = relay::read_frame(&mut stream).map_err(|error| error.to_string())?;
    if reply.get("type").and_then(Json::as_str) != Some("hello_ok") {
        return Err(format!("hello refused: {reply:?}"));
    }
    let mut state = inner.state.lock().expect("console client");
    state.connected = true;
    state.ever_connected = true;
    state.last_error.clear();
    Ok(stream)
}

fn read_votes(inner: &ClientInner, reader: &mut TcpStream) -> Result<(), String> {
    while !inner.stop.load(Ordering::SeqCst) {
        let message = relay::read_frame(reader).map_err(|error| error.to_string())?;
        let kind = message.get("type").and_then(Json::as_str);
        if kind == Some("vote") || kind == Some("terminate") {
            let expected = {
                let state = inner.state.lock().expect("console client");
                state.expect_seq + 1
            };
            let valid = relay::frame_is_authed(&message, CONSOLE_PROTOCOL, &inner.transfer_key)
                && message.get("seq").and_then(Json::as_i64) == Some(expected);
            if !valid {
                inner.state.lock().expect("console client").expect_seq += 1;
                record_error(
                    inner,
                    format!(
                        "console frame failed authentication (seq {:?}, expected {expected})",
                        message.get("seq")
                    ),
                );
                return Ok(());
            }
            inner.state.lock().expect("console client").expect_seq = expected;
        }
        match kind {
            Some("vote") => {
                let vote = inner.on_vote.lock().expect("console vote").clone();
                if let Some(vote) = vote {
                    vote(
                        text_field(&message, "flow_id"),
                        message.get("decision").and_then(Json::as_str).unwrap_or("DENY").to_string(),
                        text_field(&message, "approver_ref"),
                    );
                }
            }
            Some("terminate") => {
                let terminate = inner.on_terminate.lock().expect("console terminate").clone();
                if let Some(terminate) = terminate {
                    let reason = message.get("reason").and_then(Json::as_str).unwrap_or("operator");
                    terminate(reason.to_string());
                }
            }
            Some("busy") => return Err("console busy".to_string()),
            Some("ack") => {}
            Some(kind) => record_error(inner, format!("unexpected console frame {kind:?}")),
            None => record_error(inner, "unexpected console frame None".to_string()),
        }
    }
    Ok(())
}

fn record_error(inner: &ClientInner, error: String) {
    let callback = {
        let mut state = inner.state.lock().expect("console client");
        state.connected = false;
        state.last_error = error.clone();
        if state.ever_connected && !state.failed {
            state.failed = true;
            inner.on_failure.lock().expect("console failure").clone()
        } else {
            None
        }
    };
    if let Some(callback) = callback {
        callback(error);
    }
}

fn write_frame(stream: &mut TcpStream, message: &Json) -> Result<(), String> {
    let bytes = relay::frame(message).map_err(|error| error.to_string())?;
    stream.write_all(&bytes).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    Ok(())
}

fn claim_hello(inner: &ServerInner, message: &Json) -> Option<&'static str> {
    if !valid_hello(&inner.transfer_key, &inner.challenge, message) {
        return Some("denied_console_auth");
    }
    let nonce = message.get("nonce").and_then(Json::as_str).unwrap_or("");
    let mut auth = inner.auth.lock().expect("console auth");
    if !auth.seen.insert(nonce.to_string()) {
        return Some("replayed_hello_nonce");
    }
    None
}

fn valid_hello(transfer_key: &[u8], challenge: &str, message: &Json) -> bool {
    if message.get("type").and_then(Json::as_str) != Some("hello") {
        return false;
    }
    if message.get("version").and_then(Json::as_str) != Some(CONSOLE_PROTOCOL) {
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
    constant_time_eq(&sign_console_hello(transfer_key, nonce, challenge), mac)
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

fn append_transcript(path: &Path, kind: &str, fields: &[(&str, Json)]) {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs_f64()).unwrap_or(0.0);
    let mut pairs = vec![("kind".to_string(), Json::string(kind)), ("ts".to_string(), json_number(seconds))];
    for (key, value) in fields {
        pairs.push(((*key).to_string(), value.clone()));
    }
    let line = Json::object(pairs);
    if let Ok(mut bytes) = canonical_bytes(&line) {
        bytes.push(b'\n');
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = file.write_all(&bytes);
            let _ = file.flush();
        }
    }
}

fn write_control(path: &Path, event: &str, detail: &str) {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map(|duration| duration.as_secs_f64()).unwrap_or(0.0);
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

fn text_field(message: &Json, key: &str) -> String {
    message.get(key).and_then(Json::as_str).unwrap_or("").to_string()
}

fn preview(message: &Json) -> String {
    canonical_bytes(message).map(|bytes| String::from_utf8_lossy(&bytes).into_owned()).unwrap_or_default()
}

fn clip(value: &str) -> String {
    value.chars().take(120).collect()
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
