//! Kill authority outside the trusted host.
//!
//! The in-process watchdog can suspend and revoke, but a compromised host
//! would own that switch. This process holds the worker pid. It terminates
//! that process when authenticated heartbeats stop or an explicit terminate
//! directive arrives. After it triggers, it refuses every new session.
//!
//! The host link fails closed too: once a session has succeeded, a lost
//! guard or a `triggered` report suspends the worker. The pid is still
//! asserted by the host at registration.

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::canonical::{Json, canonical_bytes, json_number, new_id};
use crate::relay::{self, RelayFail};

type HmacSha256 = Hmac<Sha256>;
type FailureHandler = Arc<dyn Fn(String) + Send + Sync>;

pub const GUARD_PROTOCOL: &str = "voss.watchguard.1";
const DEFAULT_TICK: Duration = Duration::from_millis(500);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

pub fn sign_guard_hello(transfer_key: &[u8], nonce: &str, challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(GUARD_PROTOCOL.as_bytes());
    mac.update(b":");
    mac.update(challenge.as_bytes());
    mac.update(b":");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn sign_guard_challenge(transfer_key: &[u8], challenge: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(transfer_key).expect("HMAC accepts this key");
    mac.update(GUARD_PROTOCOL.as_bytes());
    mac.update(b":challenge:");
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn guard_challenge_frame(transfer_key: &[u8], challenge: &str) -> Json {
    Json::object([
        ("mac", Json::string(sign_guard_challenge(transfer_key, challenge))),
        ("challenge", Json::string(challenge)),
        ("type", Json::string("challenge")),
    ])
}

struct GuardState {
    pid: Option<u32>,
    registered: bool,
    triggered: bool,
    last_heartbeat: Option<Instant>,
    seen_nonces: HashSet<String>, // hello nonces, this process only
}

struct ServerInner {
    control_path: PathBuf,
    transfer_key: Vec<u8>,
    // Fresh per-process challenge: restarting the server mints a new one, so a
    // hello that echoed an earlier process's challenge (same transfer key) can
    // never open a session on this process.
    challenge: String,
    idle: Duration,
    stop: AtomicBool,
    active: AtomicBool,
    state: Mutex<GuardState>,
    listener: TcpListener,
}

pub struct WatchGuardServer {
    inner: Arc<ServerInner>,
    threads: Mutex<Option<(JoinHandle<()>, JoinHandle<()>)>>,
}

impl WatchGuardServer {
    pub fn bind(
        store_dir: impl AsRef<Path>,
        transfer_key: Vec<u8>,
        idle_timeout: Duration,
    ) -> Result<Self, String> {
        Self::bind_on(store_dir, transfer_key, idle_timeout, 0)
    }

    pub fn bind_on(
        store_dir: impl AsRef<Path>,
        transfer_key: Vec<u8>,
        idle_timeout: Duration,
        port: u16,
    ) -> Result<Self, String> {
        if transfer_key.len() < 16 {
            return Err("transfer key must be at least 16 bytes".to_string());
        }
        let store_dir = store_dir.as_ref();
        fs::create_dir_all(store_dir).map_err(|error| error.to_string())?;
        let store_dir = fs::canonicalize(store_dir).unwrap_or_else(|_| store_dir.to_path_buf());
        let address = format!("127.0.0.1:{port}");
        let listener = TcpListener::bind(address).map_err(|error| error.to_string())?;
        listener.set_nonblocking(true).map_err(|error| error.to_string())?;
        Ok(Self {
            inner: Arc::new(ServerInner {
                control_path: store_dir.join("guard-control.jsonl"),
                transfer_key,
                challenge: new_id("challenge-"),
                idle: idle_timeout.max(Duration::from_millis(200)),
                stop: AtomicBool::new(false),
                active: AtomicBool::new(false),
                state: Mutex::new(GuardState {
                    pid: None,
                    registered: false,
                    triggered: false,
                    last_heartbeat: None,
                    seen_nonces: HashSet::new(),
                }),
                listener,
            }),
            threads: Mutex::new(None),
        })
    }

    pub fn port(&self) -> u16 {
        self.inner.listener.local_addr().map(|addr| addr.port()).unwrap_or(0)
    }

    pub fn start(&self) {
        let mut slot = self.threads.lock().expect("guard threads");
        if slot.is_some() {
            return;
        }
        let serve = Arc::clone(&self.inner);
        let monitor = Arc::clone(&self.inner);
        *slot = Some((
            thread::spawn(move || serve_loop(serve)),
            thread::spawn(move || monitor_loop(monitor)),
        ));
        write_control(
            &self.inner.control_path,
            "guard_started",
            &format!("pid={}", std::process::id()),
        );
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some((serve, monitor)) = self.threads.lock().expect("guard threads").take() {
            let _ = serve.join();
            let _ = monitor.join();
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

fn dispatch(inner: &Arc<ServerInner>, stream: TcpStream) {
    let triggered = inner.state.lock().expect("guard state").triggered;
    if triggered {
        write_control(&inner.control_path, "guard_refused_triggered", "connection after trigger");
        let inner = Arc::clone(inner);
        thread::spawn(move || handle_connection(&inner, stream));
        return;
    }
    if inner.active.swap(true, Ordering::SeqCst) {
        let mut stream = stream;
        prepare_stream(&mut stream, inner.idle);
        reply(&mut stream, &Json::object([("type", Json::string("busy"))]));
        write_control(&inner.control_path, "guard_busy", "another host is connected");
        graceful_close(stream);
        return;
    }
    let inner = Arc::clone(inner);
    thread::spawn(move || {
        handle_connection(&inner, stream);
        inner.active.store(false, Ordering::SeqCst);
    });
}

fn handle_connection(inner: &ServerInner, mut stream: TcpStream) {
    prepare_stream(&mut stream, inner.idle);
    // Speak first with this process's challenge; a valid hello must MAC over it.
    reply(&mut stream, &guard_challenge_frame(&inner.transfer_key, &inner.challenge));
    let mut phase = "hello";
    let mut auth_seq = 1i64;
    let mut conn_tick: Option<i64> = None;
    while !inner.stop.load(Ordering::SeqCst) {
        if inner.state.lock().expect("guard state").triggered {
            reply(&mut stream, &ack("triggered", None));
            break;
        }
        let message = match relay::read_frame(&mut stream) {
            Ok(message) => message,
            Err(RelayFail::Timeout) => continue,
            Err(RelayFail::Closed(_)) => break,
            Err(error) => {
                write_control(&inner.control_path, "guard_stream_issue", &clip(&error.to_string()));
                break;
            }
        };
        if phase == "hello" {
            if let Some(reason) = claim_hello(inner, &message) {
                write_control(
                    &inner.control_path,
                    "guard_denied_hello",
                    &format!("{reason}:{}", clip(&preview(&message))),
                );
                reply(&mut stream, &ack("error", Some("denied_guard_auth")));
                break;
            }
            write_control(&inner.control_path, "guard_hello_ok", "guard");
            reply(&mut stream, &ack("ok", None));
            phase = "guard";
            auth_seq = 1;
            inner.state.lock().expect("guard state").last_heartbeat = Some(Instant::now());
            continue;
        }
        if !relay::frame_is_authed(&message, GUARD_PROTOCOL, &inner.transfer_key) {
            write_control(&inner.control_path, "guard_anomaly", "unauthenticated frame");
            reply(&mut stream, &ack("error", Some("denied_guard_auth")));
            break;
        }
        if message.get("seq").and_then(Json::as_i64) != Some(auth_seq) {
            write_control(
                &inner.control_path,
                "guard_anomaly",
                &format!("sequence_error expected {auth_seq}"),
            );
            reply(&mut stream, &ack("error", Some("sequence_error")));
            break;
        }
        auth_seq += 1;
        match message.get("type").and_then(Json::as_str) {
            Some("register") => {
                if inner.state.lock().expect("guard state").registered {
                    reply(&mut stream, &ack("error", Some("guard_already_registered")));
                    break;
                }
                let Some(pid) = positive_u32(message.get("pid")) else {
                    reply(&mut stream, &ack("error", Some("invalid_pid")));
                    break;
                };
                {
                    let mut state = inner.state.lock().expect("guard state");
                    state.pid = Some(pid);
                    state.registered = true;
                    state.last_heartbeat = Some(Instant::now());
                }
                write_control(&inner.control_path, "guard_register", &format!("pid={pid}"));
                reply(&mut stream, &ack("ok", None));
            }
            Some("heartbeat") => {
                let Some(tick) = nonneg_i64(message.get("tick")) else {
                    reply(&mut stream, &ack("error", Some("invalid_tick")));
                    break;
                };
                if conn_tick.is_some_and(|previous| tick <= previous) {
                    write_control(
                        &inner.control_path,
                        "guard_anomaly",
                        &format!("heartbeat tick regressed {}->{tick}", conn_tick.unwrap_or(0)),
                    );
                    reply(&mut stream, &ack("error", Some("tick_regression")));
                    break;
                }
                conn_tick = Some(tick);
                inner.state.lock().expect("guard state").last_heartbeat = Some(Instant::now());
                reply(&mut stream, &ack("ok", None));
            }
            Some("terminate") => {
                let pid = {
                    let mut state = inner.state.lock().expect("guard state");
                    state.triggered = true;
                    state.pid
                };
                let reason = message.get("reason").and_then(Json::as_str).unwrap_or("operator");
                let reason = if reason.is_empty() { "operator" } else { reason };
                write_control(&inner.control_path, "guard_terminate_directive", reason);
                if let Some(pid) = pid {
                    kill_pid(pid, "guarded worker", &format!("explicit terminate directive ({reason})"), &inner.control_path);
                }
                reply(&mut stream, &ack("triggered", None));
                break;
            }
            _ => {
                reply(&mut stream, &ack("error", Some("unknown_guard_frame")));
                break;
            }
        }
    }
    graceful_close(stream);
}

fn monitor_loop(inner: Arc<ServerInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
        maybe_trigger(&inner, "idle timeout");
    }
}

fn maybe_trigger(inner: &ServerInner, reason: &str) -> bool {
    let pid = {
        let mut state = inner.state.lock().expect("guard state");
        if state.triggered || !state.registered {
            return false;
        }
        if let Some(last) = state.last_heartbeat
            && Instant::now().saturating_duration_since(last) <= inner.idle
        {
            return false;
        }
        state.triggered = true;
        state.pid
    };
    match pid {
        None => {
            write_control(
                &inner.control_path,
                "guard_triggered_no_pid",
                "no heartbeat before registration completed",
            );
        }
        Some(pid) => {
            let seconds = inner.idle.as_secs_f64();
            kill_pid(
                pid,
                "guarded worker",
                &format!("{reason}: no heartbeat for {seconds:.1}s"),
                &inner.control_path,
            );
        }
    }
    true
}

fn kill_pid(pid: u32, subject: &str, detail: &str, control_path: &Path) {
    let mut detail = detail.to_string();
    let terminated = terminate_os(pid);
    if !terminated {
        detail = format!("{detail}; os.kill failed");
    }
    write_control(control_path, "guard_kill", &format!("terminated={terminated} {subject}: {detail}"));
}

pub(crate) fn terminate_os(pid: u32) -> bool {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &pid.to_string(), "/F"]).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    command.status().is_ok_and(|status| status.success())
}

fn valid_hello(transfer_key: &[u8], challenge: &str, message: &Json) -> bool {
    if message.get("type").and_then(Json::as_str) != Some("hello") {
        return false;
    }
    if message.get("version").and_then(Json::as_str) != Some(GUARD_PROTOCOL) {
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
    constant_time_eq(&sign_guard_hello(transfer_key, nonce, challenge), mac)
}

fn prepare_stream(stream: &mut TcpStream, idle: Duration) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let timeout = Duration::from_millis(500).min(idle / 2);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
}

fn ack(status: &str, reason: Option<&str>) -> Json {
    match reason {
        Some(reason) => Json::object([
            ("reason", Json::string(reason)),
            ("status", Json::string(status)),
            ("type", Json::string("ack")),
        ]),
        None => Json::object([
            ("status", Json::string(status)),
            ("type", Json::string("ack")),
        ]),
    }
}

fn reply(stream: &mut TcpStream, message: &Json) {
    if let Ok(bytes) = relay::frame(message) {
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

pub struct GuardHealth {
    pub ok: bool,
    pub connected: bool,
    pub registered: bool,
    pub triggered: bool,
    pub registered_pid: Option<u32>,
    pub error: String,
}

struct LinkState {
    pid: Option<u32>,
    registered: bool,
    connected: bool,
    send_seq: i64,
    ever_connected: bool,
    triggered: bool,
    failed: bool,
    last_error: String,
}

struct LinkInner {
    host: String,
    port: u16,
    transfer_key: Vec<u8>,
    tick: Duration,
    timeout: Duration,
    stop: AtomicBool,
    state: Mutex<LinkState>,
    socket: Mutex<Option<TcpStream>>,
    on_failure: Mutex<Option<FailureHandler>>,
}

pub struct WatchGuardLink {
    inner: Arc<LinkInner>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl WatchGuardLink {
    pub fn new(host: impl Into<String>, port: u16, transfer_key: Vec<u8>) -> Self {
        Self::with_timing(host, port, transfer_key, DEFAULT_TICK, DEFAULT_TIMEOUT)
    }

    pub fn with_timing(
        host: impl Into<String>,
        port: u16,
        transfer_key: Vec<u8>,
        tick: Duration,
        timeout: Duration,
    ) -> Self {
        Self {
            inner: Arc::new(LinkInner {
                host: host.into(),
                port,
                transfer_key,
                tick: tick.max(Duration::from_millis(50)),
                timeout,
                stop: AtomicBool::new(false),
                state: Mutex::new(LinkState {
                    pid: None,
                    registered: false,
                    connected: false,
                    send_seq: 0,
                    ever_connected: false,
                    triggered: false,
                    failed: false,
                    last_error: String::new(),
                }),
                socket: Mutex::new(None),
                on_failure: Mutex::new(None),
            }),
            thread: Mutex::new(None),
        }
    }

    pub fn set_on_failure(&self, callback: impl Fn(String) + Send + Sync + 'static) {
        let callback: FailureHandler = Arc::new(callback);
        let pending = {
            let mut slot = self.inner.on_failure.lock().expect("guard callback");
            *slot = Some(Arc::clone(&callback));
            let state = self.inner.state.lock().expect("guard link");
            if state.failed {
                Some(state.last_error.clone())
            } else {
                None
            }
        };
        if let Some(reason) = pending {
            let reason = if reason.is_empty() { "guard lost".to_string() } else { reason };
            callback(reason);
        }
    }

    pub fn start(&self) {
        let mut slot = self.thread.lock().expect("guard link thread");
        if slot.is_some() {
            return;
        }
        let inner = Arc::clone(&self.inner);
        *slot = Some(thread::spawn(move || run_link(inner)));
    }

    pub fn stop(&self) {
        self.inner.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.thread.lock().expect("guard link thread").take() {
            let _ = handle.join();
        }
        disconnect(&self.inner);
    }

    pub fn register_worker(&self, pid: u32) {
        self.inner.state.lock().expect("guard link").pid = Some(pid);
    }

    pub fn terminate(&self, reason: &str) -> Json {
        let reply = {
            let mut guard = self.inner.socket.lock().expect("guard socket");
            let Some(sock) = guard.as_mut() else {
                return Json::object([
                    ("reason", Json::string("guard not connected")),
                    ("status", Json::string("error")),
                ]);
            };
            (|| -> Result<Json, String> {
                let signed = next_signed(&self.inner, &Json::object([
                    ("reason", Json::string(reason)),
                    ("type", Json::string("terminate")),
                ]))?;
                send_frame(sock, &signed)?;
                relay::read_frame(sock).map_err(|error| error.to_string())
            })()
        };
        match reply {
            Ok(reply) => {
                if reply.get("status").and_then(Json::as_str) == Some("triggered") {
                    set_triggered(&self.inner, "terminate directive acked");
                }
                reply
            }
            Err(error) => {
                record_error(&self.inner, format!("guard link lost: {error}"));
                Json::object([
                    ("reason", Json::string("link_lost")),
                    ("status", Json::string("error")),
                ])
            }
        }
    }

    pub fn health(&self) -> GuardHealth {
        let state = self.inner.state.lock().expect("guard link");
        GuardHealth {
            ok: state.connected && !state.triggered && !state.failed,
            connected: state.connected,
            registered: state.registered,
            triggered: state.triggered,
            registered_pid: state.pid,
            error: state.last_error.clone(),
        }
    }

    pub fn health_json(&self) -> Json {
        let health = self.health();
        Json::object([
            ("connected", Json::Bool(health.connected)),
            ("error", optional_text(&health.error)),
            ("ok", Json::Bool(health.ok)),
            ("registered", Json::Bool(health.registered)),
            (
                "registered_pid",
                health.registered_pid.map(|pid| Json::Int(i64::from(pid))).unwrap_or(Json::Null),
            ),
            ("triggered", Json::Bool(health.triggered)),
        ])
    }
}

fn run_link(inner: Arc<LinkInner>) {
    while !inner.stop.load(Ordering::SeqCst) {
        if inner.state.lock().expect("guard link").triggered {
            return;
        }
        if let Err(error) = session(&inner) {
            if inner.stop.load(Ordering::SeqCst) {
                return;
            }
            record_error(&inner, format!("guard session failed: {error}"));
        }
        wait_tick(&inner);
    }
}

fn session(inner: &LinkInner) -> Result<(), String> {
    inner.state.lock().expect("guard link").send_seq = 0;
    connect(inner)?;
    let result = pump(inner);
    disconnect(inner);
    result
}

fn pump(inner: &LinkInner) -> Result<(), String> {
    let mut tick = 0i64;
    loop {
        if inner.stop.load(Ordering::SeqCst) {
            return Ok(());
        }
        let reply = {
            let mut guard = inner.socket.lock().expect("guard socket");
            let Some(sock) = guard.as_mut() else {
                return Ok(());
            };
            let (pid, registered) = {
                let state = inner.state.lock().expect("guard link");
                (state.pid, state.registered)
            };
            if let Some(pid) = pid
                && !registered
            {
                let signed = next_signed(inner, &Json::object([
                    ("pid", Json::Int(i64::from(pid))),
                    ("type", Json::string("register")),
                ]))?;
                send_frame(sock, &signed)?;
                let reply = relay::read_frame(sock).map_err(|error| error.to_string())?;
                if reply.get("status").and_then(Json::as_str) != Some("ok") {
                    return Err(format!("register refused: {reply:?}"));
                }
                inner.state.lock().expect("guard link").registered = true;
            }
            if inner.stop.load(Ordering::SeqCst) {
                return Ok(());
            }
            tick += 1;
            let signed = next_signed(inner, &Json::object([
                ("tick", Json::Int(tick)),
                ("type", Json::string("heartbeat")),
            ]))?;
            send_frame(sock, &signed)?;
            relay::read_frame(sock).map_err(|error| error.to_string())?
        };
        match reply.get("status").and_then(Json::as_str) {
            Some("triggered") => {
                set_triggered(inner, "guard reported triggered");
                return Ok(());
            }
            Some("ok") => {}
            _ => return Err(format!("guard replied: {reply:?}")),
        }
        wait_tick(inner);
    }
}

fn connect(inner: &LinkInner) -> Result<(), String> {
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
    if challenge.get("mac").and_then(Json::as_str) != Some(&sign_guard_challenge(&inner.transfer_key, challenge_value)) {
        return Err("challenge failed authentication".to_string());
    }
    let nonce = new_id("guard-");
    send_frame(&mut stream, &Json::object([
        ("challenge", Json::string(challenge_value)),
        ("mac", Json::string(sign_guard_hello(&inner.transfer_key, &nonce, challenge_value))),
        ("nonce", Json::string(nonce)),
        ("type", Json::string("hello")),
        ("version", Json::string(GUARD_PROTOCOL)),
    ]))?;
    let reply = relay::read_frame(&mut stream).map_err(|error| error.to_string())?;
    if reply.get("status").and_then(Json::as_str) != Some("ok") {
        return Err(format!("hello refused: {reply:?}"));
    }
    {
        let mut state = inner.state.lock().expect("guard link");
        state.ever_connected = true;
        state.connected = true;
        state.last_error.clear();
    }
    *inner.socket.lock().expect("guard socket") = Some(stream);
    Ok(())
}

fn disconnect(inner: &LinkInner) {
    let stream = inner.socket.lock().expect("guard socket").take();
    inner.state.lock().expect("guard link").connected = false;
    if let Some(stream) = stream {
        graceful_close(stream);
    }
}

fn record_error(inner: &LinkInner, error: String) {
    let callback = {
        let mut state = inner.state.lock().expect("guard link");
        state.connected = false;
        state.last_error = error.clone();
        if state.ever_connected && !state.failed {
            state.failed = true;
            inner.on_failure.lock().expect("guard callback").clone()
        } else {
            None
        }
    };
    if let Some(callback) = callback {
        callback(error);
    }
}

fn set_triggered(inner: &LinkInner, reason: &str) {
    let callback = {
        let mut state = inner.state.lock().expect("guard link");
        state.triggered = true;
        state.connected = false;
        state.last_error = reason.to_string();
        if state.failed {
            None
        } else {
            state.failed = true;
            inner.on_failure.lock().expect("guard callback").clone()
        }
    };
    if let Some(callback) = callback {
        callback(reason.to_string());
    }
}

fn wait_tick(inner: &LinkInner) {
    let deadline = Instant::now() + inner.tick;
    while Instant::now() < deadline {
        if inner.stop.load(Ordering::SeqCst) {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(Duration::from_millis(50).min(remaining));
    }
}

fn next_signed(inner: &LinkInner, message: &Json) -> Result<Json, String> {
    let seq = {
        let mut state = inner.state.lock().expect("guard link");
        state.send_seq += 1;
        state.send_seq
    };
    relay::frame_signed(GUARD_PROTOCOL, &inner.transfer_key, seq, message)
}

fn claim_hello(inner: &ServerInner, message: &Json) -> Option<&'static str> {
    if !valid_hello(&inner.transfer_key, &inner.challenge, message) {
        return Some("denied_guard_auth");
    }
    let nonce = message.get("nonce").and_then(Json::as_str).unwrap_or("");
    let mut state = inner.state.lock().expect("guard state");
    if !state.seen_nonces.insert(nonce.to_string()) {
        return Some("replayed_hello_nonce");
    }
    None
}

fn send_frame(stream: &mut TcpStream, message: &Json) -> Result<(), String> {
    let bytes = relay::frame(message).map_err(|error| error.to_string())?;
    stream.write_all(&bytes).map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    Ok(())
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

fn positive_u32(value: Option<&Json>) -> Option<u32> {
    let number = value.and_then(Json::as_i64)?;
    if number > 0 && number <= i64::from(u32::MAX) {
        Some(number as u32)
    } else {
        None
    }
}

fn nonneg_i64(value: Option<&Json>) -> Option<i64> {
    let number = value.and_then(Json::as_i64)?;
    if number >= 0 { Some(number) } else { None }
}

fn optional_text(value: &str) -> Json {
    if value.is_empty() { Json::Null } else { Json::string(value) }
}

fn preview(message: &Json) -> String {
    canonical_bytes(message)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default()
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
