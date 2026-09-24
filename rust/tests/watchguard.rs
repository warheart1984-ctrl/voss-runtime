//! External watch-guard: the kill authority is a separate process.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use voss::canonical::{Json, canonical_bytes, loads_strict, new_id};
use voss::keys::KeyRing;
use voss::relay;
use voss::runtime::VossRuntime;
use voss::watchguard::{self, WatchGuardLink, GUARD_PROTOCOL};

struct GuardProc {
    child: Child,
    store: PathBuf,
    port: u16,
    key: Vec<u8>,
}

impl Drop for GuardProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Sleeper {
    child: Child,
}

impl Drop for Sleeper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_guard(root: &Path, timeout: f64) -> GuardProc {
    fs::create_dir_all(root).unwrap();
    let store = root.join("guard_store");
    fs::create_dir_all(&store).unwrap();
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_mul(7).wrapping_add(3)).collect();
    let port_file = root.join("guard_port.txt");
    let mut child = Command::new(std::env::var("CARGO_BIN_EXE_watchguard").expect("watchguard binary"))
        .arg("--store")
        .arg(&store)
        .arg("--port-file")
        .arg(&port_file)
        .arg("--transfer-key")
        .arg(hex::encode(&key))
        .arg("--timeout")
        .arg(timeout.to_string())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn watchguard");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut port = None;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            let mut err = String::new();
            if let Some(mut stderr) = child.stderr.take() {
                let _ = stderr.read_to_string(&mut err);
            }
            panic!("guard died early: {err}");
        }
        if let Ok(text) = fs::read_to_string(&port_file)
            && let Ok(value) = text.trim().parse::<u16>()
            && value > 0
        {
            port = Some(value);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let Some(port) = port else {
        let _ = child.kill();
        panic!("guard port never published");
    };
    GuardProc { child, store, port, key }
}

fn spawn_sleeper() -> Sleeper {
    let child = Command::new("ping")
        .args(["-n", "40", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleeper");
    Sleeper { child }
}

fn link(guard: &GuardProc, tick: Duration, timeout: Duration) -> WatchGuardLink {
    WatchGuardLink::with_timing("127.0.0.1", guard.port, guard.key.clone(), tick, timeout)
}

fn wait_until(timeout: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if ready() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn wait_registered(client: &WatchGuardLink) {
    assert!(
        wait_until(Duration::from_secs(5), || client.health().registered),
        "link never registered: {:?}",
        client.health_json()
    );
}

fn wait_killed(child: &mut Child) -> bool {
    wait_until(Duration::from_secs(6), || child.try_wait().ok().flatten().is_some())
}

fn control_records(store: &Path) -> Vec<Json> {
    fs::read_to_string(store.join("guard-control.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| loads_strict(line).ok())
        .collect()
}

fn control_events(store: &Path) -> Vec<String> {
    control_records(store)
        .iter()
        .filter_map(|record| record.get("event").and_then(Json::as_str).map(str::to_string))
        .collect()
}

fn control_details(store: &Path, prefix: &str) -> String {
    control_records(store)
        .iter()
        .filter(|record| record.get("event").and_then(Json::as_str).is_some_and(|event| event.starts_with(prefix)))
        .filter_map(|record| record.get("detail").and_then(Json::as_str))
        .collect::<Vec<_>>()
        .join(" ")
}

fn raw_hello(port: u16, key: &[u8]) -> (TcpStream, Json) {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_nodelay(true).unwrap();
    let nonce = new_id("guard-");
    let hello = Json::object([
        ("mac", Json::string(watchguard::sign_guard_hello(key, &nonce))),
        ("nonce", Json::string(nonce)),
        ("type", Json::string("hello")),
        ("version", Json::string(GUARD_PROTOCOL)),
    ]);
    let bytes = relay::frame(&hello).unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let reply = relay::read_frame(&mut stream).expect("hello reply");
    (stream, reply)
}

fn send_frame(stream: &mut TcpStream, message: &Json) {
    let bytes = relay::frame(message).unwrap();
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
}

fn open_runtime(root: &Path) -> VossRuntime {
    fs::create_dir_all(root.join("workspace")).unwrap();
    let keys = KeyRing::load_or_create(root).unwrap();
    VossRuntime::open(root.join("workspace"), root.join("outbox"), root.join("audit.jsonl"), keys, None).unwrap()
}

fn envelope(runtime: &VossRuntime, path: &str) -> String {
    let value = Json::object([
        ("action", Json::string("workspace.read")),
        ("constraints", Json::empty_object()),
        ("payload", Json::empty_object()),
        ("principal", Json::string(&runtime.worker_principal)),
        ("request_id", Json::string("guard-read")),
        ("resource", Json::object([("path", Json::string(path))])),
        ("session_id", Json::string(&runtime.worker_session)),
        ("version", Json::string("1")),
    ]);
    String::from_utf8(canonical_bytes(&value).unwrap()).unwrap()
}

fn fresh(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("voss-guard-{name}-{}", new_id("")))
}

#[test]
fn heartbeats_keep_worker_alive_past_timeout() {
    let root = fresh("alive");
    let mut guard = start_guard(&root, 1.0);
    let mut worker = spawn_sleeper();
    let client = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    client.start();
    client.register_worker(worker.child.id());
    wait_registered(&client);
    thread::sleep(Duration::from_millis(2500));
    assert!(worker.child.try_wait().ok().flatten().is_none(), "worker must survive heartbeats");
    assert!(client.health().ok, "{:?}", client.health_json());
    assert!(!control_events(&guard.store).iter().any(|event| event == "guard_kill"), "{:?}", control_events(&guard.store));
    let _ = client.terminate("test teardown");
    client.stop();
    let _ = worker.child.kill();
    let _ = guard.child.kill();
}

#[test]
fn guard_kills_worker_when_heartbeats_stop() {
    let root = fresh("idle");
    let mut guard = start_guard(&root, 1.0);
    let mut worker = spawn_sleeper();
    let client = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    client.start();
    client.register_worker(worker.child.id());
    wait_registered(&client);
    assert!(worker.child.try_wait().ok().flatten().is_none());
    client.stop();
    assert!(
        wait_killed(&mut worker.child),
        "guard must terminate the worker after heartbeats stop: {}",
        control_details(&guard.store, "guard_kill")
    );
    assert!(control_details(&guard.store, "guard_kill").contains("idle timeout"), "{}", control_details(&guard.store, "guard_kill"));
    assert!(guard.child.try_wait().ok().flatten().is_none(), "guard process survives the kill");
}

#[test]
fn terminate_directive_kills_worker_then_refuses() {
    let root = fresh("term");
    let mut guard = start_guard(&root, 2.0);
    let mut worker = spawn_sleeper();
    let client = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    client.start();
    client.register_worker(worker.child.id());
    wait_registered(&client);
    let reply = client.terminate("operator");
    assert_eq!(reply.get("status").and_then(Json::as_str), Some("triggered"), "{reply:?}");
    assert!(wait_killed(&mut worker.child), "{}", control_details(&guard.store, "guard_kill"));
    assert!(client.health().triggered);
    assert!(!client.health().ok);
    assert!(
        control_details(&guard.store, "guard_kill").contains("explicit terminate directive"),
        "{}",
        control_details(&guard.store, "guard_kill")
    );
    let second = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    second.start();
    assert!(
        wait_until(Duration::from_secs(5), || !second.health().connected),
        "{:?}",
        second.health_json()
    );
    assert!(!second.health().ok, "{:?}", second.health_json());
    second.stop();
    client.stop();
    let _ = guard.child.kill();
}

#[test]
fn unauthenticated_hello_refused_worker_untouched() {
    let root = fresh("probe");
    let mut guard = start_guard(&root, 2.0);
    let mut worker = spawn_sleeper();
    let mut stranger = TcpStream::connect(format!("127.0.0.1:{}", guard.port)).unwrap();
    stranger.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stranger.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    send_frame(&mut stranger, &Json::object([
        ("mac", Json::string("00".repeat(32))),
        ("nonce", Json::string("x")),
        ("type", Json::string("hello")),
        ("version", Json::string(GUARD_PROTOCOL)),
    ]));
    let reply = relay::read_frame(&mut stranger).expect("denied hello");
    assert_eq!(reply.get("reason").and_then(Json::as_str), Some("denied_guard_auth"), "{reply:?}");
    drop(stranger);
    assert!(control_events(&guard.store).iter().any(|event| event == "guard_denied_hello"), "{:?}", control_events(&guard.store));
    let client = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    client.start();
    client.register_worker(worker.child.id());
    wait_registered(&client);
    assert!(worker.child.try_wait().ok().flatten().is_none(), "worker untouched by bad hello");
    let _ = client.terminate("test teardown");
    client.stop();
    let _ = worker.child.kill();
    let _ = guard.child.kill();
}

#[test]
fn tick_regression_is_anomaly() {
    let root = fresh("tick");
    let mut guard = start_guard(&root, 5.0);
    let (mut stream, hello) = raw_hello(guard.port, &guard.key);
    assert_eq!(hello.get("status").and_then(Json::as_str), Some("ok"), "{hello:?}");
    let sleeper = spawn_sleeper();
    send_frame(
        &mut stream,
        &relay::frame_signed(
            GUARD_PROTOCOL,
            &guard.key,
            1,
            &Json::object([
                ("pid", Json::Int(i64::from(sleeper.child.id()))),
                ("type", Json::string("register")),
            ]),
        )
        .unwrap(),
    );
    assert_eq!(relay::read_frame(&mut stream).unwrap().get("status").and_then(Json::as_str), Some("ok"));
    send_frame(
        &mut stream,
        &relay::frame_signed(
            GUARD_PROTOCOL,
            &guard.key,
            2,
            &Json::object([("tick", Json::Int(5)), ("type", Json::string("heartbeat"))]),
        )
        .unwrap(),
    );
    assert_eq!(relay::read_frame(&mut stream).unwrap().get("status").and_then(Json::as_str), Some("ok"));
    send_frame(
        &mut stream,
        &relay::frame_signed(
            GUARD_PROTOCOL,
            &guard.key,
            3,
            &Json::object([("tick", Json::Int(3)), ("type", Json::string("heartbeat"))]),
        )
        .unwrap(),
    );
    let reply = relay::read_frame(&mut stream).unwrap();
    assert_eq!(reply.get("reason").and_then(Json::as_str), Some("tick_regression"), "{reply:?}");
    drop(stream);
    assert!(control_events(&guard.store).iter().any(|event| event == "guard_anomaly"), "{:?}", control_events(&guard.store));
    let _ = guard.child.kill();
}

#[test]
fn guard_is_exclusive_one_host_connection() {
    let root = fresh("busy");
    let mut guard = start_guard(&root, 5.0);
    let (first, hello) = raw_hello(guard.port, &guard.key);
    assert_eq!(hello.get("status").and_then(Json::as_str), Some("ok"), "{hello:?}");
    thread::sleep(Duration::from_millis(200));
    let mut second = TcpStream::connect(format!("127.0.0.1:{}", guard.port)).unwrap();
    second.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let reply = relay::read_frame(&mut second).expect("busy reply");
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("busy"), "{reply:?}");
    assert!(control_events(&guard.store).iter().any(|event| event == "guard_busy"), "{:?}", control_events(&guard.store));
    drop(first);
    drop(second);
    let _ = guard.child.kill();
}

#[test]
fn guard_loss_fails_runtime_closed() {
    let root = fresh("loss");
    let mut guard = start_guard(&root, 5.0);
    let client = link(&guard, Duration::from_millis(100), Duration::from_secs(1));
    let runtime = open_runtime(&root);
    runtime.attach_guard(client);
    assert!(
        wait_until(Duration::from_secs(5), || flag(&runtime.health_report(), "watchdog")),
        "runtime must start guard-connected: {:?}",
        runtime.health_report()
    );
    fs::write(runtime.workspace_root.join("read.txt"), "ok").unwrap();
    let allowed = runtime.handle_envelope(&envelope(&runtime, "read.txt"));
    assert_eq!(allowed.get("decision").and_then(Json::as_str), Some("ALLOW"), "{allowed:?}");

    let _ = guard.child.kill();
    let _ = guard.child.wait();
    assert!(
        wait_until(Duration::from_secs(8), || {
            let health = runtime.health_report();
            !flag(&health, "watchdog") && health.get("worker_accepts_work").and_then(Json::as_bool) == Some(false)
        }),
        "watchdog must fail closed on guard loss: {:?}",
        runtime.health_report()
    );
    let report = runtime.health_report();
    assert_eq!(
        report.get("watchdog_guard").and_then(|guard| guard.get("ok")).and_then(Json::as_bool),
        Some(false),
        "{report:?}"
    );
    let denied = runtime.handle_envelope(&envelope(&runtime, "read.txt"));
    assert_eq!(denied.get("decision").and_then(Json::as_str), Some("DENY"), "{denied:?}");
    assert_eq!(denied.get("reason_code").and_then(Json::as_str), Some("denied_worker_suspended"), "{denied:?}");
    let events = runtime.audit_summary();
    assert!(
        events.get("by_event_type").and_then(|counts| counts.get("guard_failure")).is_some(),
        "{events:?}"
    );
    runtime.close();
}

fn flag(report: &Json, key: &str) -> bool {
    report.get(key).and_then(|value| value.get("ok")).and_then(Json::as_bool) == Some(true)
}
