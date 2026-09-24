//! Write-only audit relay: an independent process re-verifies the chain.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use voss::audit::AuditLog;
use voss::canonical::{Json, canonical_bytes, new_id};
use voss::keys::KeyRing;
use voss::relay::{self, AuditRelayClient, AuditRelayServer, RELAY_PROTOCOL};
use voss::runtime::VossRuntime;

struct RelayProc {
    child: Child,
    store: PathBuf,
    port: u16,
    key: Vec<u8>,
}

impl Drop for RelayProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_relay(root: &Path, timeout: f64) -> RelayProc {
    fs::create_dir_all(root).unwrap();
    let store = root.join("relay_store");
    fs::create_dir_all(&store).unwrap();
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_mul(7).wrapping_add(3)).collect();
    let port_file = root.join("relay_port.txt");
    let child = Command::new(std::env::var("CARGO_BIN_EXE_relay").expect("relay binary"))
        .arg("--store")
        .arg(&store)
        .arg("--keyring-dir")
        .arg(root)
        .arg("--port-file")
        .arg(&port_file)
        .arg("--transfer-key")
        .arg(hex::encode(&key))
        .arg("--timeout")
        .arg(timeout.to_string())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn relay");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut port = None;
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(&port_file)
            && let Ok(value) = text.trim().parse::<u16>()
            && value > 0
        {
            port = Some(value);
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    RelayProc {
        child,
        store,
        port: port.expect("relay port never published"),
        key,
    }
}

fn open_runtime(root: &Path) -> VossRuntime {
    fs::create_dir_all(root.join("workspace")).unwrap();
    let keys = KeyRing::load_or_create(root).unwrap();
    VossRuntime::open(
        root.join("workspace"),
        root.join("outbox"),
        root.join("audit.jsonl"),
        keys,
        None,
    )
    .unwrap()
}

fn attach(runtime: &VossRuntime, root: &Path, relay: &RelayProc) {
    runtime.attach_relay(AuditRelayClient::new(
        root.join("audit.jsonl"),
        "127.0.0.1",
        relay.port,
        relay.key.clone(),
    ));
}

fn envelope(runtime: &VossRuntime, request_id: &str, action: &str, resource: Json, payload: Json, constraints: Json) -> String {
    let value = Json::object([
        ("version", Json::string("1")),
        ("request_id", Json::string(request_id)),
        ("session_id", Json::string(&runtime.worker_session)),
        ("principal", Json::string(&runtime.worker_principal)),
        ("action", Json::string(action)),
        ("resource", resource),
        ("payload", payload),
        ("constraints", constraints),
    ]);
    String::from_utf8(canonical_bytes(&value).unwrap()).unwrap()
}

fn approve(runtime: &VossRuntime, proposal: &str) {
    let pending = runtime.handle_envelope(proposal);
    assert_eq!(pending.get("decision").and_then(Json::as_str), Some("REQUIRE_APPROVAL"), "{pending:?}");
    let decided = runtime.resolve_approval(
        pending.get("approval_request_id").and_then(Json::as_str).unwrap_or(""),
        "APPROVE",
        "relay-test",
    );
    assert_eq!(decided.get("decision").and_then(Json::as_str), Some("ALLOW"), "{decided:?}");
}

fn lines_of(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|line| !line.trim().is_empty()).map(|line| format!("{line}\n")).collect()
}

fn store_lines(store: &Path) -> Vec<String> {
    lines_of(&store.join("relay-audit.jsonl"))
}

fn control_events(store: &Path) -> Vec<String> {
    lines_of(&store.join("relay-control.jsonl"))
        .iter()
        .filter_map(|line| {
            voss::loads_strict(line.trim()).ok().and_then(|value| {
                value.get("event").and_then(Json::as_str).map(str::to_string)
            })
        })
        .collect()
}

fn wait_until(mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn read_challenge(stream: &mut TcpStream, key: &[u8]) -> String {
    let challenge = relay::read_frame(stream).unwrap();
    assert_eq!(challenge.get("type").and_then(Json::as_str), Some("challenge"), "{challenge:?}");
    let value = challenge.get("challenge").and_then(Json::as_str).expect("challenge value").to_string();
    let mac = relay::sign_challenge(key, &value);
    assert_eq!(challenge.get("mac").and_then(Json::as_str), Some(mac.as_str()), "{challenge:?}");
    value
}

fn raw_hello(key: &[u8], nonce: &str, challenge: &str) -> Vec<u8> {
    let hello = Json::object([
        ("type", Json::string("hello")),
        ("version", Json::string(RELAY_PROTOCOL)),
        ("challenge", Json::string(challenge)),
        ("nonce", Json::string(nonce)),
        ("mac", Json::string(relay::sign_hello(key, nonce, challenge))),
    ]);
    relay::frame(&hello).unwrap()
}

fn handshake(port: u16, key: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_nodelay(true).unwrap();
    let challenge = read_challenge(&mut stream, key);
    let bytes = raw_hello(key, &new_id("relay-"), &challenge);
    stream.write_all(&bytes).unwrap();
    let reply = relay::read_frame(&mut stream).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("hello_ok"), "{reply:?}");
    let begin = relay::frame_signed(
        RELAY_PROTOCOL,
        key,
        1,
        &Json::object([("type", Json::string("stream_begin"))]),
    )
    .unwrap();
    stream.write_all(&relay::frame(&begin).unwrap()).unwrap();
    let ready = relay::read_frame(&mut stream).unwrap();
    assert_eq!(ready.get("type").and_then(Json::as_str), Some("stream_ready"), "{ready:?}");
    stream
}

fn raw_record(event_id: &str, content: &str) -> Json {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    Json::object([
        ("schema", Json::string("voss.audit.1")),
        ("event_id", Json::string(event_id)),
        ("ts_utc", Json::Float(seconds)),
        ("event_type", Json::string("denied")),
        ("content", Json::string(content)),
    ])
}

#[test]
fn relay_mirrors_audit_and_verifies() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let runtime = open_runtime(&root);
    fs::write(runtime.workspace_root.join("notes.txt"), "notes\n").unwrap();
    attach(&runtime, &root, &relay);
    let _ = runtime.handle_envelope(&envelope(
        &runtime,
        "relay-read",
        "workspace.read",
        Json::object([("path", Json::string("notes.txt"))]),
        Json::empty_object(),
        Json::empty_object(),
    ));
    for index in 0..3 {
        approve(&runtime, &envelope(
            &runtime,
            &format!("relay-write-{index}"),
            "workspace.write",
            Json::object([("path", Json::string(format!("f{index}.txt")))]),
            Json::object([("content", Json::string(format!("c{index}")))]),
            Json::empty_object(),
        ));
        approve(&runtime, &envelope(
            &runtime,
            &format!("relay-send-{index}"),
            "external.send_mock",
            Json::object([
                ("service", Json::string("mail")),
                ("recipient", Json::string("alex@example.invalid")),
            ]),
            Json::object([
                ("subject", Json::string("hi")),
                ("body", Json::string(format!("body-{index}"))),
            ]),
            Json::object([("send_once", Json::Bool(true))]),
        ));
    }
    let mut forged = envelope(
        &runtime,
        "relay-forged",
        "workspace.read",
        Json::object([("path", Json::string("secret.txt"))]),
        Json::empty_object(),
        Json::empty_object(),
    );
    forged = forged.replace(
        &format!("\"principal\":\"{}\"", runtime.worker_principal),
        "\"principal\":\"attacker\"",
    );
    let _ = runtime.handle_envelope(&forged);
    let health = runtime.health_report();
    runtime.close();
    let audit = lines_of(&root.join("audit.jsonl"));
    assert!(
        store_lines(&relay.store).len() >= 2,
        "store={} audit={} relay={:?} events={:?}",
        store_lines(&relay.store).len(),
        audit.len(),
        health.get("relay").and_then(|value| value.get("error")).and_then(Json::as_str),
        control_events(&relay.store)
    );
    assert_eq!(store_lines(&relay.store), audit);
    let keys = KeyRing::load_or_create(&root).unwrap();
    let copy = AuditLog::open(relay.store.join("relay-audit.jsonl"), keys).unwrap();
    assert!(copy.verify_integrity());
    assert!(control_events(&relay.store).contains(&"relay_accepted_hello".to_string()));
    assert!(!control_events(&relay.store).contains(&"relay_violation".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restart_redelivery_is_idempotent() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let first = open_runtime(&root);
    attach(&first, &root, &relay);
    approve(&first, &envelope(
        &first,
        "relay-a",
        "workspace.write",
        Json::object([("path", Json::string("a.txt"))]),
        Json::object([("content", Json::string("a"))]),
        Json::empty_object(),
    ));
    first.close();

    let second = open_runtime(&root);
    attach(&second, &root, &relay);
    approve(&second, &envelope(
        &second,
        "relay-b",
        "workspace.write",
        Json::object([("path", Json::string("b.txt"))]),
        Json::object([("content", Json::string("b"))]),
        Json::empty_object(),
    ));
    wait_until(|| {
        second.health_report().get("relay").and_then(|value| value.get("ok")).and_then(Json::as_bool) == Some(true)
    });
    assert_eq!(
        second.health_report().get("relay").and_then(|value| value.get("ok")).and_then(Json::as_bool),
        Some(true)
    );
    second.close();
    assert_eq!(store_lines(&relay.store), lines_of(&root.join("audit.jsonl")));
    let keys = KeyRing::load_or_create(&root).unwrap();
    assert!(AuditLog::open(relay.store.join("relay-audit.jsonl"), keys).unwrap().verify_integrity());
    assert!(!control_events(&relay.store).contains(&"relay_violation".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn health_report_exposes_relay() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let runtime = open_runtime(&root);
    attach(&runtime, &root, &relay);
    wait_until(|| {
        let health = runtime.health_report();
        health.get("relay").and_then(|value| value.get("connected")).and_then(Json::as_bool) == Some(true)
            && health.get("relay").and_then(|value| value.get("ok")).and_then(Json::as_bool) == Some(true)
    });
    let health = runtime.health_report();
    assert!(health.get("relay").is_some_and(|value| !matches!(value, Json::Null)));
    assert_eq!(health.get("relay").and_then(|value| value.get("ok")).and_then(Json::as_bool), Some(true));
    assert_eq!(health.get("relay").and_then(|value| value.get("connected")).and_then(Json::as_bool), Some(true));
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn probe_without_credential_is_refused_and_harmless() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let mut stream = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_nodelay(true).unwrap();
    let challenge = relay::read_frame(&mut stream).unwrap();
    assert_eq!(challenge.get("type").and_then(Json::as_str), Some("challenge"), "{challenge:?}");
    let hello = Json::object([
        ("type", Json::string("hello")),
        ("version", Json::string(RELAY_PROTOCOL)),
        ("challenge", Json::string("")),
        ("nonce", Json::string(new_id("relay-"))),
        ("mac", Json::string("0".repeat(64))),
    ]);
    stream.write_all(&relay::frame(&hello).unwrap()).unwrap();
    let reply = relay::read_frame(&mut stream).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("violation"));
    assert_eq!(reply.get("reason").and_then(Json::as_str), Some("denied_hello_auth"));
    drop(stream);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(control_events(&relay.store).iter().filter(|event| *event == "relay_denied_hello").count(), 1);
    assert!(store_lines(&relay.store).is_empty());
    let runtime = open_runtime(&root);
    attach(&runtime, &root, &relay);
    approve(&runtime, &envelope(
        &runtime,
        "relay-probe",
        "workspace.write",
        Json::object([("path", Json::string("p.txt"))]),
        Json::object([("content", Json::string("p"))]),
        Json::empty_object(),
    ));
    let health = runtime.health_report();
    runtime.close();
    assert!(
        !store_lines(&relay.store).is_empty(),
        "error={:?} connected={:?} events={:?}",
        health.get("relay").and_then(|value| value.get("error")).and_then(Json::as_str),
        health.get("relay").and_then(|value| value.get("connected")).and_then(Json::as_bool),
        control_events(&relay.store)
    );
    assert!(!control_events(&relay.store).contains(&"relay_violation".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn sequence_gap_compromises_store() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let mut stream = handshake(relay.port, &relay.key);
    let message = relay::frame_signed(
        RELAY_PROTOCOL,
        &relay.key,
        5,
        &Json::object([
            ("type", Json::string("record")),
            ("record", raw_record("evt-gap", "val")),
        ]),
    )
    .unwrap();
    stream.write_all(&relay::frame(&message).unwrap()).unwrap();
    let reply = relay::read_frame(&mut stream).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("violation"));
    let reason = reply.get("reason").and_then(Json::as_str).unwrap_or("");
    assert!(reason.starts_with("sequence_gap"), "{reason}");
    drop(stream);
    thread::sleep(Duration::from_millis(200));
    assert!(control_events(&relay.store).contains(&"relay_violation".to_string()));
    assert!(store_lines(&relay.store).is_empty());
    let mut again = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    again.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    again.set_nodelay(true).unwrap();
    let challenge = relay::read_frame(&mut again).unwrap();
    assert_eq!(challenge.get("type").and_then(Json::as_str), Some("challenge"), "{challenge:?}");
    let nonce = new_id("relay-");
    let hello = Json::object([
        ("type", Json::string("hello")),
        ("version", Json::string(RELAY_PROTOCOL)),
        ("challenge", Json::string("stale")),
        ("nonce", Json::string(&nonce)),
        ("mac", Json::string(relay::sign_hello(&relay.key, &nonce, &format!("stale-{nonce}")))),
    ]);
    again.write_all(&relay::frame(&hello).unwrap()).unwrap();
    let reply = relay::read_frame(&mut again).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("refused"), "{reply:?}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn duplicate_contradiction_fails_closed() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let mut stream = handshake(relay.port, &relay.key);
    let first = relay::frame_signed(
        RELAY_PROTOCOL,
        &relay.key,
        1,
        &Json::object([
            ("type", Json::string("record")),
            ("record", raw_record("evt-dup", "v1")),
        ]),
    )
    .unwrap();
    stream.write_all(&relay::frame(&first).unwrap()).unwrap();
    assert_eq!(relay::read_frame(&mut stream).unwrap().get("type").and_then(Json::as_str), Some("ack"));
    let second = relay::frame_signed(
        RELAY_PROTOCOL,
        &relay.key,
        2,
        &Json::object([
            ("type", Json::string("record")),
            ("record", raw_record("evt-dup", "v2")),
        ]),
    )
    .unwrap();
    stream.write_all(&relay::frame(&second).unwrap()).unwrap();
    let reply = relay::read_frame(&mut stream).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("violation"));
    assert!(reply.get("reason").and_then(Json::as_str).unwrap_or("").starts_with("duplicate_contradiction"));
    drop(stream);
    thread::sleep(Duration::from_millis(200));
    assert_eq!(store_lines(&relay.store).len(), 1);
    assert!(control_events(&relay.store).contains(&"relay_violation".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn oversize_frame_refused() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let mut stream = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_nodelay(true).unwrap();
    stream.write_all(&[0xff, 0xff, 0xff, 0xff]).unwrap();
    let mut buffer = [0u8; 4096];
    let _ = stream.read(&mut buffer);
    drop(stream);
    thread::sleep(Duration::from_millis(200));
    let events = control_events(&relay.store);
    assert!(events.iter().any(|event| event.contains("oversize_frame")) || events.iter().any(|event| event == "relay_violation"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn stale_flagged_then_recovered() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    let relay = start_relay(&root, 0.4);
    let mut stream = handshake(relay.port, &relay.key);
    wait_until(|| control_events(&relay.store).contains(&"relay_stale".to_string()));
    assert!(control_events(&relay.store).contains(&"relay_stale".to_string()));
    let message = relay::frame_signed(
        RELAY_PROTOCOL,
        &relay.key,
        1,
        &Json::object([
            ("type", Json::string("record")),
            ("record", raw_record("evt-live", "val")),
        ]),
    )
    .unwrap();
    stream.write_all(&relay::frame(&message).unwrap()).unwrap();
    assert_eq!(relay::read_frame(&mut stream).unwrap().get("type").and_then(Json::as_str), Some("ack"));
    wait_until(|| control_events(&relay.store).contains(&"relay_recovered".to_string()));
    assert!(control_events(&relay.store).contains(&"relay_recovered".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn start_stop_and_port() {
    let root = std::env::temp_dir().join(format!("voss-relay-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    let server = AuditRelayServer::bind(&root, KeyRing::generate(), vec![9u8; 32], Duration::from_secs(1)).unwrap();
    server.start();
    assert!(server.port() > 0);
    server.stop();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn tampered_store_stays_compromised_on_recovery() {
    let root = std::env::temp_dir().join(format!("voss-relay-recover-{}", new_id("")));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("workspace")).unwrap();
    let _ = KeyRing::load_or_create(&root).unwrap();
    let runtime = VossRuntime::open(
        root.join("workspace"),
        root.join("outbox"),
        root.join("audit.jsonl"),
        KeyRing::load_or_create(&root).unwrap(),
        None,
    )
    .unwrap();
    runtime.close();
    let store = root.join("relay_store");
    fs::create_dir_all(&store).unwrap();
    let audit = fs::read_to_string(root.join("audit.jsonl")).unwrap();
    assert!(audit.contains("chain_hash"), "{audit}");
    fs::write(store.join("relay-audit.jsonl"), &audit).unwrap();
    let clean = AuditRelayServer::bind(
        &store,
        KeyRing::load_or_create(&root).unwrap(),
        vec![4u8; 32],
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(!clean.compromised(), "a verified store must reload");
    clean.stop();
    let marker = "\"chain_hash\":\"";
    let start = audit.find(marker).expect("chain hash") + marker.len();
    let mut tampered = audit.clone();
    tampered.replace_range(start..start + 64, &"0".repeat(64));
    fs::write(store.join("relay-audit.jsonl"), tampered).unwrap();
    let broken = AuditRelayServer::bind(
        &store,
        KeyRing::load_or_create(&root).unwrap(),
        vec![4u8; 32],
        Duration::from_secs(1),
    )
    .unwrap();
    assert!(broken.compromised(), "a rewritten chain hash must not be trusted");
    broken.stop();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn replayed_hello_nonce_is_refused_and_not_compromising() {
    let root = std::env::temp_dir().join(format!("voss-relay-replay-{}", new_id("")));
    let relay = start_relay(&root, 15.0);
    let mut first = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    first.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    first.set_nodelay(true).unwrap();
    let challenge = read_challenge(&mut first, &relay.key);
    let nonce = new_id("relay-");
    let bytes = raw_hello(&relay.key, &nonce, &challenge);
    first.write_all(&bytes).unwrap();
    assert_eq!(
        relay::read_frame(&mut first).unwrap().get("type").and_then(Json::as_str),
        Some("hello_ok")
    );
    drop(first);
    thread::sleep(Duration::from_millis(200));
    let mut replay = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    replay.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    replay.set_nodelay(true).unwrap();
    let _ = relay::read_frame(&mut replay).unwrap(); // challenge from the same process
    replay.write_all(&bytes).unwrap();
    let reply = relay::read_frame(&mut replay).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("violation"));
    assert_eq!(reply.get("reason").and_then(Json::as_str), Some("denied_hello_auth"));
    drop(replay);
    let details = lines_of(&relay.store.join("relay-control.jsonl"));
    assert!(
        details.iter().any(|line| line.contains("replayed_hello_nonce")),
        "{details:?}"
    );
    let mut fresh = TcpStream::connect(("127.0.0.1", relay.port)).unwrap();
    fresh.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    fresh.set_nodelay(true).unwrap();
    let challenge = read_challenge(&mut fresh, &relay.key);
    let bytes = raw_hello(&relay.key, &new_id("relay-"), &challenge);
    fresh.write_all(&bytes).unwrap();
    assert_eq!(
        relay::read_frame(&mut fresh).unwrap().get("type").and_then(Json::as_str),
        Some("hello_ok")
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restart_with_same_key_refuses_a_captured_hello() {
    let root = std::env::temp_dir().join(format!("voss-relay-restart-{}", new_id("")));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let key = vec![9u8; 32];
    let first = AuditRelayServer::bind(
        &root,
        KeyRing::load_or_create(&root).unwrap(),
        key.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    first.start();
    let mut stream = TcpStream::connect(("127.0.0.1", first.port())).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_nodelay(true).unwrap();
    let challenge = read_challenge(&mut stream, &key);
    let bytes = raw_hello(&key, &new_id("relay-"), &challenge);
    stream.write_all(&bytes).unwrap();
    assert_eq!(
        relay::read_frame(&mut stream).unwrap().get("type").and_then(Json::as_str),
        Some("hello_ok")
    );
    drop(stream);
    first.stop();

    let second = AuditRelayServer::bind(
        &root,
        KeyRing::load_or_create(&root).unwrap(),
        key.clone(),
        Duration::from_secs(2),
    )
    .unwrap();
    second.start();
    let mut replay = TcpStream::connect(("127.0.0.1", second.port())).unwrap();
    replay.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    replay.set_nodelay(true).unwrap();
    let _ = relay::read_frame(&mut replay).unwrap(); // this process's fresh challenge
    replay.write_all(&bytes).unwrap();
    let reply = relay::read_frame(&mut replay).unwrap();
    assert_eq!(reply.get("type").and_then(Json::as_str), Some("violation"));
    assert_eq!(reply.get("reason").and_then(Json::as_str), Some("denied_hello_auth"));
    drop(replay);
    // A legit client holding the same key still connects (fresh challenge).
    let mut legit = TcpStream::connect(("127.0.0.1", second.port())).unwrap();
    legit.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    legit.set_nodelay(true).unwrap();
    let challenge = read_challenge(&mut legit, &key);
    legit.write_all(&raw_hello(&key, &new_id("relay-"), &challenge)).unwrap();
    assert_eq!(
        relay::read_frame(&mut legit).unwrap().get("type").and_then(Json::as_str),
        Some("hello_ok")
    );
    second.stop();
    let _ = fs::remove_dir_all(root);
}
