//! External-action accounting: the receipt lives in another process.

use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use voss::canonical::{Json, canonical_bytes, loads_strict, new_id};
use voss::keys::KeyRing;
use voss::outbox::{self, OutboxError, OutboxLink, OutboxServer};
use voss::relay;
use voss::runtime::VossRuntime;

struct OutboxProc {
    child: Child,
    store: PathBuf,
    port: u16,
    key: Vec<u8>,
}

impl Drop for OutboxProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_outbox(root: &Path, drop_ack: bool, refuse: bool) -> OutboxProc {
    fs::create_dir_all(root).unwrap();
    let store = root.join("outbox_store");
    fs::create_dir_all(&store).unwrap();
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_mul(11).wrapping_add(4)).collect();
    let port_file = root.join("outbox_port.txt");
    let mut command = Command::new(std::env::var("CARGO_BIN_EXE_outbox").expect("outbox binary"));
    command
        .arg("--store")
        .arg(&store)
        .arg("--port-file")
        .arg(&port_file)
        .arg("--transfer-key")
        .arg(hex::encode(&key))
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if drop_ack {
        command.arg("--drop-ack");
    }
    if refuse {
        command.arg("--refuse");
    }
    let mut child = command.spawn().expect("spawn outbox");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut port = None;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            panic!("outbox died early");
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
        panic!("outbox port never published");
    };
    OutboxProc { child, store, port, key }
}

fn runtime_in(root: &Path) -> VossRuntime {
    let workspace = root.join("workspace");
    let outbox = root.join("outbox");
    fs::create_dir_all(&workspace).unwrap();
    fs::create_dir_all(&outbox).unwrap();
    VossRuntime::open(&workspace, &outbox, root.join("audit.jsonl"), KeyRing::generate(), None).unwrap()
}

fn envelope(runtime: &VossRuntime, action: &str, resource: Json) -> String {
    let value = Json::object([
        ("action", Json::string(action)),
        ("constraints", Json::empty_object()),
        ("payload", Json::empty_object()),
        ("principal", Json::string(&runtime.worker_principal)),
        ("request_id", Json::string(new_id("req-"))),
        ("resource", resource),
        ("session_id", Json::string(&runtime.worker_session)),
        ("version", Json::string("1")),
    ]);
    String::from_utf8(canonical_bytes(&value).unwrap()).unwrap()
}

fn send_env(runtime: &VossRuntime) -> String {
    envelope(
        runtime,
        "external.send_mock",
        Json::object([
            ("recipient", Json::string("alex@example.invalid")),
            ("service", Json::string("mail")),
        ]),
    )
}

fn approve(runtime: &VossRuntime, env: &str) -> Json {
    let response = runtime.handle_envelope(env);
    if text(&response, "decision") == "REQUIRE_APPROVAL" {
        runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "test-human")
    } else {
        response
    }
}

fn text(value: &Json, key: &str) -> String {
    value.get(key).and_then(Json::as_str).unwrap_or("").to_string()
}

fn wait_until(mut predicate: impl FnMut() -> bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    predicate()
}

fn link_ok(runtime: &VossRuntime) -> bool {
    runtime
        .health_report()
        .get("outbox_accounting")
        .and_then(|health| health.get("ok"))
        .and_then(Json::as_bool)
        == Some(true)
}

fn delivered_files(store: &Path) -> Vec<String> {
    let directory = store.join("delivered");
    let Ok(entries) = fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.ends_with(".tmp"))
        .collect();
    names.sort();
    names
}

fn receipts(store: &Path) -> Vec<Json> {
    let Ok(text) = fs::read_to_string(store.join("outbox-receipts.jsonl")) else {
        return Vec::new();
    };
    text.lines().filter_map(|line| loads_strict(line).ok()).collect()
}

fn control_events(store: &Path) -> Vec<String> {
    let Ok(body) = fs::read_to_string(store.join("outbox-control.jsonl")) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(|line| loads_strict(line).ok())
        .map(|record| text(&record, "event"))
        .collect()
}

#[test]
fn approved_delivery_produces_receipt_and_service_effect() {
    let root = std::env::temp_dir().join(format!("voss-outbox-approve-{}", new_id("")));
    let proc = start_outbox(&root, false, false);
    let runtime = runtime_in(&root);
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(|| link_ok(&runtime), Duration::from_secs(5)));
    assert_eq!(
        runtime.health_report().get("outbox_accounting").and_then(|health| health.get("ok")).and_then(Json::as_bool),
        Some(true)
    );
    let response = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&response, "decision"), "ALLOW");
    assert_eq!(response.get("result").and_then(|result| result.get("delivered")).and_then(Json::as_bool), Some(true));
    let receipt_id = response.get("result").and_then(|result| result.get("receipt_id")).and_then(Json::as_str).unwrap_or("");
    assert!(receipt_id.starts_with("rcpt-"));
    let files = delivered_files(&proc.store);
    assert_eq!(files.len(), 1);
    let recorded = loads_strict(&fs::read_to_string(proc.store.join("delivered").join(&files[0])).unwrap()).unwrap();
    assert_eq!(text(&recorded, "receipt_id"), receipt_id);
    assert_eq!(text(&recorded, "recipient"), "alex@example.invalid");
    assert_eq!(text(&recorded, "service"), "mail");
    let ledger = receipts(&proc.store);
    assert_eq!(ledger.len(), 1);
    assert_eq!(text(&ledger[0], "status"), "delivered");
    assert!(control_events(&proc.store).iter().any(|event| event == "outbox_delivered"));
    assert_eq!(fs::read_dir(&runtime.outbox_dir).unwrap().count(), 0);
    runtime.close();
}

#[test]
fn service_side_idempotency_never_double_delivers() {
    let root = std::env::temp_dir().join(format!("voss-outbox-idem-{}", new_id("")));
    let proc = start_outbox(&root, false, false);
    let link = OutboxLink::new("127.0.0.1", proc.port, proc.key.clone());
    link.start();
    assert!(wait_until(|| link.health().ok, Duration::from_secs(5)));
    let first = link.deliver("dlv-1", "mail", "a@example.invalid", "digest-a", "idem-key-1").unwrap();
    let second = link.deliver("dlv-2", "mail", "a@example.invalid", "digest-a", "idem-key-1").unwrap();
    assert_eq!(first.status, "delivered");
    assert_eq!(second.status, "duplicate");
    assert_eq!(first.receipt_id, second.receipt_id);
    assert_eq!(delivered_files(&proc.store).len(), 1);
    assert_eq!(receipts(&proc.store).len(), 1);
    assert!(control_events(&proc.store).iter().any(|event| event == "outbox_duplicate"));
    link.stop();
}

#[test]
fn dropped_ack_host_uncertain_service_proves_delivery() {
    let root = std::env::temp_dir().join(format!("voss-outbox-drop-{}", new_id("")));
    let proc = start_outbox(&root, true, false);
    let runtime = runtime_in(&root);
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(|| link_ok(&runtime), Duration::from_secs(5)));
    let response = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&response, "decision"), "UNKNOWN");
    assert_eq!(text(&response, "reason_code"), "unknown");
    assert_eq!(delivered_files(&proc.store).len(), 1);
    let ledger = receipts(&proc.store);
    assert_eq!(ledger.len(), 1);
    assert_eq!(text(&ledger[0], "status"), "delivered");
    assert_eq!(text(&ledger[0], "recipient"), "alex@example.invalid");
    assert!(control_events(&proc.store).iter().any(|event| event == "outbox_dropped_ack"));
    runtime.close();
}

#[test]
fn refusing_service_fails_closed_no_effect() {
    let root = std::env::temp_dir().join(format!("voss-outbox-refuse-{}", new_id("")));
    let proc = start_outbox(&root, false, true);
    let runtime = runtime_in(&root);
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(|| link_ok(&runtime), Duration::from_secs(5)));
    let response = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&response, "decision"), "UNKNOWN");
    assert_eq!(text(&response, "reason_code"), "denied");
    assert!(delivered_files(&proc.store).is_empty());
    assert!(receipts(&proc.store).is_empty());
    runtime.close();
}

#[test]
fn unreachable_service_fails_closed_but_reads_still_work() {
    let root = std::env::temp_dir().join(format!("voss-outbox-absent-{}", new_id("")));
    let runtime = runtime_in(&root);
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_add(2)).collect();
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", 1, key));
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        runtime.health_report().get("outbox_accounting").and_then(|health| health.get("ok")).and_then(Json::as_bool),
        Some(false)
    );
    let response = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&response, "decision"), "UNKNOWN");
    assert_eq!(text(&response, "reason_code"), "denied");
    fs::write(runtime.workspace_root.join("notes.txt"), "readable").unwrap();
    let read = envelope(&runtime, "workspace.read", Json::object([("path", Json::string("notes.txt"))]));
    assert_eq!(text(&runtime.handle_envelope(&read), "decision"), "ALLOW");
    runtime.close();
}

#[test]
fn link_loss_after_valid_session_fails_next_delivery_closed() {
    let root = std::env::temp_dir().join(format!("voss-outbox-loss-{}", new_id("")));
    let mut proc = start_outbox(&root, false, false);
    let runtime = runtime_in(&root);
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(|| link_ok(&runtime), Duration::from_secs(5)));
    let first = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&first, "decision"), "ALLOW");
    assert_eq!(delivered_files(&proc.store).len(), 1);
    let _ = proc.child.kill();
    let _ = proc.child.wait();
    let second = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&second, "decision"), "UNKNOWN");
    let reason = text(&second, "reason_code");
    assert!(reason == "denied" || reason == "unknown", "{reason}");
    assert_eq!(delivered_files(&proc.store).len(), 1);
    assert!(wait_until(
        || runtime.health_report().get("outbox_accounting").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(false),
        Duration::from_secs(5),
    ));
    assert_eq!(
        runtime.health_report().get("outbox_accounting").and_then(|health| health.get("failed")).and_then(Json::as_bool),
        Some(true)
    );
    runtime.close();
}

#[test]
fn unauthenticated_probe_refused_and_logged() {
    let root = std::env::temp_dir().join(format!("voss-outbox-probe-{}", new_id("")));
    let proc = start_outbox(&root, false, false);
    let mut probe = TcpStream::connect(("127.0.0.1", proc.port)).unwrap();
    probe.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let hello = Json::object([
        ("mac", Json::string("0".repeat(64))),
        ("nonce", Json::string(new_id("p-"))),
        ("type", Json::string("hello")),
        ("version", Json::string(outbox::OUTBOX_PROTOCOL)),
    ]);
    probe.write_all(&relay::frame(&hello).unwrap()).unwrap();
    let reply = relay::read_frame(&mut probe).unwrap();
    drop(probe);
    assert_eq!(text(&reply, "type"), "ack");
    assert_eq!(text(&reply, "status"), "error");
    assert_eq!(text(&reply, "reason"), "denied_outbox_auth");
    assert!(control_events(&proc.store).iter().any(|event| event == "outbox_denied_hello"));
    let runtime = runtime_in(&root);
    runtime.attach_outbox(OutboxLink::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(|| link_ok(&runtime), Duration::from_secs(5)));
    let response = approve(&runtime, &send_env(&runtime));
    assert_eq!(text(&response, "decision"), "ALLOW");
    assert_eq!(delivered_files(&proc.store).len(), 1);
    runtime.close();
}

#[test]
fn recorded_delivery_without_effect_file_is_uncertain() {
    let root = std::env::temp_dir().join(format!("voss-outbox-uncertain-{}", new_id("")));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let root = fs::canonicalize(&root).unwrap();
    let key = vec![7u8; 32];
    let server = OutboxServer::bind(&root, key.clone(), false, false, 0).unwrap();
    let delivered = root.join("delivered");
    fs::remove_dir_all(&delivered).unwrap();
    fs::write(&delivered, b"blocked").unwrap();
    server.start();
    let link = OutboxLink::new("127.0.0.1", server.port(), key);
    link.start();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !link.health().connected {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(link.health().connected, "{}", link.health().error);
    let digest = "ab".repeat(32);
    let first = link.deliver("dlv-1", "mail", "a@b.invalid", &digest, "req-1");
    let second = link.deliver("dlv-2", "mail", "a@b.invalid", &digest, "req-1");
    link.stop();
    server.stop();
    match first {
        Err(OutboxError::Uncertain(message)) => assert!(message.contains("recorded"), "{message}"),
        Err(OutboxError::Unavailable(message)) => panic!("first reply was unavailable: {message}"),
        Ok(receipt) => panic!("first reply was {}", receipt.status),
    }
    match second {
        Err(OutboxError::Uncertain(message)) => assert!(message.contains("recorded"), "{message}"),
        Err(OutboxError::Unavailable(message)) => panic!("retry was unavailable: {message}"),
        Ok(receipt) => panic!("retry was {}", receipt.status),
    }
    let ledger = fs::read_to_string(root.join("outbox-receipts.jsonl")).unwrap();
    assert_eq!(ledger.matches("req-1").count(), 1, "{ledger}");
    let _ = fs::remove_dir_all(&root);
}
