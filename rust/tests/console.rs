//! Operator approval console: votes and the kill switch live in another process.

use std::fs;
use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use voss::canonical::{Json, canonical_bytes, loads_strict, new_id};
use voss::console::{self, ConsoleClient};
use voss::keys::KeyRing;
use voss::relay;
use voss::runtime::VossRuntime;

struct ConsoleProc {
    child: Child,
    store: PathBuf,
    port: u16,
    key: Vec<u8>,
}

impl Drop for ConsoleProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_console(root: &Path, auto: Option<&str>, delay: &str) -> ConsoleProc {
    fs::create_dir_all(root).unwrap();
    let store = root.join("console_store");
    fs::create_dir_all(&store).unwrap();
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_mul(9).wrapping_add(5)).collect();
    let port_file = root.join("console_port.txt");
    let mut command = Command::new(std::env::var("CARGO_BIN_EXE_console").expect("console binary"));
    command
        .arg("--store")
        .arg(&store)
        .arg("--port-file")
        .arg(&port_file)
        .arg("--transfer-key")
        .arg(hex::encode(&key))
        .arg("--delay")
        .arg(delay)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(auto) = auto {
        command.arg("--auto").arg(auto);
    }
    let mut child = command.spawn().expect("spawn console");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut port = None;
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            panic!("console died early");
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
        panic!("console port never published");
    };
    ConsoleProc { child, store, port, key }
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

fn transcript(store: &Path, kind: &str) -> Vec<Json> {
    let path = store.join("console-transcript.jsonl");
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| loads_strict(line).ok())
        .filter(|record| record.get("kind").and_then(Json::as_str) == Some(kind))
        .collect()
}

fn outbox_count(dir: &Path) -> usize {
    fs::read_dir(dir).map(|entries| entries.filter_map(Result::ok).count()).unwrap_or(0)
}

#[test]
fn replayed_hello_nonce_is_refused() {
    let root = std::env::temp_dir().join(format!("voss-console-replay-{}", new_id("")));
    let proc = start_console(&root, Some("approve"), "0.2");
    let mut first = TcpStream::connect(("127.0.0.1", proc.port)).unwrap();
    first.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    first.set_nodelay(true).unwrap();
    let challenge = relay::read_frame(&mut first).unwrap();
    assert_eq!(text(&challenge, "type"), "challenge", "{challenge:?}");
    let challenge_value = text(&challenge, "challenge");
    let nonce = new_id("console-");
    let hello = Json::object([
        ("challenge", Json::string(challenge_value.clone())),
        ("mac", Json::string(console::sign_console_hello(&proc.key, &nonce, &challenge_value))),
        ("nonce", Json::string(nonce)),
        ("type", Json::string("hello")),
        ("version", Json::string(console::CONSOLE_PROTOCOL)),
    ]);
    let bytes = relay::frame(&hello).unwrap();
    first.write_all(&bytes).unwrap();
    let reply = relay::read_frame(&mut first).unwrap();
    assert_eq!(text(&reply, "type"), "hello_ok");
    drop(first);
    thread::sleep(Duration::from_millis(200));
    let mut replay = TcpStream::connect(("127.0.0.1", proc.port)).unwrap();
    replay.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    replay.set_nodelay(true).unwrap();
    let _ = relay::read_frame(&mut replay).unwrap();
    replay.write_all(&bytes).unwrap();
    let reply2 = relay::read_frame(&mut replay).unwrap();
    assert_eq!(text(&reply2, "status"), "error");
    assert_eq!(text(&reply2, "reason"), "denied_console_auth");
    drop(replay);
    let control = fs::read_to_string(proc.store.join("console-control.jsonl")).unwrap();
    let events: Vec<String> = control
        .lines()
        .filter_map(|line| loads_strict(line).ok())
        .map(|rec| text(&rec, "event"))
        .collect();
    assert!(events.iter().any(|e| e == "console_denied_hello"), "{events:?}");
}

#[test]
fn auto_approve_from_console_executes_effect() {
    let root = std::env::temp_dir().join(format!("voss-console-approve-{}", new_id("")));
    let proc = start_console(&root, Some("approve"), "0.2");
    let runtime = runtime_in(&root);
    let client = ConsoleClient::new("127.0.0.1", proc.port, proc.key.clone());
    runtime.attach_console(client);
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(true),
        Duration::from_secs(5),
    ));
    let response = runtime.handle_envelope(&send_env(&runtime));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let flow_id = text(&response, "approval_request_id");
    assert!(
        wait_until(|| outbox_count(&runtime.outbox_dir) == 1, Duration::from_secs(5)),
        "auto-approve never executed the effect"
    );
    let file = fs::read_dir(&runtime.outbox_dir).unwrap().next().unwrap().unwrap().path();
    let outbox = loads_strict(&fs::read_to_string(file).unwrap()).unwrap();
    assert_eq!(text(&outbox, "recipient"), "alex@example.invalid");
    let views = transcript(&proc.store, "view");
    let view = views.last().expect("no view was shown to the operator");
    assert_eq!(text(view, "flow_id"), flow_id);
    assert_eq!(text(view, "action"), "external.send_mock");
    assert_eq!(view.get("resource").and_then(|resource| resource.get("service")).and_then(Json::as_str), Some("mail"));
    assert_eq!(
        view.get("resource").and_then(|resource| resource.get("recipient")).and_then(Json::as_str),
        Some("alex@example.invalid")
    );
    assert!(view.get("reversible").and_then(Json::as_bool).is_some());
    assert!(view.get("risk_class").is_some());
    assert!(view.get("consequences").is_some());
    let votes = transcript(&proc.store, "vote");
    let vote = votes.last().expect("no vote came back from the console");
    assert_eq!(text(vote, "decision"), "APPROVE");
    assert!(text(vote, "approver_ref").starts_with("operator@console"));
    runtime.close();
}

#[test]
fn auto_deny_is_terminal_and_not_cached() {
    let root = std::env::temp_dir().join(format!("voss-console-deny-{}", new_id("")));
    let proc = start_console(&root, Some("deny"), "0.2");
    let runtime = runtime_in(&root);
    runtime.attach_console(ConsoleClient::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(true),
        Duration::from_secs(5),
    ));
    let env = send_env(&runtime);
    let first = runtime.handle_envelope(&env);
    assert_eq!(text(&first, "decision"), "REQUIRE_APPROVAL");
    let flow_id = text(&first, "approval_request_id");
    assert!(wait_until(
        || runtime.approval_state(&flow_id).as_deref() == Some("DENIED_OR_EXPIRED"),
        Duration::from_secs(5),
    ));
    assert_eq!(outbox_count(&runtime.outbox_dir), 0);
    let second = runtime.handle_envelope(&env);
    assert_eq!(text(&second, "decision"), "REQUIRE_APPROVAL");
    assert_ne!(text(&second, "approval_request_id"), flow_id);
    assert_eq!(outbox_count(&runtime.outbox_dir), 0);
    runtime.close();
}

#[test]
fn lost_console_fails_closed_consequential_reads_allowed() {
    let root = std::env::temp_dir().join(format!("voss-console-lost-{}", new_id("")));
    let mut proc = start_console(&root, Some("approve"), "30");
    let runtime = runtime_in(&root);
    runtime.attach_console(ConsoleClient::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(true),
        Duration::from_secs(5),
    ));
    let env = send_env(&runtime);
    let first = runtime.handle_envelope(&env);
    assert_eq!(text(&first, "decision"), "REQUIRE_APPROVAL");
    let _ = proc.child.kill();
    let _ = proc.child.wait();
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(false),
        Duration::from_secs(5),
    ));
    let second = runtime.handle_envelope(&env);
    assert_eq!(text(&second, "decision"), "DENY");
    assert_eq!(text(&second, "reason_code"), "denied_approval_unavailable");
    fs::write(runtime.workspace_root.join("notes.txt"), "readable").unwrap();
    let read = envelope(
        &runtime,
        "workspace.read",
        Json::object([("path", Json::string("notes.txt"))]),
    );
    let read_resp = runtime.handle_envelope(&read);
    assert_eq!(text(&read_resp, "decision"), "ALLOW");
    runtime.close();
}

#[test]
fn console_never_reachable_fails_closed() {
    let root = std::env::temp_dir().join(format!("voss-console-absent-{}", new_id("")));
    let runtime = runtime_in(&root);
    let key: Vec<u8> = (0u8..32).map(|index| index.wrapping_add(1)).collect();
    runtime.attach_console(ConsoleClient::new("127.0.0.1", 1, key));
    thread::sleep(Duration::from_millis(400));
    let response = runtime.handle_envelope(&send_env(&runtime));
    assert_eq!(text(&response, "decision"), "DENY");
    assert_eq!(text(&response, "reason_code"), "denied_approval_unavailable");
    fs::write(runtime.workspace_root.join("notes.txt"), "readable").unwrap();
    let read = envelope(
        &runtime,
        "workspace.read",
        Json::object([("path", Json::string("notes.txt"))]),
    );
    assert_eq!(text(&runtime.handle_envelope(&read), "decision"), "ALLOW");
    runtime.close();
}

#[test]
fn unauthenticated_probe_refused_and_logged() {
    let root = std::env::temp_dir().join(format!("voss-console-probe-{}", new_id("")));
    let proc = start_console(&root, Some("approve"), "0.2");
    let mut probe = TcpStream::connect(("127.0.0.1", proc.port)).unwrap();
    probe.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let challenge = relay::read_frame(&mut probe).unwrap();
    assert_eq!(text(&challenge, "type"), "challenge", "{challenge:?}");
    let hello = Json::object([
        ("challenge", Json::string(text(&challenge, "challenge"))),
        ("mac", Json::string("0".repeat(64))),
        ("nonce", Json::string(new_id("p-"))),
        ("type", Json::string("hello")),
        ("version", Json::string(console::CONSOLE_PROTOCOL)),
    ]);
    probe.write_all(&relay::frame(&hello).unwrap()).unwrap();
    let reply = relay::read_frame(&mut probe).unwrap();
    drop(probe);
    assert_eq!(text(&reply, "type"), "ack");
    assert_eq!(text(&reply, "status"), "error");
    assert_eq!(text(&reply, "reason"), "denied_console_auth");
    let control = fs::read_to_string(proc.store.join("console-control.jsonl")).unwrap();
    let events: Vec<String> = control
        .lines()
        .filter_map(|line| loads_strict(line).ok())
        .map(|record| text(&record, "event"))
        .collect();
    assert!(events.iter().any(|event| event == "console_denied_hello"));
    let runtime = runtime_in(&root);
    runtime.attach_console(ConsoleClient::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(true),
        Duration::from_secs(5),
    ));
    let response = runtime.handle_envelope(&send_env(&runtime));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    assert!(
        wait_until(|| outbox_count(&runtime.outbox_dir) == 1, Duration::from_secs(5)),
        "legitimate console never recovered after the probe"
    );
    runtime.close();
}

#[test]
fn terminate_directive_is_the_kill_switch() {
    let root = std::env::temp_dir().join(format!("voss-console-kill-{}", new_id("")));
    let mut proc = start_console(&root, None, "0.2");
    let runtime = runtime_in(&root);
    runtime.attach_console(ConsoleClient::new("127.0.0.1", proc.port, proc.key.clone()));
    assert!(wait_until(
        || runtime.health_report().get("operator_console").and_then(|health| health.get("ok")).and_then(Json::as_bool) == Some(true),
        Duration::from_secs(5),
    ));
    let mut worker = runtime.spawn_worker().unwrap();
    let stdin = proc.child.stdin.as_mut().unwrap();
    writeln!(stdin, "kill stop-all").unwrap();
    stdin.flush().unwrap();
    assert!(
        wait_until(|| worker.try_wait().ok().flatten().is_some(), Duration::from_secs(5)),
        "console terminate directive never killed the worker"
    );
    assert!(!runtime.watchdog.accepts_work(&runtime.worker_principal));
    let events = transcript(&proc.store, "terminate");
    assert!(!events.is_empty(), "no terminate gesture recorded");
    assert_eq!(events.last().and_then(|record| record.get("kind")).and_then(Json::as_str), Some("terminate"));
    runtime.close();
}
