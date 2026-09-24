//! Temporal drift oracle: latency ceiling and proposal-line volume.

use std::fs;
use std::path::Path;
use std::process::Child;

use voss::canonical::{Json, canonical_bytes, new_id};
use voss::keys::KeyRing;
use voss::runtime::VossRuntime;

fn runtime_in(root: &Path) -> VossRuntime {
    let workspace = root.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let runtime = VossRuntime::open(
        &workspace,
        root.join("outbox"),
        root.join("audit.jsonl"),
        KeyRing::generate(),
        None,
    )
    .unwrap();
    fs::write(runtime.workspace_root.join("notes.txt"), "x").unwrap();
    runtime
}

fn stall_bin() -> String {
    std::env::var("CARGO_BIN_EXE_stall_worker").expect("stall worker binary")
}

fn start(runtime: &VossRuntime, stall: &str, big_volume: bool) -> Child {
    let mut env = vec![("VOSS_STALL_SECONDS", stall)];
    if big_volume {
        env.push(("VOSS_BIG_VOLUME", "1"));
    }
    runtime.spawn_worker_with(stall_bin(), &env).expect("stall worker handshake")
}

fn propose_read(runtime: &VossRuntime) -> Json {
    let Json::Array(envelopes) = runtime.worker_propose("propose:read").expect("proposal") else {
        panic!("proposal list");
    };
    let text = String::from_utf8(canonical_bytes(&envelopes[0]).unwrap()).unwrap();
    runtime.handle_envelope(&text)
}

fn number(report: &Json, key: &str) -> f64 {
    report.get(key).and_then(Json::as_f64).unwrap_or(-1.0)
}

fn accepts(runtime: &VossRuntime) -> bool {
    runtime.health_report().get("worker_accepts_work").and_then(Json::as_bool) == Some(true)
}

fn stop(child: &mut Child, runtime: &VossRuntime) {
    let _ = child.kill();
    let _ = child.wait();
    runtime.close();
}

#[test]
fn fast_exchanges_stay_within_policy() {
    let root = std::env::temp_dir().join(format!("voss-temporal-fast-{}", new_id("")));
    let runtime = runtime_in(&root);
    let mut child = start(&runtime, "0", false);
    for _ in 0..2 {
        let response = propose_read(&runtime);
        assert_eq!(response.get("decision").and_then(Json::as_str), Some("ALLOW"), "{response:?}");
    }
    let report = runtime.drift_report();
    assert!(report.get("dimensions").and_then(|dims| dims.get("temporal")).is_some());
    assert_eq!(number(&report, "temporal"), 0.0, "{report:?}");
    assert!(accepts(&runtime));
    stop(&mut child, &runtime);
}

#[test]
fn stalled_worker_engages_containment() {
    let root = std::env::temp_dir().join(format!("voss-temporal-stall-{}", new_id("")));
    let runtime = runtime_in(&root);
    let mut child = start(&runtime, "3.0", false);
    for _ in 0..4 {
        let _ = propose_read(&runtime);
    }
    let report = runtime.drift_report();
    assert!(number(&report, "temporal") > 0.30, "{report:?}");
    assert!(!accepts(&runtime));
    let follow = Json::object([
        ("action", Json::string("workspace.read")),
        ("constraints", Json::empty_object()),
        ("payload", Json::empty_object()),
        ("principal", Json::string(&runtime.worker_principal)),
        ("request_id", Json::string("after-stall")),
        ("resource", Json::object([("path", Json::string("notes.txt"))])),
        ("session_id", Json::string(&runtime.worker_session)),
        ("version", Json::string("1")),
    ]);
    let text = String::from_utf8(canonical_bytes(&follow).unwrap()).unwrap();
    let denied = runtime.handle_envelope(&text);
    assert_eq!(denied.get("decision").and_then(Json::as_str), Some("DENY"), "{denied:?}");
    stop(&mut child, &runtime);
}

#[test]
fn volume_overflow_registers_anomaly() {
    let root = std::env::temp_dir().join(format!("voss-temporal-volume-{}", new_id("")));
    let runtime = runtime_in(&root);
    let mut child = start(&runtime, "0", true);
    let _ = propose_read(&runtime);
    let report = runtime.drift_report();
    assert!(number(&report, "temporal") > 0.0, "{report:?}");
    assert_eq!(report.get("temporal_anomalies").and_then(Json::as_i64), Some(1), "{report:?}");
    stop(&mut child, &runtime);
}
