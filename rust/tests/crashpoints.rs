//! Fault injection for the write-ahead ledger.
//!
//! Each case kills the runtime at one boundary, reopens the same directory,
//! and checks that recovery never re-grants or runs an effect twice.

use std::fs;
use std::path::Path;
use std::process::Command;

use voss::audit::{AuditFields, AuditLog, WAL_SCHEMA, wal_genesis};
use voss::canonical::{Json, canonical_bytes, loads_strict, new_id};
use voss::keys::KeyRing;
use voss::runtime::VossRuntime;

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

fn envelope(runtime: &VossRuntime, request_id: &str) -> String {
    let value = Json::object([
        ("version", Json::string("1")),
        ("request_id", Json::string(request_id)),
        ("session_id", Json::string(&runtime.worker_session)),
        ("principal", Json::string(&runtime.worker_principal)),
        ("action", Json::string("workspace.write")),
        ("resource", Json::object([("path", Json::string("draft.txt"))])),
        ("payload", Json::object([("content", Json::string("crash-test"))])),
        ("constraints", Json::empty_object()),
    ]);
    String::from_utf8(canonical_bytes(&value).unwrap()).unwrap()
}

fn run_crash(root: &Path, mode: &str) {
    let driver = std::env::var("CARGO_BIN_EXE_crash_driver").expect("crash driver");
    let done = Command::new(driver)
        .arg(root)
        .arg(mode)
        .output()
        .expect("spawn crash driver");
    assert_eq!(
        done.status.code(),
        Some(86),
        "mode {mode}: {}\n{}",
        done.status,
        String::from_utf8_lossy(&done.stderr)
    );
}

fn wal_records(root: &Path) -> Vec<Json> {
    let text = fs::read_to_string(root.join("wal.jsonl")).unwrap_or_default();
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            loads_strict(line)
                .unwrap()
                .get("record")
                .cloned()
                .unwrap_or(Json::Null)
        })
        .collect()
}

fn assert_clean_recovery(runtime: &VossRuntime) {
    let health = runtime.health_report();
    assert_eq!(health.get("wal_healthy").and_then(Json::as_bool), Some(true));
    assert_eq!(health.get("recovery_ok").and_then(Json::as_bool), Some(true));
    let audit = runtime.audit_text();
    assert!(audit.contains("\"event_type\":\"recovery\""));
    assert!(!audit.contains("recovery_failed"));
    assert!(runtime_audit_ok(runtime));
}

fn runtime_audit_ok(runtime: &VossRuntime) -> bool {
    !runtime.audit_text().is_empty() && {
        let health = runtime.health_report();
        health.get("audit_healthy").and_then(Json::as_bool) == Some(true)
            && audit_verifies(runtime)
    }
}

fn audit_verifies(runtime: &VossRuntime) -> bool {
    let summary = runtime.audit_summary();
    summary.get("integrity_ok").and_then(Json::as_bool) == Some(true)
}

fn text(value: &Json, key: &str) -> String {
    value.get(key).and_then(Json::as_str).unwrap_or("").to_string()
}

fn draft(runtime: &VossRuntime) -> std::path::PathBuf {
    runtime.workspace_root.join("draft.txt")
}

#[test]
fn crash_before_wal_flow_request_loses_only_that_flow() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "flow_request_prewal");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    let flows: Vec<_> = wal_records(&root)
        .into_iter()
        .filter(|record| record.get("event_type").and_then(Json::as_str) == Some("flow_request"))
        .collect();
    assert!(flows.is_empty());
    let response = runtime.handle_envelope(&envelope(&runtime, "crash-flow_request_prewal"));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let out = runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&out, "decision"), "ALLOW");
    assert_eq!(fs::read_to_string(draft(&runtime)).unwrap(), "crash-test");
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_after_flow_request_restores_pending_approval() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "flow_request");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    let flows: Vec<_> = wal_records(&root)
        .into_iter()
        .filter(|record| {
            record.get("event_type").and_then(Json::as_str) == Some("flow_request")
                && record.get("request_id").and_then(Json::as_str) == Some("crash-flow_request")
        })
        .collect();
    assert_eq!(flows.len(), 1);
    let flow_id = text(&flows[0], "flow_id");
    assert_eq!(runtime.approval_state(&flow_id).as_deref(), Some("PENDING_APPROVAL"));
    let out = runtime.resolve_approval(&flow_id, "APPROVE", "crash-test");
    assert_eq!(text(&out, "decision"), "ALLOW");
    assert_eq!(fs::read_to_string(draft(&runtime)).unwrap(), "crash-test");
    let again = runtime.handle_envelope(&envelope(&runtime, "crash-flow_request"));
    assert_eq!(text(&again, "decision"), "REQUIRE_APPROVAL");
    let decided = runtime.resolve_approval(&text(&again, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&decided, "reason_code"), "denied_replay");
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_after_approval_grants_nothing_more() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "flow_resolution");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    let flows: Vec<_> = wal_records(&root)
        .into_iter()
        .filter(|record| {
            record.get("event_type").and_then(Json::as_str) == Some("flow_request")
                && record.get("request_id").and_then(Json::as_str) == Some("crash-flow_resolution")
        })
        .collect();
    let flow_id = text(&flows[0], "flow_id");
    assert_eq!(runtime.approval_state(&flow_id).as_deref(), Some("AUTHORIZED"));
    assert!(runtime.capabilities().is_empty());
    let denied = runtime.resolve_approval(&flow_id, "APPROVE", "crash-test");
    assert_eq!(text(&denied, "decision"), "DENY");
    assert!(!draft(&runtime).exists());
    let response = runtime.handle_envelope(&envelope(&runtime, "crash-flow_resolution"));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let out = runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&out, "decision"), "ALLOW");
    assert_eq!(fs::read_to_string(draft(&runtime)).unwrap(), "crash-test");
    let executed = wal_records(&root)
        .into_iter()
        .filter(|record| record.get("event_type").and_then(Json::as_str) == Some("request_executed"))
        .count();
    assert_eq!(executed, 1);
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_after_capability_issued_effect_runs_once() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "capability_issued");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    let caps = runtime.capabilities();
    assert_eq!(caps.len(), 1);
    assert!(!caps[0].is_used());
    let response = runtime.handle_envelope(&envelope(&runtime, "crash-capability_issued"));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let out = runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&out, "decision"), "ALLOW");
    assert_eq!(fs::read_to_string(draft(&runtime)).unwrap(), "crash-test");
    let executed = wal_records(&root)
        .into_iter()
        .filter(|record| record.get("event_type").and_then(Json::as_str) == Some("request_executed"))
        .count();
    assert_eq!(executed, 1);
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_before_effect_blocks_replay() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "request_executed");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    assert!(!draft(&runtime).exists());
    let response = runtime.handle_envelope(&envelope(&runtime, "crash-request_executed"));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let decided = runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&decided, "reason_code"), "denied_replay");
    assert!(!draft(&runtime).exists());
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn crash_after_effect_never_double_executes() {
    let root = std::env::temp_dir().join(format!("voss-crash-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    run_crash(&root, "effect_done");
    let runtime = open_runtime(&root);
    assert_clean_recovery(&runtime);
    assert!(draft(&runtime).exists());
    let audit = runtime.audit_text();
    assert_eq!(audit.matches("\"event_type\":\"execution_start\"").count(), 1);
    assert_eq!(audit.matches("\"event_type\":\"execution_result\"").count(), 0);
    let response = runtime.handle_envelope(&envelope(&runtime, "crash-effect_done"));
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let decided = runtime.resolve_approval(&text(&response, "approval_request_id"), "APPROVE", "crash-test");
    assert_eq!(text(&decided, "reason_code"), "denied_replay");
    assert_eq!(fs::read_to_string(draft(&runtime)).unwrap(), "crash-test");
    let executed = wal_records(&root)
        .into_iter()
        .filter(|record| record.get("event_type").and_then(Json::as_str) == Some("request_executed"))
        .count();
    assert_eq!(executed, 1);
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn incomplete_final_record_is_trimmed() {
    let root = std::env::temp_dir().join(format!("voss-tailloss-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("wal.jsonl");
    let keys = KeyRing::generate();
    let wal = AuditLog::open_chain(&path, keys.clone(), WAL_SCHEMA, &wal_genesis().unwrap()).unwrap();
    wal.emit(
        "flow_request",
        AuditFields {
            extra: [
                ("flow_id".to_string(), Json::string("approval-a")),
                ("action".to_string(), Json::string("workspace.write")),
            ]
            .into(),
            ..AuditFields::default()
        },
    )
    .unwrap();
    wal.emit(
        "flow_request",
        AuditFields {
            extra: [
                ("flow_id".to_string(), Json::string("approval-b")),
                ("action".to_string(), Json::string("workspace.read")),
            ]
            .into(),
            ..AuditFields::default()
        },
    )
    .unwrap();
    wal.close();
    let mut raw = fs::read(&path).unwrap();
    raw.extend_from_slice(br#"{"chain_hash": "deadbeef"#);
    fs::write(&path, raw).unwrap();
    let reopened = AuditLog::open_chain(&path, keys, WAL_SCHEMA, &wal_genesis().unwrap()).unwrap();
    assert!(reopened.healthy());
    assert_eq!(reopened.records().unwrap().len(), 2);
    assert!(reopened.verify_integrity());
    reopened
        .emit(
            "flow_request",
            AuditFields {
                extra: [
                    ("flow_id".to_string(), Json::string("approval-c")),
                    ("action".to_string(), Json::string("workspace.write")),
                ]
                .into(),
                ..AuditFields::default()
            },
        )
        .unwrap();
    assert!(reopened.verify_integrity());
    reopened.close();
    let _ = fs::remove_dir_all(root);
}
