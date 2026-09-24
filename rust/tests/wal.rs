//! Durable approval state: the write-ahead ledger, restart, and fail-closed.

use std::fs;
use std::path::Path;

use voss::audit::{AuditLog, WAL_SCHEMA, wal_genesis};
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

fn envelope(
    runtime: &VossRuntime,
    request_id: &str,
    action: &str,
    resource: Json,
    payload: Json,
    constraints: Json,
) -> String {
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

fn text(value: &Json, key: &str) -> String {
    value.get(key).and_then(Json::as_str).unwrap_or("").to_string()
}

fn flag(value: &Json, key: &str) -> bool {
    value.get(key).and_then(Json::as_bool).unwrap_or(false)
}

#[test]
fn chain_roundtrip_and_verification() {
    let root = std::env::temp_dir().join(format!("voss-wal-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    let keys = KeyRing::generate();
    let wal = AuditLog::open_chain(root.join("wal.jsonl"), keys, WAL_SCHEMA, &wal_genesis().unwrap()).unwrap();
    wal.emit(
        "flow_request",
        voss::audit::AuditFields {
            extra: [
                ("flow_id".to_string(), Json::string("approval-1")),
                ("action".to_string(), Json::string("workspace.write")),
            ]
            .into_iter()
            .collect(),
            ..voss::audit::AuditFields::default()
        },
    )
    .unwrap();
    wal.emit(
        "flow_request",
        voss::audit::AuditFields {
            extra: [
                ("flow_id".to_string(), Json::string("approval-2")),
                ("action".to_string(), Json::string("external.send_mock")),
            ]
            .into_iter()
            .collect(),
            ..voss::audit::AuditFields::default()
        },
    )
    .unwrap();
    assert!(wal.verify_integrity());
    let ids: Vec<_> = wal
        .records()
        .unwrap()
        .iter()
        .filter_map(|line| line.get("record").and_then(|record| record.get("flow_id")).and_then(Json::as_str))
        .map(str::to_string)
        .collect();
    assert_eq!(ids, ["approval-1", "approval-2"]);
    wal.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn tamper_detected() {
    let root = std::env::temp_dir().join(format!("voss-wal-{}", new_id("")));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("wal.jsonl");
    let keys = KeyRing::generate();
    {
        let wal = AuditLog::open_chain(&path, keys.clone(), WAL_SCHEMA, &wal_genesis().unwrap()).unwrap();
        wal.emit(
            "flow_request",
            voss::audit::AuditFields {
                extra: [("flow_id".to_string(), Json::string("approval-1"))].into(),
                ..voss::audit::AuditFields::default()
            },
        )
        .unwrap();
        wal.emit(
            "flow_request",
            voss::audit::AuditFields {
                extra: [
                    ("flow_id".to_string(), Json::string("approval-2")),
                    ("action".to_string(), Json::string("external.send_mock")),
                ]
                .into(),
                ..voss::audit::AuditFields::default()
            },
        )
        .unwrap();
        wal.close();
    }
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<_> = raw.lines().map(str::to_string).collect();
    let mut record = loads_strict(&lines[1]).unwrap();
    if let Json::Object(object) = &mut record
        && let Some(Json::Object(payload)) = object.get_mut("record")
    {
        payload.insert("action".to_string(), Json::string("workspace.read"));
    }
    lines[1] = String::from_utf8(canonical_bytes(&record).unwrap()).unwrap();
    fs::write(&path, lines.join("\n") + "\n").unwrap();
    let reopened = AuditLog::open_chain(&path, keys, WAL_SCHEMA, &wal_genesis().unwrap()).unwrap();
    assert!(!reopened.verify_integrity());
    assert!(reopened.healthy());
    reopened.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn pending_approval_survives_restart() {
    let root = std::env::temp_dir().join(format!("voss-recovery-{}", new_id("")));
    let runtime = open_runtime(&root);
    let principal = runtime.worker_principal.clone();
    let session = runtime.worker_session.clone();
    let proposal = envelope(
        &runtime,
        "req-recover-write",
        "workspace.write",
        Json::object([("path", Json::string("draft.txt"))]),
        Json::object([("content", Json::string("recovery draft"))]),
        Json::empty_object(),
    );
    let response = runtime.handle_envelope(&proposal);
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let flow_id = text(&response, "approval_request_id");
    runtime.close();

    let restarted = open_runtime(&root);
    let health = restarted.health_report();
    assert!(flag(&health, "wal_healthy"));
    assert!(flag(&health, "recovery_ok"));
    assert_eq!(restarted.worker_principal, principal);
    assert_eq!(restarted.worker_session, session);
    assert_eq!(restarted.approval_state(&flow_id).as_deref(), Some("PENDING_APPROVAL"));
    let decided = restarted.resolve_approval(&flow_id, "APPROVE", "test-human");
    assert_eq!(text(&decided, "decision"), "ALLOW", "{decided:?}");
    let draft = fs::read_to_string(restarted.workspace_root.join("draft.txt")).unwrap();
    assert_eq!(draft, "recovery draft");
    restarted.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn consumed_request_not_replayable_after_restart() {
    let root = std::env::temp_dir().join(format!("voss-recovery-{}", new_id("")));
    let runtime = open_runtime(&root);
    let proposal = envelope(
        &runtime,
        "req-recover-send",
        "external.send_mock",
        Json::object([
            ("service", Json::string("mail")),
            ("recipient", Json::string("bob@example.invalid")),
        ]),
        Json::object([
            ("subject", Json::string("hi")),
            ("body", Json::string("once")),
        ]),
        Json::object([("send_once", Json::Bool(true))]),
    );
    let pending = runtime.handle_envelope(&proposal);
    let sent = runtime.resolve_approval(&text(&pending, "approval_request_id"), "APPROVE", "test-human");
    assert_eq!(text(&sent, "decision"), "ALLOW");
    let first = fs::read_dir(&runtime.outbox_dir).unwrap().count();
    assert_eq!(first, 1);
    runtime.close();

    let restarted = open_runtime(&root);
    assert!(flag(&restarted.health_report(), "recovery_ok"));
    let again = restarted.handle_envelope(&proposal);
    assert_eq!(text(&again, "decision"), "REQUIRE_APPROVAL");
    let replay = restarted.resolve_approval(&text(&again, "approval_request_id"), "APPROVE", "test-human");
    assert_eq!(text(&replay, "reason_code"), "denied_replay");
    assert_eq!(fs::read_dir(&restarted.outbox_dir).unwrap().count(), first);
    restarted.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn tampered_wal_fails_closed() {
    let root = std::env::temp_dir().join(format!("voss-recovery-{}", new_id("")));
    let runtime = open_runtime(&root);
    let proposal = envelope(
        &runtime,
        "req-never",
        "workspace.write",
        Json::object([("path", Json::string("draft.txt"))]),
        Json::object([("content", Json::string("should never be written"))]),
        Json::empty_object(),
    );
    let response = runtime.handle_envelope(&proposal);
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    let flow_id = text(&response, "approval_request_id");
    runtime.close();

    let path = root.join("wal.jsonl");
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<_> = raw.lines().filter(|line| !line.is_empty()).map(str::to_string).collect();
    let mut record = loads_strict(lines.last().unwrap()).unwrap();
    if let Json::Object(object) = &mut record
        && let Some(Json::Object(payload)) = object.get_mut("record")
    {
        payload.insert("action".to_string(), Json::string("workspace.read"));
    }
    let last = lines.len() - 1;
    lines[last] = String::from_utf8(canonical_bytes(&record).unwrap()).unwrap();
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let restarted = open_runtime(&root);
    let health = restarted.health_report();
    assert!(flag(&health, "wal_healthy"));
    assert!(!flag(&health, "recovery_ok"));
    assert!(!flag(&health, "worker_accepts_work"));
    let probe = envelope(
        &restarted,
        "req-probe",
        "workspace.write",
        Json::object([("path", Json::string("draft.txt"))]),
        Json::object([("content", Json::string("nope"))]),
        Json::empty_object(),
    );
    let denied = restarted.handle_envelope(&probe);
    assert_eq!(text(&denied, "decision"), "DENY");
    assert_eq!(text(&denied, "reason_code"), "denied_worker_suspended");
    let decided = restarted.resolve_approval(&flow_id, "APPROVE", "test-human");
    assert_eq!(text(&decided, "decision"), "DENY");
    restarted.close();
    assert!(!root.join("workspace").join("draft.txt").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn recovery_events_in_audit() {
    let root = std::env::temp_dir().join(format!("voss-recovery-{}", new_id("")));
    let runtime = open_runtime(&root);
    let proposal = envelope(
        &runtime,
        "req-keep",
        "workspace.write",
        Json::object([("path", Json::string("keep.txt"))]),
        Json::object([("content", Json::string("durable"))]),
        Json::empty_object(),
    );
    let response = runtime.handle_envelope(&proposal);
    assert_eq!(text(&response, "decision"), "REQUIRE_APPROVAL");
    runtime.close();

    let restarted = open_runtime(&root);
    let summary = restarted.audit_text();
    assert!(summary.contains("\"event_type\":\"recovery\""));
    assert!(!summary.contains("\"event_type\":\"recovery_failed\""));
    restarted.close();
    let _ = fs::remove_dir_all(root);
}
