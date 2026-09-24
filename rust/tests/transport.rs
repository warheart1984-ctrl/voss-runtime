//! Authenticated worker transport, including an adversarial peer.

use std::fs;
use std::path::Path;

use voss::canonical::{Json, canonical_bytes};
use voss::keys::KeyRing;
use voss::runtime::VossRuntime;

fn runtime_in(root: &Path) -> VossRuntime {
    let workspace = root.join("workspace");
    let outbox = root.join("outbox");
    fs::create_dir_all(&workspace).unwrap();
    VossRuntime::open(
        &workspace,
        &outbox,
        root.join("audit.jsonl"),
        KeyRing::generate(),
        None,
    )
    .unwrap()
}

fn accepts_work(runtime: &VossRuntime) -> bool {
    runtime
        .health_report()
        .get("worker_accepts_work")
        .and_then(Json::as_bool)
        .unwrap_or(false)
}

#[test]
fn happy_path_realtime_worker() {
    let root = std::env::temp_dir().join(format!("voss-transport-{}", voss::new_id("")));
    let runtime = runtime_in(&root);
    fs::write(runtime.workspace_root.join("notes.txt"), "hello from the trusted host\n").unwrap();
    let mut child = runtime.spawn_worker().expect("handshake");
    assert_eq!(
        runtime
            .health_report()
            .get("watchdog")
            .and_then(|value| value.get("ok"))
            .and_then(Json::as_bool),
        Some(true)
    );

    let Json::Array(envelopes) = runtime.worker_propose("propose:read").unwrap() else {
        panic!("proposal list");
    };
    assert_eq!(envelopes.len(), 1);
    let text = String::from_utf8(canonical_bytes(&envelopes[0]).unwrap()).unwrap();
    let response = runtime.handle_envelope(&text);
    assert_eq!(response.get("decision").and_then(Json::as_str), Some("ALLOW"));
    assert!(
        response
            .get("result")
            .and_then(|result| result.get("sha256"))
            .and_then(Json::as_str)
            .is_some_and(|hash| !hash.is_empty())
    );

    let Json::Array(envelopes) = runtime.worker_propose("propose:write").unwrap() else {
        panic!("proposal list");
    };
    assert_eq!(envelopes.len(), 1);
    let text = String::from_utf8(canonical_bytes(&envelopes[0]).unwrap()).unwrap();
    let response = runtime.handle_envelope(&text);
    assert_eq!(
        response.get("decision").and_then(Json::as_str),
        Some("REQUIRE_APPROVAL")
    );
    assert!(!runtime.audit_text().contains("transport_denied"));

    let _ = child.kill();
    let _ = child.wait();
    runtime.close();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn boundary_attacks_are_contained() {
    let evil = std::env::var("CARGO_BIN_EXE_evil_worker").expect("evil worker");
    let cases = [
        ("reply-forged-mac", "denied_channel_auth"),
        ("reply-replay", "denied_channel_replay"),
        ("reply-skip-seq", "denied_channel_sequence"),
        ("reply-wrong-direction", "denied_channel_wrong_direction"),
        ("reply-oversize", "denied_channel_oversize"),
    ];
    for (mode, reason) in cases {
        let root = std::env::temp_dir().join(format!("voss-evil-{mode}-{}", voss::new_id("")));
        let runtime = runtime_in(&root);
        let mut child = runtime
            .spawn_worker_with(Path::new(&evil), &[("VOSS_EVIL_MODE", mode)])
            .unwrap_or_else(|error| panic!("{mode} spawn: {}", error.message()));
        let error = runtime.worker_propose("propose:read").expect_err(mode);
        assert!(error.message().contains(reason), "{mode}: {}", error.message());
        assert!(!accepts_work(&runtime), "{mode}: worker must be suspended");
        assert!(runtime.audit_text().contains(reason), "{mode}");
        assert!(runtime.audit_text().contains("transport_denied"), "{mode}");
        let _ = child.kill();
        let _ = child.wait();
        runtime.close();
        let _ = fs::remove_dir_all(root);
    }
}

#[test]
fn forged_handshake_blocks_spawn() {
    let evil = std::env::var("CARGO_BIN_EXE_evil_worker").expect("evil worker");
    let root = std::env::temp_dir().join(format!("voss-handshake-{}", voss::new_id("")));
    let runtime = runtime_in(&root);
    let error = runtime
        .spawn_worker_with(
            Path::new(&evil),
            &[("VOSS_EVIL_MODE", "handshake-forged-mac")],
        )
        .unwrap_err();
    assert!(error.message().contains("denied_channel_auth"), "{}", error.message());
    assert!(!accepts_work(&runtime));
    assert!(runtime.audit_text().contains("denied_channel_auth"));
    runtime.close();
    let _ = fs::remove_dir_all(root);
}
