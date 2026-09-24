//! Crash-injection driver. Runs one approval to its seam, then the seam exits 86.
//!
//! Usage: `crash_driver <root> <mode>`

use std::path::PathBuf;

use voss::canonical::{Json, canonical_bytes};
use voss::crashpoint;
use voss::keys::KeyRing;
use voss::runtime::VossRuntime;

fn main() {
    let mut args = std::env::args().skip(1);
    let Some(root) = args.next() else {
        eprintln!("usage: crash_driver <root> <mode>");
        std::process::exit(2);
    };
    let Some(mode) = args.next() else {
        eprintln!("usage: crash_driver <root> <mode>");
        std::process::exit(2);
    };
    let point = match mode.as_str() {
        "flow_request_prewal" => crashpoint::FLOW_REQUEST_PREWAL,
        "flow_request" => crashpoint::FLOW_REQUEST,
        "flow_resolution" => crashpoint::FLOW_RESOLUTION,
        "capability_issued" => crashpoint::CAPABILITY_ISSUED,
        "request_executed" => crashpoint::REQUEST_EXECUTED,
        "effect_done" => crashpoint::EFFECT_DONE,
        other => {
            eprintln!("unknown crash mode {other}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run(PathBuf::from(root), &mode, point) {
        eprintln!("{error}");
        std::process::exit(1);
    }
    std::process::exit(0);
}

fn run(root: PathBuf, mode: &str, point: &str) -> Result<(), String> {
    let keys = KeyRing::load_or_create(&root).map_err(|error| error.to_string())?;
    let runtime = VossRuntime::open(
        root.join("workspace"),
        root.join("outbox"),
        root.join("audit.jsonl"),
        keys,
        None,
    )
    .map_err(|error| error.message().to_string())?;
    let proposal = envelope(&runtime, &format!("crash-{mode}"));
    if mode == "flow_request_prewal" || mode == "flow_request" {
        crashpoint::arm(point);
        let _ = runtime.handle_envelope(&proposal);
    } else {
        let pending = runtime.handle_envelope(&proposal);
        let flow_id = pending
            .get("approval_request_id")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string();
        if flow_id.is_empty() {
            return Err(format!("mode {mode} did not open an approval"));
        }
        crashpoint::arm(point);
        let _ = runtime.resolve_approval(&flow_id, "APPROVE", "crash-test");
    }
    Ok(())
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
    String::from_utf8(canonical_bytes(&value).unwrap_or_default()).unwrap_or_default()
}
