//! Deterministic crash-injection seams for fault-injection tests.
//!
//! A crash can land at any byte of progress. These seams stop the process
//! (`std::process::exit`, with no destructor or flush beyond what the ledger
//! already committed) at the write-ahead boundaries that matter. A seam fires
//! only when `VOSS_CRASHPOINT` names it, or when this process armed that same
//! name. The worker cannot arm the trusted host.

use std::sync::Mutex;

pub const FLOW_REQUEST_PREWAL: &str = "voss_cp_flow_request_prewal";
pub const FLOW_REQUEST: &str = "voss_cp_flow_request";
pub const FLOW_RESOLUTION: &str = "voss_cp_flow_resolution";
pub const CAPABILITY_ISSUED: &str = "voss_cp_capability_issued";
pub const REQUEST_EXECUTED: &str = "voss_cp_request_executed";
pub const EFFECT_DONE: &str = "voss_cp_effect_done";

pub const EXIT_CODE: i32 = 86;

static ARMED: Mutex<Option<String>> = Mutex::new(None);

pub fn arm(point: &str) {
    *ARMED.lock().expect("crashpoint") = Some(point.to_string());
}

pub fn maybe_crash(point: &str) {
    let from_env = std::env::var("VOSS_CRASHPOINT").ok();
    let armed = ARMED.lock().expect("crashpoint").clone();
    if from_env.as_deref() == Some(point) || armed.as_deref() == Some(point) {
        std::process::exit(EXIT_CODE);
    }
}
