//! In-process watchdog and kill path.
//!
//! Kill order is: stop new work, revoke capabilities, then terminate the
//! worker process. The supervisor lives in the trusted process, so it is
//! not an independent host. Containment does not edit code, memory, the
//! model, or policy.

use std::collections::BTreeMap;
use std::process::Child;
use std::sync::{Arc, Mutex};

pub struct HealthReport {
    pub ok: bool,
    pub detail: String,
}

type HealthSource = Arc<dyn Fn() -> HealthReport + Send + Sync>;
type RevokeCallback = Arc<dyn Fn(&str) -> i64 + Send + Sync>;
type AuditCallback = Arc<dyn Fn(&str, &str) + Send + Sync>;

struct WatchdogState {
    suspended: BTreeMap<String, ()>,
    processes: BTreeMap<String, Child>,
    ok: bool,
    detail: String,
    health_source: Option<HealthSource>,
    revoke: Option<RevokeCallback>,
    audit: Option<AuditCallback>,
}

pub struct Watchdog {
    state: Mutex<WatchdogState>,
}

impl Watchdog {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(WatchdogState {
                suspended: BTreeMap::new(),
                processes: BTreeMap::new(),
                ok: true,
                detail: "healthy".to_string(),
                health_source: None,
                revoke: None,
                audit: None,
            }),
        }
    }

    pub fn attach(
        &self,
        health_source: impl Fn() -> HealthReport + Send + Sync + 'static,
        revoke: impl Fn(&str) -> i64 + Send + Sync + 'static,
        audit: impl Fn(&str, &str) + Send + Sync + 'static,
    ) {
        let mut state = self.state.lock().expect("watchdog lock");
        state.health_source = Some(Arc::new(health_source));
        state.revoke = Some(Arc::new(revoke));
        state.audit = Some(Arc::new(audit));
    }

    pub fn health(&self) -> HealthReport {
        let (ok, detail, source) = {
            let state = self.state.lock().expect("watchdog lock");
            (state.ok, state.detail.clone(), state.health_source.clone())
        };
        let mut reason = String::new();
        if let Some(source) = source {
            let report = source();
            if !report.ok {
                reason = report.detail;
            }
        }
        HealthReport {
            ok: ok && reason.is_empty(),
            detail: if reason.is_empty() {
                detail
            } else {
                format!("{detail}; {reason}")
            },
        }
    }

    pub fn accepts_work(&self, worker_id: &str) -> bool {
        let state = self.state.lock().expect("watchdog lock");
        state.ok && !state.suspended.contains_key(worker_id)
    }

    pub fn register_process(&self, worker_id: &str, process: Child) {
        let mut state = self.state.lock().expect("watchdog lock");
        state.processes.insert(worker_id.to_string(), process);
    }

    pub fn suspend(&self, worker_id: &str, reason: &str) {
        {
            let mut state = self.state.lock().expect("watchdog lock");
            state.suspended.insert(worker_id.to_string(), ());
        }
        self.audit(worker_id, &format!("suspend: {reason}"));
    }

    pub fn kill(&self, worker_id: &str, reason: &str, terminate_process: bool) -> KillReport {
        let revoke = {
            let mut state = self.state.lock().expect("watchdog lock");
            state.suspended.insert(worker_id.to_string(), ());
            if terminate_process {
                state.revoke.clone()
            } else {
                None
            }
        };
        let revoked = revoke.as_ref().map(|revoke| revoke(worker_id)).unwrap_or(0);
        let mut process = {
            let mut state = self.state.lock().expect("watchdog lock");
            if terminate_process {
                state.processes.remove(worker_id)
            } else {
                None
            }
        };
        let terminated = process.as_mut().is_some_and(terminate_child);
        self.audit(worker_id, &format!("kill: {reason}"));
        KillReport {
            worker_id: worker_id.to_string(),
            reason: reason.to_string(),
            capabilities_revoked: revoked,
            process_terminated: terminated,
        }
    }

    fn audit(&self, worker_id: &str, detail: &str) {
        let callback = {
            let state = self.state.lock().expect("watchdog lock");
            state.audit.clone()
        };
        if let Some(callback) = callback {
            callback(worker_id, detail);
        }
    }
}

impl Default for Watchdog {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KillReport {
    pub worker_id: String,
    pub reason: String,
    pub capabilities_revoked: i64,
    pub process_terminated: bool,
}

fn terminate_child(process: &mut Child) -> bool {
    if process.try_wait().ok().flatten().is_some() {
        return false;
    }
    let _ = process.kill();
    process.wait().is_ok()
}
