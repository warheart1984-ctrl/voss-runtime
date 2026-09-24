//! Trusted runtime wiring.
//!
//! The worker proposes envelopes. This host normalizes them, evaluates
//! signed policy, and is the only path that can turn a human gesture into
//! an effect. Model text is never consent.
//!
//! Approval and capability memory is recovered from the write-ahead ledger
//! only when that ledger verifies. A tampered ledger suspends the worker
//! and restores nothing.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use crate::approval::{
    ApprovalController, ApprovalFlow, STATE_AUTHORIZED, STATE_COMPLETED,
    STATE_EXECUTING, STATE_PENDING_APPROVAL,
};
use crate::audit::{AuditFields, AuditLog, WAL_SCHEMA, wal_genesis};
use crate::broker::{Broker, BrokerDecision, Capability, HealthProvider, coarse_reason_code};
use crate::canonical::{Json, ProtocolError, canonical_bytes, json_number, loads_strict, new_id};
use crate::chan::{self, ChannelError, ChannelSession, MAX_LINE};
use crate::confine::WorkerJob;
use crate::keys::KeyRing;
use crate::outbox::OutboxLink;
use crate::console::ConsoleClient;
use crate::policy::{
    DECISION_DENY, DECISION_REQUIRE_APPROVAL, PolicyBundle, PolicyEngine, PolicyFields, PolicyLoader,
    Rule, build_policy_body, package_policy,
};
use crate::protocol::{CanonicalRequest, RequestNormalizer, os_realpath};
use crate::relay::AuditRelayClient;
use crate::tools::{ToolContext, ToolRegistry};
use crate::watchdog::{HealthReport, Watchdog};
use crate::watchguard::WatchGuardLink;
use crate::VERSION;

const DRIFT_CONTAIN: f64 = 0.30;
const DRIFT_FAIL: f64 = 0.50;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(15);
const TEMPORAL_CEILING_S: f64 = 2.0;
const TEMPORAL_VOLUME_CAP: usize = 16 * 1024;
const TEMPORAL_MIN_WINDOW: u64 = 10;
const CHANNEL_DRAIN_BUDGET: usize = 1024 * 1024;

const ENV_FRAGMENTS: &[&str] = &[
    "SECRET", "KEY", "TOKEN", "CRED", "PASS", "POLICY", "AUDIT", "AUTH",
];

struct Counters {
    events: u64,
    schema_violations: u64,
    identity_violations: u64,
    denied_policy: u64,
    bypass: u64,
    tamper: u64,
    replay: u64,
    contained: bool,
    exchanges: u64,
    temporal_anomalies: u64,
}

struct LiveControls {
    watchdog: Weak<Watchdog>,
}

impl HealthProvider for LiveControls {
    fn watchdog_health_ok(&self) -> bool {
        self.watchdog
            .upgrade()
            .is_some_and(|watchdog| watchdog.health().ok)
    }

    fn watchdog_accepts_work(&self, worker_id: &str) -> bool {
        self.watchdog
            .upgrade()
            .is_some_and(|watchdog| watchdog.accepts_work(worker_id))
    }
}

pub struct VossRuntime {
    pub workspace_root: PathBuf,
    pub outbox_dir: PathBuf,
    pub worker_principal: String,
    pub worker_session: String,
    pub policy_version: String,
    audit: Arc<AuditLog>,
    wal: Arc<AuditLog>,
    pub approvals: Arc<ApprovalController>,
    broker: Arc<Broker>,
    pub watchdog: Arc<Watchdog>,
    normalizer: RequestNormalizer,
    tool_names: Vec<String>,
    loader: Arc<PolicyLoader>,
    bundle: PolicyBundle,
    recovery_ok: bool,
    counters: Arc<Mutex<Counters>>,
    link: Mutex<Option<WorkerLink>>,
    bootstrap_path: Mutex<Option<PathBuf>>,
    relay: Mutex<Option<Arc<AuditRelayClient>>>,
    guard: Arc<Mutex<Option<Arc<WatchGuardLink>>>>,
    worker_pid: Arc<Mutex<Option<u32>>>,
    worker_job: Mutex<Option<WorkerJob>>,
    console: Arc<Mutex<Option<Arc<ConsoleClient>>>>,
    outbox: Arc<Mutex<Option<Arc<OutboxLink>>>>,
}

impl VossRuntime {
    pub fn open(
        workspace_root: impl AsRef<Path>,
        outbox_dir: impl AsRef<Path>,
        audit_path: impl AsRef<Path>,
        keyring: KeyRing,
        policy_package: Option<Json>,
    ) -> Result<Self, ProtocolError> {
        let workspace_root = os_realpath(workspace_root.as_ref())?;
        fs::create_dir_all(&workspace_root).map_err(io_error)?;
        fs::create_dir_all(outbox_dir.as_ref()).map_err(io_error)?;
        let outbox_dir = os_realpath(outbox_dir.as_ref())?;
        let audit_path = audit_path.as_ref();
        let (worker_principal, worker_session) = load_or_create_identity(audit_path)?;
        let package = match policy_package {
            Some(package) => package,
            None => package_policy(&default_dev_policy(&workspace_root)?, &keyring)?,
        };
        let loader = Arc::new(PolicyLoader::new(keyring.clone()));
        let bundle = loader.load_and_verify(&package)?;
        let policy_version = bundle.version.clone();
        let engine = PolicyEngine::new(bundle.clone());
        let audit = Arc::new(AuditLog::open(audit_path, keyring.clone()).map_err(audit_error)?);
        let wal_path = audit_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("wal.jsonl");
        let wal = Arc::new(
            AuditLog::open_chain(&wal_path, keyring, WAL_SCHEMA, &wal_genesis()?).map_err(audit_error)?,
        );
        let approvals = Arc::new(ApprovalController::with_wal(
            &policy_version,
            Arc::clone(&wal),
        ));
        let outbox: Arc<Mutex<Option<Arc<OutboxLink>>>> = Arc::new(Mutex::new(None));
        let tools = ToolRegistry::new(
            ToolContext::new(&workspace_root, &outbox_dir, Arc::clone(&outbox))
                .map_err(|error| ProtocolError::new(error.message()))?,
        );
        let tool_names: Vec<String> = tools.names().into_iter().map(str::to_string).collect();
        let normalizer = RequestNormalizer::new(&workspace_root, tool_names.clone())?;
        let watchdog = Arc::new(Watchdog::new());
        let controls = Arc::new(LiveControls {
            watchdog: Arc::downgrade(&watchdog),
        });
        let broker = Arc::new(Broker::new(
            engine,
            tools,
            Arc::clone(&audit),
            Arc::clone(&approvals),
            controls,
            Arc::clone(&wal),
        ));
        let loader_for_health = Arc::clone(&loader);
        let bundle_for_health = bundle.clone();
        let audit_for_health = Arc::clone(&audit);
        let guard_for_health: Arc<Mutex<Option<Arc<WatchGuardLink>>>> = Arc::new(Mutex::new(None));
        let guard_slot = Arc::clone(&guard_for_health);
        watchdog.attach(
            move || {
                if !loader_for_health.valid_now(&bundle_for_health) {
                    return HealthReport {
                        ok: false,
                        detail: "policy expired".to_string(),
                    };
                }
                if !audit_for_health.healthy() {
                    return HealthReport {
                        ok: false,
                        detail: "audit unavailable".to_string(),
                    };
                }
                let guard = guard_slot.lock().expect("guard").clone();
                if let Some(guard) = guard {
                    let report = guard.health();
                    if !report.ok {
                        let state = if report.triggered { "triggered" } else { "unreachable" };
                        let detail = if report.error.is_empty() { state.to_string() } else { report.error };
                        return HealthReport {
                            ok: false,
                            detail: format!("watch-guard {state}: {detail}"),
                        };
                    }
                }
                HealthReport {
                    ok: true,
                    detail: String::new(),
                }
            },
            {
                let broker = Arc::clone(&broker);
                move |worker_id| broker.revoke_all(worker_id, "operator")
            },
            {
                let audit = Arc::clone(&audit);
                let session = worker_session.clone();
                move |worker_id, detail| {
                    let _ = audit.emit(
                        "kill",
                        AuditFields {
                            worker_id: Some(worker_id.to_string()),
                            session_id: Some(session.clone()),
                            decision: Some("DENY".to_string()),
                            reason_code: Some("denied_worker_suspended".to_string()),
                            error: Some(detail.to_string()),
                            ..AuditFields::default()
                        },
                    );
                }
            },
        );
        let mut runtime = Self {
            workspace_root,
            outbox_dir,
            worker_principal,
            worker_session,
            policy_version,
            audit,
            wal,
            approvals,
            broker,
            watchdog,
            normalizer,
            tool_names,
            loader,
            bundle,
            recovery_ok: true,
            link: Mutex::new(None),
            bootstrap_path: Mutex::new(None),
            relay: Mutex::new(None),
            guard: guard_for_health,
            worker_pid: Arc::new(Mutex::new(None)),
            worker_job: Mutex::new(None),
            console: Arc::new(Mutex::new(None)),
            outbox,
            counters: Arc::new(Mutex::new(Counters {
                events: 0,
                schema_violations: 0,
                identity_violations: 0,
                denied_policy: 0,
                bypass: 0,
                tamper: 0,
                replay: 0,
                contained: false,
                exchanges: 0,
                temporal_anomalies: 0,
            })),
        };
        runtime.recover();
        Ok(runtime)
    }

    pub fn tool_names(&self) -> &[String] {
        &self.tool_names
    }

    pub fn policy_ok(&self) -> bool {
        self.loader.valid_now(&self.bundle)
    }

    pub fn handle_envelope(&self, envelope: &str) -> Json {
        if !self.watchdog.accepts_work(&self.worker_principal) || self.contained() {
            let _ = self.audit.emit(
                "denied",
                AuditFields {
                    worker_id: Some(self.worker_principal.clone()),
                    session_id: Some(self.worker_session.clone()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_worker_suspended".to_string()),
                    ..AuditFields::default()
                },
            );
            return deny_json("denied_worker_suspended");
        }
        let parsed = match loads_strict(envelope) {
            Ok(value) => value,
            Err(error) => return self.reject_schema(error.message()),
        };
        if parsed.as_object().is_none() {
            return self.reject_schema("envelope must be an object");
        }
        let claimed = parsed.get("principal").and_then(Json::as_str).unwrap_or("");
        if claimed != self.worker_principal {
            return self.reject_identity(
                "claimed principal does not match registered worker",
                parsed.get("request_id").and_then(Json::as_str).unwrap_or(""),
                parsed.get("action").and_then(Json::as_str).unwrap_or(""),
            );
        }
        let claimed_session = parsed.get("session_id").and_then(Json::as_str).unwrap_or("");
        if claimed_session != self.worker_session {
            return self.reject_identity(
                "claimed session does not match registered worker session",
                parsed.get("request_id").and_then(Json::as_str).unwrap_or(""),
                parsed.get("action").and_then(Json::as_str).unwrap_or(""),
            );
        }
        let request = match self.normalizer.normalize(&parsed, &self.worker_principal) {
            Ok(request) => request,
            Err(error) => return self.reject_schema(error.message()),
        };
        self.bump_events();
        let mut decision = self.broker.execute_action(&request, &self.worker_principal);
        self.tally(&decision);
        self.maybe_contain();
        self.console_intercept(&mut decision);
        decision.to_json()
    }

    pub fn resolve_approval(&self, flow_id: &str, decision: &str, approver_ref: &str) -> Json {
        resolve_approval_with(
            &ApprovalHost {
                approvals: &self.approvals,
                broker: &self.broker,
                audit: &self.audit,
                counters: &self.counters,
                watchdog: &self.watchdog,
                principal: &self.worker_principal,
                session: &self.worker_session,
            },
            flow_id,
            decision,
            approver_ref,
        )
    }

    pub fn capabilities(&self) -> Vec<crate::broker::Capability> {
        self.broker.capabilities()
    }

    pub fn approval_state(&self, flow_id: &str) -> Option<String> {
        self.approvals.get(flow_id).ok().map(|flow| flow.state)
    }

    pub fn approval_view_text(&self, flow_id: &str) -> Result<String, ProtocolError> {
        self.approvals
            .view(flow_id)
            .map(|view| view.describe())
            .map_err(|error| ProtocolError::new(error.message()))
    }

    pub fn suspend_worker(&self, reason: &str) {
        self.watchdog.suspend(&self.worker_principal, reason);
    }

    pub fn kill_worker(&self, reason: &str, terminate_process: bool) -> Json {
        if let Some(guard) = self.guard.lock().expect("guard").clone() {
            let _ = guard.terminate(reason);
        }
        if terminate_process {
            self.worker_job.lock().expect("worker job").take();
            if let Some(pid) = self.worker_pid.lock().expect("worker pid").take() {
                let _ = crate::watchguard::terminate_os(pid);
            }
        }
        let report = self
            .watchdog
            .kill(&self.worker_principal, reason, terminate_process);
        Json::object([
            ("worker_id", Json::string(report.worker_id)),
            ("reason", Json::string(report.reason)),
            ("capabilities_revoked", Json::Int(report.capabilities_revoked)),
            ("process_terminated", Json::Bool(report.process_terminated)),
        ])
    }

    pub fn revoke_all(&self, reason: &str) -> i64 {
        self.broker.revoke_all(&self.worker_principal, reason)
    }

    pub fn spawn_worker(&self) -> Result<Child, ProtocolError> {
        self.spawn_worker_with(worker_executable()?, &[])
    }

    pub fn spawn_worker_with(
        &self,
        executable: impl AsRef<Path>,
        extra_env: &[(&str, &str)],
    ) -> Result<Child, ProtocolError> {
        self.link.lock().expect("channel").take();
        if let Some(path) = self.bootstrap_path.lock().expect("bootstrap").take() {
            let _ = fs::remove_file(path);
        }
        let key = random_bytes(32)?;
        let sid = new_id("chan-");
        let bootstrap_path = self
            .audit
            .path()
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("worker-bootstrap.json");
        let document = chan::chan_bootstrap(&key, &sid);
        let mut text = canonical_bytes(&document)?;
        text.push(b'\n');
        fs::write(&bootstrap_path, text).map_err(io_error)?;
        *self.bootstrap_path.lock().expect("bootstrap") = Some(bootstrap_path.clone());

        let mut command = Command::new(executable.as_ref());
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            .current_dir(&self.workspace_root);
        for (name, value) in scrubbed_env() {
            command.env(name, value);
        }
        for (name, value) in extra_env {
            command.env(name, value);
        }
        command.env("VOSS_WORKSPACE", &self.workspace_root);
        command.env(
            "VOSS_CHANNEL_BOOTSTRAP",
            bootstrap_path.to_string_lossy().as_ref(),
        );
        self.worker_job.lock().expect("worker job").take();
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = fs::remove_file(&bootstrap_path);
                *self.bootstrap_path.lock().expect("bootstrap") = None;
                return Err(io_error(error));
            }
        };
        match crate::confine::confine_pid(child.id()) {
            Ok(job) => *self.worker_job.lock().expect("worker job") = Some(job),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = fs::remove_file(&bootstrap_path);
                *self.bootstrap_path.lock().expect("bootstrap") = None;
                return Err(ProtocolError::new(format!("worker confinement failed: {error}")));
            }
        }
        if let Some(guard) = self.guard.lock().expect("guard").clone() {
            guard.register_worker(child.id());
        }
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| ProtocolError::new("worker process has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ProtocolError::new("worker process has no stdout"))?;
        let mut link = WorkerLink {
            stdin,
            channel: ChannelSession::new(key, sid, "host").map_err(channel_protocol)?,
            pump: LinePump::start(stdout),
        };
        if let Err(error) = self.handshake(&mut link) {
            self.worker_job.lock().expect("worker job").take();
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&bootstrap_path);
            *self.bootstrap_path.lock().expect("bootstrap") = None;
            return Err(error);
        }
        *self.link.lock().expect("channel") = Some(link);
        *self.worker_pid.lock().expect("worker pid") = Some(child.id());
        Ok(child)
    }

    pub fn worker_propose(&self, prompt: &str) -> Result<Json, ProtocolError> {
        let request = Json::object([
            ("prompt", Json::string(prompt)),
            ("session_id", Json::string(&self.worker_session)),
            ("principal", Json::string(&self.worker_principal)),
        ]);
        let mut link = self.link.lock().expect("channel");
        let link = link
            .as_mut()
            .ok_or_else(|| ProtocolError::new("no authenticated channel: call spawn_worker first"))?;
        let wire = link
            .channel
            .send("prompt", &request)
            .map_err(|error| self.note_channel("propose", error))?;
        let started = std::time::Instant::now();
        link.write_line(&wire)?;
        let line = match link.read_line() {
            Ok(line) => line,
            Err(error) => return Err(self.note_channel("propose", error)),
        };
        let (msg_type, msg) = link
            .channel
            .receive(&line)
            .map_err(|error| self.note_channel("propose", error))?;
        let Some(Json::Array(envelopes)) = msg.get("envelopes") else {
            return Err(self.note_channel(
                "propose",
                ChannelError::new("denied_channel_wrong_direction"),
            ));
        };
        if msg_type != "proposal" {
            return Err(self.note_channel(
                "propose",
                ChannelError::new("denied_channel_wrong_direction"),
            ));
        }
        self.observe_exchange(started.elapsed().as_secs_f64(), line.len());
        Ok(Json::Array(envelopes.clone()))
    }

    pub fn drift_score(&self) -> f64 {
        self.drift_report()
            .get("score")
            .and_then(Json::as_f64)
            .unwrap_or(0.0)
    }

    pub fn drift_report(&self) -> Json {
        let counters = self.counters.lock().expect("drift lock");
        let window = counters.events.max(10) as f64;
        let behavioral = (counters.denied_policy + counters.tamper + counters.replay + counters.bypass)
            as f64
            / window;
        let schema = counters.schema_violations as f64 / window;
        let identity = counters.identity_violations as f64 / window;
        let temporal_window = counters.exchanges.max(TEMPORAL_MIN_WINDOW) as f64;
        let temporal = counters.temporal_anomalies as f64 / temporal_window;
        let score = behavioral.max(schema).max(identity).max(temporal);
        Json::object([
            ("method", Json::string("prototype-heuristic-max-dimension")),
            (
                "baseline",
                Json::string(format!(
                    "zero-violation baseline, minimum 10-event window; temporal declared bounds: latency ceiling {TEMPORAL_CEILING_S:.1}s, volume cap {TEMPORAL_VOLUME_CAP} B over a minimum {TEMPORAL_MIN_WINDOW}-exchange window"
                )),
            ),
            ("window", Json::Int(counters.events.max(10) as i64)),
            ("temporal_window", Json::Int(temporal_window as i64)),
            ("exchanges_sampled", Json::Int(counters.exchanges as i64)),
            ("temporal_anomalies", Json::Int(counters.temporal_anomalies as i64)),
            (
                "dimensions",
                Json::object([
                    ("schema", Json::Float(round_4(schema))),
                    ("identity", Json::Float(round_4(identity))),
                    ("behavioral", Json::Float(round_4(behavioral))),
                    ("temporal", Json::Float(round_4(temporal))),
                ]),
            ),
            ("temporal", Json::Float(round_4(temporal))),
            ("score", Json::Float(round_4(score))),
            ("threshold_contain", Json::Float(DRIFT_CONTAIN)),
            ("threshold_fail", Json::Float(DRIFT_FAIL)),
            ("contained", Json::Bool(counters.contained)),
            (
                "limitations",
                Json::string(
                    "Indicators only; monitoring is per-session, in-process, not OS-enforced.",
                ),
            ),
        ])
    }

    pub fn health_report(&self) -> Json {
        let health = self.watchdog.health();
        Json::object([
            ("runtime_version", Json::string(VERSION)),
            ("policy_version", Json::string(&self.policy_version)),
            ("policy_ok", Json::Bool(self.policy_ok())),
            ("audit_healthy", Json::Bool(self.audit.healthy())),
            ("wal_healthy", Json::Bool(self.wal.healthy())),
            ("recovery_ok", Json::Bool(self.recovery_ok)),
            (
                "watchdog",
                Json::object([
                    ("ok", Json::Bool(health.ok)),
                    ("detail", Json::string(health.detail)),
                ]),
            ),
            (
                "worker_accepts_work",
                Json::Bool(self.watchdog.accepts_work(&self.worker_principal)),
            ),
            (
                "tools",
                Json::Array(self.tool_names.iter().cloned().map(Json::String).collect()),
            ),
            (
                "relay",
                self.relay
                    .lock()
                    .expect("relay")
                    .as_ref()
                    .map(|client| client.health())
                    .unwrap_or(Json::Null),
            ),
            (
                "watchdog_guard",
                self.guard
                    .lock()
                    .expect("guard")
                    .as_ref()
                    .map(|link| link.health_json())
                    .unwrap_or(Json::Null),
            ),
            (
                "operator_console",
                self.console
                    .lock()
                    .expect("console")
                    .as_ref()
                    .map(|client| client.health_json())
                    .unwrap_or(Json::Null),
            ),
            (
                "outbox_accounting",
                self.outbox
                    .lock()
                    .expect("outbox")
                    .as_ref()
                    .map(|link| link.health_json())
                    .unwrap_or(Json::Null),
            ),
        ])
    }

    pub fn attach_outbox(&self, link: OutboxLink) {
        if let Some(previous) = self.outbox.lock().expect("outbox").take() {
            previous.stop();
        }
        let link = Arc::new(link);
        link.start();
        *self.outbox.lock().expect("outbox") = Some(link);
    }

    pub fn attach_console(&self, client: ConsoleClient) {
        if let Some(previous) = self.console.lock().expect("console").take() {
            previous.stop();
        }
        let client = Arc::new(client);
        let audit = Arc::clone(&self.audit);
        let principal = self.worker_principal.clone();
        let session = self.worker_session.clone();
        client.set_on_failure(move |reason| {
            let _ = audit.emit(
                "operator_console_unavailable",
                AuditFields {
                    worker_id: Some(principal.clone()),
                    session_id: Some(session.clone()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_approval_unavailable".to_string()),
                    error: Some(reason),
                    ..AuditFields::default()
                },
            );
        });
        let approvals = Arc::clone(&self.approvals);
        let broker = Arc::clone(&self.broker);
        let audit = Arc::clone(&self.audit);
        let counters = Arc::clone(&self.counters);
        let watchdog = Arc::clone(&self.watchdog);
        let principal = self.worker_principal.clone();
        let session = self.worker_session.clone();
        let publisher = Arc::clone(&client);
        client.set_on_vote(move |flow_id, decision, approver_ref| {
            let result = resolve_approval_with(
                &ApprovalHost {
                    approvals: &approvals,
                    broker: &broker,
                    audit: &audit,
                    counters: &counters,
                    watchdog: &watchdog,
                    principal: &principal,
                    session: &session,
                },
                &flow_id,
                &decision,
                &approver_ref,
            );
            let shown = result.get("decision").and_then(Json::as_str).unwrap_or(decision.as_str());
            publisher.publish_result(&flow_id, shown, &approver_ref);
        });
        let watchdog = Arc::clone(&self.watchdog);
        let broker = Arc::clone(&self.broker);
        let guard = Arc::clone(&self.guard);
        let worker_pid = Arc::clone(&self.worker_pid);
        let principal = self.worker_principal.clone();
        client.set_on_terminate(move |reason| {
            let detail = if reason.is_empty() {
                "operator-console: kill".to_string()
            } else {
                format!("operator-console: {reason}")
            };
            if let Some(guard) = guard.lock().expect("guard").clone() {
                let _ = guard.terminate(&detail);
            }
            if let Some(pid) = worker_pid.lock().expect("worker pid").take() {
                let _ = crate::watchguard::terminate_os(pid);
            }
            let _ = watchdog.kill(&principal, &detail, true);
            let _ = broker.revoke_all(&principal, &detail);
        });
        client.start();
        *self.console.lock().expect("console") = Some(client);
    }

    pub fn attach_guard(&self, link: WatchGuardLink) {
        if let Some(previous) = self.guard.lock().expect("guard").take() {
            previous.stop();
        }
        let link = Arc::new(link);
        let audit = Arc::clone(&self.audit);
        let watchdog = Arc::clone(&self.watchdog);
        let principal = self.worker_principal.clone();
        let session = self.worker_session.clone();
        link.set_on_failure(move |reason| {
            let _ = audit.emit(
                "guard_failure",
                AuditFields {
                    worker_id: Some(principal.clone()),
                    session_id: Some(session.clone()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_watch_guard".to_string()),
                    error: Some(reason.clone()),
                    ..AuditFields::default()
                },
            );
            watchdog.suspend(&principal, &format!("watch-guard: {reason}"));
        });
        link.start();
        *self.guard.lock().expect("guard") = Some(link);
    }

    pub fn attach_relay(&self, client: AuditRelayClient) {
        let client = Arc::new(client);
        let audit = Arc::clone(&self.audit);
        let principal = self.worker_principal.clone();
        let session = self.worker_session.clone();
        client.set_on_violation(move |reason| {
            let _ = audit.emit(
                "relay_violation",
                AuditFields {
                    worker_id: Some(principal.clone()),
                    session_id: Some(session.clone()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("audit_relay_violation".to_string()),
                    error: Some(reason),
                    ..AuditFields::default()
                },
            );
        });
        client.start();
        *self.relay.lock().expect("relay") = Some(client);
    }

    pub fn audit_summary(&self) -> Json {
        let records = self.audit.records().unwrap_or_default();
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        let mut last = Vec::new();
        for line in &records {
            let event = line
                .get("record")
                .and_then(|record| record.get("event_type"))
                .and_then(Json::as_str)
                .unwrap_or("?");
            *counts.entry(event.to_string()).or_insert(0) += 1;
            last.push(Json::object([
                ("event_type", Json::string(event)),
                (
                    "decision",
                    line.get("record")
                        .and_then(|record| record.get("decision"))
                        .cloned()
                        .unwrap_or(Json::Null),
                ),
                (
                    "reason_code",
                    line.get("record")
                        .and_then(|record| record.get("reason_code"))
                        .cloned()
                        .unwrap_or(Json::Null),
                ),
            ]));
        }
        let tail = last.into_iter().rev().take(10).collect::<Vec<_>>().into_iter().rev().collect();
        Json::object([
            ("path", Json::string(self.audit.path().display().to_string())),
            ("records", Json::Int(records.len() as i64)),
            ("integrity_ok", Json::Bool(self.audit.verify_integrity())),
            (
                "by_event_type",
                Json::object(counts.into_iter().map(|(key, value)| (key, Json::Int(value)))),
            ),
            ("last", Json::Array(tail)),
        ])
    }

    pub fn audit_text(&self) -> String {
        fs::read_to_string(self.audit.path()).unwrap_or_default()
    }

    pub fn close(&self) {
        if let Some(link) = self.outbox.lock().expect("outbox").take() {
            link.stop();
        }
        if let Some(client) = self.console.lock().expect("console").take() {
            client.stop();
        }
        if let Some(link) = self.guard.lock().expect("guard").take() {
            link.stop();
        }
        if let Some(client) = self.relay.lock().expect("relay").take() {
            client.stop();
        }
        self.worker_job.lock().expect("worker job").take();
        self.link.lock().expect("channel").take();
        if let Some(path) = self.bootstrap_path.lock().expect("bootstrap").take() {
            let _ = fs::remove_file(path);
        }
        self.audit.close();
        self.wal.close();
    }

    fn handshake(&self, link: &mut WorkerLink) -> Result<(), ProtocolError> {
        let line = match link.read_line() {
            Ok(line) => line,
            Err(error) => return Err(self.note_channel("handshake", error)),
        };
        let (msg_type, msg) = match link.channel.receive(&line) {
            Ok(value) => value,
            Err(error) => return Err(self.note_channel("handshake", error)),
        };
        if msg_type != "hello" || msg.get("ready").and_then(Json::as_bool) != Some(true) {
            return Err(self.note_channel("handshake", ChannelError::new("denied_channel_auth")));
        }
        let reply = link
            .channel
            .send("hello_ok", &Json::object([("ok", Json::Bool(true))]))
            .map_err(|error| self.note_channel("handshake", error))?;
        link.write_line(&reply)
    }

    fn note_channel(&self, phase: &str, error: ChannelError) -> ProtocolError {
        if error.code() == "denied_channel_timeout" {
            self.audit_channel_timeout(phase);
            if phase == "propose" {
                self.observe_exchange(CHANNEL_TIMEOUT.as_secs_f64(), 0);
            }
            let message = if phase == "handshake" {
                "worker channel handshake timed out"
            } else {
                "worker timed out producing a proposal"
            };
            return ProtocolError::new(message);
        }
        self.channel_violation(error.code(), phase);
        ProtocolError::new(format!("worker channel violation: {}", error.code()))
    }

    fn channel_violation(&self, reason_code: &str, phase: &str) {
        let _ = self.audit.emit(
            "transport_denied",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                decision: Some("DENY".to_string()),
                reason_code: Some(reason_code.to_string()),
                error: Some(format!("channel {phase} violation")),
                ..AuditFields::default()
            },
        );
        self.counters.lock().expect("drift lock").tamper += 1;
        self.watchdog.suspend(
            &self.worker_principal,
            &format!("channel {phase} violation"),
        );
        self.broker.revoke_all(&self.worker_principal, "channel-violation");
    }

    fn audit_channel_timeout(&self, phase: &str) {
        let _ = self.audit.emit(
            "transport_denied",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                decision: Some("DENY".to_string()),
                reason_code: Some("denied_channel_timeout".to_string()),
                error: Some(format!("channel {phase} timeout")),
                ..AuditFields::default()
            },
        );
    }

    fn recover(&mut self) {
        let records = match self.wal.records() {
            Ok(records) => records,
            Err(error) => {
                self.fail_recovery(&format!(
                    "write-ahead ledger unreadable: {}",
                    error.message()
                ));
                return;
            }
        };
        if !self.wal.verify_integrity() {
            self.fail_recovery("write-ahead ledger integrity verification failed");
            return;
        }
        let restored = match replay_wal(&records) {
            Ok(restored) => restored,
            Err(detail) => {
                self.fail_recovery(&detail);
                return;
            }
        };
        let flows = restored.flows.len() as i64;
        let capabilities = restored.caps.len() as i64;
        let executed = restored.executed.len() as i64;
        for flow in restored.flows {
            self.approvals.restore_flow(flow);
        }
        for capability in restored.caps {
            self.broker.restore_cap(capability);
        }
        for request_id in restored.executed {
            self.broker.mark_executed(&request_id);
        }
        self.recovery_ok = true;
        let _ = self.audit.emit(
            "recovery",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                decision: Some("ALLOW".to_string()),
                reason_code: Some("recovered".to_string()),
                result: Some(Json::object([
                    ("flows_restored", Json::Int(flows)),
                    ("capabilities_restored", Json::Int(capabilities)),
                    ("executed_requests_restored", Json::Int(executed)),
                ])),
                ..AuditFields::default()
            },
        );
    }

    fn fail_recovery(&mut self, detail: &str) {
        self.recovery_ok = false;
        self.broker.set_recovery_ok(false);
        self.watchdog
            .suspend(&self.worker_principal, "wal recovery failed");
        let _ = self.audit.emit(
            "recovery_failed",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                decision: Some("DENY".to_string()),
                reason_code: Some("denied_health_unavailable".to_string()),
                error: Some(detail.to_string()),
                ..AuditFields::default()
            },
        );
    }

    fn reject_identity(&self, detail: &str, request_id: &str, action: &str) -> Json {
        {
            let mut counters = self.counters.lock().expect("drift lock");
            counters.identity_violations += 1;
            counters.bypass += 1;
            counters.events += 1;
        }
        let _ = self.audit.emit(
            "identity_violation",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                request_id: Some(request_id.to_string()),
                action: Some(action.to_string()),
                policy_version: Some(self.policy_version.clone()),
                decision: Some("DENY".to_string()),
                reason_code: Some("denied_identity".to_string()),
                error: Some(detail.to_string()),
                ..AuditFields::default()
            },
        );
        self.maybe_contain();
        deny_json("denied_identity")
    }

    fn reject_schema(&self, detail: &str) -> Json {
        {
            let mut counters = self.counters.lock().expect("drift lock");
            counters.schema_violations += 1;
            counters.bypass += 1;
            counters.events += 1;
        }
        let _ = self.audit.emit(
            "schema_violation",
            AuditFields {
                worker_id: Some(self.worker_principal.clone()),
                session_id: Some(self.worker_session.clone()),
                decision: Some("DENY".to_string()),
                reason_code: Some("denied_schema".to_string()),
                error: Some(detail.to_string()),
                ..AuditFields::default()
            },
        );
        self.maybe_contain();
        deny_json("denied_schema")
    }

    fn tally(&self, decision: &BrokerDecision) {
        let mut counters = self.counters.lock().expect("drift lock");
        let reason = decision.reason_code.as_str();
        if reason == "denied_policy_no_rule" || reason == "denied_policy_conflict" {
            counters.denied_policy += 1;
        }
        if reason == "denied_approval_tamper" || reason == "denied_request_tamper" {
            counters.tamper += 1;
        }
        if reason == "denied_replay_uniqueness" {
            counters.replay += 1;
        }
        if decision.decision == "DENY"
            && reason != "denied_health_unavailable"
            && reason != "denied_approval"
        {
            counters.bypass += 1;
        }
    }

    fn observe_exchange(&self, seconds: f64, bytes_count: usize) {
        let anomaly = {
            let mut counters = self.counters.lock().expect("drift lock");
            counters.exchanges += 1;
            let anomaly = seconds > TEMPORAL_CEILING_S || bytes_count > TEMPORAL_VOLUME_CAP;
            if anomaly {
                counters.temporal_anomalies += 1;
            }
            anomaly
        };
        if anomaly {
            let _ = self.audit.emit(
                "temporal_anomaly",
                AuditFields {
                    worker_id: Some(self.worker_principal.clone()),
                    session_id: Some(self.worker_session.clone()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_temporal_oracle".to_string()),
                    error: Some(format!(
                        "exchange latency {seconds:.1}s (ceiling {TEMPORAL_CEILING_S:.1}s), volume {bytes_count} B (cap {TEMPORAL_VOLUME_CAP} B)"
                    )),
                    ..AuditFields::default()
                },
            );
        }
        self.maybe_contain();
    }

    fn maybe_contain(&self) {
        let idle = {
            let counters = self.counters.lock().expect("drift lock");
            counters.events == 0 && counters.exchanges == 0
        };
        if idle {
            return;
        }
        let score = self.drift_score();
        let already = self.contained();
        if score > DRIFT_FAIL || already {
            self.watchdog
                .suspend(&self.worker_principal, "drift > 0.50 (fail closed)");
            self.broker
                .revoke_all(&self.worker_principal, "drift-fail-closed");
            self.contain_worker("fail-closed: drift > 0.50");
            self.counters.lock().expect("drift lock").contained = true;
            return;
        }
        if score > DRIFT_CONTAIN {
            self.watchdog
                .suspend(&self.worker_principal, "drift > 0.30 (containment)");
        }
    }

    fn contain_worker(&self, reason: &str) {
        self.watchdog.suspend(&self.worker_principal, reason);
        self.broker.revoke_all(&self.worker_principal, reason);
    }

    fn bump_events(&self) {
        self.counters.lock().expect("drift lock").events += 1;
    }

    fn contained(&self) -> bool {
        self.counters.lock().expect("drift lock").contained
    }

    fn console_intercept(&self, decision: &mut BrokerDecision) {
        let Some(client) = self.console.lock().expect("console").clone() else {
            return;
        };
        if decision.decision != DECISION_REQUIRE_APPROVAL || decision.approval_request_id.is_empty() {
            return;
        }
        let flow_id = decision.approval_request_id.clone();
        if !client.health().ok {
            let _ = self.resolve_approval(&flow_id, "DENY", "operator-console-unavailable");
            decision.decision = DECISION_DENY.to_string();
            decision.reason_code = "denied_approval_unavailable".to_string();
            return;
        }
        if let Some(view) = self.approval_view_json(&flow_id) {
            client.publish_view(&flow_id, &view);
        }
    }

    fn approval_view_json(&self, flow_id: &str) -> Option<Json> {
        let view = self.approvals.view(flow_id).ok()?;
        Some(Json::object([
            ("action", Json::string(&view.action)),
            ("consequences", Json::string(&view.consequences)),
            ("expires_in_seconds", json_number(view.expires_in_seconds)),
            ("nonce", Json::string(&view.nonce)),
            ("payload_digest", Json::string(&view.payload_digest)),
            ("policy_version", Json::string(&view.policy_version)),
            ("principal", Json::string(&view.principal)),
            ("request_id", Json::string(&view.request_id)),
            ("resource", view.resource),
            ("reversible", Json::Bool(view.reversible)),
            ("risk_class", Json::string(&view.risk_class)),
        ]))
    }
}

pub fn default_dev_policy(workspace_root: &Path) -> Result<Json, ProtocolError> {
    let root = os_realpath(workspace_root)?;
    let root = root
        .to_str()
        .ok_or_else(|| ProtocolError::new("workspace path is not valid Unicode"))?;
    let mut read = Rule::allow("workspace.read");
    read.resource_prefix = Some(Json::object([("path_prefix", Json::string(root))]));
    let mut write = Rule::allow("workspace.write");
    write.approval_required = true;
    write.resource_prefix = Some(Json::object([("path_prefix", Json::string(root))]));
    let mut send = Rule::allow("external.send_mock");
    send.approval_required = true;
    send.resource_prefix = Some(Json::object([("service", Json::string("mail"))]));
    Ok(build_policy_body(
        &[read, write, send],
        &PolicyFields {
            version: "1.0.0".to_string(),
            signer: "operator-prototype".to_string(),
            ..PolicyFields::default()
        },
    ))
}

pub fn retain_env(pairs: impl IntoIterator<Item = (String, String)>) -> Vec<(String, String)> {
    pairs
        .into_iter()
        .filter(|(key, _)| !secret_like(key))
        .collect()
}

pub fn scrubbed_env() -> Vec<(String, String)> {
    retain_env(std::env::vars())
}

fn secret_like(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    ENV_FRAGMENTS.iter().any(|fragment| upper.contains(fragment))
}

fn load_or_create_identity(audit_path: &Path) -> Result<(String, String), ProtocolError> {
    let path = audit_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("identity.json");
    if let Ok(text) = fs::read_to_string(&path)
        && let Ok(value) = loads_strict(&text)
    {
        let principal = value.get("principal").and_then(Json::as_str).unwrap_or("");
        let session = value.get("session_id").and_then(Json::as_str).unwrap_or("");
        if principal.starts_with("worker-") && session.starts_with("session-") {
            return Ok((principal.to_string(), session.to_string()));
        }
    }
    let principal = new_id("worker-");
    let session = new_id("session-");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let body = Json::object([
        ("principal", Json::string(&principal)),
        ("session_id", Json::string(&session)),
    ]);
    if let Ok(bytes) = canonical_bytes(&body) {
        let _ = fs::write(path, bytes);
    }
    Ok((principal, session))
}

fn worker_executable() -> Result<PathBuf, ProtocolError> {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_worker") {
        return Ok(PathBuf::from(path));
    }
    let current = std::env::current_exe().map_err(io_error)?;
    let name = if cfg!(windows) { "worker.exe" } else { "worker" };
    if let Some(dir) = current.parent() {
        let sibling = dir.join(name);
        if sibling.is_file() {
            return Ok(sibling);
        }
        if let Some(parent) = dir.parent() {
            let adjacent = parent.join(name);
            if adjacent.is_file() {
                return Ok(adjacent);
            }
        }
    }
    Err(ProtocolError::new("worker executable was not found beside the runtime"))
}

struct ApprovalHost<'a> {
    approvals: &'a ApprovalController,
    broker: &'a Broker,
    audit: &'a AuditLog,
    counters: &'a Mutex<Counters>,
    watchdog: &'a Watchdog,
    principal: &'a str,
    session: &'a str,
}

fn resolve_approval_with(host: &ApprovalHost<'_>, flow_id: &str, decision: &str, approver_ref: &str) -> Json {
    let flow = match host.approvals.get(flow_id) {
        Ok(flow) => flow,
        Err(_) => {
            let _ = host.audit.emit(
                "denied",
                AuditFields {
                    worker_id: Some(host.principal.to_string()),
                    session_id: Some(host.session.to_string()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_approval".to_string()),
                    error: Some(format!("unknown approval flow {flow_id}")),
                    ..AuditFields::default()
                },
            );
            return deny_json("denied_approval");
        }
    };
    let result = host.broker.resolve_and_execute(
        flow_id,
        decision,
        approver_ref,
        &flow.request,
        host.principal,
    );
    {
        let mut counters = host.counters.lock().expect("drift lock");
        counters.events += 1;
        let reason = result.reason_code.as_str();
        if reason == "denied_policy_no_rule" || reason == "denied_policy_conflict" {
            counters.denied_policy += 1;
        }
        if reason == "denied_approval_tamper" || reason == "denied_request_tamper" {
            counters.tamper += 1;
        }
        if reason == "denied_replay_uniqueness" {
            counters.replay += 1;
        }
        if result.decision == "DENY" && reason != "denied_health_unavailable" && reason != "denied_approval" {
            counters.bypass += 1;
        }
    }
    maybe_contain_shared(host.counters, host.watchdog, host.broker, host.principal);
    result.to_json()
}

fn maybe_contain_shared(counters: &Mutex<Counters>, watchdog: &Watchdog, broker: &Broker, principal: &str) {
    let (idle, score, already) = {
        let counters = counters.lock().expect("drift lock");
        (
            counters.events == 0 && counters.exchanges == 0,
            round_4(score_of(&counters)),
            counters.contained,
        )
    };
    if idle {
        return;
    }
    if score > DRIFT_FAIL || already {
        watchdog.suspend(principal, "drift > 0.50 (fail closed)");
        broker.revoke_all(principal, "drift-fail-closed");
        watchdog.suspend(principal, "fail-closed: drift > 0.50");
        broker.revoke_all(principal, "fail-closed: drift > 0.50");
        counters.lock().expect("drift lock").contained = true;
        return;
    }
    if score > DRIFT_CONTAIN {
        watchdog.suspend(principal, "drift > 0.30 (containment)");
    }
}

fn score_of(counters: &Counters) -> f64 {
    let window = counters.events.max(10) as f64;
    let behavioral = (counters.denied_policy + counters.tamper + counters.replay + counters.bypass) as f64 / window;
    let schema = counters.schema_violations as f64 / window;
    let identity = counters.identity_violations as f64 / window;
    let temporal_window = counters.exchanges.max(TEMPORAL_MIN_WINDOW) as f64;
    let temporal = counters.temporal_anomalies as f64 / temporal_window;
    behavioral.max(schema).max(identity).max(temporal)
}

fn deny_json(reason: &str) -> Json {
    Json::object([
        ("decision", Json::string("DENY")),
        ("reason_code", Json::string(coarse_reason_code(reason))),
    ])
}

fn round_4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

fn io_error(error: std::io::Error) -> ProtocolError {
    ProtocolError::new(error.to_string())
}

fn audit_error(error: crate::audit::AuditUnavailableError) -> ProtocolError {
    ProtocolError::new(error.message())
}

struct Restored {
    flows: Vec<ApprovalFlow>,
    caps: Vec<Capability>,
    executed: Vec<String>,
}

fn replay_wal(records: &[Json]) -> Result<Restored, String> {
    let mut flows: BTreeMap<String, ApprovalFlow> = BTreeMap::new();
    let mut caps: BTreeMap<String, Capability> = BTreeMap::new();
    let mut executed = Vec::new();
    for line in records {
        let record = line.get("record").ok_or("write-ahead ledger inconsistent: missing record")?;
        let event = record.get("event_type").and_then(Json::as_str).unwrap_or("");
        match event {
            "flow_request" => {
                let flow = flow_from_wal(record)?;
                flows.insert(flow.flow_id.clone(), flow);
            }
            "flow_resolution" => {
                if let Some(flow) = flows.get_mut(text(record, "flow_id")?) {
                    if let Some(state) = record.get("state").and_then(Json::as_str) {
                        flow.state = state.to_string();
                    }
                    if let Some(approver) = record.get("approver_ref").and_then(Json::as_str)
                        && !approver.is_empty()
                    {
                        flow.approver_ref = approver.to_string();
                    }
                }
            }
            "flow_executing" => {
                if let Some(flow) = flows.get_mut(text(record, "flow_id")?)
                    && flow.state == STATE_AUTHORIZED
                {
                    replay_transition(flow, STATE_EXECUTING)?;
                }
            }
            "flow_outcome" => {
                if let Some(flow) = flows.get_mut(text(record, "flow_id")?) {
                    flow.outcome = record
                        .get("outcome")
                        .and_then(Json::as_str)
                        .unwrap_or("")
                        .to_string();
                    if flow.state == STATE_EXECUTING {
                        let next = if flow.outcome == STATE_COMPLETED {
                            STATE_COMPLETED
                        } else {
                            "UNKNOWN"
                        };
                        replay_transition(flow, next)?;
                    }
                }
            }
            "capability_issued" => {
                let capability = cap_from_wal(record)?;
                caps.insert(capability.cap_id.clone(), capability);
            }
            "capability_used" => {
                if let Some(capability) = caps.get_mut(text(record, "cap_id")?) {
                    capability.used_count = capability.use_limit;
                }
            }
            "capability_revoked" => {
                if let Some(capability) = caps.get_mut(text(record, "cap_id")?) {
                    capability.revoked = true;
                }
            }
            "request_executed" => executed.push(text(record, "request_id")?.to_string()),
            _ => {}
        }
    }
    Ok(Restored {
        flows: flows.into_values().collect(),
        caps: caps.into_values().collect(),
        executed,
    })
}

fn flow_from_wal(record: &Json) -> Result<ApprovalFlow, String> {
    let request = CanonicalRequest {
        version: text(record, "version")?.to_string(),
        request_id: text(record, "request_id")?.to_string(),
        session_id: text(record, "session_id")?.to_string(),
        principal: text(record, "principal")?.to_string(),
        action: text(record, "action")?.to_string(),
        resource: record
            .get("resource")
            .cloned()
            .ok_or("write-ahead ledger inconsistent: resource")?,
        payload: record
            .get("payload")
            .cloned()
            .ok_or("write-ahead ledger inconsistent: payload")?,
        constraints: record
            .get("constraints")
            .cloned()
            .ok_or("write-ahead ledger inconsistent: constraints")?,
        payload_digest: text(record, "payload_digest")?.to_string(),
        nonce: text(record, "nonce")?.to_string(),
        expires_at: number(record, "expires_at")?,
    };
    Ok(ApprovalFlow {
        flow_id: text(record, "flow_id")?.to_string(),
        policy_version: text(record, "policy_version")?.to_string(),
        nonce: request.nonce.clone(),
        expires_at: request.expires_at,
        binding_digest: text(record, "binding_digest")?.to_string(),
        request_digest: text(record, "request_digest")?.to_string(),
        state: STATE_PENDING_APPROVAL.to_string(),
        approver_ref: String::new(),
        outcome: String::new(),
        created_at: record.get("created_at").and_then(Json::as_f64).unwrap_or(0.0),
        request,
    })
}

fn cap_from_wal(record: &Json) -> Result<Capability, String> {
    Ok(Capability {
        cap_id: text(record, "cap_id")?.to_string(),
        principal: text(record, "principal")?.to_string(),
        session_id: text(record, "session_id")?.to_string(),
        action: text(record, "action")?.to_string(),
        resource: record
            .get("resource")
            .cloned()
            .ok_or("write-ahead ledger inconsistent: resource")?,
        payload_digest: text(record, "payload_digest")?.to_string(),
        constraints: record
            .get("constraints")
            .cloned()
            .ok_or("write-ahead ledger inconsistent: constraints")?,
        policy_version: text(record, "policy_version")?.to_string(),
        approval_ref: record
            .get("approval_ref")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string(),
        binding_digest: text(record, "binding_digest")?.to_string(),
        nonce: text(record, "nonce")?.to_string(),
        request_id: text(record, "request_id")?.to_string(),
        request_digest: text(record, "request_digest")?.to_string(),
        issued_at: record.get("issued_at").and_then(Json::as_f64).unwrap_or(0.0),
        expires_at: number(record, "expires_at")?,
        use_limit: record.get("use_limit").and_then(Json::as_i64).unwrap_or(1),
        used_count: 0,
        revoked: false,
        flow_id: record
            .get("flow_id")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_string(),
    })
}

fn replay_transition(flow: &mut ApprovalFlow, target: &str) -> Result<(), String> {
    let allowed = match flow.state.as_str() {
        STATE_PENDING_APPROVAL => target == STATE_AUTHORIZED || target == "DENIED_OR_EXPIRED",
        STATE_AUTHORIZED => target == STATE_EXECUTING || target == "DENIED_OR_EXPIRED",
        STATE_EXECUTING => target == STATE_COMPLETED || target == "UNKNOWN",
        _ => false,
    };
    if !allowed {
        return Err(format!(
            "write-ahead ledger inconsistent: {} -> {target}",
            flow.state
        ));
    }
    flow.state = target.to_string();
    Ok(())
}

fn text<'a>(record: &'a Json, key: &str) -> Result<&'a str, String> {
    record
        .get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("write-ahead ledger inconsistent: {key}"))
}

fn number(record: &Json, key: &str) -> Result<f64, String> {
    record
        .get(key)
        .and_then(Json::as_f64)
        .ok_or_else(|| format!("write-ahead ledger inconsistent: {key}"))
}

struct WorkerLink {
    stdin: ChildStdin,
    channel: ChannelSession,
    pump: LinePump,
}

impl WorkerLink {
    fn write_line(&mut self, line: &str) -> Result<(), ProtocolError> {
        self.stdin.write_all(line.as_bytes()).map_err(io_error)?;
        self.stdin.write_all(b"\n").map_err(io_error)?;
        self.stdin.flush().map_err(io_error)
    }

    fn read_line(&self) -> Result<String, ChannelError> {
        self.pump.read_line()
    }
}

struct LinePump {
    request: Sender<()>,
    response: Receiver<LineEvent>,
}

enum LineEvent {
    Line(String),
    Eof,
    Oversize,
    Failed,
}

impl LinePump {
    fn start(stdout: ChildStdout) -> Self {
        let (request_tx, request_rx) = mpsc::channel();
        let (response_tx, response_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            while request_rx.recv().is_ok() {
                let event = read_capped(&mut reader);
                if response_tx.send(event).is_err() {
                    break;
                }
            }
        });
        Self {
            request: request_tx,
            response: response_rx,
        }
    }

    fn read_line(&self) -> Result<String, ChannelError> {
        if self.request.send(()).is_err() {
            return Err(ChannelError::new("denied_channel_eof"));
        }
        match self.response.recv_timeout(CHANNEL_TIMEOUT) {
            Ok(LineEvent::Line(line)) => Ok(line),
            Ok(LineEvent::Eof) | Ok(LineEvent::Failed) => Err(ChannelError::new("denied_channel_eof")),
            Ok(LineEvent::Oversize) => Err(ChannelError::new("denied_channel_oversize")),
            Err(RecvTimeoutError::Timeout) => Err(ChannelError::new("denied_channel_timeout")),
            Err(RecvTimeoutError::Disconnected) => Err(ChannelError::new("denied_channel_eof")),
        }
    }
}

fn read_capped(reader: &mut BufReader<ChildStdout>) -> LineEvent {
    let mut raw = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if raw.is_empty() {
                    return LineEvent::Eof;
                }
                break;
            }
            Ok(_) => {
                raw.push(byte[0]);
                if raw.len() > MAX_LINE {
                    drain_line(reader);
                    return LineEvent::Oversize;
                }
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(_) => return LineEvent::Failed,
        }
    }
    while raw.last() == Some(&b'\n') || raw.last() == Some(&b'\r') {
        raw.pop();
    }
    match String::from_utf8(raw) {
        Ok(line) => LineEvent::Line(line),
        Err(_) => LineEvent::Failed,
    }
}

fn drain_line(reader: &mut BufReader<ChildStdout>) {
    let mut seen = 0usize;
    let mut byte = [0u8; 1];
    while seen < CHANNEL_DRAIN_BUDGET {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                seen += 1;
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn random_bytes(len: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut buffer = vec![0u8; len];
    getrandom::fill(&mut buffer).map_err(|_| ProtocolError::new("channel key generation failed"))?;
    Ok(buffer)
}

fn channel_protocol(error: ChannelError) -> ProtocolError {
    ProtocolError::new(error.code())
}
