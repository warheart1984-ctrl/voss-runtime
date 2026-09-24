//! Capability broker.
//!
//! The only component allowed to exercise tools. A capability is broker
//! memory keyed by a random id. Immediately before use the broker rechecks
//! identity, policy version, action, resource, payload digest, constraints,
//! binding digest, expiry, revocation, use count, and request uniqueness,
//! then consumes the capability.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::approval::{
    APPROVE, ApprovalController, ApprovalError, STATE_DENIED_OR_EXPIRED, STATE_PENDING_APPROVAL,
};
use crate::audit::{AuditFields, AuditLog};
use crate::crashpoint::{self, CAPABILITY_ISSUED, EFFECT_DONE, REQUEST_EXECUTED};
use crate::canonical::{Json, json_number, new_id, sha256_hex};
use crate::policy::{DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_APPROVAL, PolicyEngine};
use crate::protocol::{CanonicalRequest, action_class, approval_binding_digest, bind};
use crate::tools::{ToolError, ToolRegistry};

#[derive(Clone, Debug)]
pub struct Capability {
    pub cap_id: String,
    pub principal: String,
    pub session_id: String,
    pub action: String,
    pub resource: Json,
    pub payload_digest: String,
    pub constraints: Json,
    pub policy_version: String,
    pub approval_ref: String,
    pub binding_digest: String,
    pub nonce: String,
    pub request_id: String,
    pub request_digest: String,
    pub issued_at: f64,
    pub expires_at: f64,
    pub use_limit: i64,
    pub used_count: i64,
    pub revoked: bool,
    pub flow_id: String,
}

impl Capability {
    pub fn is_used(&self) -> bool {
        self.used_count >= self.use_limit
    }
}

#[derive(Clone, Debug)]
pub struct BrokerDecision {
    pub decision: String,
    pub reason_code: String,
    pub policy_version: String,
    pub approval_request_id: String,
    pub capability_id: String,
    pub result: Option<Json>,
    pub outcome: String,
}

impl BrokerDecision {
    fn deny(reason: &str, policy_version: &str) -> Self {
        Self {
            decision: DECISION_DENY.to_string(),
            reason_code: reason.to_string(),
            policy_version: policy_version.to_string(),
            approval_request_id: String::new(),
            capability_id: String::new(),
            result: None,
            outcome: String::new(),
        }
    }

    pub fn to_json(&self) -> Json {
        let mut pairs = vec![
            ("decision", Json::string(&self.decision)),
            ("reason_code", Json::string(coarse_reason_code(&self.reason_code))),
            ("policy_version", Json::string(&self.policy_version)),
            ("approval_request_id", Json::string(&self.approval_request_id)),
            ("capability_id", Json::string(&self.capability_id)),
        ];
        if let Some(result) = &self.result {
            pairs.push(("result", result.clone()));
        }
        Json::object(pairs)
    }
}

pub fn coarse_reason_code(full: &str) -> &'static str {
    match full {
        "policy_approval_required" => "approval_required",
        "policy_allowed" => "allowed",
        "outcome_uncertain" => "unknown",
        "denied_identity" => "denied_identity",
        "denied_schema" => "denied_invalid_envelope",
        "denied_worker_suspended" => "denied_worker_suspended",
        "denied_approval_unavailable" => "denied_approval_unavailable",
        "denied_replay_uniqueness" => "denied_replay",
        _ => "denied",
    }
}

pub trait HealthProvider: Send + Sync {
    fn watchdog_health_ok(&self) -> bool;
    fn watchdog_accepts_work(&self, worker_id: &str) -> bool;
}

struct BrokerState {
    caps: BTreeMap<String, Capability>,
    executed: BTreeSet<String>,
}

pub struct Broker {
    policy: PolicyEngine,
    tools: ToolRegistry,
    audit: Arc<AuditLog>,
    approvals: Arc<ApprovalController>,
    health: Arc<dyn HealthProvider>,
    wal: Arc<AuditLog>,
    recovery_ok: Mutex<bool>,
    state: Mutex<BrokerState>,
}

impl Broker {
    pub fn new(
        policy: PolicyEngine,
        tools: ToolRegistry,
        audit: Arc<AuditLog>,
        approvals: Arc<ApprovalController>,
        health: Arc<dyn HealthProvider>,
        wal: Arc<AuditLog>,
    ) -> Self {
        Self {
            policy,
            tools,
            audit,
            approvals,
            health,
            wal,
            recovery_ok: Mutex::new(true),
            state: Mutex::new(BrokerState {
                caps: BTreeMap::new(),
                executed: BTreeSet::new(),
            }),
        }
    }

    pub fn set_recovery_ok(&self, ok: bool) {
        if let Ok(mut flag) = self.recovery_ok.lock() {
            *flag = ok;
        }
    }

    pub fn execute_action(&self, request: &CanonicalRequest, worker_id: &str) -> BrokerDecision {
        let mut state = self.state.lock().expect("broker lock");
        if let Some(decision) = self.guard(worker_id, request) {
            return decision;
        }
        let evaluation = self.policy.evaluate(request);
        if evaluation.decision == DECISION_DENY {
            let digest = request.digest().unwrap_or_default();
            let _ = self.audit.emit(
                "denied",
                fields(
                    self.policy.version(),
                    worker_id,
                    request,
                    &digest,
                    Outcome {
                        reason: Some(evaluation.reason),
                        decision: "DENY",
                        flow_id: None,
                        capability_id: None,
                        result: None,
                        error: None,
                    },
                ),
            );
            return BrokerDecision::deny(evaluation.reason, self.policy.version());
        }
        if evaluation.decision == DECISION_REQUIRE_APPROVAL {
            let expiry = evaluation
                .rule
                .as_ref()
                .map(|rule| rule.expiry_limit_seconds as f64)
                .unwrap_or(60.0);
            let Ok(flow) = self.approvals.request(request, expiry) else {
                return BrokerDecision::deny("denied_approval", self.policy.version());
            };
            let _ = self.audit.emit(
                "approval_request",
                AuditFields {
                    worker_id: Some(worker_id.to_string()),
                    session_id: Some(request.session_id.clone()),
                    request_id: Some(request.request_id.clone()),
                    request_digest: Some(flow.request_digest.clone()),
                    flow_id: Some(flow.flow_id.clone()),
                    action: Some(request.action.clone()),
                    action_class: Some(action_class(&request.action).to_string()),
                    policy_version: Some(self.policy.version().to_string()),
                    decision: Some(DECISION_REQUIRE_APPROVAL.to_string()),
                    reason_code: Some("policy_approval_required".to_string()),
                    ..AuditFields::default()
                },
            );
            return BrokerDecision {
                decision: DECISION_REQUIRE_APPROVAL.to_string(),
                reason_code: "policy_approval_required".to_string(),
                policy_version: self.policy.version().to_string(),
                approval_request_id: flow.flow_id,
                capability_id: String::new(),
                result: None,
                outcome: String::new(),
            };
        }
        let cap = self.issue(&mut state, request, worker_id, &format!("policy:{}", self.policy.version()));
        self.use_capability(&mut state, cap, request, worker_id, "")
    }

    pub fn resolve_and_execute(
        &self,
        flow_id: &str,
        decision: &str,
        approver_ref: &str,
        request: &CanonicalRequest,
        worker_id: &str,
    ) -> BrokerDecision {
        let mut state = self.state.lock().expect("broker lock");
        if let Some(decision) = self.guard(worker_id, request) {
            return decision;
        }
        let flow = match self.approvals.get(flow_id) {
            Ok(flow) => flow,
            Err(ApprovalError { .. }) => {
                return BrokerDecision::deny("denied_approval", self.policy.version());
            }
        };
        if flow.state != STATE_PENDING_APPROVAL {
            return BrokerDecision::deny("denied_approval", self.policy.version());
        }
        if decision != APPROVE {
            let _ = self.approvals.resolve(flow_id, decision, approver_ref);
            let _ = self.audit.emit(
                "approval_resolution",
                AuditFields {
                    worker_id: Some(worker_id.to_string()),
                    session_id: Some(request.session_id.clone()),
                    request_id: Some(request.request_id.clone()),
                    flow_id: Some(flow_id.to_string()),
                    action: Some(request.action.clone()),
                    policy_version: Some(self.policy.version().to_string()),
                    decision: Some("DENY".to_string()),
                    approver_ref: Some(approver_ref.to_string()),
                    reason_code: Some("denied_approval".to_string()),
                    ..AuditFields::default()
                },
            );
            return BrokerDecision::deny("denied_approval", self.policy.version());
        }
        let digest = request.digest().unwrap_or_default();
        if digest != flow.request_digest {
            let _ = self.approvals.resolve(flow_id, "CANCEL", approver_ref);
            let _ = self.audit.emit(
                "denied",
                AuditFields {
                    worker_id: Some(worker_id.to_string()),
                    session_id: Some(request.session_id.clone()),
                    request_id: Some(request.request_id.clone()),
                    request_digest: Some(digest),
                    flow_id: Some(flow_id.to_string()),
                    action: Some(request.action.clone()),
                    policy_version: Some(self.policy.version().to_string()),
                    decision: Some("DENY".to_string()),
                    reason_code: Some("denied_approval_tamper".to_string()),
                    approver_ref: Some(approver_ref.to_string()),
                    ..AuditFields::default()
                },
            );
            return BrokerDecision::deny("denied_approval_tamper", self.policy.version());
        }
        let bound = bind(request, &flow.nonce, flow.expires_at);
        let (resolved, authorized) = match self.approvals.resolve(flow_id, APPROVE, approver_ref) {
            Ok(value) => value,
            Err(_) => return BrokerDecision::deny("denied_approval", self.policy.version()),
        };
        if !authorized {
            let reason = if resolved.state == STATE_DENIED_OR_EXPIRED {
                "denied_approval_expired"
            } else {
                "denied_approval"
            };
            let _ = self.audit.emit(
                "denied",
                fields(
                    self.policy.version(),
                    worker_id,
                    request,
                    &digest,
                    Outcome {
                        reason: Some(reason),
                        decision: "DENY",
                        flow_id: Some(flow_id),
                        capability_id: None,
                        result: None,
                        error: None,
                    },
                ),
            );
            return BrokerDecision::deny(reason, self.policy.version());
        }
        let cap = self.issue_from_flow(&mut state, &resolved, worker_id, approver_ref);
        self.use_capability(&mut state, cap, &bound, worker_id, flow_id)
    }

    pub fn revoke_all(&self, worker_id: &str, reason: &str) -> i64 {
        let mut state = self.state.lock().expect("broker lock");
        let mut revoked = 0;
        let ids: Vec<String> = state.caps.keys().cloned().collect();
        for id in ids {
            let Some(cap) = state.caps.get_mut(&id) else {
                continue;
            };
            if cap.principal == worker_id && !cap.revoked {
                cap.revoked = true;
                revoked += 1;
                let cap_id = cap.cap_id.clone();
                let request_id = cap.request_id.clone();
                let _ = self.audit.emit(
                    "revocation",
                    AuditFields {
                        worker_id: Some(worker_id.to_string()),
                        session_id: Some(cap.session_id.clone()),
                        request_id: Some(cap.request_id.clone()),
                        action: Some(cap.action.clone()),
                        policy_version: Some(cap.policy_version.clone()),
                        capability_id: Some(cap.cap_id.clone()),
                        reason_code: Some("denied_capability_revoked".to_string()),
                        error: Some(format!("revoked: {reason}")),
                        ..AuditFields::default()
                    },
                );
                wal_emit(&self.wal, "capability_revoked", [
                    ("cap_id", Json::string(cap_id)),
                    ("request_id", Json::string(request_id)),
                    ("reason", Json::string(reason)),
                ]);
            }
        }
        revoked
    }

    pub fn restore_cap(&self, capability: Capability) {
        self.state
            .lock()
            .expect("broker lock")
            .caps
            .insert(capability.cap_id.clone(), capability);
    }

    pub fn capabilities(&self) -> Vec<Capability> {
        self.state.lock().expect("broker lock").caps.values().cloned().collect()
    }

    pub fn mark_executed(&self, request_id: &str) {
        self.state
            .lock()
            .expect("broker lock")
            .executed
            .insert(request_id.to_string());
    }

    fn guard(&self, worker_id: &str, request: &CanonicalRequest) -> Option<BrokerDecision> {
        let mut problems = Vec::new();
        if !self.policy.valid() {
            problems.push("policy");
        }
        if !self.audit.healthy() {
            problems.push("audit");
        }
        if !self.wal.healthy() {
            problems.push("wal");
        }
        if !self.recovery_ok.lock().map(|flag| *flag).unwrap_or(false) {
            problems.push("recovery");
        }
        if !self.health.watchdog_health_ok() {
            problems.push("watchdog");
        }
        if !self.health.watchdog_accepts_work(worker_id) {
            problems.push("watchdog-suspended");
        }
        if problems.is_empty() {
            return None;
        }
        let detail = format!("unavailable controls: {}", problems.join(", "));
        let digest = request.digest().ok();
        let _ = self.audit.emit(
            "denied",
            AuditFields {
                worker_id: Some(worker_id.to_string()),
                session_id: Some(request.session_id.clone()),
                request_id: Some(request.request_id.clone()),
                request_digest: digest,
                action: Some(request.action.clone()),
                policy_version: Some(self.policy.version().to_string()),
                decision: Some("DENY".to_string()),
                reason_code: Some("denied_health_unavailable".to_string()),
                error: Some(detail),
                ..AuditFields::default()
            },
        );
        Some(BrokerDecision::deny(
            "denied_health_unavailable",
            self.policy.version(),
        ))
    }

    fn issue(
        &self,
        state: &mut BrokerState,
        request: &CanonicalRequest,
        worker_id: &str,
        approval_ref: &str,
    ) -> Capability {
        let nonce = new_id("nonce-");
        let expires_at = wall_now() + 60.0;
        let bound = bind(request, &nonce, expires_at);
        let binding_digest = bound
            .binding_digest(self.policy.version())
            .unwrap_or_default();
        let request_digest = request.digest().unwrap_or_default();
        self.store(
            state,
            Capability {
                cap_id: new_id("cap-"),
                principal: worker_id.to_string(),
                session_id: request.session_id.clone(),
                action: request.action.clone(),
                resource: request.resource.clone(),
                payload_digest: request.payload_digest.clone(),
                constraints: request.constraints.clone(),
                policy_version: self.policy.version().to_string(),
                approval_ref: approval_ref.to_string(),
                binding_digest,
                nonce,
                request_id: request.request_id.clone(),
                request_digest,
                issued_at: wall_now(),
                expires_at,
                use_limit: 1,
                used_count: 0,
                revoked: false,
                flow_id: String::new(),
            },
        )
    }

    fn issue_from_flow(
        &self,
        state: &mut BrokerState,
        flow: &crate::approval::ApprovalFlow,
        worker_id: &str,
        approver_ref: &str,
    ) -> Capability {
        let request = &flow.request;
        let approval_ref = if flow.approver_ref.is_empty() {
            if approver_ref.is_empty() {
                "approval:flow".to_string()
            } else {
                approver_ref.to_string()
            }
        } else {
            flow.approver_ref.clone()
        };
        self.store(
            state,
            Capability {
                cap_id: new_id("cap-"),
                principal: worker_id.to_string(),
                session_id: request.session_id.clone(),
                action: request.action.clone(),
                resource: request.resource.clone(),
                payload_digest: request.payload_digest.clone(),
                constraints: request.constraints.clone(),
                policy_version: flow.policy_version.clone(),
                approval_ref,
                binding_digest: flow.binding_digest.clone(),
                nonce: flow.nonce.clone(),
                request_id: request.request_id.clone(),
                request_digest: flow.request_digest.clone(),
                issued_at: wall_now(),
                expires_at: flow.expires_at,
                use_limit: 1,
                used_count: 0,
                revoked: false,
                flow_id: flow.flow_id.clone(),
            },
        )
    }

    fn store(&self, state: &mut BrokerState, capability: Capability) -> Capability {
        let _ = self.audit.emit(
            "capability_issued",
            AuditFields {
                worker_id: Some(capability.principal.clone()),
                session_id: Some(capability.session_id.clone()),
                request_id: Some(capability.request_id.clone()),
                request_digest: Some(capability.request_digest.clone()),
                action: Some(capability.action.clone()),
                policy_version: Some(capability.policy_version.clone()),
                capability_id: Some(capability.cap_id.clone()),
                flow_id: if capability.flow_id.is_empty() {
                    None
                } else {
                    Some(capability.flow_id.clone())
                },
                decision: Some("ALLOW".to_string()),
                reason_code: Some("policy_allowed".to_string()),
                approver_ref: Some(capability.approval_ref.clone()),
                ..AuditFields::default()
            },
        );
        state.caps.insert(capability.cap_id.clone(), capability.clone());
        wal_emit(&self.wal, "capability_issued", capability_record(&capability));
        crashpoint::maybe_crash(CAPABILITY_ISSUED);
        capability
    }

    fn use_capability(
        &self,
        state: &mut BrokerState,
        capability: Capability,
        request: &CanonicalRequest,
        worker_id: &str,
        flow_id: &str,
    ) -> BrokerDecision {
        let Some(capability) = state.caps.get(&capability.cap_id).cloned() else {
            let _ = self.audit.emit(
                "denied",
                fields(
                    self.policy.version(),
                    worker_id,
                    request,
                    "",
                    Outcome {
                        reason: Some("denied_capability_forged"),
                        decision: "DENY",
                        flow_id: None,
                        capability_id: None,
                        result: None,
                        error: None,
                    },
                ),
            );
            return BrokerDecision::deny("denied_capability_forged", self.policy.version());
        };
        if let Some(reason) = validate_capability(&capability, request, worker_id, self.policy.version(), &state.executed)
        {
            let digest = request.digest().unwrap_or_default();
            let _ = self.audit.emit(
                "denied",
                fields(
                    self.policy.version(),
                    worker_id,
                    request,
                    &digest,
                    Outcome {
                        reason: Some(reason),
                        decision: "DENY",
                        flow_id: Some(&capability.flow_id),
                        capability_id: Some(&capability.cap_id),
                        result: None,
                        error: None,
                    },
                ),
            );
            return BrokerDecision::deny(reason, self.policy.version());
        }
        {
            let stored = state.caps.get_mut(&capability.cap_id).expect("capability exists");
            stored.used_count += 1;
        }
        state.executed.insert(request.request_id.clone());
        wal_emit(&self.wal, "capability_used", [
            ("cap_id", Json::string(&capability.cap_id)),
            ("request_id", Json::string(&request.request_id)),
        ]);
        wal_emit(&self.wal, "request_executed", [
            ("request_id", Json::string(&request.request_id)),
        ]);
        crashpoint::maybe_crash(REQUEST_EXECUTED);
        let digest = request.digest().unwrap_or_default();
        if self.audit.emit(
            "execution_start",
            fields(
                self.policy.version(),
                worker_id,
                request,
                &digest,
                Outcome {
                    reason: Some("policy_allowed"),
                    decision: "ALLOW",
                    flow_id: Some(flow_id),
                    capability_id: Some(&capability.cap_id),
                    result: None,
                    error: None,
                },
            ),
        ).is_err() {
            return BrokerDecision::deny("denied_audit_unavailable", self.policy.version());
        }
        if !flow_id.is_empty() {
            let _ = self.approvals.mark_executing(flow_id);
        }
        match self.tools.execute(&capability.action, request) {
            Err(ToolError::Uncertain(error)) => {
                let _ = self.audit.emit(
                    "execution_result",
                    fields(
                        self.policy.version(),
                        worker_id,
                        request,
                        &digest,
                        Outcome {
                            reason: Some("outcome_uncertain"),
                            decision: "UNKNOWN",
                            flow_id: Some(flow_id),
                            capability_id: Some(&capability.cap_id),
                            result: Some(Json::object([("status", Json::string("uncertain"))])),
                            error: Some(error.message()),
                        },
                    ),
                );
                if !flow_id.is_empty() {
                    let _ = self.approvals.mark_outcome(flow_id, "UNKNOWN");
                }
                BrokerDecision {
                    decision: "UNKNOWN".to_string(),
                    reason_code: "outcome_uncertain".to_string(),
                    policy_version: self.policy.version().to_string(),
                    approval_request_id: String::new(),
                    capability_id: capability.cap_id,
                    result: Some(Json::object([("status", Json::string("uncertain"))])),
                    outcome: String::new(),
                }
            }
            Err(ToolError::Failure(error)) => {
                let _ = self.audit.emit(
                    "execution_result",
                    fields(
                        self.policy.version(),
                        worker_id,
                        request,
                        &digest,
                        Outcome {
                            reason: Some("denied_tool_failure"),
                            decision: "UNKNOWN",
                            flow_id: Some(flow_id),
                            capability_id: Some(&capability.cap_id),
                            result: Some(Json::empty_object()),
                            error: Some(error.message()),
                        },
                    ),
                );
                if !flow_id.is_empty() {
                    let _ = self.approvals.mark_outcome(flow_id, "UNKNOWN");
                }
                BrokerDecision {
                    decision: "UNKNOWN".to_string(),
                    reason_code: "denied_tool_failure".to_string(),
                    policy_version: self.policy.version().to_string(),
                    approval_request_id: String::new(),
                    capability_id: capability.cap_id,
                    result: Some(Json::object([("error", Json::string(error.message()))])),
                    outcome: String::new(),
                }
            }
            Ok(result) => {
                crashpoint::maybe_crash(EFFECT_DONE);
                let _ = self.audit.emit(
                    "execution_result",
                    AuditFields {
                        worker_id: Some(worker_id.to_string()),
                        session_id: Some(request.session_id.clone()),
                        request_id: Some(request.request_id.clone()),
                        request_digest: Some(digest),
                        action: Some(request.action.clone()),
                        action_class: Some(action_class(&request.action).to_string()),
                        policy_version: Some(self.policy.version().to_string()),
                        decision: Some("ALLOW".to_string()),
                        outcome: Some("COMPLETED".to_string()),
                        capability_id: Some(capability.cap_id.clone()),
                        flow_id: if flow_id.is_empty() {
                            None
                        } else {
                            Some(flow_id.to_string())
                        },
                        result: Some(audit_safe_result(&result)),
                        ..AuditFields::default()
                    },
                );
                if !flow_id.is_empty() {
                    let _ = self.approvals.mark_outcome(flow_id, "COMPLETED");
                }
                BrokerDecision {
                    decision: DECISION_ALLOW.to_string(),
                    reason_code: "policy_allowed".to_string(),
                    policy_version: self.policy.version().to_string(),
                    approval_request_id: String::new(),
                    capability_id: capability.cap_id,
                    result: Some(result),
                    outcome: "COMPLETED".to_string(),
                }
            }
        }
    }
}

fn wal_emit(wal: &AuditLog, event_type: &str, pairs: impl IntoIterator<Item = (&'static str, Json)>) {
    let _ = wal.emit(
        event_type,
        AuditFields {
            extra: pairs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
            ..AuditFields::default()
        },
    );
}

fn capability_record(capability: &Capability) -> Vec<(&'static str, Json)> {
    vec![
        ("cap_id", Json::string(&capability.cap_id)),
        ("principal", Json::string(&capability.principal)),
        ("session_id", Json::string(&capability.session_id)),
        ("action", Json::string(&capability.action)),
        ("resource", capability.resource.clone()),
        ("payload_digest", Json::string(&capability.payload_digest)),
        ("constraints", capability.constraints.clone()),
        ("policy_version", Json::string(&capability.policy_version)),
        ("approval_ref", Json::string(&capability.approval_ref)),
        ("binding_digest", Json::string(&capability.binding_digest)),
        ("nonce", Json::string(&capability.nonce)),
        ("request_id", Json::string(&capability.request_id)),
        ("request_digest", Json::string(&capability.request_digest)),
        ("issued_at", json_number(capability.issued_at)),
        ("expires_at", json_number(capability.expires_at)),
        ("use_limit", Json::Int(capability.use_limit)),
        ("flow_id", Json::string(&capability.flow_id)),
    ]
}

fn validate_capability(
    capability: &Capability,
    request: &CanonicalRequest,
    worker_id: &str,
    policy_version: &str,
    executed: &BTreeSet<String>,
) -> Option<&'static str> {
    let now = wall_now();
    if capability.principal != worker_id || capability.principal != request.principal {
        return Some("denied_identity");
    }
    if capability.session_id != request.session_id {
        return Some("denied_identity");
    }
    if capability.revoked {
        return Some("denied_capability_revoked");
    }
    if now > capability.expires_at {
        return Some("denied_capability_expired");
    }
    if capability.is_used() {
        return Some("denied_capability_used");
    }
    if capability.action != request.action
        || capability.policy_version != policy_version
        || capability.resource != request.resource
        || capability.payload_digest != request.payload_digest
        || capability.constraints != request.constraints
    {
        return Some("denied_request_tamper");
    }
    if executed.contains(&request.request_id) {
        return Some("denied_replay_uniqueness");
    }
    let Ok(request_digest) = request.digest() else {
        return Some("denied_request_tamper");
    };
    let Ok(expected) = approval_binding_digest(
        &request_digest,
        &capability.policy_version,
        &capability.nonce,
        capability.expires_at,
    ) else {
        return Some("denied_request_tamper");
    };
    if expected != capability.binding_digest {
        return Some("denied_request_tamper");
    }
    None
}

fn audit_safe_result(result: &Json) -> Json {
    let Some(object) = result.as_object() else {
        return Json::empty_object();
    };
    let mut safe = Vec::new();
    for (key, value) in object {
        if key == "content" || key == "subject" || key == "body" || key == "recipient" {
            continue;
        }
        safe.push((key.as_str(), value.clone()));
    }
    if object.contains_key("recipient") {
        let recipient = object.get("recipient").cloned().unwrap_or(Json::Null);
        if let Ok(digest) = sha256_hex(&recipient) {
            safe.push(("recipient_sha256", Json::string(digest)));
        }
    }
    let payload_sha = object.get("sha256").cloned().unwrap_or(Json::Null);
    safe.push(("payload_sha256", payload_sha));
    Json::object(safe)
}

struct Outcome<'a> {
    reason: Option<&'a str>,
    decision: &'a str,
    flow_id: Option<&'a str>,
    capability_id: Option<&'a str>,
    result: Option<Json>,
    error: Option<&'a str>,
}

fn fields(
    policy_version: &str,
    worker_id: &str,
    request: &CanonicalRequest,
    digest: &str,
    outcome: Outcome<'_>,
) -> AuditFields {
    AuditFields {
        worker_id: Some(worker_id.to_string()),
        session_id: Some(request.session_id.clone()),
        request_id: Some(request.request_id.clone()),
        request_digest: if digest.is_empty() {
            None
        } else {
            Some(digest.to_string())
        },
        action: Some(request.action.clone()),
        action_class: Some(action_class(&request.action).to_string()),
        policy_version: Some(policy_version.to_string()),
        decision: Some(outcome.decision.to_string()),
        reason_code: outcome.reason.map(str::to_string),
        flow_id: outcome.flow_id.filter(|value| !value.is_empty()).map(str::to_string),
        capability_id: outcome.capability_id.map(str::to_string),
        result: outcome.result,
        error: outcome.error.map(str::to_string),
        ..AuditFields::default()
    }
}

fn wall_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

