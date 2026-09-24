//! Trusted human approval flow.
//!
//! The model can propose a canonical request. It cannot construct the view
//! the operator sees, and its text is never treated as consent. Approval
//! binds the request digest, policy version, nonce, and expiry, and it is
//! single-use.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit::{AuditFields, AuditLog};
use crate::crashpoint::{self, FLOW_REQUEST, FLOW_REQUEST_PREWAL, FLOW_RESOLUTION};
use crate::canonical::{Json, json_number, new_id};
use crate::protocol::{CanonicalRequest, action_class};

pub const STATE_PENDING_APPROVAL: &str = "PENDING_APPROVAL";
pub const STATE_AUTHORIZED: &str = "AUTHORIZED";
pub const STATE_EXECUTING: &str = "EXECUTING";
pub const STATE_COMPLETED: &str = "COMPLETED";
pub const STATE_UNKNOWN: &str = "UNKNOWN";
pub const STATE_DENIED_OR_EXPIRED: &str = "DENIED_OR_EXPIRED";

pub const APPROVE: &str = "APPROVE";
pub const DENY: &str = "DENY";
pub const CANCEL: &str = "CANCEL";

#[derive(Debug)]
pub struct ApprovalError {
    message: String,
}

impl ApprovalError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ApprovalError {}

#[derive(Clone, Debug)]
pub struct ApprovalView {
    pub request_id: String,
    pub action: String,
    pub principal: String,
    pub resource: Json,
    pub payload_digest: String,
    pub policy_version: String,
    pub nonce: String,
    pub expires_at: f64,
    pub expires_in_seconds: f64,
    pub risk_class: String,
    pub consequences: String,
    pub reversible: bool,
}

impl ApprovalView {
    pub fn describe(&self) -> String {
        format!(
            "Action:        {action}\n\
             Principal:     {principal}\n\
             Target:        {resource:?}\n\
             Payload sha256:{digest}\n\
             Policy:        {policy}\n\
             Nonce:         {nonce}\n\
             Expires in:    {expires:.0}s\n\
             Risk class:    {risk}\n\
             Consequences:  {consequences}\n\
             Reversible:    {reversible}",
            action = self.action,
            principal = self.principal,
            resource = self.resource,
            digest = self.payload_digest,
            policy = self.policy_version,
            nonce = self.nonce,
            expires = self.expires_in_seconds,
            risk = self.risk_class,
            consequences = self.consequences,
            reversible = self.reversible,
        )
    }
}

#[derive(Clone, Debug)]
pub struct ApprovalFlow {
    pub flow_id: String,
    pub request: CanonicalRequest,
    pub policy_version: String,
    pub nonce: String,
    pub expires_at: f64,
    pub binding_digest: String,
    pub request_digest: String,
    pub state: String,
    pub approver_ref: String,
    pub outcome: String,
    pub created_at: f64,
}

pub struct ApprovalController {
    policy_version: String,
    flows: Mutex<BTreeMap<String, ApprovalFlow>>,
    now: Box<dyn Fn() -> f64 + Send + Sync>,
    wal: Option<Arc<AuditLog>>,
}

impl ApprovalController {
    pub fn new(policy_version: impl Into<String>) -> Self {
        Self::with_clock(policy_version, system_now)
    }

    pub fn with_clock(
        policy_version: impl Into<String>,
        now: impl Fn() -> f64 + Send + Sync + 'static,
    ) -> Self {
        Self {
            policy_version: policy_version.into(),
            flows: Mutex::new(BTreeMap::new()),
            now: Box::new(now),
            wal: None,
        }
    }

    pub fn with_wal(policy_version: impl Into<String>, wal: Arc<AuditLog>) -> Self {
        let mut controller = Self::new(policy_version);
        controller.wal = Some(wal);
        controller
    }

    pub fn request(&self, request: &CanonicalRequest, expiry_seconds: f64) -> Result<ApprovalFlow, ApprovalError> {
        if expiry_seconds <= 0.0 {
            return Err(ApprovalError::new("approval expiry must be positive"));
        }
        let nonce = new_id("nonce-");
        let created_at = (self.now)();
        let expires_at = json_number(created_at + expiry_seconds)
            .as_f64()
            .unwrap_or(created_at + expiry_seconds);
        let bound = crate::protocol::bind(request, &nonce, expires_at);
        let binding_digest = bound
            .binding_digest(&self.policy_version)
            .map_err(|error| ApprovalError::new(error.message()))?;
        let request_digest = bound
            .digest()
            .map_err(|error| ApprovalError::new(error.message()))?;
        let flow = ApprovalFlow {
            flow_id: new_id("approval-"),
            request: bound,
            policy_version: self.policy_version.clone(),
            nonce,
            expires_at,
            binding_digest,
            request_digest,
            state: STATE_PENDING_APPROVAL.to_string(),
            approver_ref: String::new(),
            outcome: String::new(),
            created_at,
        };
        self.flows
            .lock()
            .expect("approval lock")
            .insert(flow.flow_id.clone(), flow.clone());
        crashpoint::maybe_crash(FLOW_REQUEST_PREWAL);
        self.note("flow_request", [
            ("flow_id", Json::string(&flow.flow_id)),
            ("version", Json::string(&flow.request.version)),
            ("request_id", Json::string(&flow.request.request_id)),
            ("session_id", Json::string(&flow.request.session_id)),
            ("principal", Json::string(&flow.request.principal)),
            ("action", Json::string(&flow.request.action)),
            ("resource", flow.request.resource.clone()),
            ("payload", flow.request.payload.clone()),
            ("constraints", flow.request.constraints.clone()),
            ("payload_digest", Json::string(&flow.request.payload_digest)),
            ("policy_version", Json::string(&flow.policy_version)),
            ("nonce", Json::string(&flow.nonce)),
            ("expires_at", json_number(flow.expires_at)),
            ("binding_digest", Json::string(&flow.binding_digest)),
            ("request_digest", Json::string(&flow.request_digest)),
            ("created_at", json_number(flow.created_at)),
        ]);
        crashpoint::maybe_crash(FLOW_REQUEST);
        Ok(flow)
    }

    pub fn view(&self, flow_id: &str) -> Result<ApprovalView, ApprovalError> {
        let flow = self.get(flow_id)?;
        let now = (self.now)();
        Ok(ApprovalView {
            request_id: flow.request.request_id.clone(),
            action: flow.request.action.clone(),
            principal: flow.request.principal.clone(),
            resource: flow.request.resource.clone(),
            payload_digest: flow.request.payload_digest.clone(),
            policy_version: flow.policy_version.clone(),
            nonce: flow.nonce.clone(),
            expires_at: flow.expires_at,
            expires_in_seconds: (flow.expires_at - now).max(0.0),
            risk_class: action_class(&flow.request.action).to_string(),
            consequences: consequences(&flow.request.action),
            reversible: reversible(&flow.request.action),
        })
    }

    pub fn get(&self, flow_id: &str) -> Result<ApprovalFlow, ApprovalError> {
        self.flows
            .lock()
            .expect("approval lock")
            .get(flow_id)
            .cloned()
            .ok_or_else(|| ApprovalError::new("approval flow not found"))
    }

    pub fn resolve(
        &self,
        flow_id: &str,
        decision: &str,
        approver_ref: &str,
    ) -> Result<(ApprovalFlow, bool), ApprovalError> {
        let mut flows = self.flows.lock().expect("approval lock");
        self.purge_expired(&mut flows);
        let Some(flow) = flows.get_mut(flow_id) else {
            return Err(ApprovalError::new("approval flow not found"));
        };
        if is_terminal(&flow.state) {
            return Ok((flow.clone(), false));
        }
        let decision = decision.to_ascii_uppercase();
        if (self.now)() > flow.expires_at {
            if flow.state == STATE_PENDING_APPROVAL {
                transition(flow, STATE_DENIED_OR_EXPIRED)?;
            }
            let expired = flow.clone();
            drop(flows);
            self.note_resolution(&expired, "EXPIRED", approver_ref, false);
            return Ok((expired, false));
        }
        if decision == APPROVE {
            if flow.state != STATE_PENDING_APPROVAL {
                return Ok((flow.clone(), false));
            }
            flow.approver_ref = approver_ref.to_string();
            transition(flow, STATE_AUTHORIZED)?;
            let approved = flow.clone();
            drop(flows);
            self.note_resolution(&approved, APPROVE, approver_ref, true);
            crashpoint::maybe_crash(FLOW_RESOLUTION);
            return Ok((approved, true));
        }
        if decision == DENY || decision == CANCEL {
            transition(flow, STATE_DENIED_OR_EXPIRED)?;
            let denied = flow.clone();
            let logged = decision.clone();
            drop(flows);
            self.note_resolution(&denied, &logged, approver_ref, false);
            return Ok((denied, false));
        }
        Ok((flow.clone(), false))
    }

    pub fn mark_executing(&self, flow_id: &str) -> Result<ApprovalFlow, ApprovalError> {
        let mut flows = self.flows.lock().expect("approval lock");
        let flow = flows
            .get_mut(flow_id)
            .ok_or_else(|| ApprovalError::new("approval flow not found"))?;
        if flow.state == STATE_AUTHORIZED {
            transition(flow, STATE_EXECUTING)?;
            let flow_id = flow.flow_id.clone();
            drop(flows);
            self.note("flow_executing", [("flow_id", Json::string(&flow_id))]);
            return self.get(&flow_id);
        }
        Ok(flow.clone())
    }

    pub fn mark_outcome(&self, flow_id: &str, outcome: &str) -> Result<(), ApprovalError> {
        let mut flows = self.flows.lock().expect("approval lock");
        let flow = flows
            .get_mut(flow_id)
            .ok_or_else(|| ApprovalError::new("approval flow not found"))?;
        flow.outcome = outcome.to_string();
        let next = if outcome == STATE_COMPLETED {
            STATE_COMPLETED
        } else {
            STATE_UNKNOWN
        };
        if flow.state == STATE_EXECUTING {
            transition(flow, next)?;
            let logged = flow.clone();
            drop(flows);
            self.note("flow_outcome", [
                ("flow_id", Json::string(&logged.flow_id)),
                ("outcome", Json::string(outcome)),
                ("state", Json::string(&logged.state)),
            ]);
            return Ok(());
        }
        Ok(())
    }

    pub fn restore_flow(&self, flow: ApprovalFlow) {
        self.flows
            .lock()
            .expect("approval lock")
            .insert(flow.flow_id.clone(), flow);
    }

    fn note_resolution(&self, flow: &ApprovalFlow, decision: &str, approver_ref: &str, authorized: bool) {
        self.note("flow_resolution", [
            ("flow_id", Json::string(&flow.flow_id)),
            ("decision", Json::string(decision)),
            ("approver_ref", Json::string(approver_ref)),
            ("state", Json::string(&flow.state)),
            ("authorized", Json::Bool(authorized)),
        ]);
    }

    fn note(&self, event: &str, pairs: impl IntoIterator<Item = (&'static str, Json)>) {
        let Some(wal) = &self.wal else {
            return;
        };
        let _ = wal.emit(
            event,
            AuditFields {
                extra: pairs
                    .into_iter()
                    .map(|(key, value)| (key.to_string(), value))
                    .collect(),
                ..AuditFields::default()
            },
        );
    }

    fn purge_expired(&self, flows: &mut BTreeMap<String, ApprovalFlow>) {
        let now = (self.now)();
        for flow in flows.values_mut() {
            if flow.state == STATE_PENDING_APPROVAL && now > flow.expires_at {
                let _ = transition(flow, STATE_DENIED_OR_EXPIRED);
            }
        }
    }
}

fn is_terminal(state: &str) -> bool {
    state == STATE_DENIED_OR_EXPIRED || state == STATE_COMPLETED || state == STATE_UNKNOWN
}

fn transition(flow: &mut ApprovalFlow, target: &str) -> Result<(), ApprovalError> {
    if is_terminal(&flow.state) {
        return Err(ApprovalError::new(format!(
            "flow is terminal in state {}",
            flow.state
        )));
    }
    let allowed = match flow.state.as_str() {
        STATE_PENDING_APPROVAL => target == STATE_AUTHORIZED || target == STATE_DENIED_OR_EXPIRED,
        STATE_AUTHORIZED => target == STATE_EXECUTING || target == STATE_DENIED_OR_EXPIRED,
        STATE_EXECUTING => target == STATE_COMPLETED || target == STATE_UNKNOWN,
        _ => false,
    };
    if !allowed {
        return Err(ApprovalError::new(format!(
            "invalid transition {} -> {target}",
            flow.state
        )));
    }
    flow.state = target.to_string();
    Ok(())
}

fn consequences(action: &str) -> String {
    match action {
        "workspace.read" => "Reads a file from the allowlisted workspace".to_string(),
        "workspace.write" => {
            "Creates or overwrites a draft file in the workspace (reversible)".to_string()
        }
        _ => "Simulated external effect (mock mail). Not recallable in production.".to_string(),
    }
}

fn reversible(action: &str) -> bool {
    action == "workspace.read" || action == "workspace.write"
}

fn system_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
