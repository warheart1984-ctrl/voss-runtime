//! Signed policy bundles and the default-deny policy engine.
//!
//! A capability is granted only when a signed policy bundle explicitly
//! permits the principal, action, and resource within the validity interval.
//! The model and worker never possess the policy signing key.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, SecondsFormat, Utc};

use crate::canonical::{Json, ProtocolError, canonical_bytes, loads_strict};
use crate::keys::KeyRing;
use crate::protocol::{CanonicalRequest, path_prefix_matches};

pub const DECISION_ALLOW: &str = "ALLOW";
pub const DECISION_REQUIRE_APPROVAL: &str = "REQUIRE_APPROVAL";
pub const DECISION_DENY: &str = "DENY";

const RUNTIME_MIN_VERSION: &str = "1";
const DEFAULT_POLICY_VERSION: &str = "1.0.0";

const BODY_FIELDS: &[&str] = &[
    "version",
    "signer",
    "created_at",
    "valid_from",
    "valid_until",
    "min_runtime_version",
    "audit_required",
    "revocation_reference",
    "rules",
];

const RULE_FIELDS: &[&str] = &[
    "principal",
    "action",
    "resource_prefix",
    "decision",
    "approval_required",
    "expiry_limit_seconds",
];

const PROTOTYPE_ACTIONS: &[&str] = &["workspace.read", "workspace.write", "external.send_mock"];

#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    pub principal: String,
    pub action: String,
    pub resource_prefix: Option<Json>,
    pub decision: String,
    pub approval_required: bool,
    pub expiry_limit_seconds: i64,
}

impl Rule {
    pub fn allow(action: impl Into<String>) -> Self {
        Self {
            principal: "*".to_string(),
            action: action.into(),
            resource_prefix: None,
            decision: DECISION_ALLOW.to_string(),
            approval_required: false,
            expiry_limit_seconds: 60,
        }
    }

    pub fn require_approval(action: impl Into<String>) -> Self {
        Self {
            approval_required: true,
            decision: DECISION_REQUIRE_APPROVAL.to_string(),
            ..Self::allow(action)
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolicyBundle {
    pub version: String,
    pub signer: String,
    pub created_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub min_runtime_version: String,
    pub audit_required: bool,
    pub revocation_reference: String,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug)]
pub struct PolicyFields {
    pub version: String,
    pub signer: String,
    pub created_at: String,
    pub valid_from: String,
    pub valid_until: String,
    pub min_runtime_version: String,
    pub audit_required: bool,
    pub revocation_reference: String,
}

impl Default for PolicyFields {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            version: DEFAULT_POLICY_VERSION.to_string(),
            signer: "operator-prototype".to_string(),
            created_at: format_iso(now),
            valid_from: format_iso(now - chrono::Duration::seconds(60)),
            valid_until: format_iso(now + chrono::Duration::hours(1)),
            min_runtime_version: RUNTIME_MIN_VERSION.to_string(),
            audit_required: true,
            revocation_reference: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Evaluation {
    pub decision: &'static str,
    pub reason: &'static str,
    pub rule: Option<Rule>,
}

pub fn build_policy_body(rules: &[Rule], fields: &PolicyFields) -> Json {
    Json::object([
        ("version", Json::string(&fields.version)),
        ("signer", Json::string(&fields.signer)),
        ("created_at", Json::string(&fields.created_at)),
        ("valid_from", Json::string(&fields.valid_from)),
        ("valid_until", Json::string(&fields.valid_until)),
        (
            "min_runtime_version",
            Json::string(&fields.min_runtime_version),
        ),
        ("audit_required", Json::Bool(fields.audit_required)),
        (
            "revocation_reference",
            Json::string(&fields.revocation_reference),
        ),
        (
            "rules",
            Json::Array(rules.iter().map(rule_to_json).collect()),
        ),
    ])
}

pub fn package_policy(body: &Json, keyring: &KeyRing) -> Result<Json, ProtocolError> {
    let bytes = canonical_bytes(body)?;
    let signature = keyring.sign_policy(&bytes);
    let normalized = loads_strict(std::str::from_utf8(&bytes).map_err(|_| {
        ProtocolError::new("policy body is not valid ASCII after canonicalization")
    })?)?;
    Ok(Json::object([
        ("policy", normalized),
        ("signature", Json::string(signature)),
    ]))
}

fn rule_to_json(rule: &Rule) -> Json {
    Json::object([
        ("principal", Json::string(&rule.principal)),
        ("action", Json::string(&rule.action)),
        (
            "resource_prefix",
            rule.resource_prefix.clone().unwrap_or(Json::Null),
        ),
        ("decision", Json::string(&rule.decision)),
        ("approval_required", Json::Bool(rule.approval_required)),
        ("expiry_limit_seconds", Json::Int(rule.expiry_limit_seconds)),
    ])
}

pub struct PolicyLoader {
    keyring: KeyRing,
    now: Box<dyn Fn() -> f64 + Send + Sync>,
}

impl PolicyLoader {
    pub fn new(keyring: KeyRing) -> Self {
        Self {
            keyring,
            now: Box::new(system_now),
        }
    }

    pub fn with_clock(keyring: KeyRing, now: impl Fn() -> f64 + Send + Sync + 'static) -> Self {
        Self {
            keyring,
            now: Box::new(now),
        }
    }

    pub fn load_and_verify(&self, data: &Json) -> Result<PolicyBundle, ProtocolError> {
        let package = data
            .as_object()
            .ok_or_else(|| ProtocolError::new("policy package must be an object"))?;
        let body = package
            .get("policy")
            .and_then(Json::as_object)
            .ok_or_else(|| ProtocolError::new("policy package must contain body and signature"))?;
        let signature = package
            .get("signature")
            .and_then(Json::as_str)
            .ok_or_else(|| ProtocolError::new("policy package must contain body and signature"))?;

        let body_json = Json::Object(body.clone());
        let body_bytes = canonical_bytes(&body_json)?;
        if !self.keyring.verify_policy(&body_bytes, signature) {
            return Err(ProtocolError::new("policy signature is invalid"));
        }

        let unknown: Vec<&String> = body
            .keys()
            .filter(|key| !BODY_FIELDS.contains(&key.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(ProtocolError::new(format!(
                "unknown policy body fields: {unknown:?}"
            )));
        }

        let version = required_string(body.get("version"), "policy version missing")?;
        let signer = required_string(body.get("signer"), "policy signer missing")?;
        let audit_required = match body.get("audit_required") {
            None => true,
            Some(Json::Bool(true)) => true,
            _ => {
                return Err(ProtocolError::new(
                    "policy must require audit (audit_required=False rejected)",
                ));
            }
        };
        let min_runtime = body.get("min_runtime_version").and_then(Json::as_str);
        if min_runtime != Some(RUNTIME_MIN_VERSION) {
            return Err(ProtocolError::new(
                "policy min_runtime_version is not supported",
            ));
        }
        let rules_data = body
            .get("rules")
            .and_then(|value| match value {
                Json::Array(items) if !items.is_empty() => Some(items),
                _ => None,
            })
            .ok_or_else(|| ProtocolError::new("policy must declare at least one rule"))?;

        let mut rules = Vec::new();
        for (index, rule) in rules_data.iter().enumerate() {
            rules.push(rule_from_json(rule, index)?);
        }
        if !rules
            .iter()
            .any(|rule| rule.approval_required || rule.decision == DECISION_REQUIRE_APPROVAL)
        {
            return Err(ProtocolError::new(
                "policy removes the last human approval gate",
            ));
        }

        let now = (self.now)();
        if !interval_covers(body.get("valid_from"), body.get("valid_until"), now) {
            return Err(ProtocolError::new(
                "policy validity interval does not cover the current time",
            ));
        }

        Ok(PolicyBundle {
            version,
            signer,
            created_at: body
                .get("created_at")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            valid_from: body
                .get("valid_from")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            valid_until: body
                .get("valid_until")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            min_runtime_version: min_runtime.unwrap().to_string(),
            audit_required,
            revocation_reference: body
                .get("revocation_reference")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            rules,
        })
    }

    pub fn load_str(&self, text: &str) -> Result<PolicyBundle, ProtocolError> {
        self.load_and_verify(&loads_strict(text)?)
    }

    pub fn now(&self) -> f64 {
        (self.now)()
    }

    pub fn valid_now(&self, bundle: &PolicyBundle) -> bool {
        let start = Json::string(&bundle.valid_from);
        let end = Json::string(&bundle.valid_until);
        interval_covers(Some(&start), Some(&end), (self.now)())
    }
}

pub struct PolicyEngine {
    pub bundle: PolicyBundle,
}

impl PolicyEngine {
    pub fn new(bundle: PolicyBundle) -> Self {
        Self { bundle }
    }

    pub fn version(&self) -> &str {
        &self.bundle.version
    }

    pub fn valid(&self) -> bool {
        true
    }

    pub fn evaluate(&self, request: &CanonicalRequest) -> Evaluation {
        let mut matches = Vec::new();
        for rule in &self.bundle.rules {
            if rule.principal != "*" && rule.principal != request.principal {
                continue;
            }
            if rule.action != request.action {
                continue;
            }
            if !resource_matches(rule.resource_prefix.as_ref(), &request.resource) {
                continue;
            }
            matches.push(rule);
        }
        if matches.is_empty() {
            return Evaluation {
                decision: DECISION_DENY,
                reason: "denied_policy_no_rule",
                rule: None,
            };
        }
        let effective: BTreeSet<&str> = matches
            .iter()
            .map(|rule| effective_decision(rule))
            .collect();
        if effective.len() != 1 {
            return Evaluation {
                decision: DECISION_DENY,
                reason: "denied_policy_conflict",
                rule: None,
            };
        }
        let decision = *effective.iter().next().expect("one effective decision");
        let rule = matches[0].clone();
        if decision == DECISION_REQUIRE_APPROVAL {
            Evaluation {
                decision: DECISION_REQUIRE_APPROVAL,
                reason: "policy_approval_required",
                rule: Some(rule),
            }
        } else {
            Evaluation {
                decision: DECISION_ALLOW,
                reason: "policy_allowed",
                rule: Some(rule),
            }
        }
    }
}

fn effective_decision(rule: &Rule) -> &'static str {
    if rule.approval_required || rule.decision == DECISION_REQUIRE_APPROVAL {
        DECISION_REQUIRE_APPROVAL
    } else {
        DECISION_ALLOW
    }
}

fn resource_matches(prefix: Option<&Json>, resource: &Json) -> bool {
    let Some(prefix) = prefix else {
        return true;
    };
    let Some(expected_object) = prefix.as_object() else {
        return false;
    };
    let actual_object = resource.as_object();
    for (key, expected) in expected_object {
        if key == "path_prefix" {
            let (Some(expected_path), Some(actual_path)) = (
                expected.as_str(),
                actual_object
                    .and_then(|object| object.get("path"))
                    .and_then(Json::as_str),
            ) else {
                return false;
            };
            if !path_prefix_matches(expected_path, actual_path) {
                return false;
            }
        } else if actual_object.and_then(|object| object.get(key)) != Some(expected) {
            return false;
        }
    }
    true
}

fn rule_from_json(value: &Json, index: usize) -> Result<Rule, ProtocolError> {
    let object = value
        .as_object()
        .ok_or_else(|| ProtocolError::new(format!("rule {index}: invalid principal")))?;
    let unknown: Vec<&String> = object
        .keys()
        .filter(|key| !RULE_FIELDS.contains(&key.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(ProtocolError::new(format!(
            "rule {index}: unknown fields {unknown:?}"
        )));
    }
    let principal = object
        .get("principal")
        .and_then(Json::as_str)
        .unwrap_or("*");
    if principal.is_empty() {
        return Err(ProtocolError::new(format!(
            "rule {index}: invalid principal"
        )));
    }
    let action = object.get("action").and_then(Json::as_str).unwrap_or("");
    if action.is_empty() {
        return Err(ProtocolError::new(format!("rule {index}: invalid action")));
    }
    if !PROTOTYPE_ACTIONS.contains(&action) {
        return Err(ProtocolError::new(format!(
            "rule {index}: action {action:?} is not deployed in this prototype"
        )));
    }
    let decision = object
        .get("decision")
        .and_then(Json::as_str)
        .unwrap_or(DECISION_ALLOW);
    if decision != DECISION_ALLOW && decision != DECISION_REQUIRE_APPROVAL {
        return Err(ProtocolError::new(format!(
            "rule {index}: unsupported decision {decision:?}"
        )));
    }
    let approval_required = match object.get("approval_required") {
        None => false,
        Some(Json::Bool(value)) => *value,
        Some(_) => {
            return Err(ProtocolError::new(format!(
                "rule {index}: invalid approval_required"
            )));
        }
    };
    let expiry = match object.get("expiry_limit_seconds") {
        None => 60,
        Some(Json::Int(value)) if (1..=86_400).contains(value) => *value,
        _ => {
            return Err(ProtocolError::new(format!(
                "rule {index}: invalid expiry_limit_seconds"
            )));
        }
    };
    let resource_prefix = match object.get("resource_prefix") {
        None | Some(Json::Null) => None,
        Some(Json::Object(prefix)) => Some(Json::Object(prefix.clone())),
        Some(_) => {
            return Err(ProtocolError::new(format!(
                "rule {index}: resource_prefix must be an object or null"
            )));
        }
    };
    Ok(Rule {
        principal: principal.to_string(),
        action: action.to_string(),
        resource_prefix,
        decision: decision.to_string(),
        approval_required,
        expiry_limit_seconds: expiry,
    })
}

fn required_string(value: Option<&Json>, message: &str) -> Result<String, ProtocolError> {
    match value.and_then(Json::as_str) {
        Some(text) if !text.is_empty() => Ok(text.to_string()),
        _ => Err(ProtocolError::new(message)),
    }
}

fn interval_covers(start: Option<&Json>, end: Option<&Json>, now: f64) -> bool {
    let (Some(start), Some(end)) = (
        start.and_then(Json::as_str).and_then(parse_iso),
        end.and_then(Json::as_str).and_then(parse_iso),
    ) else {
        return false;
    };
    start <= now && now <= end
}

fn parse_iso(value: &str) -> Option<f64> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(unix_seconds(parsed.with_timezone(&Utc)));
    }
    let naive = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.f")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S"))
        .ok()?;
    Some(unix_seconds(naive.and_utc()))
}

fn unix_seconds(time: DateTime<Utc>) -> f64 {
    time.timestamp() as f64 + f64::from(time.timestamp_subsec_nanos()) / 1_000_000_000.0
}

fn format_iso(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Micros, false)
}

fn system_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
