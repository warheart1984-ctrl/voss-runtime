//! Canonical request envelopes and the normalizer.
//!
//! The adapter may only produce version-1 envelopes. Unknown fields,
//! duplicate keys, malformed resources, unsupported actions, and a principal
//! that does not match the registered worker are rejected before policy
//! evaluation. The approval nonce and expiry are chosen by the trusted
//! controller, never by the worker.

use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

use crate::RUNTIME_PROTOCOL_VERSION;
use crate::canonical::{Json, ProtocolError, new_id, sha256_hex};

pub const WORKSPACE_READ: &str = "workspace.read";
pub const WORKSPACE_WRITE: &str = "workspace.write";
pub const EXTERNAL_SEND_MOCK: &str = "external.send_mock";

const ALLOWED_ENVELOPE_FIELDS: &[&str] = &[
    "version",
    "request_id",
    "session_id",
    "principal",
    "action",
    "resource",
    "payload",
    "constraints",
];

const MAX_ID_LEN: usize = 128;
const MAX_IO_BYTES: i64 = 1_000_000;

#[derive(Clone, Debug, PartialEq)]
pub struct CanonicalRequest {
    pub version: String,
    pub request_id: String,
    pub session_id: String,
    pub principal: String,
    pub action: String,
    pub resource: Json,
    pub payload: Json,
    pub constraints: Json,
    pub payload_digest: String,
    pub nonce: String,
    pub expires_at: f64,
}

impl CanonicalRequest {
    pub fn digest(&self) -> Result<String, ProtocolError> {
        sha256_hex(&Json::object([
            ("version", Json::string(&self.version)),
            ("request_id", Json::string(&self.request_id)),
            ("session_id", Json::string(&self.session_id)),
            ("principal", Json::string(&self.principal)),
            ("action", Json::string(&self.action)),
            ("resource", self.resource.clone()),
            ("payload_digest", Json::string(&self.payload_digest)),
            ("constraints", self.constraints.clone()),
        ]))
    }

    pub fn binding_digest(&self, policy_version: &str) -> Result<String, ProtocolError> {
        if self.nonce.is_empty() || self.expires_at == 0.0 {
            return Err(ProtocolError::new(
                "binding fields (nonce, expiry) are not set",
            ));
        }
        approval_binding_digest(&self.digest()?, policy_version, &self.nonce, self.expires_at)
    }
}

pub fn approval_binding_digest(
    request_digest: &str,
    policy_version: &str,
    nonce: &str,
    expires_at: f64,
) -> Result<String, ProtocolError> {
    sha256_hex(&Json::object([
        ("request", Json::string(request_digest)),
        ("policy_version", Json::string(policy_version)),
        ("nonce", Json::string(nonce)),
        ("expires_at", Json::Float(round_to_6(expires_at))),
    ]))
}

pub fn bind(
    request: &CanonicalRequest,
    nonce: impl Into<String>,
    expires_at: f64,
) -> CanonicalRequest {
    let mut bound = request.clone();
    bound.nonce = nonce.into();
    bound.expires_at = expires_at;
    bound
}

pub fn action_class(action: &str) -> &'static str {
    match action {
        WORKSPACE_READ => "A0",
        WORKSPACE_WRITE => "A1",
        _ => "A2",
    }
}

pub fn proposed_request_id() -> String {
    new_id("req-")
}

pub struct RequestNormalizer {
    workspace_root: PathBuf,
    actions: BTreeSet<String>,
}

impl RequestNormalizer {
    pub fn new(
        workspace_root: impl AsRef<Path>,
        actions: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            workspace_root: os_realpath(workspace_root.as_ref())?,
            actions: actions
                .into_iter()
                .map(|action| action.as_ref().to_string())
                .collect(),
        })
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn normalize(
        &self,
        envelope: &Json,
        expected_principal: &str,
    ) -> Result<CanonicalRequest, ProtocolError> {
        let object = envelope
            .as_object()
            .ok_or_else(|| ProtocolError::new("envelope must be a JSON object"))?;

        let unknown: Vec<&String> = object
            .keys()
            .filter(|key| !ALLOWED_ENVELOPE_FIELDS.contains(&key.as_str()))
            .collect();
        if !unknown.is_empty() {
            return Err(ProtocolError::new(format!(
                "unknown envelope fields: {unknown:?}"
            )));
        }

        let version = object.get("version").and_then(Json::as_str);
        if version != Some(RUNTIME_PROTOCOL_VERSION) {
            return Err(ProtocolError::new("unsupported protocol version"));
        }

        for field in ["request_id", "session_id", "principal"] {
            if !identifier_ok(object.get(field).and_then(Json::as_str)) {
                return Err(ProtocolError::new(format!(
                    "field {field:?} is not a valid identifier"
                )));
            }
        }

        let principal = object.get("principal").and_then(Json::as_str).unwrap_or("");
        if principal != expected_principal {
            return Err(ProtocolError::new(
                "envelope principal does not match the registered worker identity",
            ));
        }

        let action = object.get("action").and_then(Json::as_str).unwrap_or("");
        if action.is_empty() || !self.actions.contains(action) {
            return Err(ProtocolError::new(format!(
                "action is not registered: {action:?}"
            )));
        }

        let resource = object
            .get("resource")
            .and_then(Json::as_object)
            .ok_or_else(|| ProtocolError::new("resource must be an object"))?;
        let payload = object
            .get("payload")
            .filter(|value| value.as_object().is_some())
            .cloned()
            .ok_or_else(|| ProtocolError::new("payload must be an object"))?;
        let constraints = object
            .get("constraints")
            .and_then(Json::as_object)
            .ok_or_else(|| ProtocolError::new("constraints must be an object"))?;

        let resource = self.validate_resource(action, resource)?;
        let constraints = validate_constraints(action, constraints)?;
        let payload_digest = sha256_hex(&payload)?;

        Ok(CanonicalRequest {
            version: version.unwrap().to_string(),
            request_id: object
                .get("request_id")
                .and_then(Json::as_str)
                .unwrap()
                .to_string(),
            session_id: object
                .get("session_id")
                .and_then(Json::as_str)
                .unwrap()
                .to_string(),
            principal: principal.to_string(),
            action: action.to_string(),
            resource,
            payload,
            constraints,
            payload_digest,
            nonce: String::new(),
            expires_at: 0.0,
        })
    }

    pub fn normalize_str(
        &self,
        text: &str,
        expected_principal: &str,
    ) -> Result<CanonicalRequest, ProtocolError> {
        self.normalize(&crate::canonical::loads_strict(text)?, expected_principal)
    }

    fn validate_resource(
        &self,
        action: &str,
        resource: &std::collections::BTreeMap<String, Json>,
    ) -> Result<Json, ProtocolError> {
        if action == WORKSPACE_READ || action == WORKSPACE_WRITE {
            if resource.len() != 1 || !resource.contains_key("path") {
                return Err(ProtocolError::new(
                    "workspace actions require exactly a path resource",
                ));
            }
            let path_value = resource
                .get("path")
                .and_then(Json::as_str)
                .ok_or_else(|| ProtocolError::new("resource path must be a non-empty string"))?;
            let path = resolve_within_root(path_value, &self.workspace_root)?;
            if action == WORKSPACE_READ {
                let metadata = std::fs::metadata(&path).ok();
                if !metadata.is_some_and(|metadata| metadata.is_file()) {
                    return Err(ProtocolError::new("read target is not a regular file"));
                }
            } else if std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_dir()) {
                return Err(ProtocolError::new("write target is a directory"));
            }
            let path_text = path_to_text(&path)?;
            return Ok(Json::object([("path", Json::string(path_text))]));
        }

        if action == EXTERNAL_SEND_MOCK {
            if resource.len() != 2
                || !resource.contains_key("service")
                || !resource.contains_key("recipient")
            {
                return Err(ProtocolError::new(
                    "external action requires service and recipient",
                ));
            }
            if resource.get("service").and_then(Json::as_str) != Some("mail") {
                return Err(ProtocolError::new("unsupported service"));
            }
            let recipient = resource
                .get("recipient")
                .and_then(Json::as_str)
                .unwrap_or("");
            if !mock_email(recipient) {
                return Err(ProtocolError::new(
                    "recipient must be a mock-only email address (@invalid or @test)",
                ));
            }
            return Ok(Json::object([
                ("service", Json::string("mail")),
                ("recipient", Json::string(recipient)),
            ]));
        }

        Err(ProtocolError::new(format!(
            "action has no resource validator: {action}"
        )))
    }
}

pub fn resolve_within_root(
    path_str: &str,
    workspace_root: &Path,
) -> Result<PathBuf, ProtocolError> {
    if path_str.trim().is_empty() {
        return Err(ProtocolError::new(
            "resource path must be a non-empty string",
        ));
    }
    if path_str != path_str.trim() {
        return Err(ProtocolError::new(
            "resource path must not have leading or trailing whitespace",
        ));
    }
    if path_str.contains('\0') {
        return Err(ProtocolError::new(
            "resource path must be a non-empty string",
        ));
    }
    let root = os_realpath(workspace_root)?;
    let candidate = if Path::new(path_str).is_absolute() {
        PathBuf::from(path_str)
    } else {
        root.join(path_str)
    };
    let real = os_realpath(&candidate)?;
    if !contained_within(&real, &root) {
        return Err(ProtocolError::new("resource path escapes the workspace"));
    }
    Ok(real)
}

pub(crate) fn path_prefix_matches(expected: &str, actual: &str) -> bool {
    let Ok(expected_real) = os_realpath(Path::new(expected)) else {
        return false;
    };
    let expected_norm = strip_trailing_sep(&normcase(&expected_real));
    let actual_norm = normcase(Path::new(actual));
    contained_text(&actual_norm, &expected_norm)
}

pub(crate) fn os_realpath(path: &Path) -> Result<PathBuf, ProtocolError> {
    let absolute = std::path::absolute(path)
        .map_err(|error| ProtocolError::new(format!("cannot resolve path: {error}")))?;
    Ok(resolve_existing(&normalize_lexical(&absolute)))
}

fn normalize_lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(out.components().next_back(), Some(Component::Normal(_))) {
                    out.pop();
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn resolve_existing(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return simplify(&canonical);
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name))
            if parent.as_os_str() != path.as_os_str() && !parent.as_os_str().is_empty() =>
        {
            resolve_existing(parent).join(name)
        }
        _ => simplify(path),
    }
}

fn simplify(path: &Path) -> PathBuf {
    let simplified = dunce::simplified(path);
    let text = simplified.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        if let Some(unc) = rest.strip_prefix(r"UNC\") {
            PathBuf::from(format!(r"\\{unc}"))
        } else {
            PathBuf::from(rest.to_string())
        }
    } else {
        simplified.to_path_buf()
    }
}

fn contained_within(path: &Path, root: &Path) -> bool {
    contained_text(&normcase(path), &strip_trailing_sep(&normcase(root)))
}

fn contained_text(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{root}{}", separator()))
}

fn normcase(path: &Path) -> String {
    let mut text = path.to_string_lossy().into_owned();
    if cfg!(windows) {
        text = text.replace('/', "\\").to_lowercase();
    }
    text
}

fn strip_trailing_sep(text: &str) -> String {
    let mut trimmed = text.to_string();
    let sep = separator();
    while trimmed.ends_with(sep) && trimmed.chars().count() > 1 {
        trimmed.pop();
    }
    if trimmed.is_empty() {
        sep.to_string()
    } else {
        trimmed
    }
}

fn separator() -> char {
    if cfg!(windows) { '\\' } else { '/' }
}

fn path_to_text(path: &Path) -> Result<String, ProtocolError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| ProtocolError::new("resource path is not valid Unicode"))
}

fn identifier_ok(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    !value.is_empty()
        && value.len() <= MAX_ID_LEN
        && value.chars().all(|ch| (0x21..=0x7E).contains(&(ch as u32)))
}

fn mock_email(recipient: &str) -> bool {
    let Some((local, domain)) = recipient.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || !local
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '%' | '+' | '-'))
    {
        return false;
    }
    let Some((label, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !label.is_empty()
        && !label.contains('.')
        && label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        && (tld == "invalid" || tld == "test")
}

fn validate_constraints(
    action: &str,
    constraints: &std::collections::BTreeMap<String, Json>,
) -> Result<Json, ProtocolError> {
    let allowed: &[&str] = match action {
        WORKSPACE_READ | WORKSPACE_WRITE => &["size_max"],
        EXTERNAL_SEND_MOCK => &["send_once"],
        _ => {
            return Err(ProtocolError::new(format!(
                "action has no constraint schema: {action}"
            )));
        }
    };
    let unknown: Vec<&String> = constraints
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .collect();
    if !unknown.is_empty() {
        return Err(ProtocolError::new(format!(
            "unknown constraint fields: {unknown:?}"
        )));
    }
    let mut cleaned = Vec::new();
    if action == WORKSPACE_READ || action == WORKSPACE_WRITE {
        if let Some(value) = constraints.get("size_max") {
            let size = value
                .as_i64()
                .ok_or_else(|| ProtocolError::new("constraint 'size_max' has an invalid type"))?;
            if !(1..=MAX_IO_BYTES).contains(&size) {
                return Err(ProtocolError::new("constraint 'size_max' is out of range"));
            }
            cleaned.push(("size_max", Json::Int(size)));
        }
    } else if let Some(value) = constraints.get("send_once") {
        if value.as_bool() != Some(true) {
            return Err(ProtocolError::new(
                "constraint 'send_once' has an invalid value",
            ));
        }
        cleaned.push(("send_once", Json::Bool(true)));
    }
    Ok(Json::object(cleaned))
}

fn round_to_6(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let factor = 1_000_000.0;
    (value * factor).round() / factor
}
