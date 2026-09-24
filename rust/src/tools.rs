//! Broker-owned tool executions.
//!
//! Exactly three tools exist: workspace read, workspace write, and a
//! simulated external send. There is no shell, network, or delete tool.
//! Each tool re-checks the canonical path at the execution boundary.
//! File bytes are hashed directly. They are not passed through JSON
//! canonicalization, which would reject newlines.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::canonical::{Json, new_id, sha256_bytes_hex, sha256_hex};
use crate::outbox::{OutboxError, OutboxLink};
use crate::protocol::{CanonicalRequest, os_realpath, resolve_within_root};

const MAX_WORKSPACE_BYTES: i64 = 1_000_000;

#[derive(Debug)]
pub struct ToolFailure {
    message: String,
}

impl ToolFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for ToolFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ToolFailure {}

#[derive(Debug)]
pub struct UncertainOutcome {
    message: String,
}

impl UncertainOutcome {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for UncertainOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for UncertainOutcome {}

pub struct ToolContext {
    workspace_root: PathBuf,
    outbox_dir: PathBuf,
    outbox: Arc<Mutex<Option<Arc<OutboxLink>>>>,
}

impl ToolContext {
    pub fn new(
        workspace_root: impl AsRef<Path>,
        outbox_dir: impl AsRef<Path>,
        outbox: Arc<Mutex<Option<Arc<OutboxLink>>>>,
    ) -> Result<Self, ToolFailure> {
        let workspace_root = os_realpath(workspace_root.as_ref())
            .map_err(|error| ToolFailure::new(error.message()))?;
        let outbox_dir = os_realpath(outbox_dir.as_ref()).or_else(|_| {
            fs::create_dir_all(outbox_dir.as_ref()).ok();
            os_realpath(outbox_dir.as_ref())
        })
        .map_err(|error| ToolFailure::new(error.message()))?;
        fs::create_dir_all(&workspace_root).map_err(|error| ToolFailure::new(error.to_string()))?;
        fs::create_dir_all(&outbox_dir).map_err(|error| ToolFailure::new(error.to_string()))?;
        Ok(Self {
            workspace_root,
            outbox_dir,
            outbox,
        })
    }

    pub fn read(&self, request: &CanonicalRequest) -> Result<Json, ToolFailure> {
        let path = self.workspace_file(request)?;
        let limit = max_bytes(request);
        let bytes = fs::read(&path).map_err(|error| ToolFailure::new(format!("cannot read {}: {error}", path.display())))?;
        if bytes.len() as i64 > limit {
            return Err(ToolFailure::new(format!(
                "file exceeds size constraint ({} > {limit})",
                bytes.len()
            )));
        }
        let content = String::from_utf8(bytes.clone())
            .map_err(|_| ToolFailure::new(format!("cannot read {}: not utf-8", path.display())))?;
        Ok(Json::object([
            ("bytes", Json::Int(bytes.len() as i64)),
            ("sha256", Json::string(sha256_bytes_hex(&bytes))),
            ("content", Json::string(content)),
        ]))
    }

    pub fn write(&self, request: &CanonicalRequest) -> Result<Json, ToolFailure> {
        let path = self.workspace_file(request)?;
        let limit = max_bytes(request);
        let payload = request
            .payload
            .as_object()
            .ok_or_else(|| ToolFailure::new("write content must be a string"))?;
        if payload.keys().any(|key| key != "content") {
            let extra: Vec<&String> = payload.keys().filter(|key| key.as_str() != "content").collect();
            return Err(ToolFailure::new(format!(
                "unexpected write payload fields: {extra:?}"
            )));
        }
        let content = payload
            .get("content")
            .and_then(Json::as_str)
            .unwrap_or("");
        if payload.get("content").is_some_and(|value| value.as_str().is_none()) {
            return Err(ToolFailure::new("write content must be a string"));
        }
        let data = content.as_bytes();
        if data.len() as i64 > limit {
            return Err(ToolFailure::new(format!(
                "content exceeds size constraint ({} > {limit})",
                data.len()
            )));
        }
        let parent = path.parent().unwrap_or(Path::new(""));
        if !contained(parent, &self.workspace_root) {
            return Err(ToolFailure::new("write target escapes the workspace"));
        }
        fs::create_dir_all(parent).map_err(|error| ToolFailure::new(error.to_string()))?;
        let temporary = PathBuf::from(format!("{}.part-{}", path.display(), new_id("")));
        {
            let mut file = fs::File::create(&temporary)
                .map_err(|error| ToolFailure::new(format!("cannot write {}: {error}", path.display())))?;
            file.write_all(data)
                .map_err(|error| ToolFailure::new(format!("cannot write {}: {error}", path.display())))?;
        }
        fs::rename(&temporary, &path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            ToolFailure::new(format!("cannot write {}: {error}", path.display()))
        })?;
        Ok(Json::object([
            ("bytes", Json::Int(data.len() as i64)),
            ("sha256", Json::string(sha256_bytes_hex(data))),
        ]))
    }

    pub fn send_mock(&self, request: &CanonicalRequest) -> Result<Json, ToolError> {
        let resource = request
            .resource
            .as_object()
            .ok_or_else(|| ToolError::Failure(ToolFailure::new("unsupported service")))?;
        if resource.get("service").and_then(Json::as_str) != Some("mail") {
            return Err(ToolError::Failure(ToolFailure::new("unsupported service")));
        }
        let recipient = resource
            .get("recipient")
            .and_then(Json::as_str)
            .ok_or_else(|| ToolError::Failure(ToolFailure::new("invalid recipient")))?;
        let payload = request
            .payload
            .as_object()
            .ok_or_else(|| ToolError::Failure(ToolFailure::new("unexpected send payload fields: []")))?;
        if payload
            .keys()
            .any(|key| key != "subject" && key != "body" && key != "simulate_uncertain")
        {
            return Err(ToolError::Failure(ToolFailure::new("unexpected send payload fields")));
        }
        if payload.get("simulate_uncertain").and_then(Json::as_bool) == Some(true) {
            return Err(ToolError::Uncertain(UncertainOutcome::new(
                "mock delivery outcome is ambiguous",
            )));
        }
        let subject = payload.get("subject").and_then(Json::as_str).unwrap_or("");
        let body = payload.get("body").and_then(Json::as_str).unwrap_or("");
        if let Some(link) = self.outbox.lock().expect("outbox").clone() {
            return deliver_via_accounting(&link, request, recipient, subject, body);
        }
        let effect_id = new_id("effect-");
        let subject_sha = sha256_hex(&Json::object([("subject", Json::string(subject))]))
            .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
        let body_sha = sha256_hex(&Json::object([("body", Json::string(body))]))
            .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
        let recipient_sha = sha256_hex(&Json::object([("recipient", Json::string(recipient))]))
            .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
        let effect = Json::object([
            ("effect_id", Json::string(&effect_id)),
            ("request_id", Json::string(&request.request_id)),
            ("session_id", Json::string(&request.session_id)),
            ("principal", Json::string(&request.principal)),
            ("recipient", Json::string(recipient)),
            ("subject_sha256", Json::string(&subject_sha)),
            ("body_sha256", Json::string(&body_sha)),
            ("delivered_at_utc", Json::Float(wall_now())),
        ]);
        let path = self.outbox_dir.join(format!("{effect_id}.json"));
        let text = canonical_text(&effect).map_err(ToolError::Failure)?;
        fs::write(&path, text).map_err(|error| {
            ToolError::Failure(ToolFailure::new(format!("cannot record external event: {error}")))
        })?;
        Ok(Json::object([
            ("effect_id", Json::string(effect_id)),
            ("recipient_sha256", Json::string(recipient_sha)),
            ("subject_sha256", Json::string(subject_sha)),
            ("body_sha256", Json::string(body_sha)),
            ("delivered", Json::Bool(true)),
        ]))
    }

    fn workspace_file(&self, request: &CanonicalRequest) -> Result<PathBuf, ToolFailure> {
        let path = request
            .resource
            .get("path")
            .and_then(Json::as_str)
            .ok_or_else(|| ToolFailure::new("resource path must be a non-empty string"))?;
        resolve_within_root(path, &self.workspace_root).map_err(|error| ToolFailure::new(error.message()))
    }
}

pub struct ToolRegistry {
    context: ToolContext,
}

impl ToolRegistry {
    pub fn new(context: ToolContext) -> Self {
        Self { context }
    }

    pub fn names(&self) -> Vec<&'static str> {
        vec!["external.send_mock", "workspace.read", "workspace.write"]
    }

    pub fn execute(&self, action: &str, request: &CanonicalRequest) -> Result<Json, ToolError> {
        match action {
            "workspace.read" => self.context.read(request).map_err(ToolError::Failure),
            "workspace.write" => self.context.write(request).map_err(ToolError::Failure),
            "external.send_mock" => self.context.send_mock(request),
            _ => Err(ToolError::Failure(ToolFailure::new(format!(
                "no such tool: {action}"
            )))),
        }
    }
}

pub enum ToolError {
    Failure(ToolFailure),
    Uncertain(UncertainOutcome),
}

impl ToolError {
    pub fn message(&self) -> &str {
        match self {
            Self::Failure(error) => error.message(),
            Self::Uncertain(error) => error.message(),
        }
    }
}

fn deliver_via_accounting(
    link: &OutboxLink,
    request: &CanonicalRequest,
    recipient: &str,
    subject: &str,
    body: &str,
) -> Result<Json, ToolError> {
    let payload_digest = sha256_hex(&Json::object([
        ("body", Json::string(body)),
        ("subject", Json::string(subject)),
    ]))
    .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
    let subject_sha = sha256_hex(&Json::object([("subject", Json::string(subject))]))
        .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
    let body_sha = sha256_hex(&Json::object([("body", Json::string(body))]))
        .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
    let recipient_sha = sha256_hex(&Json::object([("recipient", Json::string(recipient))]))
        .map_err(|error| ToolError::Failure(ToolFailure::new(error.message())))?;
    let ack = match link.deliver(&new_id("dlv-"), "mail", recipient, &payload_digest, &request.request_id) {
        Ok(ack) => ack,
        Err(OutboxError::Uncertain(message)) => {
            return Err(ToolError::Uncertain(UncertainOutcome::new(format!(
                "external delivery sent but never acknowledged: {message}"
            ))));
        }
        Err(OutboxError::Unavailable(message)) => {
            return Err(ToolError::Failure(ToolFailure::new(format!(
                "external accounting service unavailable: {message}"
            ))));
        }
    };
    Ok(Json::object([
        ("accounting", Json::string("outbox-service")),
        ("body_sha256", Json::string(body_sha)),
        ("delivered", Json::Bool(true)),
        ("receipt_id", Json::string(ack.receipt_id)),
        ("recipient_sha256", Json::string(recipient_sha)),
        ("subject_sha256", Json::string(subject_sha)),
    ]))
}

fn max_bytes(request: &CanonicalRequest) -> i64 {
    request
        .constraints
        .get("size_max")
        .and_then(Json::as_i64)
        .unwrap_or(MAX_WORKSPACE_BYTES)
}

fn contained(path: &Path, root: &Path) -> bool {
    let path = norm(path);
    let root = norm(root).trim_end_matches('\\').trim_end_matches('/').to_string();
    path == root || path.starts_with(&format!("{root}\\")) || path.starts_with(&format!("{root}/"))
}

fn norm(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

fn canonical_text(value: &Json) -> Result<Vec<u8>, ToolFailure> {
    crate::canonical::canonical_bytes(value).map_err(|error| ToolFailure::new(error.message()))
}

fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::CanonicalRequest;

    fn write_request(content: &str) -> CanonicalRequest {
        CanonicalRequest {
            version: "1".to_string(),
            request_id: "req".to_string(),
            session_id: "sess".to_string(),
            principal: "worker".to_string(),
            action: "workspace.write".to_string(),
            resource: Json::object([("path", Json::string("notes.txt"))]),
            payload: Json::object([("content", Json::string(content))]),
            constraints: Json::empty_object(),
            payload_digest: String::new(),
            nonce: "nonce".to_string(),
            expires_at: 0.0,
        }
    }

    #[test]
    fn replacing_a_workspace_file_keeps_the_new_bytes() {
        let root = std::env::temp_dir().join(format!("voss-write-{}", new_id("")));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let outbox = root.join("outbox");
        fs::create_dir_all(&outbox).unwrap();
        let context = ToolContext::new(&root, &outbox, Arc::new(Mutex::new(None))).unwrap();
        context.write(&write_request("old")).unwrap();
        context.write(&write_request("new")).unwrap();
        let text = fs::read_to_string(root.join("notes.txt")).unwrap();
        assert_eq!(text, "new");
        let _ = fs::remove_dir_all(&root);
    }
}
