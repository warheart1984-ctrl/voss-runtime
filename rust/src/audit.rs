//! Authenticated append-only audit log.
//!
//! Each record is chained to the previous record with an HMAC-SHA256 tag.
//! The audit key stays in the trusted process. Payloads are stored by
//! digest. A rewritten line fails verification.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::canonical::{Json, ProtocolError, canonical_bytes, loads_strict, new_id, sha256_hex};
use crate::keys::KeyRing;

pub const SCHEMA: &str = "voss.audit.1";
pub const GENESIS: &str = "90dbf1efb2b86d52023ca6d654ab124be2c774c18c3acb1808a07f59940da3e6";
pub const WAL_SCHEMA: &str = "voss.wal.1";

pub fn wal_genesis() -> Result<String, ProtocolError> {
    sha256_hex(&Json::object([("genesis", Json::string("voss-wal-chain"))]))
}

#[derive(Debug)]
pub struct AuditUnavailableError {
    message: String,
}

impl AuditUnavailableError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for AuditUnavailableError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AuditUnavailableError {}

#[derive(Clone, Debug, Default)]
pub struct AuditFields {
    pub worker_id: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub request_digest: Option<String>,
    pub action: Option<String>,
    pub action_class: Option<String>,
    pub policy_version: Option<String>,
    pub decision: Option<String>,
    pub reason_code: Option<String>,
    pub approver_ref: Option<String>,
    pub capability_id: Option<String>,
    pub flow_id: Option<String>,
    pub result: Option<Json>,
    pub error: Option<String>,
    pub outcome: Option<String>,
    pub extra: BTreeMap<String, Json>,
}

struct AuditState {
    file: File,
    last_hash: String,
    closed: bool,
}

pub struct AuditLog {
    path: PathBuf,
    keyring: KeyRing,
    schema: String,
    genesis: String,
    state: Mutex<AuditState>,
}

impl AuditLog {
    pub fn open(path: impl AsRef<Path>, keyring: KeyRing) -> Result<Self, AuditUnavailableError> {
        Self::open_chain(path, keyring, SCHEMA, GENESIS)
    }

    pub fn open_chain(
        path: impl AsRef<Path>,
        keyring: KeyRing,
        schema: &str,
        genesis: &str,
    ) -> Result<Self, AuditUnavailableError> {
        let path = path.as_ref().to_path_buf();
        if schema == WAL_SCHEMA {
            trim_partial_tail(&path);
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                AuditUnavailableError::new(format!("cannot create audit directory: {error}"))
            })?;
        }
        let last_hash = scan_tail(&path, genesis)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| AuditUnavailableError::new(format!("cannot open audit log: {error}")))?;
        Ok(Self {
            path,
            keyring,
            schema: schema.to_string(),
            genesis: genesis.to_string(),
            state: Mutex::new(AuditState {
                file,
                last_hash,
                closed: false,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn healthy(&self) -> bool {
        self.state.lock().map(|state| !state.closed).unwrap_or(false)
    }

    pub fn emit(&self, event_type: &str, fields: AuditFields) -> Result<Json, AuditUnavailableError> {
        let mut payload = Json::object([
            ("schema", Json::string(&self.schema)),
            ("event_id", Json::string(new_id("evt-"))),
            ("ts_utc", stable_timestamp()),
            ("event_type", Json::string(event_type)),
        ]);
        insert_opt(&mut payload, "worker_id", fields.worker_id);
        insert_opt(&mut payload, "session_id", fields.session_id);
        insert_opt(&mut payload, "request_id", fields.request_id);
        insert_opt(&mut payload, "request_digest", fields.request_digest);
        insert_opt(&mut payload, "action", fields.action);
        insert_opt(&mut payload, "action_class", fields.action_class);
        insert_opt(&mut payload, "policy_version", fields.policy_version);
        insert_opt(&mut payload, "decision", fields.decision);
        insert_opt(&mut payload, "reason_code", fields.reason_code);
        insert_opt(&mut payload, "approver_ref", fields.approver_ref);
        insert_opt(&mut payload, "capability_id", fields.capability_id);
        insert_opt(&mut payload, "flow_id", fields.flow_id);
        insert_opt(&mut payload, "error", fields.error);
        insert_opt(&mut payload, "outcome", fields.outcome);
        if let Some(result) = fields.result {
            insert_json(&mut payload, "result", result);
        }
        for (key, value) in fields.extra {
            insert_json(&mut payload, &key, value);
        }

        let payload_bytes = canonical_bytes(&payload).map_err(unavailable)?;
        let mut state = self.state.lock().expect("audit lock");
        if state.closed {
            return Err(AuditUnavailableError::new(
                "audit log is unavailable (fail closed)",
            ));
        }
        let previous = state.last_hash.clone();
        let mut mac_input = previous.clone().into_bytes();
        mac_input.extend_from_slice(&payload_bytes);
        let mac = self.keyring.mac_audit(&mac_input);
        let record_text = String::from_utf8(payload_bytes.clone()).map_err(|error| {
            AuditUnavailableError::new(error.to_string())
        })?;
        let chain_hash = sha256_hex(&Json::object([
            ("prev", Json::string(&previous)),
            ("record", Json::string(record_text)),
        ]))
        .map_err(unavailable)?;
        let line = Json::object([
            ("chain_prev", Json::string(&previous)),
            ("chain_mac", Json::string(&mac)),
            ("chain_hash", Json::string(&chain_hash)),
            ("record", payload.clone()),
        ]);
        let mut encoded = canonical_bytes(&line).map_err(unavailable)?;
        encoded.push(b'\n');
        state.file.write_all(&encoded).map_err(|error| {
            AuditUnavailableError::new(format!("cannot append audit record: {error}"))
        })?;
        state.file.flush().map_err(|error| {
            AuditUnavailableError::new(format!("cannot flush audit record: {error}"))
        })?;
        state.last_hash = chain_hash;
        Ok(line)
    }

    pub fn records(&self) -> Result<Vec<Json>, AuditUnavailableError> {
        let file = File::open(&self.path).map_err(|error| {
            AuditUnavailableError::new(format!("cannot read audit log: {error}"))
        })?;
        let mut records = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = line.map_err(|error| {
                AuditUnavailableError::new(format!("cannot read audit log: {error}"))
            })?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            records.push(loads_strict(line).map_err(unavailable)?);
        }
        Ok(records)
    }

    pub fn verify_integrity(&self) -> bool {
        let Ok(records) = self.records() else {
            return false;
        };
        let mut digest = self.genesis.clone();
        for line in records {
            let Some(previous) = line.get("chain_prev").and_then(Json::as_str) else {
                return false;
            };
            let Some(mac) = line.get("chain_mac").and_then(Json::as_str) else {
                return false;
            };
            let Some(chain) = line.get("chain_hash").and_then(Json::as_str) else {
                return false;
            };
            let Some(payload) = line.get("record") else {
                return false;
            };
            if previous != digest {
                return false;
            }
            let Ok(payload_bytes) = canonical_bytes(payload) else {
                return false;
            };
            let mut mac_input = digest.clone().into_bytes();
            mac_input.extend_from_slice(&payload_bytes);
            if !constant_time_eq(&self.keyring.mac_audit(&mac_input), mac) {
                return false;
            }
            let Ok(record_text) = String::from_utf8(payload_bytes) else {
                return false;
            };
            let Ok(expected_chain) = sha256_hex(&Json::object([
                ("prev", Json::string(&digest)),
                ("record", Json::string(record_text)),
            ])) else {
                return false;
            };
            if chain != expected_chain {
                return false;
            }
            digest = chain.to_string();
        }
        true
    }

    pub fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
        }
    }
}

fn trim_partial_tail(path: &Path) {
    let Ok(raw) = std::fs::read(path) else {
        return;
    };
    if raw.is_empty() {
        return;
    }
    let lines = split_keepends(&raw);
    for (index, raw_line) in lines.iter().enumerate() {
        let trimmed = trim_ascii(raw_line);
        if trimmed.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(trimmed);
        if loads_strict(&text).is_err() {
            if index != lines.len() - 1 {
                return;
            }
            let mut kept = Vec::new();
            for line in &lines[..index] {
                kept.extend_from_slice(line);
            }
            let _ = std::fs::write(path, kept);
            return;
        }
    }
}

fn split_keepends(raw: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'\n' {
            lines.push(&raw[start..=index]);
            start = index + 1;
        } else if raw[index] == b'\r' {
            let end = if index + 1 < raw.len() && raw[index + 1] == b'\n' {
                index + 1
            } else {
                index
            };
            lines.push(&raw[start..=end]);
            index = end;
            start = end + 1;
        }
        index += 1;
    }
    if start < raw.len() {
        lines.push(&raw[start..]);
    }
    lines
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace()).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|byte| !byte.is_ascii_whitespace()).map(|index| index + 1).unwrap_or(start);
    &bytes[start..end]
}

fn scan_tail(path: &Path, genesis: &str) -> Result<String, AuditUnavailableError> {
    if !path.exists() {
        return Ok(genesis.to_string());
    }
    let file = File::open(path).map_err(|error| {
        AuditUnavailableError::new(format!("cannot read audit tail at {}: {error}", path.display()))
    })?;
    let mut digest = genesis.to_string();
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|error| {
            AuditUnavailableError::new(format!("cannot read audit tail: {error}"))
        })?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record = loads_strict(line).map_err(|_| {
            AuditUnavailableError::new(format!("cannot read audit tail at {}", path.display()))
        })?;
        if let Some(chain) = record.get("chain_hash").and_then(Json::as_str) {
            digest = chain.to_string();
        }
    }
    Ok(digest)
}

fn insert_opt(payload: &mut Json, key: &str, value: Option<String>) {
    if let Some(value) = value {
        insert_json(payload, key, Json::string(value));
    }
}

fn insert_json(payload: &mut Json, key: &str, value: Json) {
    if let Json::Object(object) = payload {
        object.insert(key.to_string(), value);
    }
}

fn unavailable(error: ProtocolError) -> AuditUnavailableError {
    AuditUnavailableError::new(error.message())
}

fn stable_timestamp() -> Json {
    let mut value = Json::Float(wall_now());
    for _ in 0..4 {
        let Ok(rendered) = canonical_bytes(&value) else {
            return value;
        };
        let Ok(text) = String::from_utf8(rendered) else {
            return value;
        };
        let Ok(parsed) = loads_strict(&text) else {
            return value;
        };
        let Ok(again) = canonical_bytes(&parsed) else {
            return parsed;
        };
        if again == text.as_bytes() {
            return parsed;
        }
        value = parsed;
    }
    value
}

fn wall_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.bytes().zip(right.bytes()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}
