//! Trusted key material.
//!
//! These keys stay in the trusted process. They are not placed in a worker
//! environment, model context, tool output, or audit record. HMAC-SHA256 is
//! the authenticated-origin mechanism permitted where origin authentication
//! is required.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;

use crate::canonical::{Json, canonical_bytes, loads_strict};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct KeyRing {
    policy_key: Vec<u8>,
    audit_key: Vec<u8>,
}

impl KeyRing {
    pub fn new(
        policy_secret: impl AsRef<[u8]>,
        audit_secret: impl AsRef<[u8]>,
    ) -> Result<Self, KeyError> {
        let policy_key = policy_secret.as_ref().to_vec();
        let audit_key = audit_secret.as_ref().to_vec();
        if policy_key.is_empty() || audit_key.is_empty() {
            return Err(KeyError::new("key material must be non-empty"));
        }
        Ok(Self {
            policy_key,
            audit_key,
        })
    }

    pub fn load_or_create(directory: impl AsRef<Path>) -> Result<Self, KeyError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory).map_err(|error| {
            KeyError::new(format!("cannot create key directory: {error}"))
        })?;
        let path = directory.join("keys.json");
        for _ in 0..50 {
            if path.is_file() {
                let text = fs::read_to_string(&path).map_err(|error| {
                    KeyError::new(format!("cannot load key store: {error}"))
                })?;
                let value = loads_strict(&text).map_err(|_| {
                    KeyError::new("cannot load key store: invalid key file")
                })?;
                let policy = decode_key(value.get("policy_key"))?;
                let audit = decode_key(value.get("audit_key"))?;
                return Self::new(policy, audit);
            }
            let ring = Self::generate();
            let body = Json::object([
                ("policy_key", Json::string(hex::encode(&ring.policy_key))),
                ("audit_key", Json::string(hex::encode(&ring.audit_key))),
            ]);
            let bytes = canonical_bytes(&body).map_err(|error| KeyError::new(error.message()))?;
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(&bytes).map_err(|error| {
                        KeyError::new(format!("cannot create key store: {error}"))
                    })?;
                    return Ok(ring);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => {
                    return Err(KeyError::new(format!("cannot create key store: {error}")));
                }
            }
        }
        Err(KeyError::new("cannot create key store"))
    }

    pub fn generate() -> Self {
        let mut policy_key = vec![0u8; 32];
        let mut audit_key = vec![0u8; 32];
        getrandom::fill(&mut policy_key)
            .expect("operating system random source is required for keys");
        getrandom::fill(&mut audit_key)
            .expect("operating system random source is required for keys");
        Self {
            policy_key,
            audit_key,
        }
    }

    pub fn sign_policy(&self, policy_bytes: &[u8]) -> String {
        mac_hex(&self.policy_key, policy_bytes)
    }

    pub fn verify_policy(&self, policy_bytes: &[u8], signature: &str) -> bool {
        if signature.len() != 64
            || !signature
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return false;
        }
        constant_time_eq(&self.sign_policy(policy_bytes), signature)
    }

    pub fn mac_audit(&self, payload_bytes: &[u8]) -> String {
        mac_hex(&self.audit_key, payload_bytes)
    }
}

impl fmt::Debug for KeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyRing([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError {
    message: String,
}

impl KeyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for KeyError {}

fn decode_key(value: Option<&Json>) -> Result<Vec<u8>, KeyError> {
    let text = value.and_then(Json::as_str).unwrap_or("");
    if text.is_empty() || !text.len().is_multiple_of(2) {
        return Err(KeyError::new("cannot load key store: missing key"));
    }
    hex::decode(text).map_err(|_| KeyError::new("cannot load key store: invalid key file"))
}

fn mac_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts this key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
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
