//! Authenticated adapter-to-host channel.
//!
//! Both sides share this protocol. The MAC covers the canonical body with a
//! per-spawn key that arrives in a one-time bootstrap file. The key never
//! rides in an environment variable whose name looks like a secret. This
//! module imports nothing privileged, so the untrusted worker can use it to
//! verify the host as well as to sign its own proposals.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::canonical::{Json, canonical_bytes, json_number, loads_strict};

type HmacSha256 = Hmac<Sha256>;

pub const SCHEMA: &str = "voss.chan.v1";
pub const MAX_LINE: usize = 65536;

const ADAPTER_TO_HOST: &[&str] = &["hello", "proposal", "goodbye_ok"];
const HOST_TO_ADAPTER: &[&str] = &["hello_ok", "prompt", "denied"];
const DIR_ADAPTER: &str = "a2h";
const DIR_HOST: &str = "h2a";

#[derive(Debug)]
pub struct ChannelError {
    pub reason_code: String,
}

impl ChannelError {
    pub fn new(reason_code: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.into(),
        }
    }

    pub fn code(&self) -> &str {
        &self.reason_code
    }
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason_code)
    }
}

pub struct ChannelSession {
    key: Vec<u8>,
    sid: String,
    peer_dir: &'static str,
    send_dir: &'static str,
    allowed_send: &'static [&'static str],
    allowed_peer: &'static [&'static str],
    send_seq: i64,
    recv_seq: i64,
}

impl ChannelSession {
    pub fn new(key: Vec<u8>, sid: impl Into<String>, role: &str) -> Result<Self, ChannelError> {
        let (peer_dir, send_dir, allowed_send, allowed_peer) = match role {
            "host" => (DIR_ADAPTER, DIR_HOST, HOST_TO_ADAPTER, ADAPTER_TO_HOST),
            "adapter" => (DIR_HOST, DIR_ADAPTER, ADAPTER_TO_HOST, HOST_TO_ADAPTER),
            _ => return Err(ChannelError::new("denied_channel_auth")),
        };
        Ok(Self {
            key,
            sid: sid.into(),
            peer_dir,
            send_dir,
            allowed_send,
            allowed_peer,
            send_seq: 0,
            recv_seq: 1,
        })
    }

    pub fn send(&mut self, msg_type: &str, msg: &Json) -> Result<String, ChannelError> {
        if !self.allowed_send.contains(&msg_type) {
            return Err(ChannelError::new("denied_channel_wrong_direction"));
        }
        self.send_seq += 1;
        wire_line(&self.key, &self.sid, self.send_dir, self.send_seq, msg_type, msg)
    }

    pub fn receive(&mut self, text: &str) -> Result<(String, Json), ChannelError> {
        let (body, wire_mac) = parse_wire(text)?;
        if body.get("chan").and_then(Json::as_str) != Some(SCHEMA) {
            return Err(ChannelError::new("denied_channel_auth"));
        }
        if body.get("sid").and_then(Json::as_str) != Some(self.sid.as_str()) {
            return Err(ChannelError::new("denied_channel_bad_session"));
        }
        if body.get("dir").and_then(Json::as_str) != Some(self.peer_dir) {
            return Err(ChannelError::new("denied_channel_wrong_direction"));
        }
        let Some(seq) = json_i64(body.get("seq")) else {
            return Err(ChannelError::new("denied_channel_auth"));
        };
        let Some(msg_type) = body.get("type").and_then(Json::as_str) else {
            return Err(ChannelError::new("denied_channel_wrong_direction"));
        };
        if !self.allowed_peer.contains(&msg_type) {
            return Err(ChannelError::new("denied_channel_wrong_direction"));
        }
        let Some(msg) = body.get("msg").filter(|value| matches!(value, Json::Object(_))) else {
            return Err(ChannelError::new("denied_channel_auth"));
        };
        let expected = mac_hex(&self.key, &body)?;
        if !constant_time_eq(&expected, &wire_mac) {
            return Err(ChannelError::new("denied_channel_auth"));
        }
        if seq < self.recv_seq {
            return Err(ChannelError::new("denied_channel_replay"));
        }
        if seq > self.recv_seq {
            return Err(ChannelError::new("denied_channel_sequence"));
        }
        self.recv_seq += 1;
        Ok((msg_type.to_string(), msg.clone()))
    }
}

pub fn wire_line(
    key: &[u8],
    sid: &str,
    direction: &str,
    seq: i64,
    msg_type: &str,
    msg: &Json,
) -> Result<String, ChannelError> {
    let body = Json::object([
        ("chan", Json::string(SCHEMA)),
        ("sid", Json::string(sid)),
        ("dir", Json::string(direction)),
        ("seq", Json::Int(seq)),
        ("type", Json::string(msg_type)),
        ("msg", msg.clone()),
    ]);
    let mac = mac_hex(key, &body)?;
    let record = Json::object([("mac", Json::string(mac)), ("body", body)]);
    let bytes = canonical_bytes(&record).map_err(|_| ChannelError::new("denied_channel_auth"))?;
    String::from_utf8(bytes).map_err(|_| ChannelError::new("denied_channel_auth"))
}

pub fn chan_bootstrap(key: &[u8], sid: &str) -> Json {
    Json::object([
        ("v", Json::Int(1)),
        ("schema", Json::string(SCHEMA)),
        ("sid", Json::string(sid)),
        ("key_hex", Json::string(hex::encode(key))),
        ("issued_at", issued_at()),
    ])
}

pub fn read_bootstrap(text: &str) -> Result<(Vec<u8>, String), ChannelError> {
    let data = loads_strict(text).map_err(|_| ChannelError::new("denied_channel_bootstrap"))?;
    let version_ok = matches!(data.get("v"), Some(Json::Int(1)) | Some(Json::Uint(1)));
    let schema_ok = data.get("schema").and_then(Json::as_str) == Some(SCHEMA);
    let sid = data.get("sid").and_then(Json::as_str).unwrap_or("");
    let key_hex = data.get("key_hex").and_then(Json::as_str).unwrap_or("");
    if !version_ok || !schema_ok || sid.is_empty() {
        return Err(ChannelError::new("denied_channel_bootstrap"));
    }
    let key = hex::decode(key_hex).map_err(|_| ChannelError::new("denied_channel_bootstrap"))?;
    if key.len() < 16 {
        return Err(ChannelError::new("denied_channel_bootstrap"));
    }
    Ok((key, sid.to_string()))
}

pub fn consume_bootstrap(path: &Path) -> Result<(Vec<u8>, String), ChannelError> {
    let text = fs::read_to_string(path).map_err(|_| ChannelError::new("denied_channel_bootstrap"))?;
    let _ = fs::remove_file(path);
    read_bootstrap(&text)
}

fn issued_at() -> Json {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    json_number(seconds)
}

fn parse_wire(text: &str) -> Result<(Json, String), ChannelError> {
    let line = loads_strict(text).map_err(|_| ChannelError::new("denied_channel_auth"))?;
    let Some(body) = line.get("body").filter(|value| matches!(value, Json::Object(_))) else {
        return Err(ChannelError::new("denied_channel_auth"));
    };
    let Some(wire_mac) = line.get("mac").and_then(Json::as_str) else {
        return Err(ChannelError::new("denied_channel_auth"));
    };
    Ok((body.clone(), wire_mac.to_string()))
}

fn mac_hex(key: &[u8], body: &Json) -> Result<String, ChannelError> {
    let bytes = canonical_bytes(body).map_err(|_| ChannelError::new("denied_channel_auth"))?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| ChannelError::new("denied_channel_auth"))?;
    mac.update(&bytes);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn json_i64(value: Option<&Json>) -> Option<i64> {
    match value {
        Some(Json::Int(number)) => Some(*number),
        Some(Json::Uint(number)) if *number <= i64::MAX as u64 => Some(*number as i64),
        _ => None,
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}
