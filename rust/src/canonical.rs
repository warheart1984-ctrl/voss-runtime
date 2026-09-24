//! Strict JSON parsing and canonical serialization.
//!
//! Hashes, policy signatures, and approval bindings are computed over one
//! ASCII byte representation: object keys sorted by Unicode code point,
//! compact separators, and non-ASCII characters escaped as `\uXXXX`.
//! Duplicate keys, trailing data, and non-finite numbers are rejected.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    message: String,
}

impl ProtocolError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    String(String),
    Array(Vec<Json>),
    Object(BTreeMap<String, Json>),
}

impl PartialEq for Json {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(left), Self::Bool(right)) => left == right,
            (Self::Int(left), Self::Int(right)) => left == right,
            (Self::Uint(left), Self::Uint(right)) => left == right,
            (Self::Int(left), Self::Uint(right)) => *left >= 0 && *left as u64 == *right,
            (Self::Uint(left), Self::Int(right)) => *right >= 0 && *left == *right as u64,
            (Self::Float(left), Self::Float(right)) => left.to_bits() == right.to_bits(),
            (Self::String(left), Self::String(right)) => left == right,
            (Self::Array(left), Self::Array(right)) => left == right,
            (Self::Object(left), Self::Object(right)) => left == right,
            _ => false,
        }
    }
}

impl Json {
    pub fn empty_object() -> Self {
        Self::Object(BTreeMap::new())
    }

    pub fn object<I, K>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, Json)>,
        K: Into<String>,
    {
        let mut object = BTreeMap::new();
        for (key, value) in pairs {
            object.insert(key.into(), value);
        }
        Self::Object(object)
    }

    pub fn string(value: impl AsRef<str>) -> Self {
        Self::String(value.as_ref().to_string())
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Self::Object(object) => Some(object),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(value) => Some(*value),
            Self::Uint(value) if *value <= i64::MAX as u64 => Some(*value as i64),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(value) => Some(*value),
            Self::Int(value) => Some(*value as f64),
            Self::Uint(value) => Some(*value as f64),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|object| object.get(key))
    }
}

pub fn loads_strict(text: &str) -> Result<Json, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let value = Json::deserialize(&mut deserializer).map_err(map_decode_error)?;
    deserializer.end().map_err(map_decode_error)?;
    Ok(value)
}

fn map_decode_error(error: serde_json::Error) -> ProtocolError {
    let message = error.to_string();
    if let Some(start) = message.find("duplicate key in JSON object:") {
        let detail = message[start..]
            .split(" at line")
            .next()
            .unwrap_or(message.as_str());
        return ProtocolError::new(detail.trim());
    }
    if message.contains("NaN") || message.contains("Infinity") || message.contains("non-finite") {
        return ProtocolError::new("non-finite constants are not allowed");
    }
    ProtocolError::new(format!("invalid JSON: {message}"))
}

pub fn canonical_bytes(value: &Json) -> Result<Vec<u8>, ProtocolError> {
    let mut out = String::new();
    write_canonical(&mut out, value)?;
    Ok(out.into_bytes())
}

/// A finite number rounded to 6 decimal places, then parsed back so a later
/// canonicalization of the same value does not change the text.
pub fn json_number(value: f64) -> Json {
    let rounded = if value.is_finite() {
        (value * 1_000_000.0).round() / 1_000_000.0
    } else {
        0.0
    };
    let mut current = Json::Float(rounded);
    for _ in 0..4 {
        let Ok(rendered) = canonical_bytes(&current) else {
            return current;
        };
        let Ok(text) = String::from_utf8(rendered.clone()) else {
            return current;
        };
        let Ok(parsed) = loads_strict(&text) else {
            return current;
        };
        let Ok(again) = canonical_bytes(&parsed) else {
            return parsed;
        };
        if again == rendered {
            return parsed;
        }
        current = parsed;
    }
    current
}

pub fn sha256_hex(value: &Json) -> Result<String, ProtocolError> {
    Ok(sha256_bytes_hex(&canonical_bytes(value)?))
}

pub fn sha256_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .expect("operating system random source is required for identifiers");
    format!("{prefix}{}", hex::encode(bytes))
}

fn write_canonical(out: &mut String, value: &Json) -> Result<(), ProtocolError> {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(value) => out.push_str(&value.to_string()),
        Json::Uint(value) => out.push_str(&value.to_string()),
        Json::Float(value) => out.push_str(&format_python_float(*value)?),
        Json::String(value) => write_string(out, value)?,
        Json::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(out, item)?;
            }
            out.push(']');
        }
        Json::Object(object) => {
            out.push('{');
            for (index, (key, item)) in object.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, key)?;
                out.push(':');
                write_canonical(out, item)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_string(out: &mut String, value: &str) -> Result<(), ProtocolError> {
    if value.chars().any(|ch| (ch as u32) < 0x20) {
        return Err(ProtocolError::new(
            "control characters are not allowed in strings",
        ));
    }
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if !ch.is_ascii() => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
    Ok(())
}

fn format_python_float(value: f64) -> Result<String, ProtocolError> {
    if !value.is_finite() {
        return Err(ProtocolError::new("non-finite floats are not allowed"));
    }
    if value == 0.0 {
        return Ok(if value.is_sign_negative() {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        });
    }
    let mut buffer = ryu::Buffer::new();
    Ok(pythonize_ryu(buffer.format_finite(value)))
}

fn pythonize_ryu(raw: &str) -> String {
    let (negative, digits, exp10) = decompose_ryu(raw);
    if digits == "0" {
        return if negative {
            "-0.0".to_string()
        } else {
            "0.0".to_string()
        };
    }
    let scientific = exp10 + digits.len() as i32 - 1;
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    if !(-4..16).contains(&scientific) {
        out.push(digits.as_bytes()[0] as char);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        if scientific >= 0 {
            out.push_str(&format!("e+{scientific:02}"));
        } else {
            out.push_str(&format!("e-{:02}", scientific.abs()));
        }
        return out;
    }
    if scientific >= 0 {
        let integer_len = scientific as usize + 1;
        if digits.len() <= integer_len {
            out.push_str(&digits);
            out.extend(std::iter::repeat_n('0', integer_len - digits.len()));
            out.push_str(".0");
        } else {
            out.push_str(&digits[..integer_len]);
            out.push('.');
            out.push_str(&digits[integer_len..]);
        }
        return out;
    }
    let zeros = (-scientific - 1) as usize;
    out.push_str("0.");
    out.extend(std::iter::repeat_n('0', zeros));
    out.push_str(&digits);
    out
}

fn decompose_ryu(raw: &str) -> (bool, String, i32) {
    let (negative, rest) = match raw.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, raw),
    };
    let (coefficient, exponent) = if let Some((coefficient, exponent)) = rest.split_once('e') {
        (coefficient, exponent.parse::<i32>().unwrap_or(0))
    } else if let Some((coefficient, exponent)) = rest.split_once('E') {
        (coefficient, exponent.parse::<i32>().unwrap_or(0))
    } else {
        (rest, 0)
    };
    let (whole, fraction) = match coefficient.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (coefficient, ""),
    };
    let mut digits = String::new();
    digits.push_str(whole);
    digits.push_str(fraction);
    let mut exp10 = exponent - fraction.len() as i32;
    let leading = digits.bytes().take_while(|byte| *byte == b'0').count();
    if leading == digits.len() {
        return (negative, "0".to_string(), 0);
    }
    digits = digits[leading..].to_string();
    let trailing = digits
        .bytes()
        .rev()
        .take_while(|byte| *byte == b'0')
        .count();
    if trailing > 0 {
        digits.truncate(digits.len() - trailing);
        exp10 += trailing as i32;
    }
    (negative, digits, exp10)
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Json::Int(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        if value <= i64::MAX as u64 {
            Ok(Json::Int(value as i64))
        } else {
            Ok(Json::Uint(value))
        }
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
        if !value.is_finite() {
            return Err(de::Error::custom("non-finite constants are not allowed"));
        }
        Ok(Json::Float(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Json::String(value.to_string()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        Ok(Json::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Json::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(Json::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Json>()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut object = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!(
                    "duplicate key in JSON object: {}",
                    python_repr(&key)
                )));
            }
            let value = map.next_value::<Json>()?;
            object.insert(key, value);
        }
        Ok(Json::Object(object))
    }
}

fn python_repr(value: &str) -> String {
    if value.contains('\'') || value.contains('\\') {
        format!("{value:?}")
    } else {
        format!("'{value}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_matches_the_python_prototype() {
        let object = loads_strict(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(canonical_bytes(&object).unwrap(), br#"{"a":2,"b":1}"#);

        let nested = loads_strict(r#"{"nested":{"z":true,"a":null},"arr":[1,"x",false]}"#).unwrap();
        assert_eq!(
            canonical_bytes(&nested).unwrap(),
            br#"{"arr":[1,"x",false],"nested":{"a":null,"z":true}}"#
        );

        assert_eq!(
            canonical_bytes(&Json::string("cafe \u{00e9}")).unwrap(),
            br#""cafe \u00e9""#
        );
        assert_eq!(
            canonical_bytes(&Json::string("\u{2603}")).unwrap(),
            br#""\u2603""#
        );
        assert_eq!(
            canonical_bytes(&Json::string("\u{1F600}")).unwrap(),
            br#""\ud83d\ude00""#
        );

        let numbers = loads_strict(r#"{"e":1e-06,"f":1.0,"g":0.1,"h":1.5}"#).unwrap();
        assert_eq!(
            canonical_bytes(&numbers).unwrap(),
            br#"{"e":1e-06,"f":1.0,"g":0.1,"h":1.5}"#
        );
        assert_eq!(
            canonical_bytes(&loads_strict("1e16").unwrap()).unwrap(),
            b"1e+16"
        );
        assert_eq!(
            canonical_bytes(&loads_strict("1e15").unwrap()).unwrap(),
            b"1000000000000000.0"
        );
        assert_eq!(
            canonical_bytes(&loads_strict("1.23e-10").unwrap()).unwrap(),
            b"1.23e-10"
        );
        assert_eq!(
            canonical_bytes(&loads_strict("1.5e20").unwrap()).unwrap(),
            b"1.5e+20"
        );
        assert_eq!(
            sha256_hex(&loads_strict(r#"{"version":"1","request_id":"req-1"}"#).unwrap()).unwrap(),
            "c10fccfc22af86a59ba14a8bd20ae3d04c2ee19b12863a80b408a560d1545152"
        );
        assert_eq!(
            sha256_hex(&Json::empty_object()).unwrap(),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }

    #[test]
    fn duplicate_keys_and_controls_are_rejected() {
        let error = loads_strict(r#"{"a":1,"a":2}"#).unwrap_err();
        assert!(error.message().contains("duplicate key"));
        let error = canonical_bytes(&Json::string("bad\nvalue")).unwrap_err();
        assert!(error.message().contains("control characters"));
    }
}
