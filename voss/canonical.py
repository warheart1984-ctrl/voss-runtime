"""Strict JSON parsing and canonical serialization (Voss RFC 6.1, 6.3).

The broker, policy engine, approval flow, and audit all serialize through
here so that hashes, bindings, and MACs are computed over one canonical
byte representation.  Unknown fields, duplicate keys, control characters,
and non-finite numbers are rejected rather than silently normalized.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, List, Tuple


class ProtocolError(ValueError):
    """A rejected encoding, envelope, or canonicalization."""


def _no_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError(f"duplicate key in JSON object: {key!r}")
        result[key] = value
    return result


def loads_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate keys and non-finite constants."""
    if not isinstance(text, str):
        raise ProtocolError("payload must be a JSON string")

    def _reject_constant(_value: str) -> Any:
        raise ProtocolError("non-finite constants are not allowed")

    try:
        return json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc


def _normalize(value: Any) -> Any:
    """Return an ordered, JSON-only representation or raise."""
    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError(f"non-string object key: {key!r}")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, str):
        if any(ord(ch) < 0x20 for ch in value):
            raise ProtocolError("control characters are not allowed in strings")
        return value
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):  # NaN / inf
            raise ProtocolError("non-finite floats are not allowed")
        return value
    raise ProtocolError(f"value type not allowed in canonical form: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Deterministic UTF-8/ASCII byte serialization of a JSON value."""
    normalized = _normalize(value)
    try:
        return json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"cannot canonicalize value: {exc}") from exc


def sha256_hex(value: Any) -> str:
    """SHA-256 digest over the canonical bytes of a JSON value."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def new_id(prefix: str = "") -> str:
    """Cryptographically random identifier; never supplied or chosen by the model."""
    return f"{prefix}{secrets.token_hex(16)}"