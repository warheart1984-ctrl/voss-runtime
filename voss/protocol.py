"""Canonical request envelopes (Voss RFC 6.1) and the normalizer.

The model adapter may only produce version %(version)s envelopes; the
normalizer converts them into typed, canonical requests.  Unknown fields,
duplicate keys, malformed resources, unsupported actions, and requests
whose self-asserted principal does not match the registered worker are
rejected before policy evaluation.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Set

from .canonical import ProtocolError, new_id, sha256_hex
from . import RUNTIME_PROTOCOL_VERSION

ALLOWED_ENVELOPE_FIELDS = {
    "version", "request_id", "session_id", "principal",
    "action", "resource", "payload", "constraints",
}

WORKSPACE_ACTIONS = {"workspace.read", "workspace.write"}
EXTERNAL_ACTIONS = {"external.send_mock"}
KNOWN_ACTIONS = WORKSPACE_ACTIONS | EXTERNAL_ACTIONS

_MAX_ID_LEN = 128
_MAX_IO_BYTES = 1_000_000
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.(invalid|test)$")


def _identifier_ok(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if not value or len(value) > _MAX_ID_LEN:
        return False
    return all(0x21 <= ord(ch) <= 0x7E for ch in value)


def _action_class(action: str) -> str:
    if action == "workspace.read":
        return "A0"
    if action == "workspace.write":
        return "A1"
    if action in EXTERNAL_ACTIONS:
        return "A2"
    return "A2"  # unknown actions are still attributed before denial


def action_class(action: str) -> str:
    return _action_class(action)


def resolve_within_root(path_str: Any, workspace_root: str) -> str:
    """Canonicalize a proposed path and require containment in the workspace."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ProtocolError("resource path must be a non-empty string")
    if path_str != path_str.strip():
        raise ProtocolError("resource path must not have leading or trailing whitespace")
    root = os.path.realpath(os.path.abspath(workspace_root))
    candidate = path_str if os.path.isabs(path_str) else os.path.join(root, path_str)
    real = os.path.realpath(os.path.normpath(candidate))
    if not _contained_within(real, root):
        raise ProtocolError("resource path escapes the workspace")
    return real


def _contained_within(path: str, root: str) -> bool:
    folded_path = os.path.normcase(path)
    folded_root = os.path.normcase(root).rstrip(os.sep)
    if not folded_root:
        folded_root = os.path.normcase(root)
    return folded_path == folded_root or folded_path.startswith(folded_root + os.sep)


def _validate_email(recipient: Any) -> str:
    if not isinstance(recipient, str) or not _EMAIL_RE.match(recipient):
        raise ProtocolError("recipient must be a mock-only email address (@invalid or @test)")
    return recipient


@dataclass(frozen=True)
class CanonicalRequest:
    """A validated, typed request. Payload is committed by digest.

    ``nonce`` and ``expires_at`` are chosen by the *trusted* approval
    controller, never by the worker.  ``digest()`` covers everything shown
    to (or claimable by) the worker; ``binding_digest()`` additionally
    binds policy version, nonce, and expiry for human approval.
    """

    version: str
    request_id: str
    session_id: str
    principal: str
    action: str
    resource: Dict[str, Any]
    payload: Dict[str, Any]
    constraints: Dict[str, Any]
    payload_digest: str
    nonce: str = ""
    expires_at: float = 0.0

    def digest(self) -> str:
        return sha256_hex({
            "version": self.version,
            "request_id": self.request_id,
            "session_id": self.session_id,
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "payload_digest": self.payload_digest,
            "constraints": self.constraints,
        })

    def binding_digest(self, policy_version: str) -> str:
        if not self.nonce or not self.expires_at:
            raise ProtocolError("binding fields (nonce, expiry) are not set")
        return sha256_hex({
            "request": self.digest(),
            "policy_version": policy_version,
            "nonce": self.nonce,
            "expires_at": round(self.expires_at, 6),
        })


def bind(cr: CanonicalRequest, nonce: str, expires_at: float) -> CanonicalRequest:
    """Return a copy of ``cr`` carrying the trusted binding fields."""
    return CanonicalRequest(
        version=cr.version,
        request_id=cr.request_id,
        session_id=cr.session_id,
        principal=cr.principal,
        action=cr.action,
        resource=cr.resource,
        payload=cr.payload,
        constraints=cr.constraints,
        payload_digest=cr.payload_digest,
        nonce=nonce,
        expires_at=expires_at,
    )


_CONSTRAINT_SCHEMAS: Dict[str, Dict[str, Any]] = {
    "workspace.read": {"size_max": {"type": int, "max": _MAX_IO_BYTES}},
    "workspace.write": {"size_max": {"type": int, "max": _MAX_IO_BYTES}},
    "external.send_mock": {"send_once": {"value": True}},
}


class RequestNormalizer:
    """Converts a raw envelope into a canonical request, or rejects it."""

    def __init__(self, workspace_root: str, allowlisted_actions: Set[str]):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))
        self.actions = set(allowlisted_actions)

    def normalize(self, envelope: Any, expected_principal: str) -> CanonicalRequest:
        if not isinstance(envelope, dict):
            raise ProtocolError("envelope must be a JSON object")

        unknown = set(envelope) - ALLOWED_ENVELOPE_FIELDS
        if unknown:
            raise ProtocolError(f"unknown envelope fields: {sorted(unknown)}")

        version = envelope.get("version")
        if version != RUNTIME_PROTOCOL_VERSION:
            raise ProtocolError("unsupported protocol version")

        for field in ("request_id", "session_id", "principal"):
            if not _identifier_ok(envelope.get(field)):
                raise ProtocolError(f"field {field!r} is not a valid identifier")

        principal = envelope["principal"]
        if principal != expected_principal:
            raise ProtocolError(
                "envelope principal does not match the registered worker identity"
            )

        action = envelope["action"]
        if not isinstance(action, str) or action not in self.actions:
            raise ProtocolError(f"action is not registered: {action!r}")

        resource = envelope.get("resource")
        payload = envelope.get("payload")
        constraints = envelope.get("constraints")
        if not isinstance(resource, dict):
            raise ProtocolError("resource must be an object")
        if not isinstance(payload, dict):
            raise ProtocolError("payload must be an object")
        if not isinstance(constraints, dict):
            raise ProtocolError("constraints must be an object")

        resource = self._validate_resource(action, resource)
        constraints = self._validate_constraints(action, constraints)
        payload_digest = sha256_hex(payload)

        return CanonicalRequest(
            version=version,
            request_id=envelope["request_id"],
            session_id=envelope["session_id"],
            principal=principal,
            action=action,
            resource=resource,
            payload=payload,
            constraints=constraints,
            payload_digest=payload_digest,
        )

    def _validate_resource(self, action: str, resource: Dict[str, Any]) -> Dict[str, Any]:
        if action in WORKSPACE_ACTIONS:
            if set(resource) != {"path"}:
                raise ProtocolError("workspace actions require exactly a path resource")
            path = resolve_within_root(resource["path"], self.workspace_root)
            if action == "workspace.read":
                if not os.path.isfile(path):
                    raise ProtocolError("read target is not a regular file")
            elif action == "workspace.write":
                if os.path.isdir(path):
                    raise ProtocolError("write target is a directory")
            return {"path": path}

        if action == "external.send_mock":
            if set(resource) != {"service", "recipient"}:
                raise ProtocolError("external action requires service and recipient")
            if resource["service"] != "mail":
                raise ProtocolError("unsupported service")
            return {
                "service": "mail",
                "recipient": _validate_email(resource.get("recipient")),
            }

        raise ProtocolError(f"action has no resource validator: {action}")

    def _validate_constraints(self, action: str, constraints: Dict[str, Any]) -> Dict[str, Any]:
        schema = _CONSTRAINT_SCHEMAS.get(action)
        if schema is None:
            raise ProtocolError(f"action has no constraint schema: {action}")
        unknown = set(constraints) - set(schema)
        if unknown:
            raise ProtocolError(f"unknown constraint fields: {sorted(unknown)}")
        cleaned: Dict[str, Any] = {}
        for key, spec in schema.items():
            if key not in constraints:
                continue
            value = constraints[key]
            if "value" in spec:
                if value != spec["value"]:
                    raise ProtocolError(f"constraint {key!r} has an invalid value")
                cleaned[key] = value
            else:
                if not isinstance(value, spec["type"]) or isinstance(value, bool):
                    raise ProtocolError(f"constraint {key!r} has an invalid type")
                if not (0 < value <= spec["max"]):
                    raise ProtocolError(f"constraint {key!r} is out of range")
                cleaned[key] = value
        return cleaned


def proposed_request_id() -> str:
    """Generate a request identifier for the worker side (envelope id)."""
    return new_id("req-")