"""Signed policy bundles and the default-deny policy engine (Voss RFC 4).

A capability is granted only when a signed policy bundle explicitly
permits the principal, action, and resource within the validity interval.
Missing, malformed, expired, unsigned, or conflicting policy is a denial.
The model and worker never possess the policy signing key.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .canonical import ProtocolError, canonical_bytes, loads_strict
from .keys import KeyRing
from .protocol import CanonicalRequest

RUNTIME_MIN_VERSION = "1"
DEFAULT_POLICY_VERSION = "1.0.0"

DECISION_ALLOW = "ALLOW"
DECISION_REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
DECISION_DENY = "DENY"

_ALLOWED_DECISIONS = {DECISION_ALLOW, DECISION_REQUIRE_APPROVAL}
_BODY_FIELDS = {
    "version", "signer", "created_at", "valid_from", "valid_until",
    "min_runtime_version", "audit_required", "revocation_reference", "rules",
}
_RULE_FIELDS = {
    "principal", "action", "resource_prefix", "decision",
    "approval_required", "expiry_limit_seconds",
}


@dataclass(frozen=True)
class Rule:
    principal: str = "*"                       # exact worker principal or "*"
    action: str = ""
    resource_prefix: Optional[Dict[str, Any]] = None
    decision: str = DECISION_ALLOW
    approval_required: bool = False
    expiry_limit_seconds: int = 60


@dataclass
class PolicyBundle:
    version: str
    signer: str
    created_at: str
    valid_from: str
    valid_until: str
    min_runtime_version: str
    audit_required: bool
    revocation_reference: str
    rules: List[Rule] = field(default_factory=list)


class PolicyLoadError(ProtocolError):
    pass


def rule_to_dict(rule: Rule) -> Dict[str, Any]:
    prefix = rule.resource_prefix
    return {
        "principal": rule.principal,
        "action": rule.action,
        "resource_prefix": prefix,
        "decision": rule.decision,
        "approval_required": bool(rule.approval_required),
        "expiry_limit_seconds": int(rule.expiry_limit_seconds),
    }


def build_policy_body(
    rules: Sequence[Rule],
    *,
    version: str = DEFAULT_POLICY_VERSION,
    signer: str = "operator-prototype",
    created_at: Optional[str] = None,
    valid_from: Optional[str] = None,
    valid_until: Optional[str] = None,
    min_runtime_version: str = RUNTIME_MIN_VERSION,
    audit_required: bool = True,
    revocation_reference: str = "",
) -> Dict[str, Any]:
    from datetime import datetime, timedelta, timezone

    now = datetime.now(timezone.utc)
    created_at = created_at or now.isoformat()
    valid_from = valid_from or (now - timedelta(seconds=60)).isoformat()
    valid_until = valid_until or (now + timedelta(hours=1)).isoformat()
    return {
        "version": version,
        "signer": signer,
        "created_at": created_at,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "min_runtime_version": min_runtime_version,
        "audit_required": bool(audit_required),
        "revocation_reference": revocation_reference,
        "rules": [rule_to_dict(r) for r in rules],
    }


def package_policy(body: Dict[str, Any], keyring: KeyRing) -> Dict[str, Any]:
    """Sign the canonical policy body with the Operator key."""
    body_bytes = canonical_bytes(body)
    return {
        "policy": loads_strict(canonical_bytes(body).decode("ascii")),
        "signature": keyring.sign_policy(body_bytes),
    }


def _rule_from_dict(data: Dict[str, Any], index: int) -> Rule:
    unknown = set(data) - _RULE_FIELDS
    if unknown:
        raise PolicyLoadError(f"rule {index}: unknown fields {sorted(unknown)}")
    principal = data.get("principal", "*")
    action = data.get("action")
    if not isinstance(principal, str) or not principal:
        raise PolicyLoadError(f"rule {index}: invalid principal")
    if not isinstance(action, str) or not action:
        raise PolicyLoadError(f"rule {index}: invalid action")
    decision = data.get("decision", DECISION_ALLOW)
    if decision not in _ALLOWED_DECISIONS:
        raise PolicyLoadError(f"rule {index}: unsupported decision {decision!r}")
    approval_required = bool(data.get("approval_required", False))
    expiry = data.get("expiry_limit_seconds", 60)
    if not isinstance(expiry, int) or isinstance(expiry, bool) or not (1 <= expiry <= 86400):
        raise PolicyLoadError(f"rule {index}: invalid expiry_limit_seconds")
    prefix = data.get("resource_prefix")
    if prefix is not None and not isinstance(prefix, dict):
        raise PolicyLoadError(f"rule {index}: resource_prefix must be an object or null")
    if action not in ("workspace.read", "workspace.write", "external.send_mock"):
        # The prototype only ships these action classes; anything else in a
        # signed bundle would represent tooling that does not exist here.
        raise PolicyLoadError(f"rule {index}: action {action!r} is not deployed in this prototype")
    return Rule(
        principal=principal,
        action=action,
        resource_prefix=dict(prefix) if prefix else None,
        decision=decision,
        approval_required=approval_required,
        expiry_limit_seconds=expiry,
    )


class PolicyLoader:
    """Loads, verifies, and performs integrity checks on a policy bundle."""

    def __init__(self, keyring: KeyRing, now: Optional[float] = None):
        self._keyring = keyring
        self._now_func = now or (lambda: __import__("time").time())

    def load_and_verify(self, data: Any) -> PolicyBundle:
        if not isinstance(data, dict):
            raise PolicyLoadError("policy package must be an object")
        body = data.get("policy")
        signature = data.get("signature")
        if not isinstance(body, dict) or not isinstance(signature, str):
            raise PolicyLoadError("policy package must contain body and signature")

        body_bytes = canonical_bytes(body)
        if not self._keyring.verify_policy(body_bytes, signature):
            raise PolicyLoadError("policy signature is invalid")

        unknown = set(body) - _BODY_FIELDS
        if unknown:
            raise PolicyLoadError(f"unknown policy body fields: {sorted(unknown)}")

        version = body.get("version")
        signer = body.get("signer")
        audit_required = body.get("audit_required", True)
        min_runtime = body.get("min_runtime_version")
        rules_data = body.get("rules")

        if not isinstance(version, str) or not version:
            raise PolicyLoadError("policy version missing")
        if not isinstance(signer, str) or not signer:
            raise PolicyLoadError("policy signer missing")
        if audit_required is not True:
            raise PolicyLoadError("policy must require audit (audit_required=False rejected)")
        if min_runtime != RUNTIME_MIN_VERSION:
            raise PolicyLoadError("policy min_runtime_version is not supported")
        if not isinstance(rules_data, list) or not rules_data:
            raise PolicyLoadError("policy must declare at least one rule")

        rules = [_rule_from_dict(r, i) for i, r in enumerate(rules_data)]

        # Human control path: at least one conditional action must exist that
        # requires human approval.  A bundle that removes the last approval
        # gate is rejected (RFC 4.3 / Binding 8.1).
        if not any(r.approval_required or r.decision == DECISION_REQUIRE_APPROVAL for r in rules):
            raise PolicyLoadError("policy removes the last human approval gate")

        now = self._now_func()
        if not self._iso_within(body.get("valid_from"), body.get("valid_until"), now):
            raise PolicyLoadError("policy validity interval does not cover the current time")

        return PolicyBundle(
            version=version,
            signer=signer,
            created_at=body.get("created_at", ""),
            valid_from=body.get("valid_from", ""),
            valid_until=body.get("valid_until", ""),
            min_runtime_version=min_runtime,
            audit_required=True,
            revocation_reference=body.get("revocation_reference", ""),
            rules=rules,
        )

    def _iso_within(self, start: Any, end: Any, now: float) -> bool:
        from datetime import datetime, timezone

        def parse(value: Any) -> Optional[float]:
            if not isinstance(value, str):
                return None
            try:
                dt = datetime.fromisoformat(value)
            except ValueError:
                return None
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()

        start_ts = parse(start)
        end_ts = parse(end)
        if start_ts is None or end_ts is None:
            return False
        return start_ts <= now <= end_ts

    def now(self) -> float:
        return self._now_func()

    def valid_now(self, bundle: PolicyBundle) -> bool:
        return self._iso_within(bundle.valid_from, bundle.valid_until, self._now_func())


class PolicyEngine:
    """Trusted, deterministic evaluation.  Default-deny."""

    def __init__(self, bundle: PolicyBundle):
        self.bundle = bundle

    @property
    def version(self) -> str:
        return self.bundle.version

    @property
    def valid(self) -> bool:
        return self.bundle is not None

    def evaluate(
        self, cr: CanonicalRequest
    ) -> Tuple[str, str, Optional[Rule]]:
        matches: List[Rule] = []
        for rule in self.bundle.rules:
            if rule.principal not in ("*", cr.principal):
                continue
            if rule.action != cr.action:
                continue
            if not self._matches_resource(rule.resource_prefix, cr.resource):
                continue
            matches.append(rule)

        if not matches:
            return DECISION_DENY, "denied_policy_no_rule", None

        effective = {self._effective(r) for r in matches}
        if len(effective) != 1:
            # Conflicting rules: fail closed (RFC 4.1).
            return DECISION_DENY, "denied_policy_conflict", None

        decision = effective.pop()
        rule = matches[0]
        if decision == DECISION_REQUIRE_APPROVAL:
            return DECISION_REQUIRE_APPROVAL, "policy_approval_required", rule
        return DECISION_ALLOW, "policy_allowed", rule

    def _effective(self, rule: Rule) -> str:
        if rule.approval_required or rule.decision == DECISION_REQUIRE_APPROVAL:
            return DECISION_REQUIRE_APPROVAL
        return DECISION_ALLOW

    def _matches_resource(self, prefix: Optional[Dict[str, Any]], resource: Dict[str, Any]) -> bool:
        if prefix is None:
            return True
        import os

        for key, expected in prefix.items():
            actual = resource.get("path" if key == "path_prefix" else key)
            if key == "path_prefix":
                if not isinstance(actual, str) or not isinstance(expected, str):
                    return False
                expected_norm = os.path.normcase(os.path.realpath(os.path.abspath(expected))).rstrip(os.sep)
                actual_norm = os.path.normcase(actual)
                if not (actual_norm == expected_norm or actual_norm.startswith(expected_norm + os.sep)):
                    return False
            elif actual != expected:
                return False
        return True