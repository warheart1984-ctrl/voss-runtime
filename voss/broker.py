"""Capability broker (Voss RFC 4.2, 6.2, 6.3).

The only component allowed to exercise tools.  Capabilities are protected
state held in the broker's memory, keyed by an unforgeable random id; the
worker only ever receives the capability_id reference.  Immediately before
use the broker re-validates identity, policy version, action/resource
match, payload digest, binding digest, constraints, expiry, revocation,
use count, and duplicate-request state, then consumes atomically.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence

from .approval import (
    APPROVE,
    ApprovalController,
    ApprovalError,
    STATE_AUTHORIZED,
    STATE_DENIED_OR_EXPIRED,
    STATE_EXECUTING,
    STATE_PENDING_APPROVAL,
)
from .audit import AuditLog, AuditUnavailableError
from .canonical import ProtocolError, new_id, sha256_hex
from .crashpoint import (
    CP_CAPABILITY_ISSUED,
    CP_EFFECT_DONE,
    CP_REQUEST_EXECUTED,
    maybe_crash,
)
from .policy import DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_APPROVAL, PolicyEngine
from .protocol import CanonicalRequest, bind as bind_request
from .tools import ToolFailure, ToolRegistry, UncertainOutcome


class ControlUnavailable(RuntimeError):
    pass


@dataclass
class Capability:
    """Authoritative broker-held grant. Not serialized to the worker."""

    cap_id: str
    principal: str
    session_id: str
    action: str
    resource: Dict[str, Any]
    payload_digest: str
    constraints: Dict[str, Any]
    policy_version: str
    approval_ref: str
    binding_digest: str
    nonce: str
    request_id: str
    request_digest: str
    issued_at: float
    expires_at: float
    use_limit: int = 1
    used_count: int = 0
    revoked: bool = False
    flow_id: str = ""

    @property
    def used(self) -> bool:
        return self.used_count >= self.use_limit


@dataclass
class BrokerDecision:
    decision: str                       # ALLOW | REQUIRE_APPROVAL | DENY | UNKNOWN
    reason_code: str = ""
    policy_version: str = ""
    approval_request_id: str = ""
    capability_id: str = ""
    result: Optional[Dict[str, Any]] = None
    outcome: str = ""                   # COMPLETED | UNKNOWN when executed

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "decision": self.decision,
            "reason_code": coarse_reason_code(self.reason_code),
            "policy_version": self.policy_version,
            "approval_request_id": self.approval_request_id,
            "capability_id": self.capability_id,
        }
        if self.result is not None:
            out["result"] = self.result
        return out


_COARSE = {
    "policy_approval_required": "approval_required",
    "policy_allowed": "allowed",
    "outcome_uncertain": "unknown",
    "denied_policy": "denied",
    "denied_policy_no_rule": "denied",
    "denied_policy_conflict": "denied",
    "denied_identity": "denied_identity",
    "denied_schema": "denied_invalid_envelope",
    "denied_worker_suspended": "denied_worker_suspended",
    "denied_health_unavailable": "denied",
    "denied_approval_unavailable": "denied_approval_unavailable",
    "denied_approval": "denied",
    "denied_approval_tamper": "denied",
    "denied_approval_expired": "denied",
    "denied_capability_forged": "denied",
    "denied_capability_revoked": "denied",
    "denied_capability_expired": "denied",
    "denied_capability_used": "denied",
    "denied_request_tamper": "denied",
    "denied_replay_uniqueness": "denied_replay",
    "denied_tool_failure": "denied",
}


def coarse_reason_code(full: str) -> str:
    return _COARSE.get(full, "denied")


class Broker:
    """Trusted mediator. Default-deny at every boundary."""

    def __init__(
        self,
        policy_engine: PolicyEngine,
        tools: ToolRegistry,
        audit: AuditLog,
        approvals: ApprovalController,
        health_provider: Any,
        wal: Any = None,
    ):
        self._policy = policy_engine
        self._tools = tools
        self._audit = audit
        self._approvals = approvals
        self._health = health_provider          # exposes .watchdog and .policy_ok()
        self._wal = wal                         # durable write-ahead state (optional)
        self._recovery_ok = True
        self._caps: Dict[str, Capability] = {}
        self._executed_request_ids: set = set()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ health

    def _guard(self, worker_id: str) -> None:
        problems: list = []
        if not self._policy.valid:
            problems.append("policy")
        if not self._audit.healthy():
            problems.append("audit")
        if self._wal is not None and not self._wal.healthy():
            problems.append("wal")
        if not self._recovery_ok:
            problems.append("recovery")
        if not self._health.watchdog_health().ok:
            problems.append("watchdog")
        if not self._health.watchdog_accepts_work(worker_id):
            problems.append("watchdog-suspended")
        if problems:
            raise ControlUnavailable("unavailable controls: " + ", ".join(problems))

    def _safe_emit(self, event_type: str, **kwargs: Any) -> None:
        try:
            self._audit.emit(event_type, **kwargs)
        except AuditUnavailableError:
            pass

    def _wal_emit(self, event_type: str, **kwargs: Any) -> None:
        if self._wal is None:
            return
        try:
            self._wal.emit(event_type, **kwargs)
        except Exception:
            pass  # durability loss is enforced at the guard, never silently granted

    # ------------------------------------------------------------- entry points

    def execute_action(self, cr: CanonicalRequest, worker_id: str) -> BrokerDecision:
        with self._lock:
            try:
                self._guard(worker_id)
            except ControlUnavailable as exc:
                self._safe_emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, policy_version=self._policy.version,
                    decision="DENY", reason_code="denied_health_unavailable",
                    error=str(exc),
                )
                return BrokerDecision(DECISION_DENY, "denied_health_unavailable", self._policy.version)

            decision, reason, rule = self._policy.evaluate(cr)
            if decision == DECISION_DENY:
                self._audit.emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, action_class=cr.action,
                    policy_version=self._policy.version, decision="DENY",
                    reason_code=reason,
                )
                return BrokerDecision(DECISION_DENY, reason, self._policy.version)

            if decision == DECISION_REQUIRE_APPROVAL:
                expiry = float(rule.expiry_limit_seconds if rule else 60)
                flow = self._approvals.request(cr, expiry)
                self._audit.emit(
                    "approval_request", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=flow.request_digest,
                    flow_id=flow.flow_id, action=cr.action,
                    action_class=_action_class(cr.action),
                    policy_version=self._policy.version, decision="REQUIRE_APPROVAL",
                    reason_code="policy_approval_required",
                )
                return BrokerDecision(
                    DECISION_REQUIRE_APPROVAL, "policy_approval_required",
                    self._policy.version, approval_request_id=flow.flow_id,
                )

            # policy ALLOW (A0 observe) -> issue then immediately consume.
            cap = self._issue(cr, worker_id, approval_ref=f"policy:{self._policy.version}")
            return self._use(cap, cr, worker_id, flow_id="")

    def resolve_and_execute(
        self, flow_id: str, decision: str, approver_ref: str,
        cr: CanonicalRequest, worker_id: str,
    ) -> BrokerDecision:
        with self._lock:
            try:
                self._guard(worker_id)
            except ControlUnavailable as exc:
                self._safe_emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, policy_version=self._policy.version,
                    decision="DENY", reason_code="denied_health_unavailable",
                    error=str(exc),
                )
                return BrokerDecision(DECISION_DENY, "denied_health_unavailable", self._policy.version)

            try:
                flow = self._approvals.get(flow_id)
            except ApprovalError:
                return BrokerDecision(DECISION_DENY, "denied_approval", self._policy.version)

            if flow.state != STATE_PENDING_APPROVAL:
                return BrokerDecision(DECISION_DENY, "denied_approval", self._policy.version)

            if decision != APPROVE:
                self._approvals.resolve(flow_id, decision, approver_ref)
                self._audit.emit(
                    "approval_resolution", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, flow_id=flow_id,
                    action=cr.action, policy_version=self._policy.version,
                    decision="DENY", approver_ref=approver_ref,
                    reason_code="denied_approval",
                )
                return BrokerDecision(DECISION_DENY, "denied_approval", self._policy.version)

            # Re-bind: the request submitted for execution must be the one the
            # human approved (payload, resource, principal, constraints).
            if cr.digest() != flow.request_digest:
                self._approvals.resolve(flow_id, "CANCEL", approver_ref)
                self._audit.emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    flow_id=flow_id, action=cr.action,
                    policy_version=self._policy.version, decision="DENY",
                    reason_code="denied_approval_tamper", approver_ref=approver_ref,
                )
                return BrokerDecision(DECISION_DENY, "denied_approval_tamper", self._policy.version)

            bound_cr = bind_request(cr, flow.nonce, flow.expires_at)
            flow, authorized = self._approvals.resolve(flow_id, APPROVE, approver_ref)
            if not authorized:
                self._audit.emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, flow_id=flow_id, action=cr.action,
                    policy_version=self._policy.version, decision="DENY",
                    reason_code=(
                        "denied_approval_expired"
                        if flow.state == STATE_DENIED_OR_EXPIRED else "denied_approval"
                    ),
                )
                return BrokerDecision(
                    DECISION_DENY,
                    "denied_approval_expired" if flow.state == STATE_DENIED_OR_EXPIRED else "denied_approval",
                    self._policy.version,
                )

            cap = self._issue_from_flow(flow, worker_id, approver_ref)
            return self._use(cap, bound_cr, worker_id, flow_id=flow.flow_id)

    # ---------------------------------------------------------------- issuing

    def _issue(self, cr: CanonicalRequest, worker_id: str, approval_ref: str) -> Capability:
        nonce = new_id("nonce-")
        bound = bind_request(cr, nonce, time.time() + 60)
        return self._store_capability(
            Capability(
                cap_id=new_id("cap-"),
                principal=worker_id,
                session_id=cr.session_id,
                action=cr.action,
                resource=cr.resource,
                payload_digest=cr.payload_digest,
                constraints=cr.constraints,
                policy_version=self._policy.version,
                approval_ref=approval_ref,
                binding_digest=bound.binding_digest(self._policy.version),
                nonce=nonce,
                request_id=cr.request_id,
                request_digest=cr.digest(),
                issued_at=time.time(),
                expires_at=bound.expires_at,
                use_limit=1,
            )
        )

    def _issue_from_flow(self, flow, worker_id: str, approver_ref: str) -> Capability:
        cr = flow.cr
        return self._store_capability(
            Capability(
                cap_id=new_id("cap-"),
                principal=worker_id,
                session_id=cr.session_id,
                action=cr.action,
                resource=cr.resource,
                payload_digest=cr.payload_digest,
                constraints=cr.constraints,
                policy_version=flow.policy_version,
                approval_ref=approx(flow.approver_ref or approver_ref),
                binding_digest=flow.binding_digest,
                nonce=flow.nonce,
                request_id=cr.request_id,
                request_digest=flow.request_digest,
                issued_at=time.time(),
                expires_at=flow.expires_at,
                use_limit=1,
                flow_id=flow.flow_id,
            )
        )

    def _store_capability(self, cap: Capability) -> Capability:
        with self._lock:
            self._caps[cap.cap_id] = cap
            self._audit.emit(
                "capability_issued", worker_id=cap.principal, session_id=cap.session_id,
                request_id=cap.request_id, request_digest=cap.request_digest,
                action=cap.action, policy_version=cap.policy_version,
                capability_id=cap.cap_id, flow_id=cap.flow_id,
                decision="ALLOW", reason_code="policy_allowed", approver_ref=cap.approval_ref,
            )
            self._wal_emit(
                "capability_issued",
                cap_id=cap.cap_id,
                principal=cap.principal,
                session_id=cap.session_id,
                action=cap.action,
                resource=cap.resource,
                payload_digest=cap.payload_digest,
                constraints=cap.constraints,
                policy_version=cap.policy_version,
                approval_ref=cap.approval_ref,
                binding_digest=cap.binding_digest,
                nonce=cap.nonce,
                request_id=cap.request_id,
                request_digest=cap.request_digest,
                issued_at=round(cap.issued_at, 6),
                expires_at=round(cap.expires_at, 6),
                use_limit=cap.use_limit,
                flow_id=cap.flow_id,
            )
            maybe_crash(CP_CAPABILITY_ISSUED)
        return cap

    # -------------------------------------------------------------- execution

    def _use(self, cap: Capability, cr: CanonicalRequest, worker_id: str, flow_id: str) -> BrokerDecision:
        with self._lock:
            cap = self._caps.get(cap.cap_id)
            if cap is None:
                self._audit.emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, action=cr.action,
                    policy_version=self._policy.version, decision="DENY",
                    reason_code="denied_capability_forged",
                )
                return BrokerDecision(DECISION_DENY, "denied_capability_forged", self._policy.version)

            reason = self._validate_capability(cap, cr, worker_id)
            if reason is not None:
                self._audit.emit(
                    "denied", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, policy_version=self._policy.version,
                    decision="DENY", reason_code=reason,
                    capability_id=cap.cap_id, flow_id=cap.flow_id,
                )
                return BrokerDecision(DECISION_DENY, reason, self._policy.version)

            cap.used_count += 1
            self._executed_request_ids.add(cr.request_id)
            # Durable consumption is recorded before the effect, so a crash
            # mid-execution still restores "used" + replay-uniqueness on boot.
            self._wal_emit(
                "capability_used", cap_id=cap.cap_id, request_id=cap.request_id,
            )
            self._wal_emit("request_executed", request_id=cr.request_id)
            maybe_crash(CP_REQUEST_EXECUTED)

            self._audit.emit(
                "execution_start", worker_id=worker_id, session_id=cr.session_id,
                request_id=cr.request_id, request_digest=cr.digest(),
                action=cr.action, action_class=_action_class(cr.action),
                policy_version=self._policy.version, decision="ALLOW",
                capability_id=cap.cap_id, flow_id=cap.flow_id, approver_ref=cap.approval_ref,
            )

            if flow_id:
                self._approvals.mark_executing(flow_id)

            try:
                result = self._tools.execute(cap.action, cr)
                maybe_crash(CP_EFFECT_DONE)  # effect materialized, unlogged
            except UncertainOutcome as exc:
                self._audit.emit(
                    "execution_result", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, action_class=_action_class(cr.action),
                    policy_version=self._policy.version, decision="UNKNOWN",
                    reason_code="outcome_uncertain", capability_id=cap.cap_id,
                    flow_id=cap.flow_id, result={"status": "uncertain"}, error=str(exc),
                )
                if flow_id:
                    self._approvals.mark_outcome(flow_id, "UNKNOWN")
                return BrokerDecision("UNKNOWN", "outcome_uncertain", self._policy.version,
                                      capability_id=cap.cap_id, result={"status": "uncertain"})
            except ToolFailure as exc:
                self._audit.emit(
                    "execution_result", worker_id=worker_id, session_id=cr.session_id,
                    request_id=cr.request_id, request_digest=cr.digest(),
                    action=cr.action, action_class=_action_class(cr.action),
                    policy_version=self._policy.version, decision="UNKNOWN",
                    reason_code="denied_tool_failure", capability_id=cap.cap_id,
                    flow_id=cap.flow_id, result={}, error=str(exc),
                )
                if flow_id:
                    self._approvals.mark_outcome(flow_id, "UNKNOWN")
                return BrokerDecision("UNKNOWN", "denied_tool_failure", self._policy.version,
                                      capability_id=cap.cap_id, result={"error": str(exc)})

            self._audit.emit(
                "execution_result", worker_id=worker_id, session_id=cr.session_id,
                request_id=cr.request_id, request_digest=cr.digest(),
                action=cr.action, action_class=_action_class(cr.action),
                policy_version=self._policy.version, decision="ALLOW",
                outcome="COMPLETED", capability_id=cap.cap_id, flow_id=cap.flow_id,
                result=self._audit_safe_result(result),
            )
            if flow_id:
                self._approvals.mark_outcome(flow_id, "COMPLETED")
            return BrokerDecision(
                DECISION_ALLOW, "policy_allowed", self._policy.version,
                capability_id=cap.cap_id, result=result, outcome="COMPLETED",
            )

    def _validate_capability(self, cap: Capability, cr: CanonicalRequest, worker_id: str) -> Optional[str]:
        now = time.time()
        if cap.principal != worker_id or cap.principal != cr.principal:
            return "denied_identity"
        if cap.session_id != cr.session_id:
            return "denied_identity"
        if cap.revoked:
            return "denied_capability_revoked"
        if now > cap.expires_at:
            return "denied_capability_expired"
        if cap.used:
            return "denied_capability_used"
        if cap.action != cr.action:
            return "denied_request_tamper"
        if cap.policy_version != self._policy.version:
            return "denied_request_tamper"
        if cap.resource != cr.resource:
            return "denied_request_tamper"
        if cap.payload_digest != cr.payload_digest:
            return "denied_request_tamper"
        if cap.constraints != cr.constraints:
            return "denied_request_tamper"
        if cap.request_id in self._executed_request_ids:
            return "denied_replay_uniqueness"
        expected = sha256_hex({
            "request": cr.digest(),
            "policy_version": cap.policy_version,
            "nonce": cap.nonce,
            "expires_at": round(cap.expires_at, 6),
        })
        if expected != cap.binding_digest:
            return "denied_request_tamper"
        return None

    # ------------------------------------------------------------- revocation

    def revoke_all(self, worker_id: str, reason: str = "operator") -> int:
        with self._lock:
            revoked = 0
            for cap in self._caps.values():
                if cap.principal == worker_id and not cap.revoked:
                    cap.revoked = True
                    revoked += 1
                    self._safe_emit(
                        "revocation", worker_id=worker_id, session_id=cap.session_id,
                        request_id=cap.request_id, action=cap.action,
                        policy_version=cap.policy_version, capability_id=cap.cap_id,
                        reason_code="denied_capability_revoked", error=f"revoked: {reason}",
                    )
                    self._wal_emit(
                        "capability_revoked", cap_id=cap.cap_id,
                        request_id=cap.request_id, reason=reason,
                    )
            return revoked

    # -------------------------------------------------------------- recovery

    def restore_cap(self, cap: Capability) -> None:
        """Rehydrate a capability during trusted recovery (no WAL write)."""
        with self._lock:
            self._caps[cap.cap_id] = cap

    def mark_executed(self, request_id: str) -> None:
        with self._lock:
            self._executed_request_ids.add(request_id)

    def set_recovery_ok(self, ok: bool) -> None:
        with self._lock:
            self._recovery_ok = bool(ok)

    def capabilities(self, worker_id: Optional[str] = None) -> Sequence[Capability]:
        with self._lock:
            caps = self._caps.values()
            if worker_id:
                caps = [c for c in caps if c.principal == worker_id]
            return list(caps)

    def executed_request_ids(self) -> Sequence[str]:
        with self._lock:
            return list(self._executed_request_ids)

    # -------------------------------------------------------------- utilities

    def _audit_safe_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Never write payload plaintext to audit; keep digests and sizes."""
        safe: Dict[str, Any] = {}
        for key, value in result.items():
            if key in ("content", "subject", "body", "recipient"):
                continue
            safe[key] = value
        safe.pop("subject", None)
        safe.pop("body", None)
        safe.pop("recipient", None)
        if "recipient" in result:
            safe["recipient_sha256"] = sha256_hex(result.get("recipient"))
        safe["payload_sha256"] = result.get("sha256")
        return safe


def approx(value: str) -> str:
    return value or "approval:flow"


def _action_class(action: str) -> str:
    from .protocol import action_class

    return action_class(action)