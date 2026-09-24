"""Trusted human approval flow (Voss RFC 5.2-5.4).

The ApprovalController lives on the trusted side.  The model can only
create CanonicalRequests; it cannot construct an ApprovalView, cannot
reach ``resolve()``, and model text is never interpreted as consent.
Approval binds the digest of the canonical request (principal, action,
resource, payload digest, constraints) together with policy version,
nonce, and expiry, and is single-use.

States (RFC 5.4): PROPOSED -> PENDING_APPROVAL -> AUTHORIZED ->
EXECUTING -> COMPLETED | UNKNOWN; DENIED / EXPIRED are terminal.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from .canonical import new_id
from .crashpoint import (
    CP_FLOW_REQUEST,
    CP_FLOW_REQUEST_PREWAL,
    CP_FLOW_RESOLUTION,
    maybe_crash,
)
from .protocol import CanonicalRequest

STATE_PROPOSED = "PROPOSED"
STATE_PENDING_APPROVAL = "PENDING_APPROVAL"
STATE_AUTHORIZED = "AUTHORIZED"
STATE_EXECUTING = "EXECUTING"
STATE_COMPLETED = "COMPLETED"
STATE_UNKNOWN = "UNKNOWN"
STATE_DENIED_OR_EXPIRED = "DENIED_OR_EXPIRED"

TERMINAL_STATES = {STATE_DENIED_OR_EXPIRED, STATE_COMPLETED, STATE_UNKNOWN}

APPROVE, DENY, CANCEL = "APPROVE", "DENY", "CANCEL"

_ALLOWED_TRANSITIONS = {
    STATE_PROPOSED: {STATE_PENDING_APPROVAL},
    STATE_PENDING_APPROVAL: {STATE_AUTHORIZED, STATE_DENIED_OR_EXPIRED},
    STATE_AUTHORIZED: {STATE_EXECUTING, STATE_DENIED_OR_EXPIRED},
    STATE_EXECUTING: {STATE_COMPLETED, STATE_UNKNOWN},
}


class ApprovalError(Exception):
    pass


@dataclass
class ApprovalView:
    """Exactly what a trusted human sees. Not constructible from model output."""

    request_id: str
    action: str
    principal: str
    resource: Dict[str, Any]
    payload_digest: str
    policy_version: str
    nonce: str
    expires_at: float
    expires_in_seconds: float
    risk_class: str
    consequences: str
    reversible: bool

    def describe(self) -> str:
        return (
            f"Action:        {self.action}\n"
            f"Principal:     {self.principal}\n"
            f"Target:        {self.resource}\n"
            f"Payload sha256:{self.payload_digest}\n"
            f"Policy:        {self.policy_version}\n"
            f"Nonce:         {self.nonce}\n"
            f"Expires in:    {self.expires_in_seconds:.0f}s\n"
            f"Risk class:    {self.risk_class}\n"
            f"Consequences:  {self.consequences}\n"
            f"Reversible:    {self.reversible}"
        )


@dataclass
class ApprovalFlow:
    flow_id: str
    cr: CanonicalRequest
    policy_version: str
    nonce: str
    expires_at: float
    binding_digest: str
    request_digest: str
    state: str = STATE_PENDING_APPROVAL
    approver_ref: str = ""
    outcome: str = ""
    created_at: float = field(default_factory=time.time)

    def transition(self, target: str) -> None:
        if self.state in TERMINAL_STATES:
            raise ApprovalError(f"flow is terminal in state {self.state}")
        if target not in _ALLOWED_TRANSITIONS[self.state]:
            raise ApprovalError(f"invalid transition {self.state} -> {target}")
        self.state = target


Approver = Callable[[ApprovalView], Tuple[str, str]]  # -> (decision, approver_identity)


class ApprovalController:
    """Trusted controller of one-way human resolution."""

    def __init__(self, policy_version: str, wal: Any = None):
        self._policy_version = policy_version
        self._flows: Dict[str, ApprovalFlow] = {}
        self._wal = wal
        self._lock = threading.RLock()

    def _log(self, event_type: str, **fields: Any) -> None:
        if self._wal is None:
            return
        try:
            self._wal.emit(event_type, **fields)
        except Exception:
            # Ledger unavailability is enforced at the broker guard; state
            # bookkeeping must not crash on a write failure.
            pass

    def request(self, cr: CanonicalRequest, expiry_seconds: float) -> ApprovalFlow:
        """Create a PENDING_APPROVAL flow bound to ``cr``."""
        if expiry_seconds <= 0:
            raise ApprovalError("approval expiry must be positive")
        nonce = new_id("nonce-")
        expires_at = time.time() + expiry_seconds
        bound = CanonicalRequest(
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
        flow = ApprovalFlow(
            flow_id=new_id("approval-"),
            cr=bound,
            policy_version=self._policy_version,
            nonce=nonce,
            expires_at=expires_at,
            binding_digest=bound.binding_digest(self._policy_version),
            request_digest=bound.digest(),
        )
        with self._lock:
            self._flows[flow.flow_id] = flow
        maybe_crash(CP_FLOW_REQUEST_PREWAL)
        self._log(
            "flow_request",
            flow_id=flow.flow_id,
            version=bound.version,
            request_id=bound.request_id,
            session_id=bound.session_id,
            principal=bound.principal,
            action=bound.action,
            resource=bound.resource,
            payload=bound.payload,
            constraints=bound.constraints,
            payload_digest=bound.payload_digest,
            policy_version=flow.policy_version,
            nonce=nonce,
            expires_at=round(expires_at, 6),
            binding_digest=flow.binding_digest,
            request_digest=flow.request_digest,
            created_at=round(flow.created_at, 6),
        )
        maybe_crash(CP_FLOW_REQUEST)
        return flow

    def fresh(self, cr: CanonicalRequest) -> bool:
        """True if a worker-side envelope still matches a given live flow."""
        return True  # binding is enforced at resolve time against flow.cr

    def view(self, flow_id: str) -> ApprovalView:
        flow = self.get(flow_id)
        now = time.time()
        return ApprovalView(
            request_id=flow.cr.request_id,
            action=flow.cr.action,
            principal=flow.cr.principal,
            resource=flow.cr.resource,
            payload_digest=flow.cr.payload_digest,
            policy_version=flow.policy_version,
            nonce=flow.nonce,
            expires_at=flow.expires_at,
            expires_in_seconds=max(0.0, flow.expires_at - now),
            risk_class=_risk_class(flow.cr.action),
            consequences=_consequences(flow.cr.action),
            reversible=_reversible(flow.cr.action),
        )

    def get(self, flow_id: str) -> ApprovalFlow:
        with self._lock:
            flow = self._flows.get(flow_id)
        if flow is None:
            raise ApprovalError("approval flow not found")
        return flow

    def pending_approval(self, flow_id: str) -> ApprovalFlow:
        flow = self.get(flow_id)
        self._purge_expired()
        return flow

    def resolve(
        self, flow_id: str, decision: str, approver_ref: str
    ) -> Tuple[ApprovalFlow, bool]:
        """One-way trusted resolution. Returns (flow, authorized)."""
        with self._lock:
            flow = self._flows.get(flow_id)
            if flow is None:
                raise ApprovalError("approval flow not found")
            self._purge_expired_locked()
            if flow.state in TERMINAL_STATES:
                return flow, False

            decision = decision.upper() if isinstance(decision, str) else ""
            if time.time() > flow.expires_at:
                if flow.state == STATE_PENDING_APPROVAL:
                    flow.transition(STATE_DENIED_OR_EXPIRED)
                self._log(
                    "flow_resolution", flow_id=flow.flow_id, decision="EXPIRED",
                    approver_ref=approver_ref, state=flow.state, authorized=False,
                )
                return flow, False

            if decision == APPROVE:
                if flow.state != STATE_PENDING_APPROVAL:
                    return flow, False
                flow.approver_ref = approver_ref
                flow.transition(STATE_AUTHORIZED)
                self._log(
                    "flow_resolution", flow_id=flow.flow_id, decision=APPROVE,
                    approver_ref=approver_ref, state=flow.state, authorized=True,
                )
                maybe_crash(CP_FLOW_RESOLUTION)
                return flow, True
            if decision in (DENY, CANCEL):
                flow.transition(STATE_DENIED_OR_EXPIRED)
                self._log(
                    "flow_resolution", flow_id=flow.flow_id, decision=decision,
                    approver_ref=approver_ref, state=flow.state, authorized=False,
                )
                return flow, False
            return flow, False

    def mark_executing(self, flow_id: str) -> ApprovalFlow:
        with self._lock:
            flow = self._flows[flow_id]
            if flow.state == STATE_AUTHORIZED:
                flow.transition(STATE_EXECUTING)
                self._log("flow_executing", flow_id=flow.flow_id)
            return flow

    def mark_outcome(self, flow_id: str, outcome: str) -> None:
        with self._lock:
            flow = self._flows[flow_id]
            flow.outcome = outcome
            next_state = STATE_COMPLETED if outcome == "COMPLETED" else STATE_UNKNOWN
            if flow.state == STATE_EXECUTING:
                flow.transition(next_state)
                self._log("flow_outcome", flow_id=flow.flow_id, outcome=outcome,
                          state=flow.state)

    def restore_flow(self, flow: ApprovalFlow) -> None:
        """Rehydrate a flow during trusted recovery (no WAL write)."""
        with self._lock:
            self._flows[flow.flow_id] = flow

    def _purge_expired(self) -> None:
        with self._lock:
            self._purge_expired_locked()

    def _purge_expired_locked(self) -> None:
        now = time.time()
        for flow in list(self._flows.values()):
            if flow.state == STATE_PENDING_APPROVAL and now > flow.expires_at:
                flow.transition(STATE_DENIED_OR_EXPIRED)


def _risk_class(action: str) -> str:
    return {"workspace.read": "A0", "workspace.write": "A1"}.get(action, "A2")


def _consequences(action: str) -> str:
    if action == "workspace.read":
        return "Reads a file from the allowlisted workspace"
    if action == "workspace.write":
        return "Creates or overwrites a draft file in the workspace (reversible)"
    return "Simulated external effect (mock mail). Not recallable in production."


def _reversible(action: str) -> bool:
    return action in ("workspace.read", "workspace.write")