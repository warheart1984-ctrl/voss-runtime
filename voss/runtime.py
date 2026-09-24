"""Runtime wiring (Voss RFC 3, 9.2, 10).

Wires the untrusted worker channel to the trusted normalizer, policy
engine, approval controller, broker, audit, and watchdog.  Approvals are
only ever consumed through the trusted host interfaces (``Runtime.resolve``
/ ``Runtime.approve``); model text is never interpreted as consent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence

from . import __version__ as VOSS_VERSION
from .approval import (
    ApprovalController,
    ApprovalError,
    ApprovalFlow,
    STATE_AUTHORIZED,
    STATE_COMPLETED,
    STATE_EXECUTING,
    STATE_PENDING_APPROVAL,
)
from .audit import AuditLog
from .broker import Broker, BrokerDecision, Capability, coarse_reason_code
from .confine import confine_pid, release_job
from .canonical import ProtocolError, loads_strict, new_id
from .chan import (
    MAX_LINE,
    ChannelError,
    ChannelSession,
    ChannelTimeoutError,
    chan_bootstrap,
    unlink_quiet,
)
from .keys import KeyRing
from .policy import (
    DECISION_DENY,
    DECISION_REQUIRE_APPROVAL,
    PolicyBundle,
    PolicyEngine,
    PolicyLoadError,
    PolicyLoader,
    Rule,
    build_policy_body,
    package_policy,
)
from .protocol import CanonicalRequest, RequestNormalizer, action_class
from .tools import ToolContext, ToolRegistry
from .wal import WriteAheadLog
from .watchdog import HealthReport, Watchdog

_DRIFT_CONTAIN_THRESHOLD = 0.30
_DRIFT_FAIL_THRESHOLD = 0.50
_CHANNEL_TIMEOUT_S = 15.0
_CHANNEL_LINE_READ_CAP = MAX_LINE
_CHANNEL_DRAIN_BUDGET = 1024 * 1024

# Temporal oracle (Binding 4.4, latency/resource dimension).  Declared
# bounds that become anomalies when exceeded on a worker exchange:
# response latency above the ceiling, or proposal-line volume above the cap.
_TEMPORAL_CEILING_S = 2.0
_TEMPORAL_VOLUME_CAP = 16 * 1024
_TEMPORAL_MIN_WINDOW = 10


def _clean_env(parent: Dict[str, str]) -> Dict[str, str]:
    frags = ("SECRET", "KEY", "TOKEN", "CRED", "PASS", "POLICY", "AUDIT", "AUTH")
    return {
        k: v for k, v in parent.items()
        if not any(frag in k.upper() for frag in frags)
    }


def default_dev_policy(workspace_root: str) -> Dict[str, Any]:
    rules = [
        Rule(principal="*", action="workspace.read",
             resource_prefix={"path_prefix": workspace_root},
             decision="ALLOW", approval_required=False, expiry_limit_seconds=60),
        Rule(principal="*", action="workspace.write",
             resource_prefix={"path_prefix": workspace_root},
             decision="ALLOW", approval_required=True, expiry_limit_seconds=60),
        Rule(principal="*", action="external.send_mock",
             resource_prefix={"service": "mail"},
             decision="ALLOW", approval_required=True, expiry_limit_seconds=60),
    ]
    return build_policy_body(rules, version="1.0.0", signer="operator-prototype")


class VossRuntime:
    """Development-profile Voss runtime. Trusted host object."""

    def __init__(
        self,
        workspace_root: str,
        outbox_dir: str,
        audit_path: str,
        keyring: Optional[KeyRing] = None,
        policy_package: Optional[Dict[str, Any]] = None,
        wal_path: Optional[str] = None,
        audit_relay=None,
        watchdog_guard=None,
        operator_console=None,
        outbox_accounting=None,
    ):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))
        self.outbox_dir = os.path.realpath(os.path.abspath(outbox_dir))
        self.keyring = keyring or KeyRing.generate()

        # Worker identity persists across trusted-host restarts so approvals
        # bound to principal + session remain usable after recovery.
        self._load_or_create_identity(
            os.path.join(os.path.dirname(audit_path) or ".", "identity.json")
        )
        if policy_package is None:
            policy_package = default_dev_policy(self.workspace_root)
            policy_package = package_policy(policy_package, self.keyring)

        self._loader = PolicyLoader(self.keyring)
        try:
            self._bundle: PolicyBundle = self._loader.load_and_verify(policy_package)
        except PolicyLoadError as exc:
            raise PolicyLoadError(f"cannot load policy bundle: {exc}") from exc

        self.policy = PolicyEngine(self._bundle)
        self.policy_version = self._bundle.version
        self.audit = AuditLog(audit_path, self.keyring)
        if wal_path is None:
            wal_path = os.path.join(os.path.dirname(audit_path) or ".", "wal.jsonl")
        self.wal_path = wal_path
        self._wal = WriteAheadLog(wal_path, self.keyring)
        self.approvals = ApprovalController(self.policy_version, wal=self._wal)
        self.outbox_accounting = outbox_accounting
        self.tools = ToolRegistry(ToolContext(
            self.workspace_root, self.outbox_dir,
            outbox_link=outbox_accounting,
        ))
        self.normalizer = RequestNormalizer(self.workspace_root, self.tools.names())

        self.watchdog = Watchdog(self.worker_principal)
        self.broker = Broker(
            self.policy, self.tools, self.audit, self.approvals,
            health_provider=self, wal=self._wal,
        )
        self.watchdog.attach(
            health_source=self._watchdog_health_source,
            revoke_fn=self.broker.revoke_all,
            audit_fn=self._watchdog_audit_event,
        )

        self._lock = threading.RLock()
        self._events = 0
        self._schema_violations = 0
        self._identity_violations = 0
        self._denied_policy = 0
        self._bypass = 0
        self._tamper = 0
        self._replay = 0
        self._exchanges = 0
        self._temporal_anomalies = 0
        self._contained = False
        self._recovery_ok = True
        self._channel: Optional[ChannelSession] = None
        self._bootstrap_path: Optional[str] = None
        self._worker_job = None
        self.audit_relay = audit_relay
        if self.audit_relay is not None:
            def _relay_violation(reason: str) -> None:
                try:
                    self.audit.emit(
                        "relay_violation", worker_id=self.worker_principal,
                        session_id=self.worker_session, decision="DENY",
                        reason_code="audit_relay_violation", error=str(reason),
                    )
                except Exception:
                    pass
            self.audit_relay.set_on_violation(_relay_violation)
            self.audit_relay.start()
        self.watchdog_guard = watchdog_guard
        if self.watchdog_guard is not None:

            def _guard_failure(reason: str) -> None:
                try:
                    self.audit.emit(
                        "guard_failure", worker_id=self.worker_principal,
                        session_id=self.worker_session, decision="DENY",
                        reason_code="denied_watch_guard", error=str(reason),
                    )
                except Exception:
                    pass
                self.watchdog.suspend(
                    self.worker_principal, f"watch-guard: {reason}")

            self.watchdog_guard.set_on_failure(_guard_failure)
            self.watchdog_guard.start()
        self.operator_console = operator_console
        if self.operator_console is not None:

            def _console_failure(reason: str) -> None:
                try:
                    self.audit.emit(
                        "operator_console_unavailable", worker_id=self.worker_principal,
                        session_id=self.worker_session, decision="DENY",
                        reason_code="denied_approval_unavailable", error=str(reason),
                    )
                except Exception:
                    pass

            if hasattr(self.operator_console, "set_on_failure"):
                self.operator_console.set_on_failure(_console_failure)
            self.operator_console.set_on_vote(self._console_vote)
            self.operator_console.set_on_terminate(self._console_terminate)
            self.operator_console.start()
        if self.outbox_accounting is not None:
            self.outbox_accounting.start()
        self._recover_state()

    # ------------------------------------------------------------ health API

    def policy_ok(self) -> bool:
        return self._loader.valid_now(self._bundle)

    def watchdog_health(self) -> HealthReport:
        return self.watchdog.health()

    def watchdog_accepts_work(self, worker_id: str) -> bool:
        return self.watchdog.accepts_work(worker_id)

    def _watchdog_health_source(self) -> HealthReport:
        if not self.policy_ok():
            return HealthReport(False, "policy expired")
        if not self.audit.healthy():
            return HealthReport(False, "audit unavailable")
        guard = getattr(self, "watchdog_guard", None)
        if guard is not None:
            g = guard.health()
            if not g["ok"]:
                state = "triggered" if g["triggered"] else "unreachable"
                detail = g["error"] or state
                return HealthReport(False, f"watch-guard {state}: {detail}")
        return HealthReport(True)

    def _watchdog_audit_event(self, worker_id: str, detail: str) -> None:
        try:
            self.audit.emit(
                "kill", worker_id=worker_id, session_id=self.worker_session,
                decision="DENY", reason_code="denied_worker_suspended", error=detail,
            )
        except Exception:
            pass

    # ---------------------------------------------------------------- recovery

    def _load_or_create_identity(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            principal = str(data["principal"])
            session_id = str(data["session_id"])
            if principal.startswith("worker-") and session_id.startswith("session-"):
                self.worker_principal = principal
                self.worker_session = session_id
                return
        except (OSError, ValueError, KeyError, TypeError):
            pass
        self.worker_principal = new_id("worker-")
        self.worker_session = new_id("session-")
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {"principal": self.worker_principal,
                     "session_id": self.worker_session},
                    handle, indent=0,
                )
        except OSError:
            pass  # non-persistent identity: approvals may not survive restart

    def _fail_recovery(self, detail: str) -> None:
        """A tampered or unusable ledger means no grants survive: fail closed."""
        self._recovery_ok = False
        self.broker.set_recovery_ok(False)
        self.watchdog.suspend(self.worker_principal, "wal recovery failed")
        try:
            self.audit.emit(
                "recovery_failed", worker_id=self.worker_principal,
                session_id=self.worker_session, decision="DENY",
                reason_code="denied_health_unavailable", error=detail,
            )
        except Exception:
            pass

    def _recover_state(self) -> None:
        """Replay the write-ahead ledger.  Verified chain -> restore grants;
        anything else -> deny everything (nothing is trusted from disk)."""
        try:
            verified = self._wal.verify_integrity()
            records = list(self._wal.records())
        except Exception as exc:  # unreadable ledger
            self._fail_recovery(f"write-ahead ledger unreadable: {exc}")
            return

        if not verified:
            self._fail_recovery("write-ahead ledger integrity verification failed")
            return

        flows: Dict[str, ApprovalFlow] = {}
        caps: Dict[str, Capability] = {}
        executed = set()
        try:
            for line in records:
                payload = line.get("record", {})
                etype = payload.get("event_type")
                if etype == "flow_request":
                    flows[payload["flow_id"]] = self._flow_from_wal(payload)
                elif etype == "flow_resolution":
                    flow = flows.get(payload.get("flow_id"))
                    if flow is not None:
                        flow.state = payload.get("state", flow.state)
                        if payload.get("approver_ref"):
                            flow.approver_ref = payload["approver_ref"]
                elif etype == "flow_executing":
                    flow = flows.get(payload.get("flow_id"))
                    if flow is not None and flow.state == STATE_AUTHORIZED:
                        flow.transition(STATE_EXECUTING)
                elif etype == "flow_outcome":
                    flow = flows.get(payload.get("flow_id"))
                    if flow is not None:
                        flow.outcome = payload.get("outcome", "")
                        if flow.state == STATE_EXECUTING:
                            flow.transition(
                                STATE_COMPLETED if flow.outcome == "COMPLETED"
                                else "UNKNOWN"
                            )
                elif etype == "capability_issued":
                    cap = self._cap_from_wal(payload)
                    caps[cap.cap_id] = cap
                elif etype == "capability_used":
                    cap = caps.get(payload.get("cap_id"))
                    if cap is not None:
                        cap.used_count = cap.use_limit
                elif etype == "capability_revoked":
                    cap = caps.get(payload.get("cap_id"))
                    if cap is not None:
                        cap.revoked = True
                elif etype == "request_executed":
                    executed.add(payload["request_id"])
        except Exception as exc:
            # Authentic chain but inconsistent structure: still not trusted.
            self._fail_recovery(f"write-ahead ledger inconsistent: {exc}")
            return

        for flow in flows.values():
            self.approvals.restore_flow(flow)
        for cap in caps.values():
            self.broker.restore_cap(cap)
        for request_id in executed:
            self.broker.mark_executed(request_id)

        self._recovery_ok = True
        try:
            self.audit.emit(
                "recovery", worker_id=self.worker_principal,
                session_id=self.worker_session, decision="ALLOW",
                reason_code="recovered",
                result={
                    "flows_restored": len(flows),
                    "capabilities_restored": len(caps),
                    "executed_requests_restored": len(executed),
                },
            )
        except Exception:
            pass

    def _flow_from_wal(self, payload: Dict[str, Any]) -> ApprovalFlow:
        cr = CanonicalRequest(
            version=payload["version"],
            request_id=payload["request_id"],
            session_id=payload["session_id"],
            principal=payload["principal"],
            action=payload["action"],
            resource=payload["resource"],
            payload=payload["payload"],
            constraints=payload["constraints"],
            payload_digest=payload["payload_digest"],
            nonce=payload["nonce"],
            expires_at=payload["expires_at"],
        )
        return ApprovalFlow(
            flow_id=payload["flow_id"],
            cr=cr,
            policy_version=payload["policy_version"],
            nonce=payload["nonce"],
            expires_at=payload["expires_at"],
            binding_digest=payload["binding_digest"],
            request_digest=payload["request_digest"],
            state=STATE_PENDING_APPROVAL,
            created_at=payload.get("created_at", time.time()),
        )

    def _cap_from_wal(self, payload: Dict[str, Any]) -> Capability:
        return Capability(
            cap_id=payload["cap_id"],
            principal=payload["principal"],
            session_id=payload["session_id"],
            action=payload["action"],
            resource=payload["resource"],
            payload_digest=payload["payload_digest"],
            constraints=payload["constraints"],
            policy_version=payload["policy_version"],
            approval_ref=payload.get("approval_ref", ""),
            binding_digest=payload["binding_digest"],
            nonce=payload["nonce"],
            request_id=payload["request_id"],
            request_digest=payload["request_digest"],
            issued_at=payload.get("issued_at", 0.0),
            expires_at=payload["expires_at"],
            use_limit=payload.get("use_limit", 1),
            flow_id=payload.get("flow_id", ""),
        )

    # ------------------------------------------------------------ request path

    def handle_envelope(self, envelope_str: str) -> Dict[str, Any]:
        """Process one worker envelope. Coarse response only for the worker."""
        with self._lock:
            if not self.watchdog.accepts_work(self.worker_principal):
                self.audit.emit(
                    "denied", worker_id=self.worker_principal,
                    session_id=self.worker_session, decision="DENY",
                    reason_code="denied_worker_suspended",
                )
                return {"decision": "DENY", "reason_code": "denied_worker_suspended"}

            if self._contained:
                self.audit.emit(
                    "denied", worker_id=self.worker_principal,
                    session_id=self.worker_session, decision="DENY",
                    reason_code="denied_worker_suspended",
                )
                return {"decision": "DENY", "reason_code": "denied_worker_suspended"}

            try:
                envelope = loads_strict(envelope_str)
            except ProtocolError as exc:
                return self._reject_schema(envelope_str, str(exc))

            if not isinstance(envelope, dict):
                return self._reject_schema(envelope_str, "envelope must be an object")

            claimed = envelope.get("principal")
            if claimed != self.worker_principal:
                return self._reject_identity(
                    "claimed principal %r does not match registered worker" % (claimed,),
                    str(envelope.get("request_id", "")),
                    str(envelope.get("action", "")),
                )

            claimed_session = envelope.get("session_id")
            if claimed_session != self.worker_session:
                return self._reject_identity(
                    "claimed session does not match registered worker session",
                    str(envelope.get("request_id", "")),
                    str(envelope.get("action", "")),
                )

            try:
                cr = self.normalizer.normalize(envelope, self.worker_principal)
            except ProtocolError as exc:
                return self._reject_schema(envelope_str, str(exc))

            self._events += 1
            decision: BrokerDecision = self.broker.execute_action(cr, self.worker_principal)
            self._tally(decision, cr)
            self._maybe_contain()
            self._console_intercept(decision)
            return decision.to_dict()

    # ---------------------------------------------------- operator console

    def _console_vote(self, flow_id: str, decision: str, approver_ref: str) -> None:
        """A human gesture arrived from the separate console process."""
        try:
            result = self.resolve_approval(flow_id, decision, approver_ref)
        except Exception:
            return
        console = getattr(self, "operator_console", None)
        if console is not None:
            try:
                console.publish_result(flow_id,
                                       result.get("decision", decision),
                                       approver_ref)
            except Exception:
                pass

    def _console_terminate(self, reason: str) -> None:
        """Kill switch from the console: suspend, revoke, kill the worker."""
        detail = "operator-console: %s" % (reason or "kill")
        try:
            self.kill_worker(reason=detail, terminate_process=True)
        except Exception:
            pass

    def _console_intercept(self, decision: BrokerDecision) -> None:
        """Consequential approvals need a live console; otherwise fail closed."""
        console = getattr(self, "operator_console", None)
        if console is None or decision.decision != DECISION_REQUIRE_APPROVAL:
            return
        flow_id = decision.approval_request_id
        if not flow_id:
            return
        if not console.health()["ok"]:
            try:
                self.resolve_approval(flow_id, "DENY",
                                      "operator-console-unavailable")
            except Exception:
                pass
            decision.decision = DECISION_DENY
            decision.reason_code = "denied_approval_unavailable"
            return
        try:
            console.publish_view(flow_id, self.approval_view_dict(flow_id))
        except Exception:
            pass

    def _reject_identity(self, detail: str, request_id: str, action: str) -> Dict[str, Any]:
        self._identity_violations += 1
        self._bypass += 1
        self._events += 1
        self.audit.emit(
            "identity_violation", worker_id=self.worker_principal,
            session_id=self.worker_session, request_id=request_id,
            action=action, policy_version=self.policy_version,
            decision="DENY", reason_code="denied_identity", error=detail,
        )
        self._maybe_contain()
        return {"decision": "DENY", "reason_code": coarse_reason_code("denied_identity")}

    def _reject_schema(self, raw: str, detail: str) -> Dict[str, Any]:
        self._schema_violations += 1
        self._bypass += 1
        self._events += 1
        self.audit.emit(
            "schema_violation", worker_id=self.worker_principal,
            session_id=self.worker_session, decision="DENY",
            reason_code="denied_schema", error=detail,
        )
        self._maybe_contain()
        return {"decision": "DENY", "reason_code": coarse_reason_code("denied_schema")}

    def _tally(self, decision: BrokerDecision, cr) -> None:
        reason = decision.reason_code
        if reason == "denied_policy_no_rule" or reason == "denied_policy_conflict":
            self._denied_policy += 1
        if reason in ("denied_approval_tamper", "denied_request_tamper"):
            self._tamper += 1
        if reason == "denied_replay_uniqueness":
            self._replay += 1
        if decision.decision == "DENY" and reason not in (
            "denied_health_unavailable", "denied_approval",
        ):
            self._bypass += 1

    # ------------------------------------------------------------ approvals

    def approval_view_dict(self, flow_id: str) -> Dict[str, Any]:
        view = self.approvals.view(flow_id)
        return {
            "request_id": view.request_id,
            "action": view.action,
            "principal": view.principal,
            "resource": view.resource,
            "payload_digest": view.payload_digest,
            "policy_version": view.policy_version,
            "nonce": view.nonce,
            "expires_in_seconds": view.expires_in_seconds,
            "risk_class": view.risk_class,
            "consequences": view.consequences,
            "reversible": view.reversible,
        }

    def resolve_approval(self, flow_id: str, decision: str, approver_ref: str) -> Dict[str, Any]:
        """Trusted-host path: a human decision on a pending approval."""
        try:
            flow = self.approvals.get(flow_id)
        except ApprovalError:
            self.audit.emit(
                "denied", worker_id=self.worker_principal,
                session_id=self.worker_session, decision="DENY",
                reason_code="denied_approval",
                error=f"unknown approval flow {flow_id}",
            )
            return {"decision": "DENY", "reason_code": coarse_reason_code("denied_approval")}
        result = self.broker.resolve_and_execute(
            flow_id, decision, approver_ref, flow.cr, self.worker_principal,
        )
        self._events += 1
        self._tally(result, flow.cr)
        self._maybe_contain()
        return result.to_dict()

    def deny_approval(self, flow_id: str, approver_ref: str, decision: str = "DENY") -> Dict[str, Any]:
        return self.resolve_approval(flow_id, decision, approver_ref)

    # ------------------------------------------------------------ containment

    def suspend_worker(self, reason: str = "drift") -> None:
        self.watchdog.suspend(self.worker_principal, reason)

    def _release_worker_job(self) -> None:
        job = self._worker_job
        self._worker_job = None
        if job is not None:
            release_job(job)

    def kill_worker(self, reason: str = "operator", proc: Optional[subprocess.Popen] = None, terminate_process: bool = True) -> Dict[str, Any]:
        if terminate_process:
            self._release_worker_job()
        if proc is not None:
            self.watchdog.register_process(self.worker_principal, proc)
        guard = getattr(self, "watchdog_guard", None)
        if guard is not None:
            try:
                guard.terminate(reason)
            except Exception:
                pass
        return self.watchdog.kill(self.worker_principal, reason, terminate_process=terminate_process)

    def _observe_exchange(self, seconds: float, bytes_count: int) -> None:
        """Temporal oracle: observe one worker round-trip (Binding 4.4).

        A worker that stalls past the declared response ceiling, or floods the
        channel with an oversized proposal line, registers one temporal
        anomaly; the ratio over the exchange window feeds the drift score.
        """
        self._exchanges += 1
        if seconds > _TEMPORAL_CEILING_S or bytes_count > _TEMPORAL_VOLUME_CAP:
            self._temporal_anomalies += 1
            try:
                self.audit.emit(
                    "temporal_anomaly", worker_id=self.worker_principal,
                    session_id=self.worker_session, decision="DENY",
                    reason_code="denied_temporal_oracle",
                    error=(
                        f"exchange latency {seconds:.1f}s "
                        f"(ceiling {_TEMPORAL_CEILING_S}s), "
                        f"volume {bytes_count} B (cap {_TEMPORAL_VOLUME_CAP} B)"
                    ),
                )
            except Exception:
                pass
        self._maybe_contain()

    def _maybe_contain(self) -> None:
        if self._events == 0 and self._exchanges == 0:
            return
        score = self.drift_score()
        if score > _DRIFT_FAIL_THRESHOLD or self._contained:
            self.watchdog.suspend(self.worker_principal, "drift > 0.50 (fail closed)")
            self.broker.revoke_all(self.worker_principal, reason="drift-fail-closed")
            self.contain_worker("fail-closed: drift > 0.50")
            self._contained = True
            return
        if score > _DRIFT_CONTAIN_THRESHOLD:
            self.watchdog.suspend(self.worker_principal, "drift > 0.30 (containment)")

    def contain_worker(self, reason: str = "operator") -> Dict[str, Any]:
        self.watchdog.suspend(self.worker_principal, reason)
        revoked = self.broker.revoke_all(self.worker_principal, reason=reason)
        return {"suspended": True, "capabilities_revoked": revoked}

    # ---------------------------------------------------------------- drill

    def drift_report(self) -> Dict[str, Any]:
        # Prototype heuristic over a minimum 10-event window (Binding 4.4
        # requires declared baseline/window; thresholds D>0.30 contain,
        # D>0.50 fail closed, strict comparisons).  The temporal dimension is
        # its own declared window over worker exchanges (latency ceiling
        # _TEMPORAL_CEILING_S, volume cap _TEMPORAL_VOLUME_CAP).
        window = max(10, self._events)
        behavioral = (self._denied_policy + self._tamper + self._replay + self._bypass) / window
        schema = self._schema_violations / window
        identity = self._identity_violations / window
        temporal_window = max(_TEMPORAL_MIN_WINDOW, self._exchanges)
        temporal = (self._temporal_anomalies / temporal_window
                    if temporal_window else 0.0)
        dims = {"schema": round(schema, 4), "identity": round(identity, 4),
                "behavioral": round(behavioral, 4),
                "temporal": round(temporal, 4)}
        candidates = [schema, identity, behavioral, temporal]
        score = max(candidates) if candidates else 0.0
        return {
            "method": "prototype-heuristic-max-dimension",
            "baseline": ("zero-violation baseline, minimum 10-event window; "
                         "temporal declared bounds: latency ceiling "
                         f"{_TEMPORAL_CEILING_S}s, volume cap "
                         f"{_TEMPORAL_VOLUME_CAP} B over a minimum "
                         f"{_TEMPORAL_MIN_WINDOW}-exchange window"),
            "window": window,
            "temporal_window": temporal_window,
            "exchanges_sampled": self._exchanges,
            "temporal_anomalies": self._temporal_anomalies,
            "dimensions": dims,
            "temporal": round(temporal, 4),
            "score": round(score, 4),
            "threshold_contain": _DRIFT_CONTAIN_THRESHOLD,
            "threshold_fail": _DRIFT_FAIL_THRESHOLD,
            "contained": self._contained,
            "limitations": "Indicators only; monitoring is per-session, in-process, not OS-enforced.",
        }

    def drift_score(self) -> float:
        return float(self.drift_report()["score"])

    def health_report(self) -> Dict[str, Any]:
        return {
            "runtime_version": VOSS_VERSION,
            "policy_version": self.policy_version,
            "policy_ok": self.policy_ok(),
            "audit_healthy": self.audit.healthy(),
            "wal_healthy": self._wal.healthy(),
            "recovery_ok": self._recovery_ok,
            "watchdog": {"ok": self.watchdog.health().ok, "detail": self.watchdog.health().detail},
            "worker_accepts_work": self.watchdog.accepts_work(self.worker_principal),
            "tools": self.tools.names(),
            "seconds_since_epoch": time.time(),
            "relay": (self.audit_relay.health() if self.audit_relay is not None else None),
            "watchdog_guard": (
                self.watchdog_guard.health()
                if getattr(self, "watchdog_guard", None) is not None else None
            ),
            "operator_console": (
                self.operator_console.health()
                if getattr(self, "operator_console", None) is not None else None
            ),
            "outbox_accounting": (
                self.outbox_accounting.health()
                if getattr(self, "outbox_accounting", None) is not None else None
            ),
        }

    # ------------------------------------------------------------ worker proc

    def spawn_worker(self, module: str = "voss.worker") -> subprocess.Popen:
        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        channel_key = os.urandom(32)
        channel_sid = new_id("chan-")
        bootstrap_path = os.path.join(
            os.path.dirname(self.audit.path) or ".", "worker-bootstrap.json")
        with open(bootstrap_path, "w", encoding="utf-8") as handle:
            json.dump(chan_bootstrap(channel_key, channel_sid), handle)
        try:
            os.chmod(bootstrap_path, 0o600)
        except OSError:
            pass
        self._channel = ChannelSession(channel_key, channel_sid, "host")
        self._bootstrap_path = bootstrap_path

        env = _clean_env(dict(os.environ))
        env["VOSS_WORKSPACE"] = self.workspace_root
        env["VOSS_CHANNEL_BOOTSTRAP"] = bootstrap_path
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.Popen(
            [sys.executable, "-m", module],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
            cwd=package_root,
            bufsize=1,
        )
        self.watchdog.register_process(self.worker_principal, proc)
        try:
            self._worker_job = confine_pid(proc.pid)
        except OSError as exc:
            self._terminate_quiet(proc)
            unlink_quiet(bootstrap_path)
            self._channel = None
            self._bootstrap_path = None
            raise RuntimeError(f"worker confinement failed: {exc}") from exc
        guard = getattr(self, "watchdog_guard", None)
        if guard is not None:
            guard.register_worker(proc.pid)
        try:
            self._channel_handshake(proc)
        except Exception:
            self._release_worker_job()
            self._terminate_quiet(proc)
            unlink_quiet(bootstrap_path)
            self._channel = None
            self._bootstrap_path = None
            raise
        return proc

    def _channel_handshake(self, proc: subprocess.Popen) -> None:
        try:
            line = self._read_worker_line(proc, _CHANNEL_TIMEOUT_S)
            msg_type, msg = self._channel.receive(line)
        except ChannelError as exc:
            self._channel_violation(exc.reason_code, "handshake")
            raise RuntimeError(
                f"worker channel handshake failed: {exc.reason_code}")
        except ChannelTimeoutError:
            self._audit_timeout("handshake")
            raise RuntimeError("worker channel handshake timed out")
        if msg_type != "hello" or msg.get("ready") is not True:
            self._channel_violation("denied_channel_auth", "handshake")
            raise RuntimeError("worker failed the channel handshake")
        proc.stdin.write(
            self._channel.send("hello_ok", {"ok": True}) + "\n")
        proc.stdin.flush()

    def _read_worker_line(self, proc: subprocess.Popen,
                          timeout: float) -> str:
        box: List[Any] = []

        def _read() -> None:
            try:
                box.append(proc.stdout.readline(_CHANNEL_LINE_READ_CAP + 1))
            except Exception as exc:  # pipe torn down under us
                box.append(exc)

        reader = threading.Thread(target=_read)
        reader.daemon = True
        reader.start()
        reader.join(timeout)
        if reader.is_alive():
            raise ChannelTimeoutError("worker produced no line in time")
        if not box:
            raise ChannelTimeoutError("worker produced no line")
        if isinstance(box[0], Exception):
            raise ChannelTimeoutError("worker stream failed")
        line = box[0]
        if not line:
            raise ChannelError("denied_channel_eof")
        if len(line) > _CHANNEL_LINE_READ_CAP:
            # Desynchronize: drain the remainder, then fail closed.
            try:
                proc.stdout.readline(_CHANNEL_DRAIN_BUDGET)
            except Exception:
                pass
            raise ChannelError("denied_channel_oversize")
        return line

    def _channel_violation(self, reason_code: str, phase: str) -> None:
        """A channel verification failure is unambiguous boundary evidence:
        suspend the worker and revoke, and make the attempt visible in audit."""
        try:
            self.audit.emit(
                "transport_denied", worker_id=self.worker_principal,
                session_id=self.worker_session, decision="DENY",
                reason_code=reason_code, error=f"channel {phase} violation",
            )
        except Exception:
            pass
        self._tamper += 1
        self.watchdog.suspend(self.worker_principal, f"channel {phase} violation")
        self.broker.revoke_all(self.worker_principal, reason="channel-violation")

    def _audit_timeout(self, phase: str) -> None:
        try:
            self.audit.emit(
                "transport_denied", worker_id=self.worker_principal,
                session_id=self.worker_session, decision="DENY",
                reason_code="denied_channel_timeout",
                error=f"channel {phase} timeout",
            )
        except Exception:
            pass

    def _terminate_quiet(self, proc: subprocess.Popen) -> None:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except Exception:
                    proc.kill()
        except Exception:
            pass

    def worker_propose(self, proc: subprocess.Popen, prompt: str) -> List[Dict]:
        if self._channel is None:
            raise RuntimeError("no authenticated channel: call spawn_worker first")
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("worker process has no pipes")
        request = {
            "prompt": prompt,
            "session_id": self.worker_session,
            "principal": self.worker_principal,
        }
        start = time.monotonic()
        try:
            proc.stdin.write(self._channel.send("prompt", request) + "\n")
            proc.stdin.flush()
            line = self._read_worker_line(proc, _CHANNEL_TIMEOUT_S)
            msg_type, msg = self._channel.receive(line)
        except ChannelError as exc:
            self._channel_violation(exc.reason_code, "propose")
            raise RuntimeError(f"worker channel violation: {exc.reason_code}")
        except ChannelTimeoutError:
            self._audit_timeout("propose")
            self._observe_exchange(_CHANNEL_TIMEOUT_S, 0)
            raise RuntimeError("worker timed out producing a proposal")
        if msg_type != "proposal" or not isinstance(msg.get("envelopes"), list):
            self._channel_violation("denied_channel_wrong_direction", "propose")
            raise RuntimeError("worker did not return a proposal list")
        self._observe_exchange(time.monotonic() - start, len(line))
        return msg["envelopes"]

    def audit_summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        last: List[Dict[str, Any]] = []
        for line_record in self.audit.records():
            rec = line_record["record"]
            event_type = rec.get("event_type", "?")
            counts[event_type] = counts.get(event_type, 0) + 1
            last.append({"event_type": event_type, "decision": rec.get("decision"), "reason_code": rec.get("reason_code")})
        return {
            "path": self.audit.path,
            "records": len(last),
            "integrity_ok": self.audit.verify_integrity(),
            "by_event_type": counts,
            "last": last[-10:],
        }

    def close(self) -> None:
        if self.outbox_accounting is not None:
            self.outbox_accounting.stop()
            self.outbox_accounting = None
        if self.operator_console is not None:
            self.operator_console.stop()
            self.operator_console = None
        if self.watchdog_guard is not None:
            self.watchdog_guard.stop()
            self.watchdog_guard = None
        if self.audit_relay is not None:
            # Stop the forwarder first so close() has a chance to drain
            # pending records while the audit file is still open.
            self.audit_relay.stop()
            self.audit_relay = None
        self.audit.close()
        self._wal.close()
        self._release_worker_job()
        if self._bootstrap_path is not None:
            unlink_quiet(self._bootstrap_path)
            self._bootstrap_path = None
        self._channel = None