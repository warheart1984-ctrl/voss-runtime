"""Authenticated, append-only audit log (Voss RFC 9.1).

Each record is chained to the previous record with an HMAC-SHA256 tag
computed with a key held only in the trusted process, so a worker cannot
authentically append or silently edit records.  payloads are stored by
digest, never as plaintext.  Verify integrity walks the whole chain.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

from .canonical import canonical_bytes, loads_strict, new_id, sha256_hex
from .keys import KeyRing

SCHEMA = "voss.audit.1"
GENESIS = sha256_hex({"genesis": "voss-audit-chain"})


class AuditUnavailableError(RuntimeError):
    pass


class AuditLog:
    """Authenticated, append-only ledger with MAC-chained records.

    Subclasses override ``SCHEMA``/``GENESIS`` to derive separate ledgers
    (e.g. the write-ahead recovery ledger) that share the exact chaining.
    """

    SCHEMA = SCHEMA
    GENESIS = GENESIS

    def __init__(self, path: str, keyring: KeyRing):
        self.path = path
        self._keyring = keyring
        self._lock = threading.RLock()
        self._closed = False
        self._fd = open(path, "a", encoding="utf-8")
        self._last_hash = self._scan_tail()

    def _scan_tail(self) -> str:
        digest = self.GENESIS
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    record = loads_strict(line)
                    digest = record.get("chain_hash", digest)
        except (OSError, ValueError):
            raise AuditUnavailableError(f"cannot read audit tail at {self.path}")
        return digest

    def healthy(self) -> bool:
        try:
            return not self._closed and self._fd is not None and not self._fd.closed
        except ValueError:
            return False

    def emit(
        self,
        event_type: str,
        *,
        worker_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        request_digest: Optional[str] = None,
        action: Optional[str] = None,
        action_class: Optional[str] = None,
        policy_version: Optional[str] = None,
        decision: Optional[str] = None,
        reason_code: Optional[str] = None,
        approver_ref: Optional[str] = None,
        capability_id: Optional[str] = None,
        flow_id: Optional[str] = None,
        result: Optional[Any] = None,
        error: Optional[str] = None,
        **extra: Any,
    ) -> Dict[str, Any]:
        if not self.healthy():
            raise AuditUnavailableError("audit log is unavailable (fail closed)")

        fields = {
            "schema": self.SCHEMA,
            "event_id": new_id("evt-"),
            "ts_utc": time.time(),
            "event_type": event_type,
            "worker_id": worker_id,
            "session_id": session_id,
            "request_id": request_id,
            "request_digest": request_digest,
            "action": action,
            "action_class": action_class,
            "policy_version": policy_version,
            "decision": decision,
            "reason_code": reason_code,
            "approver_ref": approver_ref,
            "capability_id": capability_id,
            "flow_id": flow_id,
            "result": result,
            "error": error,
        }
        fields.update(extra)
        payload = {k: v for k, v in fields.items() if v is not None}

        payload_bytes = canonical_bytes(payload)
        prev = self._last_hash
        mac = self._keyring.mac_audit(prev.encode("ascii") + payload_bytes)
        chain_hash = sha256_hex({"prev": prev, "record": payload_bytes.decode("ascii")})
        line_record = {
            "chain_prev": prev,
            "chain_mac": mac,
            "chain_hash": chain_hash,
            "record": payload,
        }

        with self._lock:
            if not self.healthy():
                raise AuditUnavailableError("audit log is unavailable (fail closed)")
            self._fd.write(json.dumps(line_record, sort_keys=True) + "\n")
            self._fd.flush()
            self._last_hash = chain_hash
        return line_record

    def records(self) -> Iterator[Dict[str, Any]]:
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield loads_strict(line)

    def count(self) -> int:
        return sum(1 for _ in self.records())

    def verify_integrity(self) -> bool:
        digest = self.GENESIS
        try:
            for line_record in self.records():
                prev = line_record.get("chain_prev")
                mac = line_record.get("chain_mac")
                chain = line_record.get("chain_hash")
                payload = line_record.get("record")
                if prev != digest:
                    return False
                payload_bytes = canonical_bytes(payload)
                expected_mac = self._keyring.mac_audit(digest.encode("ascii") + payload_bytes)
                if not _eq(expected_mac, mac):
                    return False
                expected_chain = sha256_hex({"prev": digest, "record": payload_bytes.decode("ascii")})
                if chain != expected_chain:
                    return False
                digest = chain
        except (OSError, ValueError, TypeError):
            return False
        return True

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                try:
                    self._fd.close()
                except OSError:
                    pass


def _eq(a: str, b: Any) -> bool:
    import hmac

    if not isinstance(b, str):
        return False
    return hmac.compare_digest(a, b)