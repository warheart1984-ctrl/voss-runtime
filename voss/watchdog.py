"""Independent watchdog and kill path (Voss RFC 7.4, Binding 4.7).

The watchdog does not depend on the worker it supervises.  Kill order:
stop new work -> revoke capabilities -> terminate the OS process.  State
preservation is best-effort and never delays containment.  Health and
`accepts_work` are consulted by the broker before every protected use.
"""
from __future__ import annotations

import subprocess
import threading
import time
from typing import Any, Callable, Dict, Optional

StateInfo = Any


class HealthReport:
    def __init__(self, ok: bool, detail: str = ""):
        self.ok = ok
        self.detail = detail

    def __bool__(self) -> bool:
        return self.ok


class Watchdog:
    """Supervisor that can suspend/terminate a worker and revoke grants."""

    def __init__(self, worker_id: Optional[str] = None):
        self._worker_id = worker_id
        self._suspended: set = set()
        self._procs: Dict[str, subprocess.Popen] = {}
        self._lock = threading.RLock()
        self._ok = True
        self._detail = "healthy"
        self._health_source: Optional[Callable[[], StateInfo]] = None
        self._revoke_fn: Optional[Callable[[str], int]] = None
        self._audit_fn: Optional[Callable[[str, str], None]] = None

    def attach(
        self,
        *,
        health_source: Optional[Callable[[], StateInfo]] = None,
        revoke_fn: Optional[Callable[[str], int]] = None,
        audit_fn: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._health_source = health_source
        self._revoke_fn = revoke_fn
        self._audit_fn = audit_fn

    # -------------------------------------------------------------- status

    def health(self) -> HealthReport:
        reason = ""
        if self._health_source is not None:
            source = self._health_source()
            if isinstance(source, HealthReport):
                if not source.ok:
                    reason = source.detail
        return HealthReport(self._ok and not reason, self._detail + ("; " + reason if reason else ""))

    def accepts_work(self, worker_id: str) -> bool:
        return self._ok and worker_id not in self._suspended

    # --------------------------------------------------------------- control

    def register_process(self, worker_id: str, proc: subprocess.Popen) -> None:
        with self._lock:
            self._procs[worker_id] = proc

    def suspend(self, worker_id: str, reason: str = "drift") -> None:
        """Stop new work and withhold outputs; reversible containment."""
        with self._lock:
            self._suspended.add(worker_id)
        if self._audit_fn:
            self._audit_fn(worker_id, f"suspend: {reason}")

    def resume(self, worker_id: str) -> None:
        with self._lock:
            self._suspended.discard(worker_id)

    def kill(
        self, worker_id: str, reason: str = "operator", terminate_process: bool = True
    ) -> Dict[str, Any]:
        """Stop new work -> revoke capabilities -> terminate the process."""
        with self._lock:
            self._suspended.add(worker_id)

            revoked = 0
            if self._revoke_fn and terminate_process:
                try:
                    revoked = int(self._revoke_fn(worker_id))
                except Exception:  # containment must not be blocked
                    revoked = -1

            terminated = False
            proc = self._procs.get(worker_id)
            if proc is not None and terminate_process:
                terminated = self._terminate(proc)

        if self._audit_fn:
            self._audit_fn(worker_id, f"kill: {reason}")
        return {
            "worker_id": worker_id,
            "reason": reason,
            "capabilities_revoked": revoked,
            "process_terminated": terminated,
        }

    def _terminate(self, proc: subprocess.Popen) -> bool:
        if proc.poll() is not None:
            return False
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        except OSError:
            return False
        return proc.poll() is not None


def sleep_now(duration: float) -> None:
    time.sleep(duration)