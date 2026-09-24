"""Fault-injection tests for the write-ahead ledger (RFC 5.5).

Each case kills the runtime at a precise boundary, reopens the same
runtime directory, and asserts exactly what ``_recover_state`` restored
and — critically — that no crash ever turns into an effect running twice or
a grant that wasn't human-approved.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from voss.approval import STATE_AUTHORIZED, STATE_PENDING_APPROVAL
from voss.keys import KeyRing
from voss.wal import WriteAheadLog

from tests._support import envelope, make_runtime, submit

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CRASH_CODE = 86


def _run_crash(root: str, mode: str) -> None:
    done = subprocess.run(
        [sys.executable, "-m", "tests._crash_driver", root, mode],
        capture_output=True, text=True, encoding="utf-8", cwd=PKG_ROOT,
        timeout=90,
    )
    assert done.returncode == CRASH_CODE, (
        f"mode {mode}: expected crash at {CRASH_CODE}, got "
        f"{done.returncode}\n{done.stderr[-800:]}")


def _wal_records(root: str):
    path = os.path.join(root, "wal.jsonl")
    out = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                out.append(json.loads(line)["record"])
    return out


class CrashInjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="voss-crash-")

    def _reopen(self):
        return make_runtime(self.root)

    def _draft_path(self, rt) -> str:
        return os.path.join(rt.workspace_root, "draft.txt")

    def _assert_clean_recovery(self, rt) -> None:
        report = rt.health_report()
        self.assertTrue(report["wal_healthy"])
        self.assertTrue(report["recovery_ok"])
        events = [r["record"]["event_type"] for r in rt.audit.records()]
        self.assertIn("recovery", events)
        self.assertNotIn("recovery_failed", events)
        self.assertTrue(rt.audit.verify_integrity())

    def test_crash_before_wal_flow_request_loses_only_that_flow(self) -> None:
        _run_crash(self.root, "flow_request_prewal")
        rt = self._reopen()
        self._assert_clean_recovery(rt)
        # Nothing was recorded for the flow, so nothing is restored.
        flows = [r for r in _wal_records(self.root)
                 if r.get("event_type") == "flow_request"]
        self.assertEqual(flows, [])
        # The request is simply re-proposed and works normally.
        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-flow_request_prewal",
                       payload={"content": "crash-test"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        out = rt.resolve_approval(resp["approval_request_id"], "APPROVE",
                                  "crash-test")
        self.assertEqual(out["decision"], "ALLOW")
        with open(self._draft_path(rt), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "crash-test")
        rt.close()

    def test_crash_after_flow_request_restores_pending_approval(self) -> None:
        _run_crash(self.root, "flow_request")
        rt = self._reopen()
        self._assert_clean_recovery(rt)

        flows = [r for r in _wal_records(self.root)
                 if r.get("event_type") == "flow_request"
                 and r.get("request_id") == "crash-flow_request"]
        self.assertEqual(len(flows), 1)
        flow_id = flows[0]["flow_id"]
        self.assertEqual(rt.approvals.get(flow_id).state,
                         STATE_PENDING_APPROVAL)

        out = rt.resolve_approval(flow_id, "APPROVE", "crash-test")
        self.assertEqual(out["decision"], "ALLOW")
        with open(self._draft_path(rt), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "crash-test")
        # A replayed copy of the same proposal cannot trigger a second effect.
        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-flow_request",
                       payload={"content": "crash-test"})
        again = submit(rt, env)
        self.assertEqual(again["decision"], "REQUIRE_APPROVAL")
        decided = rt.resolve_approval(again["approval_request_id"], "APPROVE",
                                      "crash-test")
        self.assertEqual(decided["reason_code"], "denied_replay")
        rt.close()

    def test_crash_after_approval_grants_nothing_more(self) -> None:
        # Approval was granted (AUTHORIZED) but no capability was issued:
        # the grant must NOT execute on its own after restart.
        _run_crash(self.root, "flow_resolution")
        rt = self._reopen()
        self._assert_clean_recovery(rt)

        flows = [r for r in _wal_records(self.root)
                 if r.get("event_type") == "flow_request"
                 and r.get("request_id") == "crash-flow_resolution"]
        flow_id = flows[0]["flow_id"]
        self.assertEqual(rt.approvals.get(flow_id).state, STATE_AUTHORIZED)
        self.assertEqual(rt.broker.capabilities(), [])

        denied = rt.resolve_approval(flow_id, "APPROVE", "crash-test")
        self.assertEqual(denied["decision"], "DENY")  # no silent re-grant
        self.assertFalse(os.path.exists(self._draft_path(rt)))

        # A fresh proposal goes through the normal human gate once.
        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-flow_resolution",
                       payload={"content": "crash-test"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        out = rt.resolve_approval(resp["approval_request_id"], "APPROVE",
                                  "crash-test")
        self.assertEqual(out["decision"], "ALLOW")
        with open(self._draft_path(rt), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "crash-test")
        executed = [r for r in _wal_records(self.root)
                    if r.get("event_type") == "request_executed"]
        self.assertEqual(len(executed), 1)
        rt.close()

    def test_crash_after_capability_issued_effect_runs_once(self) -> None:
        # The capability is restored but nothing executed; a fresh human
        # approval on the same proposal executes exactly once.
        _run_crash(self.root, "capability_issued")
        rt = self._reopen()
        self._assert_clean_recovery(rt)

        caps = rt.broker.capabilities(rt.worker_principal)
        self.assertEqual(len(caps), 1)
        self.assertFalse(caps[0].used)  # crash pre-execution

        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-capability_issued",
                       payload={"content": "crash-test"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        out = rt.resolve_approval(resp["approval_request_id"], "APPROVE",
                                  "crash-test")
        self.assertEqual(out["decision"], "ALLOW")
        with open(self._draft_path(rt), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "crash-test")
        executed = [r for r in _wal_records(self.root)
                    if r.get("event_type") == "request_executed"]
        self.assertEqual(len(executed), 1)
        rt.close()

    def test_crash_before_effect_blocks_replay(self) -> None:
        # The request was declared executed in the ledger the instant before
        # the effect would run; on restart the same proposal is refused.
        _run_crash(self.root, "request_executed")
        rt = self._reopen()
        self._assert_clean_recovery(rt)
        self.assertFalse(os.path.exists(self._draft_path(rt)))

        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-request_executed",
                       payload={"content": "crash-test"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        decided = rt.resolve_approval(resp["approval_request_id"], "APPROVE",
                                      "crash-test")
        self.assertEqual(decided["reason_code"], "denied_replay")
        self.assertFalse(os.path.exists(self._draft_path(rt)))
        rt.close()

    def test_crash_after_effect_never_double_executes(self) -> None:
        # The effect happened; its result event was never logged.  Restart
        # must not re-run it, even though execution_result is missing.
        _run_crash(self.root, "effect_done")
        rt = self._reopen()
        self._assert_clean_recovery(rt)
        self.assertTrue(os.path.exists(self._draft_path(rt)))
        start = [r["record"] for r in rt.audit.records()
                 if r["record"].get("event_type") == "execution_start"]
        self.assertEqual(len(start), 1)
        results = [r["record"] for r in rt.audit.records()
                   if r["record"].get("event_type") == "execution_result"]
        self.assertEqual(results, [])  # the final event was in the crash window

        env = envelope(rt, "workspace.write", path="draft.txt",
                       request_id="crash-effect_done",
                       payload={"content": "crash-test"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        decided = rt.resolve_approval(resp["approval_request_id"], "APPROVE",
                                      "crash-test")
        self.assertEqual(decided["reason_code"], "denied_replay")
        with open(self._draft_path(rt), encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "crash-test")  # one write only
        executed = [r for r in _wal_records(self.root)
                    if r.get("event_type") == "request_executed"]
        self.assertEqual(len(executed), 1)
        rt.close()


class PartialTailTruncationTest(unittest.TestCase):
    def test_incomplete_final_record_is_trimmed(self) -> None:
        tmp = tempfile.mkdtemp(prefix="voss-tailloss-")
        keyring = KeyRing.generate()

        # Append real records, then simulate a crash mid-append by leaving a
        # half-written final line.
        path = os.path.join(tmp, "wal.jsonl")
        wal = WriteAheadLog(path, keyring)
        wal.emit("flow_request", flow_id="approval-a", action="workspace.write")
        wal.emit("flow_request", flow_id="approval-b", action="workspace.read")
        wal.close()

        with open(path, "a", encoding="utf-8") as handle:
            handle.write('{"chain_hash": "deadbeef')
        assert os.path.exists(path)

        reopened = WriteAheadLog(path, keyring)
        self.assertTrue(reopened.healthy())
        records = list(reopened.records())
        self.assertEqual(len(records), 2)
        self.assertTrue(reopened.verify_integrity())
        # Runtime still appends cleanly afterwards.
        reopened.emit("flow_request", flow_id="approval-c",
                      action="workspace.write")
        self.assertTrue(reopened.verify_integrity())
        reopened.close()


if __name__ == "__main__":
    unittest.main()