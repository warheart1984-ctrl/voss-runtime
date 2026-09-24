"""Durable approval state: write-ahead ledger, recovery, and fail-closed."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from voss.approval import STATE_PENDING_APPROVAL
from voss.keys import KeyRing
from voss.wal import WriteAheadLog

from tests._support import approve, envelope, make_runtime, outbox_files, submit


class WriteAheadLogUnitTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-wal-")
        self.keyring = KeyRing.generate()

    def test_chain_roundtrip_and_verification(self) -> None:
        wal = WriteAheadLog(os.path.join(self.tmp, "wal.jsonl"), self.keyring)
        wal.emit("flow_request", flow_id="approval-1", action="workspace.write")
        wal.emit("flow_request", flow_id="approval-2", action="external.send_mock")
        self.assertTrue(wal.verify_integrity())
        ids = [r["record"]["flow_id"] for r in wal.records()]
        self.assertEqual(ids, ["approval-1", "approval-2"])
        wal.close()

    def test_tamper_detected(self) -> None:
        path = os.path.join(self.tmp, "wal.jsonl")
        wal = WriteAheadLog(path, self.keyring)
        wal.emit("flow_request", flow_id="approval-1", action="workspace.write")
        wal.emit("flow_request", flow_id="approval-2", action="external.send_mock")
        wal.close()

        lines = open(path, "r", encoding="utf-8").readlines()
        record = json.loads(lines[1])
        record["record"]["action"] = "workspace.read"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

        reopened = WriteAheadLog(path, self.keyring)
        self.assertFalse(reopened.verify_integrity())
        self.assertTrue(reopened.healthy())  # readable, but NOT trustworthy
        reopened.close()


class RecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-recovery-")

    def _restart(self):
        return make_runtime(self.tmp)

    def test_pending_approval_survives_restart(self) -> None:
        rt = make_runtime(self.tmp)
        env = envelope(rt, "workspace.write", path="draft.txt",
                       payload={"content": "recovery draft"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        flow_id = resp["approval_request_id"]
        rt.close()

        rt2 = self._restart()
        report = rt2.health_report()
        self.assertTrue(report["wal_healthy"])
        self.assertTrue(report["recovery_ok"])
        # The identity too must survive so the approval binding stays valid.
        self.assertEqual(rt2.worker_principal, rt.worker_principal)
        self.assertEqual(rt2.worker_session, rt.worker_session)
        self.assertEqual(rt2.approvals.get(flow_id).state, STATE_PENDING_APPROVAL)

        decided = rt2.resolve_approval(flow_id, "APPROVE", "test-human")
        self.assertEqual(decided["decision"], "ALLOW")
        with open(os.path.join(rt2.workspace_root, "draft.txt"), "r",
                  encoding="utf-8") as handle:
            self.assertEqual(handle.read(), "recovery draft")
        rt2.close()

    def test_consumed_request_not_replayable_after_restart(self) -> None:
        rt = make_runtime(self.tmp)
        env = envelope(rt, "external.send_mock", recipient="bob@example.invalid",
                       payload={"subject": "hi", "body": "once"})
        resp = approve(rt, env)
        self.assertEqual(resp["decision"], "ALLOW")
        first = outbox_files(rt.outbox_dir)
        self.assertEqual(len(first), 1)
        rt.close()

        rt2 = self._restart()
        self.assertTrue(rt2.health_report()["recovery_ok"])
        # Same untrusted request replayed after restart.
        again = submit(rt2, env)
        self.assertEqual(again["decision"], "REQUIRE_APPROVAL")
        decided = rt2.resolve_approval(again["approval_request_id"], "APPROVE", "test-human")
        self.assertEqual(decided["reason_code"], "denied_replay")
        self.assertEqual(outbox_files(rt2.outbox_dir), first)  # no new effect
        rt2.close()

    def test_tampered_wal_fails_closed(self) -> None:
        rt = make_runtime(self.tmp)
        env = envelope(rt, "workspace.write", path="draft.txt",
                       payload={"content": "should never be written"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        flow_id = resp["approval_request_id"]
        rt.close()

        path = os.path.join(self.tmp, "wal.jsonl")
        lines = open(path, "r", encoding="utf-8").readlines()
        record = json.loads(lines[-1])
        record["record"]["action"] = "workspace.read"
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

        rt2 = self._restart()
        report = rt2.health_report()
        self.assertTrue(report["wal_healthy"])  # readable, but NOT trustworthy
        self.assertFalse(report["recovery_ok"])
        self.assertFalse(rt2.watchdog.accepts_work(rt2.worker_principal))

        probe = submit(rt2, envelope(rt2, "workspace.write", path="draft.txt",
                                     payload={"content": "nope"}))
        self.assertEqual(probe["decision"], "DENY")
        self.assertEqual(probe["reason_code"], "denied_worker_suspended")
        decided = rt2.resolve_approval(flow_id, "APPROVE", "test-human")
        self.assertEqual(decided["decision"], "DENY")
        rt2.close()

        self.assertFalse(os.path.exists(os.path.join(self.tmp, "workspace", "draft.txt")))

    def test_recovery_events_in_audit(self) -> None:
        rt = make_runtime(self.tmp)
        env = envelope(rt, "workspace.write", path="keep.txt",
                       payload={"content": "durable"})
        resp = submit(rt, env)
        self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
        rt.close()

        rt2 = self._restart()
        types = [r["record"]["event_type"] for r in rt2.audit.records()
                 if r["record"].get("event_type") in ("recovery", "recovery_failed")]
        self.assertIn("recovery", types)
        self.assertNotIn("recovery_failed", types)
        rt2.close()


if __name__ == "__main__":
    unittest.main()