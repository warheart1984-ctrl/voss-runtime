import json
import os
import tempfile
import unittest

from tests._support import make_runtime, outbox_files


class EndToEndSubprocessTest(unittest.TestCase):
    """Full flow: separate worker OS process <-> trusted runtime."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-e2e-")
        self.rt = make_runtime(self._tmp)
        self.workspace = self.rt.workspace_root
        with open(os.path.join(self.workspace, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("Write me a draft then email it.\n")
        self.proc = self.rt.spawn_worker()
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.rt.close()

    def test_worker_proposals_flow_through_broker(self):
        # 1) A0 observe read, no approval.
        envelopes = self.rt.worker_propose(self.proc, "propose:read")
        self.assertEqual(len(envelopes), 1)
        resp = self.rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
        self.assertEqual(resp.get("decision"), "ALLOW")
        self.assertIn("content", resp.get("result", {}))

        # 2) A1 workspace write with an approval gesture.
        envelopes = self.rt.worker_propose(self.proc, "propose:write")
        resp = self.rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        out = self.rt.resolve_approval(resp["approval_request_id"], "APPROVE", "operator@console")
        self.assertEqual(out.get("decision"), "ALLOW")
        draft = os.path.join(self.workspace, "drafts", "update.md")
        with open(draft, encoding="utf-8") as f:
            self.assertIn("Draft update", f.read())

        # 3) A2 external mock send, human approved, exactly one effect.
        envelopes = self.rt.worker_propose(self.proc, "propose:email")
        resp = self.rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        out = self.rt.resolve_approval(resp["approval_request_id"], "APPROVE", "operator@console")
        self.assertEqual(out.get("decision"), "ALLOW")
        self.assertEqual(len(outbox_files(self.rt.outbox_dir)), 1)

        # 4) Malicious proposals are denied at the boundary, not executed.
        envelopes = self.rt.worker_propose(self.proc, "propose:delete")
        for env in envelopes:
            resp = self.rt.handle_envelope(json.dumps(env, sort_keys=True))
            self.assertEqual(resp.get("decision"), "DENY", env["action"])

        # 5) Traversal and identity forgery are denied.
        for prompt in ("propose:escape", "propose:admin"):
            for env in self.rt.worker_propose(self.proc, prompt):
                resp = self.rt.handle_envelope(json.dumps(env, sort_keys=True))
                self.assertEqual(resp.get("decision"), "DENY", prompt)

        # Audit is authentic and complete, including the denial trail.
        self.assertTrue(self.rt.audit.verify_integrity())
        events = [r["record"]["event_type"] for r in self.rt.audit.records()]
        for expected in ("approval_request", "capability_issued", "execution_start",
                         "execution_result", "schema_violation", "denied"):
            self.assertIn(expected, events, expected)

    def test_null_prompt_still_yields_proposals(self):
        envelopes = self.rt.worker_propose(self.proc, "unrelated")
        self.assertEqual(len(envelopes), 1)
        resp = self.rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
        self.assertEqual(resp.get("decision"), "ALLOW")


class WatchdogKillDrillTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-kill-")
        self.rt = make_runtime(self._tmp)
        self.proc = self.rt.spawn_worker()

    def tearDown(self):
        try:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.rt.close()

    def test_kill_stops_new_work_revokes_caps_and_terminates(self):
        # Issue a capability first.
        env = self.rt.worker_propose(self.proc, "propose:email")[0]
        resp = self.rt.handle_envelope(json.dumps(env, sort_keys=True))
        out = self.rt.resolve_approval(resp["approval_request_id"], "APPROVE", "drill")
        self.assertEqual(out.get("decision"), "ALLOW")
        self.assertGreaterEqual(len(self.rt.broker.capabilities(self.rt.worker_principal)), 1)

        # Independent kill path.
        result = self.rt.kill_worker(reason="kill-drill", proc=self.proc)
        self.assertTrue(result["process_terminated"])
        self.assertGreaterEqual(result["capabilities_revoked"], 1)
        self.assertTrue(self.proc.poll() is not None)

        # New work is refused and capabilities are all revoked.
        env = self.rt.worker_propose(self.proc, "propose:read") if self.proc.poll() is None else None
        if env is not None:
            resp = self.rt.handle_envelope(json.dumps(env[0], sort_keys=True))
            self.assertEqual(resp.get("decision"), "DENY")
        else:
            direct = {
                "version": "1", "request_id": "req-k", "session_id": self.rt.worker_session,
                "principal": self.rt.worker_principal, "action": "workspace.read",
                "resource": {"path": "notes.txt"}, "payload": {},
                "constraints": {},
            }
            resp = self.rt.handle_envelope(json.dumps(direct, sort_keys=True))
            self.assertEqual(resp.get("decision"), "DENY")
            self.assertEqual(resp.get("reason_code"), "denied_worker_suspended")

        for cap in self.rt.broker.capabilities(self.rt.worker_principal):
            self.assertTrue(cap.revoked)

        kill_events = [r["record"] for r in self.rt.audit.records()
                       if r["record"]["event_type"] == "kill"]
        self.assertTrue(kill_events)


if __name__ == "__main__":
    unittest.main()