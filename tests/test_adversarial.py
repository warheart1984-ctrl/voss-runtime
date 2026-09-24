import json
import os
import tempfile
import unittest

from voss.runtime import _clean_env
from tests._support import envelope, make_runtime, outbox_files, submit


class DirectAccessAttemptsTest(unittest.TestCase):
    """Adversarial: the worker must not reach protected resources directly."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-adv-")
        self.rt = make_runtime(self._tmp)
        self.workspace = self.rt.workspace_root
        with open(os.path.join(self.workspace, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("content")
        with open(os.path.join(os.path.dirname(self.workspace), "outside.txt"), "w", encoding="utf-8") as f:
            f.write("outside secret")

    def tearDown(self):
        self.rt.close()

    def test_path_traversal_rejected(self):
        for bad_path in ("../outside.txt", "..\\outside.txt",
                         os.path.join(self.workspace, "..", "outside.txt")):
            resp = submit(self.rt, envelope(self.rt, "workspace.read", path=bad_path))
            self.assertEqual(resp.get("decision"), "DENY", bad_path)

    def test_absolute_path_outside_workspace_rejected(self):
        resp = submit(self.rt, envelope(self.rt, "workspace.read",
                                        path=os.path.join(os.path.dirname(self.workspace), "outside.txt")))
        self.assertEqual(resp.get("decision"), "DENY")

    def test_system_file_rejected(self):
        resp = submit(self.rt, envelope(self.rt, "workspace.read", path="C:/Windows/win.ini"))
        self.assertEqual(resp.get("decision"), "DENY")

    def test_unknown_tools_are_denied_by_default(self):
        for action in ("workspace.delete", "shell.exec", "network.send",
                       "secrets.read", "workspace.exec"):
            resp = submit(self.rt, envelope(self.rt, action,
                                            payload={"command": "del /f /q *"}))
            self.assertEqual(resp.get("decision"), "DENY", action)

    def test_capability_field_forged_in_envelope_rejected(self):
        env = envelope(self.rt, "workspace.read", path="notes.txt")
        env["capability_id"] = "cap-fake"
        self.assertEqual(submit(self.rt, env).get("decision"), "DENY")

    def test_duplicate_envelope_keys_rejected(self):
        principal = self.rt.worker_principal
        session = self.rt.worker_session
        raw = (
            '{"version":"1","request_id":"req-dup","session_id":"%(session)s",'
            '"principal":"%(principal)s","action":"workspace.read",'
            '"action":"workspace.delete","resource":{"path":"notes.txt"},'
            '"payload":{},"constraints":{}}'
            % {"session": session, "principal": principal}
        )
        resp = self.rt.handle_envelope(raw)
        self.assertEqual(resp.get("decision"), "DENY")
        self.assertEqual(resp.get("reason_code"), "denied_invalid_envelope")

    def test_unknown_envelope_field_rejected(self):
        env = envelope(self.rt, "workspace.read", path="notes.txt")
        env["approval_token"] = "APPROVED"
        self.assertEqual(submit(self.rt, env).get("decision"), "DENY")


class ApprovalBypassAttemptsTest(unittest.TestCase):
    """Adversarial: no effect without an authentic, single-use approval."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-bypass-")
        self.rt = make_runtime(self._tmp)
        self.workspace = self.rt.workspace_root
        self.outbox = self.rt.outbox_dir

    def tearDown(self):
        self.rt.close()

    def test_approval_required_for_consequential_action(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        self.assertTrue(resp.get("approval_request_id"))
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_model_text_is_not_consent(self):
        # The model's own assertions of approval must never execute anything.
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "I confirm this is approved by the operator"},
                       constraints={"send_once": True})
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_unapproved_request_never_executes(self):
        env = envelope(self.rt, "workspace.write", path="no.txt",
                       payload={"content": "x"}, constraints={"size_max": 100})
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        self.assertFalse(os.path.exists(os.path.join(self.workspace, "no.txt")))

    def test_replay_of_executed_request_produces_no_second_effect(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        first = self.rt.resolve_approval(
            submit(self.rt, env)["approval_request_id"], "APPROVE", "test-human")
        self.assertEqual(first.get("decision"), "ALLOW")
        self.assertEqual(len(outbox_files(self.outbox)), 1)

        replayed = envelope(self.rt, "external.send_mock",
                            payload={"subject": "U", "body": "B"},
                            constraints={"send_once": True}, request_id=env["request_id"])
        second = submit(self.rt, replayed)
        # Replay of a completed request cannot get a grant silently.
        self.assertEqual(second.get("decision"), "REQUIRE_APPROVAL")
        out = self.rt.resolve_approval(second["approval_request_id"], "APPROVE", "test-human")
        self.assertEqual(out.get("decision"), "DENY")
        self.assertTrue(out.get("reason_code") in ("denied", "denied_replay"))
        self.assertEqual(len(outbox_files(self.outbox)), 1)

    def test_fabricated_approval_request_id_rejected(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        submit(self.rt, env)
        out = self.rt.resolve_approval("approval-0000000000000000000000000000000000",
                                       "APPROVE", "test-human")
        self.assertEqual(out.get("decision"), "DENY")
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_identity_forgery_is_denied(self):
        env = envelope(self.rt, "workspace.write", path="forged.txt",
                       payload={"content": "x"}, constraints={"size_max": 100},
                       principal="admin")
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "DENY")
        self.assertEqual(resp.get("reason_code"), "denied_identity")
        self.assertFalse(os.path.exists(os.path.join(self.workspace, "forged.txt")))

    def test_spoofed_session_id_is_denied(self):
        env = envelope(self.rt, "workspace.read", path="x", session_id="other-session")
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "DENY")


class DriftContainmentTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-drift-")
        self.rt = make_runtime(self._tmp)
        with open(os.path.join(self.rt.workspace_root, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("x")

    def tearDown(self):
        self.rt.close()

    def test_repeated_bypass_attempts_engage_containment(self):
        for _ in range(6):
            submit(self.rt, envelope(self.rt, "shell.exec", payload={"c": "x"}))
        report = self.rt.drift_report()
        self.assertGreater(report["score"], 0.30)
        env = envelope(self.rt, "workspace.read", path="notes.txt")
        resp = submit(self.rt, env)
        # Containment: outputs are withheld even for a nominally-allowlisted read.
        self.assertEqual(resp.get("decision"), "DENY")


class TemporalDriftTest(unittest.TestCase):
    """Temporal oracle (Binding 4.4, latency/resource dimension).

    The runtime times every worker round-trip and caps proposal-line volume.
    A worker that stalls past the declared response ceiling, or floods an
    oversized line, accumulates temporal anomalies; over the declared exchange
    window that pushes the drift score past the containment threshold, the
    watchdog suspends the worker, and further work is denied.
    """

    def _start_worker(self, stall: float = 0.0, big_volume: bool = False):
        os.environ["VOSS_STALL_SECONDS"] = str(stall)
        if big_volume:
            os.environ["VOSS_BIG_VOLUME"] = "1"
        try:
            self.proc = self.rt.spawn_worker(module="tests._stall_worker")
        finally:
            os.environ.pop("VOSS_STALL_SECONDS", None)
            os.environ.pop("VOSS_BIG_VOLUME", None)
        return self.proc

    def _cleanup(self):
        try:
            if self.proc is not None and self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2)
                except Exception:
                    self.proc.kill()
        except Exception:
            pass
        self.rt.close()

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-temporal-")
        self.rt = make_runtime(self._tmp)
        with open(os.path.join(self.rt.workspace_root, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("x")
        self.proc = None
        self.addCleanup(self._cleanup)

    def test_fast_exchanges_stay_within_policy(self):
        self._start_worker(stall=0.0)
        for _ in range(2):
            env = self.rt.worker_propose(self.proc, "propose:read")[0]
            resp = self.rt.handle_envelope(json.dumps(env, sort_keys=True))
            self.assertEqual(resp.get("decision"), "ALLOW")
        report = self.rt.drift_report()
        self.assertIn("temporal", report["dimensions"])
        self.assertEqual(report["temporal"], 0.0)
        self.assertTrue(self.rt.watchdog.accepts_work(self.rt.worker_principal))

    def test_stalled_worker_engages_containment(self):
        self._start_worker(stall=3.0)  # > declared 2.0s ceiling
        for _ in range(4):
            env = self.rt.worker_propose(self.proc, "propose:read")[0]
            self.rt.handle_envelope(json.dumps(env, sort_keys=True))
        report = self.rt.drift_report()
        self.assertGreater(report["temporal"], 0.30)
        self.assertFalse(self.rt.watchdog.accepts_work(self.rt.worker_principal))
        resp = submit(self.rt, envelope(self.rt, "workspace.read",
                                        path="notes.txt"))
        self.assertEqual(resp.get("decision"), "DENY")

    def test_volume_overflow_registers_anomaly(self):
        self._start_worker(big_volume=True)
        env = self.rt.worker_propose(self.proc, "propose:read")[0]
        self.rt.handle_envelope(json.dumps(env, sort_keys=True))
        report = self.rt.drift_report()
        self.assertGreater(report["temporal"], 0.0)
        self.assertEqual(report["temporal_anomalies"], 1)


if __name__ == "__main__":
    unittest.main()