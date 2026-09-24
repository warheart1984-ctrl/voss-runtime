import json
import os
import tempfile
import time
import unittest

from voss.canonical import new_id, sha256_hex
from tests._support import approve, envelope, make_runtime, outbox_files, submit


class BrokerExecutionTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-broker-")
        self.rt = make_runtime(self._tmp)
        self.workspace = self.rt.workspace_root
        self.outbox = self.rt.outbox_dir
        with open(os.path.join(self.workspace, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("trusted content line")

    def tearDown(self):
        self.rt.close()

    # ------------------------------------------------------------------ A0

    def test_read_requires_no_approval_but_is_logged(self):
        resp = submit(self.rt, envelope(self.rt, "workspace.read", path="notes.txt"))
        self.assertEqual(resp.get("decision"), "ALLOW")
        self.assertEqual(resp["result"]["content"], "trusted content line")
        events = [r["record"]["event_type"] for r in self.rt.audit.records()]
        self.assertIn("execution_result", events)
        # Audit stores a digest, never the plaintext content.
        audit_text = open(self.rt.audit.path, encoding="utf-8").read()
        self.assertNotIn("trusted content line", audit_text)
        self.assertIn("payload_sha256", json.dumps(
            [r["record"] for r in self.rt.audit.records()]))

    # ------------------------------------------------------------------ A1/A2

    def test_write_requires_approval_and_executes_once(self):
        env = envelope(self.rt, "workspace.write", path="drafts/update.md",
                       payload={"content": "Draft body"}, constraints={"size_max": 1000})
        resp = approve(self.rt, env)
        self.assertEqual(resp.get("decision"), "ALLOW")
        target = os.path.join(self.workspace, "drafts", "update.md")
        with open(target, encoding="utf-8") as f:
            self.assertEqual(f.read(), "Draft body")

        # Same request_id replayed with a fresh approval is still denied:
        # one request_id may never produce two external effects.
        dup = approve(self.rt, envelope(self.rt, "workspace.write", path="drafts/update.md",
                                        payload={"content": "Draft body"}, constraints={"size_max": 1000},
                                        request_id=env["request_id"]))
        self.assertEqual(dup.get("decision"), "DENY")
        self.assertEqual(dup.get("reason_code"), "denied_replay")

    def test_email_approval_bound_and_single_use(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "Update", "body": "See draft"},
                       constraints={"send_once": True})
        resp = approve(self.rt, env)
        self.assertEqual(resp.get("decision"), "ALLOW")
        self.assertEqual(resp["result"]["recipient_sha256"],
                         sha256_hex({"recipient": "alex@example.invalid"}))
        self.assertEqual(resp["result"]["delivered"], True)
        self.assertEqual(len(outbox_files(self.outbox)), 1)

        # Replay of the identical request_id cannot produce a second effect.
        dup_env = envelope(self.rt, "external.send_mock",
                           payload={"subject": "Update", "body": "See draft"},
                           constraints={"send_once": True}, request_id=env["request_id"])
        dup = approve(self.rt, dup_env)
        self.assertEqual(dup.get("decision"), "DENY")
        self.assertEqual(dup.get("reason_code"), "denied_replay")
        self.assertEqual(len(outbox_files(self.outbox)), 1)

    def test_payload_tamper_after_approval_invalidates(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "Update", "body": "See draft"},
                       constraints={"send_once": True})
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "REQUIRE_APPROVAL")
        flow_id = resp["approval_request_id"]

        # The worker advertises a different payload than was approved.
        tampered = envelope(self.rt, "external.send_mock",
                            payload={"subject": "Update", "body": "INJECTED BODY"},
                            constraints={"send_once": True},
                            request_id=env["request_id"])
        tampered_cr = self.rt.normalizer.normalize(tampered, self.rt.worker_principal)
        out = self.rt.broker.resolve_and_execute(
            flow_id, "APPROVE", "test-human", tampered_cr, self.rt.worker_principal)
        self.assertEqual(out.decision, "DENY")
        self.assertIn("tamper", out.reason_code)
        self.assertEqual(len(outbox_files(self.outbox)), 0)
        # The flow is now terminal; a fresh envelope needs a new approval.
        self.assertEqual(self.rt.approvals.get(flow_id).state, "DENIED_OR_EXPIRED")

    def test_resource_tamper_after_approval_invalidates(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "Update", "body": "See draft"},
                       constraints={"send_once": True}, recipient="alex@example.invalid")
        resp = submit(self.rt, env)
        flow_id = resp["approval_request_id"]
        tampered = envelope(self.rt, "external.send_mock",
                            payload={"subject": "Update", "body": "See draft"},
                            constraints={"send_once": True},
                            recipient="mallory@example.invalid",
                            request_id=env["request_id"])
        tampered_cr = self.rt.normalizer.normalize(tampered, self.rt.worker_principal)
        out = self.rt.broker.resolve_and_execute(
            flow_id, "APPROVE", "test-human", tampered_cr, self.rt.worker_principal)
        self.assertEqual(out.decision, "DENY")
        self.assertIn("tamper", out.reason_code)
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_deny_and_cancel_fail_closed(self):
        for decision in ("DENY", "CANCEL"):
            env = envelope(self.rt, "external.send_mock",
                           payload={"subject": "U", "body": "B"},
                           constraints={"send_once": True})
            resp = approve(self.rt, env, decision=decision)
            self.assertEqual(resp.get("decision"), "DENY")
            self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_approval_timeout_fails_closed(self):
        # Build a runtime whose policy approvals expire very fast.
        tmp = tempfile.mkdtemp(prefix="voss-timeout-")
        rt = make_runtime(tmp, expiry=1)
        env = envelope(rt, "external.send_mock", payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        resp = submit(rt, env)
        flow_id = resp["approval_request_id"]
        time.sleep(1.1)
        out = rt.resolve_approval(flow_id, "APPROVE", "late-human")
        self.assertEqual(out.get("decision"), "DENY")
        self.assertEqual(len(outbox_files(rt.outbox_dir)), 0)

    def test_uncertain_outcome_is_unknown_and_never_retried(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B", "simulate_uncertain": True},
                       constraints={"send_once": True})
        resp = approve(self.rt, env)
        self.assertEqual(resp.get("decision"), "UNKNOWN")
        self.assertEqual(resp.get("reason_code"), "unknown")

        # No automatic retry: the same request_id is recorded as executed and
        # the flow is terminal UNKNOWN.
        dup = approve(self.rt, envelope(self.rt, "external.send_mock",
                                        payload={"subject": "U", "body": "B", "simulate_uncertain": True},
                                        constraints={"send_once": True},
                                        request_id=env["request_id"]))
        self.assertEqual(dup.get("decision"), "DENY")
        self.assertEqual(dup.get("reason_code"), "denied_replay")
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_capability_revocation_blocks_use(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        resp = approve(self.rt, env)
        self.assertEqual(resp.get("decision"), "ALLOW")
        n = self.rt.broker.revoke_all(self.rt.worker_principal, reason="test")
        self.assertGreaterEqual(n, 1)
        # A follow-up proposal still needs approval but its capability would be
        # revoked at issuance; the watchdog-suspended path blocks entirely when
        # containment has engaged.
        for cap in self.rt.broker.capabilities(self.rt.worker_principal):
            self.assertTrue(cap.revoked)

    def test_capability_expiry_fails_closed_whitebox(self):
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        resp = approve(self.rt, env)
        cap = self.rt.broker.capabilities(self.rt.worker_principal)[-1]
        cap.expires_at = time.time() - 10
        cr = self.rt.normalizer.normalize(
            envelope(self.rt, "external.send_mock", payload={"subject": "U", "body": "B"},
                     constraints={"send_once": True}), self.rt.worker_principal)
        out = self.rt.broker._use(cap, cr, self.rt.worker_principal, cap.flow_id)
        self.assertEqual(out.decision, "DENY")
        self.assertEqual(out.reason_code, "denied_capability_expired")

    def test_forged_capability_reference_is_rejected(self):
        # The worker cannot attach a capability to an envelope at all.
        forged = envelope(self.rt, "external.send_mock",
                          payload={"subject": "U", "body": "B"},
                          constraints={"send_once": True})
        forged["capability_id"] = "cap-00000000000000000000000000000000"
        resp = submit(self.rt, forged)
        self.assertEqual(resp.get("decision"), "DENY")
        self.assertEqual(len(outbox_files(self.outbox)), 0)

    def test_audit_fail_closed_blocks_protected_action(self):
        self.rt.audit.close()
        env = envelope(self.rt, "external.send_mock",
                       payload={"subject": "U", "body": "B"},
                       constraints={"send_once": True})
        resp = submit(self.rt, env)
        self.assertEqual(resp.get("decision"), "DENY")
        self.assertEqual(resp.get("reason_code"), "denied")
        self.assertEqual(len(outbox_files(self.outbox)), 0)


if __name__ == "__main__":
    unittest.main()