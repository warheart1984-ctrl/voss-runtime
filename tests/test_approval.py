import time
import unittest

from voss.approval import (
    APPROVE,
    ApprovalController,
    ApprovalError,
    CANCEL,
    DENY,
    STATE_AUTHORIZED,
    STATE_DENIED_OR_EXPIRED,
    STATE_PENDING_APPROVAL,
)
from voss.canonical import new_id
from voss.protocol import CanonicalRequest


def _cr():
    return CanonicalRequest(
        version="1",
        request_id=new_id("req-"),
        session_id="s",
        principal="worker-1",
        action="external.send_mock",
        resource={"service": "mail", "recipient": "alex@example.invalid"},
        payload={"subject": "s", "body": "b"},
        constraints={"send_once": True},
        payload_digest="digest",
    )


class ApprovalTest(unittest.TestCase):
    def test_request_binding_includes_required_fields(self):
        ctrl = ApprovalController("1.0.0")
        flow = ctrl.request(_cr(), 60.0)
        self.assertEqual(flow.state, STATE_PENDING_APPROVAL)
        self.assertTrue(flow.nonce.startswith("nonce-"))
        self.assertTrue(flow.binding_digest)
        view = ctrl.view(flow.flow_id)
        self.assertEqual(view.policy_version, "1.0.0")
        self.assertEqual(view.payload_digest, flow.cr.payload_digest)
        self.assertEqual(view.nonce, flow.nonce)
        self.assertAlmostEqual(view.expires_in_seconds, 60.0, delta=5)

    def test_approve_authorizes_with_identity(self):
        ctrl = ApprovalController("1.0.0")
        flow = ctrl.request(_cr(), 60.0)
        resolved, authorized = ctrl.resolve(flow.flow_id, APPROVE, "operator@console")
        self.assertTrue(authorized)
        self.assertEqual(resolved.state, STATE_AUTHORIZED)
        self.assertEqual(resolved.approver_ref, "operator@console")

    def test_deny_and_cancel_are_terminal(self):
        for decision in (DENY, CANCEL):
            ctrl = ApprovalController("1.0.0")
            flow = ctrl.request(_cr(), 60.0)
            resolved, authorized = ctrl.resolve(flow.flow_id, decision, "test-human")
            self.assertFalse(authorized)
            self.assertEqual(resolved.state, STATE_DENIED_OR_EXPIRED)

    def test_expiry_is_failure(self):
        ctrl = ApprovalController("1.0.0")
        flow = ctrl.request(_cr(), 0.1)
        time.sleep(0.15)
        ctrl.pending_approval(flow.flow_id)  # triggers purge
        resolved, authorized = ctrl.resolve(flow.flow_id, APPROVE, "test-human")
        self.assertFalse(authorized)
        self.assertEqual(resolved.state, STATE_DENIED_OR_EXPIRED)

    def test_terminal_flow_cannot_be_reapproved(self):
        ctrl = ApprovalController("1.0.0")
        flow = ctrl.request(_cr(), 60.0)
        ctrl.resolve(flow.flow_id, DENY, "test-human")
        resolved, authorized = ctrl.resolve(flow.flow_id, APPROVE, "test-human")
        self.assertFalse(authorized)
        self.assertEqual(resolved.state, STATE_DENIED_OR_EXPIRED)

    def test_unknown_flow_rejected(self):
        ctrl = ApprovalController("1.0.0")
        with self.assertRaises(ApprovalError):
            ctrl.get(new_id("nope-"))

    def test_binding_digest_ties_to_payload_and_policy(self):
        ctrl = ApprovalController("1.0.0")
        flow_a = ctrl.request(_cr(), 60.0)
        changed = _cr()
        changed = CanonicalRequest(**{**changed.__dict__, "payload_digest": "different"})
        flow_b = ctrl.request(changed, 60.0)
        self.assertNotEqual(flow_a.binding_digest, flow_b.binding_digest)


if __name__ == "__main__":
    unittest.main()