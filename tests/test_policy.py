import json
import os
import tempfile
import unittest

from voss.keys import KeyRing
from voss.policy import (
    PolicyEngine,
    PolicyLoadError,
    PolicyLoader,
    Rule,
    build_policy_body,
    package_policy,
)
from tests._support import dev_policy_package, envelope, make_runtime


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-policy-")
        self.keyring = KeyRing.generate()
        self.workspace = os.path.join(self._tmp, "workspace")
        os.makedirs(self.workspace, exist_ok=True)
        self.pkg = dev_policy_package(self.keyring, self.workspace)

    def test_dev_policy_loads_and_verifies(self):
        bundle = PolicyLoader(self.keyring).load_and_verify(self.pkg)
        self.assertEqual(bundle.version, "1.0.0")
        self.assertTrue(bundle.audit_required)
        self.assertEqual(len(bundle.rules), 3)

    def test_tampered_signature_rejected(self):
        wrong = KeyRing.generate()
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(wrong).load_and_verify(self.pkg)

    def test_tampered_policy_body_rejected(self):
        body = dict(self.pkg["policy"])
        body["signer"] = "attacker"
        bad = {"policy": body, "signature": self.pkg["signature"]}
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(self.keyring).load_and_verify(bad)

    def test_audit_disabled_rejected(self):
        # A bundle that disables required audit is rejected (RFC 4.3).
        rules = [
            {"principal": "*", "action": "workspace.read", "resource_prefix": None,
             "decision": "ALLOW", "approval_required": False, "expiry_limit_seconds": 60},
            {"principal": "*", "action": "external.send_mock", "resource_prefix": {"service": "mail"},
             "decision": "ALLOW", "approval_required": True, "expiry_limit_seconds": 60},
        ]
        body = build_policy_body(
            [], version="1.0.0", audit_required=False,
        )
        body["rules"] = rules
        pkg = package_policy(body, self.keyring)
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(self.keyring).load_and_verify(pkg)

    def test_no_human_approval_gate_rejected(self):
        # Removing the last human control path must be rejected (RFC 4.3).
        rules = [
            Rule(principal="*", action="workspace.read", resource_prefix=None,
                 decision="ALLOW", approval_required=False, expiry_limit_seconds=60),
        ]
        body = build_policy_body(rules, version="1.0.0")
        pkg = package_policy(body, self.keyring)
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(self.keyring).load_and_verify(pkg)

    def test_expired_policy_rejected(self):
        from datetime import datetime, timedelta, timezone

        rules = dev_policy_package(self.keyring, self.workspace)["policy"]["rules"]
        body = build_policy_body(
            [],
            version="1.0.0",
            valid_from=(datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(),
            valid_until=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        )
        body["rules"] = rules
        pkg = package_policy(body, self.keyring)
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(self.keyring).load_and_verify(pkg)

    def test_unknown_body_field_rejected(self):
        body = dict(self.pkg["policy"])
        body["surprise"] = True
        pkg = package_policy(body, self.keyring)
        with self.assertRaises(PolicyLoadError):
            PolicyLoader(self.keyring).load_and_verify(pkg)


class PolicyEvaluationTest(unittest.TestCase):
    def test_default_deny_missing_rule(self):
        # Policy has no rule for workspace.read -> default deny.
        tmp = tempfile.mkdtemp(prefix="voss-deny-")
        workspace = os.path.join(tmp, "workspace")
        os.makedirs(workspace, exist_ok=True)
        keyring = KeyRing.generate()
        rules = [
            Rule(principal="*", action="external.send_mock", resource_prefix={"service": "mail"},
                 decision="ALLOW", approval_required=True, expiry_limit_seconds=60),
        ]
        body = build_policy_body(rules, version="1.0.0", signer="operator-test")
        rt = make_runtime(tmp, policy_package=package_policy(body, keyring), keyring=keyring)
        with open(os.path.join(workspace, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("x")
        decision = rt.handle_envelope(
            json.dumps(envelope(rt, "workspace.read", path="notes.txt"), sort_keys=True),
        )
        self.assertEqual(decision.get("decision"), "DENY")
        self.assertEqual(decision.get("reason_code"), "denied")
        rt.close()

    def test_conservative_conflict_denies(self):
        # Conflicting rules for the same (principal, action) must fail closed.
        tmp = tempfile.mkdtemp(prefix="voss-conflict-")
        workspace = os.path.join(tmp, "workspace")
        os.makedirs(workspace, exist_ok=True)
        keyring = KeyRing.generate()
        rules = [
            Rule(principal="*", action="workspace.read", resource_prefix={"path_prefix": workspace},
                 decision="ALLOW", approval_required=False, expiry_limit_seconds=60),
            Rule(principal="*", action="workspace.read", resource_prefix={"path_prefix": workspace},
                 decision="ALLOW", approval_required=True, expiry_limit_seconds=60),
        ]
        body = build_policy_body(rules, version="1.0.0", signer="operator-test")
        rt = make_runtime(tmp, policy_package=package_policy(body, keyring), keyring=keyring)
        with open(os.path.join(workspace, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("hello")
        decision = rt.handle_envelope(json.dumps(envelope(rt, "workspace.read", path="notes.txt"),
                                                 sort_keys=True))
        # Conflicting rules -> DENY (fail closed), never silent ALLOW.
        self.assertEqual(decision.get("decision"), "DENY")
        self.assertEqual(decision.get("reason_code"), "denied")
        rt.close()

    def test_engine_allow_and_approval_gates(self):
        rt = make_runtime(tempfile.mkdtemp(prefix="voss-engine-"))
        with open(os.path.join(rt.workspace_root, "notes.txt"), "w", encoding="utf-8") as f:
            f.write("x")
        read_cr = rt.normalizer.normalize(
            envelope(rt, "workspace.read", path="notes.txt"), rt.worker_principal)
        write_cr = rt.normalizer.normalize(
            envelope(rt, "workspace.write", path="draft.txt", payload={"content": "c"}),
            rt.worker_principal)
        send_cr = rt.normalizer.normalize(
            envelope(rt, "external.send_mock", payload={"subject": "s", "body": "b"}),
            rt.worker_principal)
        d1, r1, rule1 = rt.policy.evaluate(read_cr)
        d2, r2, _ = rt.policy.evaluate(write_cr)
        d3, r3, _ = rt.policy.evaluate(send_cr)
        self.assertEqual((d1, r1), ("ALLOW", "policy_allowed"))
        self.assertEqual((d2, r2), ("REQUIRE_APPROVAL", "policy_approval_required"))
        self.assertEqual((d3, r3), ("REQUIRE_APPROVAL", "policy_approval_required"))
        self.assertIsNotNone(rule1)
        rt.close()


if __name__ == "__main__":
    unittest.main()