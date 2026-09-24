import json
import os
import tempfile
import unittest

from voss.audit import AuditLog, AuditUnavailableError
from voss.keys import KeyRing


class AuditTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="voss-audit-")
        self.path = os.path.join(self._tmp, "audit.jsonl")
        self.keyring = KeyRing.generate()

    def test_chain_evolves_and_verifies(self):
        log = AuditLog(self.path, self.keyring)
        prev = None
        for i in range(3):
            rec = log.emit("decision", decision="DENY", request_id=f"req-{i}")
            if prev is not None:
                self.assertEqual(rec["chain_prev"], prev)
            prev = rec["chain_hash"]
        self.assertTrue(log.verify_integrity())
        log.close()

    def test_tamper_detected(self):
        log = AuditLog(self.path, self.keyring)
        log.emit("decision", decision="DENY", reason_code="denied_policy_no_rule")
        log.close()

        with open(self.path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        tampered = json.loads(lines[0])
        tampered["record"]["decision"] = "ALLOW"   # attacker rewrites a record
        lines[0] = json.dumps(tampered, sort_keys=True) + "\n"
        with open(self.path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        log = AuditLog(self.path, self.keyring)
        self.assertFalse(log.verify_integrity())
        log.close()

    def test_unavailable_audit_raises(self):
        log = AuditLog(self.path, self.keyring)
        log.close()
        with self.assertRaises(AuditUnavailableError):
            log.emit("decision", decision="DENY")

    def test_no_plaintext_payload_or_secrets(self):
        log = AuditLog(self.path, self.keyring)
        plaintext_body = "super sensitive draft body content"
        log.emit(
            "execution_result",
            decision="ALLOW",
            result={"payload_sha256": "abc", "bytes": 5},
            worker_id="worker-x",
        )
        log.close()
        text = open(self.path, encoding="utf-8").read()
        self.assertNotIn(plaintext_body, text)
        self.assertNotIn(self.keyring._audit_key.hex(), text)  # internal-only key
        self.assertNotIn(self.keyring._policy_key.hex(), text)

    def test_healthy_false_after_close(self):
        log = AuditLog(self.path, self.keyring)
        self.assertTrue(log.healthy())
        log.close()
        self.assertFalse(log.healthy())


if __name__ == "__main__":
    unittest.main()