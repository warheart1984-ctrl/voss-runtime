"""End-to-end authenticated transport tests with an adversarial peer (RFC 9.2).

The trusted runtime must accept a well-behaved adapter and refuse, contain,
and audit every forged / replayed / desynchronized / oversized message.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests._support import make_runtime

MODE_FOR_REASON = [
    ("reply-forged-mac", "denied_channel_auth"),
    ("reply-replay", "denied_channel_replay"),
    ("reply-skip-seq", "denied_channel_sequence"),
    ("reply-wrong-direction", "denied_channel_wrong_direction"),
    ("reply-oversize", "denied_channel_oversize"),
]


class AuthenticatedTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-transport-")

    def _spawn_evil(self, rt, mode):
        os.environ["VOSS_EVIL_MODE"] = mode
        try:
            return rt.spawn_worker(module="tests._evil_worker")
        finally:
            os.environ.pop("VOSS_EVIL_MODE", None)

    def _transport_denied_codes(self, rt):
        return [
            r["record"]["reason_code"]
            for r in rt.audit.records()
            if r["record"].get("event_type") == "transport_denied"
        ]

    def test_happy_path_realtime_worker(self) -> None:
        rt = make_runtime(self.tmp)
        with open(os.path.join(rt.workspace_root, "notes.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("hello from the trusted host\n")
        proc = rt.spawn_worker()
        self.assertTrue(rt.health_report()["watchdog"]["ok"])

        envelopes = rt.worker_propose(proc, "propose:read")
        self.assertEqual(len(envelopes), 1)
        resp = rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
        self.assertEqual(resp["decision"], "ALLOW")
        self.assertTrue(resp["result"]["sha256"])

        # More than one authenticated exchange keeps sequences aligned.
        envelopes = rt.worker_propose(proc, "propose:write")
        self.assertEqual(len(envelopes), 1)
        self.assertEqual(
            rt.handle_envelope(json.dumps(envelopes[0], sort_keys=True))
            .get("decision"), "REQUIRE_APPROVAL")

        self.assertEqual(self._transport_denied_codes(rt), [])
        rt.kill_worker(reason="test-done", proc=proc)
        rt.close()

    def test_boundary_attacks_are_contained(self) -> None:
        for mode, reason in MODE_FOR_REASON:
            with self.subTest(mode=mode):
                rt = make_runtime(self.tmp)
                proc = self._spawn_evil(rt, mode)
                with self.assertRaises(RuntimeError) as ctx:
                    rt.worker_propose(proc, "propose:read")
                self.assertIn(reason, str(ctx.exception))
                self.assertFalse(
                    rt.watchdog.accepts_work(rt.worker_principal),
                    f"{mode}: worker must be suspended")
                self.assertIn(reason, self._transport_denied_codes(rt))
                rt.kill_worker(reason="test-done", proc=proc)
                rt.close()

    def test_forged_handshake_blocks_spawn(self) -> None:
        rt = make_runtime(self.tmp)
        os.environ["VOSS_EVIL_MODE"] = "handshake-forged-mac"
        try:
            with self.assertRaises(RuntimeError) as ctx:
                rt.spawn_worker(module="tests._evil_worker")
            self.assertIn("denied_channel_auth", str(ctx.exception))
        finally:
            os.environ.pop("VOSS_EVIL_MODE", None)
        self.assertFalse(rt.watchdog.accepts_work(rt.worker_principal))
        self.assertIn("denied_channel_auth", self._transport_denied_codes(rt))
        rt.close()


if __name__ == "__main__":
    unittest.main()