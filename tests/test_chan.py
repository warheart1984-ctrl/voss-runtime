"""Authenticated channel protocol unit tests (Voss RFC 9.2, Binding 4.1)."""

from __future__ import annotations

import json
import os
import unittest

import voss.chan as chan
from voss.canonical import new_id


class ChannelSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.key = os.urandom(32)
        self.sid = new_id("chan-")

    def _pair(self):
        host = chan.ChannelSession(self.key, self.sid, "host")
        adapter = chan.ChannelSession(self.key, self.sid, "adapter")
        return host, adapter

    def test_round_trip_both_roles(self) -> None:
        host, adapter = self._pair()
        adapter_line = adapter.send("hello", {"adapter": "fake", "ready": True})
        msg_type, msg = host.receive(adapter_line)
        self.assertEqual((msg_type, msg["adapter"]), ("hello", "fake"))

        host_line = host.send("prompt", {"prompt": "p", "session_id": "s",
                                         "principal": "w"})
        msg_type, msg = adapter.receive(host_line)
        self.assertEqual((msg_type, msg["prompt"]), ("prompt", "p"))

    def test_forged_mac_rejected(self) -> None:
        host, adapter = self._pair()
        line = adapter.send("hello", {"ready": True})
        record = json.loads(line)
        record["mac"] = "f" * 64
        with self.assertRaises(chan.ChannelError) as ctx:
            host.receive(json.dumps(record, sort_keys=True))
        self.assertEqual(ctx.exception.reason_code, "denied_channel_auth")

    def test_replay_rejected(self) -> None:
        host, adapter = self._pair()
        hello = adapter.send("hello", {"ready": True})
        host.receive(hello)
        with self.assertRaises(chan.ChannelError) as ctx:
            host.receive(hello)  # duplicate a2h seq
        self.assertEqual(ctx.exception.reason_code, "denied_channel_replay")

    def test_sequence_gap_rejected(self) -> None:
        host, adapter = self._pair()
        adapter.send("hello", {"ready": True})
        probe = chan.wire_line(self.key, self.sid, "a2h", 5, "proposal",
                               {"envelopes": []})
        with self.assertRaises(chan.ChannelError) as ctx:
            host.receive(probe)
        self.assertEqual(ctx.exception.reason_code, "denied_channel_sequence")

    def test_wrong_direction_rejected(self) -> None:
        host, adapter = self._pair()
        adapter.send("hello", {"ready": True})
        fake_host = chan.wire_line(self.key, self.sid, "h2a", 1, "prompt",
                                   {"prompt": "", "session_id": "",
                                    "principal": ""})
        with self.assertRaises(chan.ChannelError) as ctx:
            host.receive(fake_host)
        self.assertEqual(ctx.exception.reason_code,
                         "denied_channel_wrong_direction")

    def test_wrong_session_rejected(self) -> None:
        host, adapter = self._pair()
        other = chan.wire_line(self.key, "chan-other", "a2h", 1, "hello",
                               {"ready": True})
        with self.assertRaises(chan.ChannelError) as ctx:
            host.receive(other)
        self.assertEqual(ctx.exception.reason_code, "denied_channel_bad_session")

    def test_send_rejects_host_bound_types_from_adapter(self) -> None:
        _, adapter = self._pair()
        with self.assertRaises(chan.ChannelError):
            adapter.send("prompt", {"prompt": ""})


class BootstrapTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        key = os.urandom(32)
        sid = new_id("chan-")
        text = json.dumps(chan.chan_bootstrap(key, sid))
        loaded_key, loaded_sid = chan.read_bootstrap(text)
        self.assertEqual(loaded_key, key)
        self.assertEqual(loaded_sid, sid)

    def test_tampered_bootstrap_rejected(self) -> None:
        data = chan.chan_bootstrap(os.urandom(32), new_id("chan-"))
        data["key_hex"] = "not-hex"
        with self.assertRaises(chan.ChannelError) as ctx:
            chan.read_bootstrap(json.dumps(data))
        self.assertEqual(ctx.exception.reason_code,
                         "denied_channel_bootstrap")

    def test_reject_short_key(self) -> None:
        data = chan.chan_bootstrap(b"short", new_id("chan-"))
        with self.assertRaises(chan.ChannelError):
            chan.read_bootstrap(json.dumps(data))


if __name__ == "__main__":
    unittest.main()