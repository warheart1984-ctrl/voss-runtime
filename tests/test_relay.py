"""Tests for the remote audit relay (RFC 9.1 write-only aggregator store).

The relay is a separate process that re-verifies every record's HMAC chain
itself and stores a byte-identical, independently verifiable copy of the
audit trail.  These tests prove the relay is faithful when legitimate, and
that nothing an attacker with no valid credential — or a corrupted host
stream — can do to it silently rewrites or poisons the store.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from voss.audit import AuditLog
from voss.keys import KeyRing
from voss.relay import (
    RELAY_PROTOCOL,
    AuditRelayClient,
    AuditRelayServer,
    _frame,
    _read_frame,
    _sign_challenge,
    _sign_hello,
    frame_signed,
)
from voss.canonical import new_id

from tests._support import envelope, make_runtime, approve

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _start_relay(tmp, timeout=15.0, transfer_key=None):
    transfer_key = transfer_key or os.urandom(32)
    store = os.path.join(tmp, "relay_store")
    os.makedirs(store, exist_ok=True)
    port_file = os.path.join(tmp, "relay_port.txt")
    proc = subprocess.Popen(
        [sys.executable, "-m", "voss.relay",
         "--store", store, "--keyring-dir", tmp,
         "--port-file", port_file, "--transfer-key", transfer_key.hex(),
         "--timeout", str(timeout)],
        cwd=PKG_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"relay died early: {proc.stderr.read()}")
        if os.path.exists(port_file):
            with open(port_file, encoding="utf-8") as handle:
                raw = handle.read().strip()
                if raw:
                    port = int(raw)
                    break
        time.sleep(0.05)
    assert port is not None, "relay port never published"
    return proc, store, port, transfer_key


def _client(tmp, port, transfer_key):
    return AuditRelayClient(
        os.path.join(tmp, "audit.jsonl"), "127.0.0.1", port, transfer_key,
    )


def _store_lines(store):
    path = os.path.join(store, "relay-audit.jsonl")
    try:
        with open(path, encoding="utf-8") as handle:
            return [line for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def _audit_lines(tmp):
    path = os.path.join(tmp, "audit.jsonl")
    try:
        with open(path, encoding="utf-8") as handle:
            return [line for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def _control_events(store):
    path = os.path.join(store, "relay-control.jsonl")
    try:
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line)["event"] for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def _control_details(store, event_prefix):
    path = os.path.join(store, "relay-control.jsonl")
    out = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec["event"].startswith(event_prefix):
                    out.append(rec["detail"])
    except FileNotFoundError:
        pass
    return out


def _sock_handshake(port, transfer_key):
    """Open a low-level client, auth it, and return (socket, ready dict)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    challenge = _read_frame(s)
    assert challenge.get("type") == "challenge", challenge
    nonce = new_id("relay-")
    s.sendall(_frame({"type": "hello", "version": RELAY_PROTOCOL,
                      "challenge": challenge["challenge"], "nonce": nonce,
                      "mac": _sign_hello(transfer_key, nonce,
                                         challenge["challenge"])}))
    reply = _read_frame(s)
    assert reply.get("type") == "hello_ok", reply
    s.sendall(_frame(frame_signed(
        RELAY_PROTOCOL, transfer_key, 1, {"type": "stream_begin"})))
    ready = _read_frame(s)
    assert ready.get("type") == "stream_ready", ready
    return s, ready


def _raw_record(event_id, content="val"):
    return {"schema": "voss.audit.1", "event_id": event_id,
            "ts_utc": time.time(), "event_type": "denied", "content": content}


def _stop_proc(proc) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()


class RelayMirrorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-relay-")
        self.proc, self.store, self.port, self.key = _start_relay(self.tmp)
        self.addCleanup(_stop_proc, self.proc)

    def test_relay_mirrors_audit_and_verifies(self) -> None:
        rt = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        # A few legitimate events of different kinds.
        rt.handle_envelope(json.dumps(envelope(rt, "workspace.read", path="notes.txt"),
                                      sort_keys=True))
        for i in range(3):
            approve(rt, envelope(rt, "workspace.write", path=f"f{i}.txt",
                                 payload={"content": f"c{i}"}))
            approve(rt, envelope(rt, "external.send_mock",
                                 recipient="alex@example.invalid"))
        # A deliberate denial so the denial trail is relayed too.
        forged = envelope(rt, "workspace.read", path="secret.txt",
                          principal="attacker")
        rt.handle_envelope(json.dumps(forged, sort_keys=True))
        rt.close()

        time.sleep(0.3)  # let tailer flush the last reads
        self.assertTrue(len(_store_lines(self.store)) >= 2)
        # Byte-identical relay store (independent re-chaining matches).
        self.assertEqual(_store_lines(self.store), _audit_lines(self.tmp))
        # Independently verifiable with the same audit chaining rules.
        keyring = KeyRing.load_or_create(self.tmp)
        self.assertTrue(AuditLog(os.path.join(self.store, "relay-audit.jsonl"),
                                 keyring).verify_integrity())
        self.assertGreaterEqual(_control_events(self.store).count("relay_accepted_hello"), 1)
        self.assertNotIn("relay_violation", _control_events(self.store))

    def test_restart_redelivery_is_idempotent(self) -> None:
        # Session 1 writes some records.
        rt1 = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        approve(rt1, envelope(rt1, "workspace.write", path="a.txt",
                              payload={"content": "a"}))
        rt1.close()
        time.sleep(0.2)

        # Session 2 is a fresh client that must replay the whole file (most of
        # it as acks) and then continue the chain with new records.
        rt2 = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        approve(rt2, envelope(rt2, "workspace.write", path="b.txt",
                              payload={"content": "b"}))
        self.assertTrue(rt2.audit_relay.health()["ok"])
        rt2.close()
        time.sleep(0.3)

        self.assertEqual(_store_lines(self.store), _audit_lines(self.tmp))
        keyring = KeyRing.load_or_create(self.tmp)
        self.assertTrue(AuditLog(os.path.join(self.store, "relay-audit.jsonl"),
                                 keyring).verify_integrity())
        self.assertNotIn("relay_violation", _control_events(self.store))

    def test_health_report_exposes_relay(self) -> None:
        rt = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        time.sleep(0.3)
        relay = rt.health_report()["relay"]
        self.assertIsNotNone(relay)
        self.assertTrue(relay["ok"])
        self.assertTrue(relay["connected"])
        rt.close()


class RelayAdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-relay-")
        self.proc, self.store, self.port, self.key = _start_relay(self.tmp)
        self.addCleanup(_stop_proc, self.proc)

    def test_probe_without_credential_is_refused_and_harmless(self) -> None:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        self.assertEqual(_read_frame(s).get("type"), "challenge")
        nonce = new_id("relay-")
        s.sendall(_frame({"type": "hello", "version": RELAY_PROTOCOL,
                          "challenge": "", "nonce": nonce, "mac": "0" * 64}))
        reply = _read_frame(s)
        self.assertEqual(reply.get("type"), "violation")
        self.assertEqual(reply.get("reason"), "denied_hello_auth")
        s.close()
        time.sleep(0.2)
        self.assertEqual(_control_events(self.store).count("relay_denied_hello"), 1)
        # The false probe did not compromise or poison the store.
        self.assertEqual(_store_lines(self.store), [])
        rt = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        time.sleep(0.3)
        approve(rt, envelope(rt, "workspace.write", path="p.txt",
                             payload={"content": "p"}))
        rt.close()
        time.sleep(0.2)
        self.assertGreater(len(_store_lines(self.store)), 0)
        self.assertNotIn("relay_violation", _control_events(self.store))

    def test_sequence_gap_compromises_store(self) -> None:
        s, _ready = _sock_handshake(self.port, self.key)
        s.sendall(_frame(frame_signed(
            RELAY_PROTOCOL, self.key, 5,
            {"type": "record", "record": _raw_record("evt-gap")})))
        reply = _read_frame(s)
        self.assertEqual(reply.get("type"), "violation")
        self.assertTrue(str(reply.get("reason")).startswith("sequence_gap"))
        s.close()
        time.sleep(0.2)
        self.assertIn("relay_violation", _control_events(self.store))
        self.assertEqual(_store_lines(self.store), [])  # nothing was stored
        # Store refuses a legit host afterwards (fail closed).
        s2 = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        self.assertEqual(_read_frame(s2).get("type"), "challenge")
        nonce = new_id("relay-")
        s2.sendall(_frame({"type": "hello", "version": RELAY_PROTOCOL,
                           "nonce": nonce,
                           "mac": _sign_hello(self.key, nonce,
                                              f"stale-{nonce}")}))
        self.assertEqual(_read_frame(s2).get("type"), "refused")
        s2.close()

    def test_duplicate_contradiction_fails_closed(self) -> None:
        s, _ready = _sock_handshake(self.port, self.key)
        s.sendall(_frame(frame_signed(
            RELAY_PROTOCOL, self.key, 1,
            {"type": "record", "record": _raw_record("evt-dup", "v1")})))
        self.assertEqual(_read_frame(s).get("type"), "ack")
        s.sendall(_frame(frame_signed(
            RELAY_PROTOCOL, self.key, 2,
            {"type": "record", "record": _raw_record("evt-dup", "v2")})))
        reply = _read_frame(s)
        self.assertEqual(reply.get("type"), "violation")
        self.assertTrue(str(reply.get("reason")).startswith("duplicate_contradiction"))
        s.close()
        time.sleep(0.2)
        self.assertEqual(len(_store_lines(self.store)), 1)  # only the honest one
        self.assertIn("relay_violation", _control_events(self.store))

    def test_oversize_frame_refused(self) -> None:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        s.sendall(b"\xff\xff\xff\xff")  # length 1 GiB > MAX_FRAME
        # server should close/refuse without reading the body
        try:
            s.settimeout(5.0)
            data = s.recv(4096)
            self.assertTrue(data)  # got a reply, either violation or close
        except (socket.timeout, OSError):
            pass
        s.close()
        time.sleep(0.2)
        events = _control_events(self.store)
        self.assertTrue(any("oversize_frame" in e for e in events)
                        or "relay_violation" in events)

    def test_replayed_hello_nonce_is_refused_and_not_compromising(self) -> None:
        # Capture a valid authenticated hello (challenge + nonce + mac), then
        # replay it within the same process: the single-use nonce refuses it.
        first = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        first_challenge = _read_frame(first)
        assert first_challenge.get("type") == "challenge", first_challenge
        nonce = new_id("relay-")
        hello = {"type": "hello", "version": RELAY_PROTOCOL,
                 "challenge": first_challenge["challenge"], "nonce": nonce,
                 "mac": _sign_hello(self.key, nonce,
                                    first_challenge["challenge"])}
        first.sendall(_frame(hello))
        self.assertEqual(_read_frame(first).get("type"), "hello_ok")
        first.close()
        time.sleep(0.2)

        # Same key holder replays the captured hello: single-use nonce.
        replay = socket.create_connection(("127.0.0.1", self.port), timeout=5.0)
        self.assertEqual(_read_frame(replay).get("type"), "challenge")
        replay.sendall(_frame(hello))
        reply = _read_frame(replay)
        self.assertEqual(reply.get("type"), "violation")
        self.assertEqual(reply.get("reason"), "denied_hello_auth")
        replay.close()
        time.sleep(0.2)

        details = _control_details(self.store, "relay_denied_hello")
        self.assertTrue(any("replayed_hello_nonce" in d for d in details))
        # The replay must not poison the store: a fresh host still works.
        rt = make_runtime(self.tmp, audit_relay=_client(self.tmp, self.port, self.key))
        approve(rt, envelope(rt, "workspace.write", path="p.txt",
                             payload={"content": "p"}))
        rt.close()
        time.sleep(0.2)
        self.assertGreater(len(_store_lines(self.store)), 0)
        self.assertNotIn("relay_violation", _control_events(self.store))


class RelayStaleTest(unittest.TestCase):
    def test_stale_flagged_then_recovered(self) -> None:
        tmp = tempfile.mkdtemp(prefix="voss-relay-")
        proc, store, port, key = _start_relay(tmp, timeout=0.4)
        self.addCleanup(_stop_proc, proc)
        s, _ready = _sock_handshake(port, key)
        # No records: the relay must flag staleness within ~0.4s.
        deadline = time.time() + 5
        while "relay_stale" not in _control_events(store) and time.time() < deadline:
            time.sleep(0.05)
        self.assertIn("relay_stale", _control_events(store))
        # A record resumes the stream and marks recovery.
        s.sendall(_frame(frame_signed(
            RELAY_PROTOCOL, key, 1,
            {"type": "record", "record": _raw_record("evt-live")})))
        self.assertEqual(_read_frame(s).get("type"), "ack")
        deadline = time.time() + 5
        while "relay_recovered" not in _control_events(store) and time.time() < deadline:
            time.sleep(0.05)
        self.assertIn("relay_recovered", _control_events(store))
        s.close()


class RelayRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp(prefix="voss-relay-recover-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.keyring = KeyRing.load_or_create(self.tmp)
        audit = AuditLog(os.path.join(self.tmp, "audit.jsonl"), self.keyring)
        audit.emit("probe", worker_id="w")
        audit.close()
        self.store = os.path.join(self.tmp, "store")
        os.makedirs(self.store)
        self.dest = os.path.join(self.store, "relay-audit.jsonl")
        shutil.copy(os.path.join(self.tmp, "audit.jsonl"), self.dest)

    def test_clean_store_reloads_uncompromised(self) -> None:
        server = AuditRelayServer(self.store, KeyRing.load_or_create(self.tmp), os.urandom(32))
        self.addCleanup(server.stop)
        self.assertFalse(server.compromised)
        self.assertGreater(server._stored_count, 0)

    def test_tampered_chain_hash_stays_compromised(self) -> None:
        with open(self.dest, encoding="utf-8") as handle:
            text = handle.read()
        import re
        text, count = re.subn(
            r'("chain_hash"\s*:\s*")[0-9a-fA-F]{64}',
            lambda match: match.group(1) + ("0" * 64),
            text,
            count=1,
        )
        self.assertEqual(count, 1)
        with open(self.dest, "w", encoding="utf-8") as handle:
            handle.write(text)
        server = AuditRelayServer(self.store, KeyRing.load_or_create(self.tmp), os.urandom(32))
        self.addCleanup(server.stop)
        self.assertTrue(server.compromised)
        from voss.audit import GENESIS
        self.assertEqual(server._head, GENESIS)


class RelayServerUnitTest(unittest.TestCase):
    def test_start_stop_and_port(self) -> None:
        tmp = tempfile.mkdtemp(prefix="voss-relay-")
        keyring = KeyRing.generate()
        server = AuditRelayServer(tmp, keyring, os.urandom(32), timeout=1.0)
        server.start()
        self.assertGreater(server.port, 0)
        server.stop()

    def test_restart_with_same_key_refuses_a_captured_hello(self) -> None:
        # The nonce cache dies with the process, so a restarted server that
        # still holds the same transfer key would treat a captured hello as
        # fresh against the nonce set alone. The per-process challenge closes
        # that: the captured hello carries the previous process's challenge.
        tmp = tempfile.mkdtemp(prefix="voss-relay-")
        key = os.urandom(32)
        first = AuditRelayServer(tmp, KeyRing.generate(), key, timeout=2.0)
        first.start()
        self.addCleanup(first.stop)
        sock = socket.create_connection(("127.0.0.1", first.port), timeout=5.0)
        first_challenge = _read_frame(sock)
        assert first_challenge.get("type") == "challenge", first_challenge
        nonce = new_id("relay-")
        hello = {"type": "hello", "version": RELAY_PROTOCOL,
                 "challenge": first_challenge["challenge"], "nonce": nonce,
                 "mac": _sign_hello(key, nonce,
                                    first_challenge["challenge"])}
        blob = _frame(hello)
        sock.sendall(blob)
        self.assertEqual(_read_frame(sock).get("type"), "hello_ok")
        sock.close()
        first.stop()

        # Restart with the same transfer key: the captured hello must be
        # refused because its challenge is stale for the new process.
        second = AuditRelayServer(tmp, KeyRing.generate(), key, timeout=2.0)
        second.start()
        self.addCleanup(second.stop)
        replay = socket.create_connection(("127.0.0.1", second.port), timeout=5.0)
        self.assertEqual(_read_frame(replay).get("type"), "challenge")
        replay.sendall(blob)
        reply = _read_frame(replay)
        self.assertEqual(reply.get("type"), "violation")
        self.assertEqual(reply.get("reason"), "denied_hello_auth")
        replay.close()
        # A legit client holding the same key still connects (fresh challenge).
        s2, _ready = _sock_handshake(second.port, key)
        s2.close()


if __name__ == "__main__":
    unittest.main()