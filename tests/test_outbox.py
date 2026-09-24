"""Tests for the external-action transport with independent accounting (RFC 12).

The external side of an action lives in its OWN OS process (``python -m
voss.outbox``).  The trusted host keeps no copy of the delivered event; it
must deliver over the authenticated link and get a service-side receipt.
These tests prove:

- a human-approved external action is delivered once, with a service-side
  receipt, a service-owned delivered file, and a receipt ledger entry;
- service-side idempotency: the same idempotency key can never produce a
  second effect, even if asked again;
- a delivery whose acknowledgement is dropped mid-flight is *uncertain* on
  the host side (merge: the host cannot claim completion) while the
  service ledger independently proves the delivery happened;
- a refusing/unreachable service fails the execution closed with no effect
  and no receipt, and does not block non-external actions (reads);
- a service lost after a valid session fails the next delivery closed;
- an unauthenticated probe is refused and logged without disturbing a
  legitimate host.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from voss.canonical import new_id
from voss.outbox import OutboxLink, OutboxServer, OutboxUncertain, _sign_outbox_hello
from voss.relay import _frame, _read_frame

from tests._support import approve, envelope, make_runtime, submit

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _start_outbox(tmp, *, drop_ack=False, refuse=False, transfer_key=None):
    transfer_key = transfer_key or os.urandom(32)
    store = os.path.join(tmp, "outbox_store")
    os.makedirs(store, exist_ok=True)
    port_file = os.path.join(tmp, "outbox_port.txt")
    argv = [sys.executable, "-m", "voss.outbox",
            "--store", store, "--port-file", port_file,
            "--transfer-key", transfer_key.hex()]
    if drop_ack:
        argv.append("--drop-ack")
    if refuse:
        argv.append("--refuse")
    proc = subprocess.Popen(
        argv, cwd=PKG_ROOT, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"outbox died early: {proc.stderr.read()}")
        if os.path.exists(port_file):
            with open(port_file, encoding="utf-8") as handle:
                raw = handle.read().strip()
                if raw:
                    port = int(raw)
                    break
        time.sleep(0.05)
    assert port is not None, "outbox port never published"
    return proc, store, port, transfer_key


def _wait(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _wait_link_ok(link):
    assert _wait(lambda: link.health()["ok"]), "outbox link never established"


def _delivered_files(store):
    directory = os.path.join(store, "delivered")
    if not os.path.exists(directory):
        return []
    return sorted(os.listdir(directory))


def _read_receipts(store):
    records = []
    path = os.path.join(store, "outbox-receipts.jsonl")
    if not os.path.exists(path):
        return records
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            records.append(json.loads(line))
    return records


def _control_events(store):
    events = []
    path = os.path.join(store, "outbox-control.jsonl")
    if not os.path.exists(path):
        return events
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            events.append(json.loads(line)["event"])
    return events


def _control_details(store, event_prefix):
    out = []
    path = os.path.join(store, "outbox-control.jsonl")
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec["event"].startswith(event_prefix):
                out.append(rec["detail"])
    return out


class OutboxTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def _stop_proc(self, proc):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


class OutboxAccountingTest(OutboxTestBase):
    def test_approved_delivery_produces_receipt_and_service_effect(self):
        proc, store, port, key = _start_outbox(self.tmp)
        try:
            rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.outbox_accounting)
            self.assertTrue(rt.health_report()["outbox_accounting"]["ok"])

            env = envelope(rt, "external.send_mock")
            resp = approve(rt, env)
            self.assertEqual(resp["decision"], "ALLOW")
            self.assertTrue(resp["result"]["delivered"])
            self.assertTrue(resp["result"]["receipt_id"].startswith("rcpt-"))

            files = _delivered_files(store)
            self.assertEqual(len(files), 1)
            recorded = json.loads(open(
                os.path.join(store, "delivered", files[0]),
                encoding="utf-8").read())
            self.assertEqual(recorded["receipt_id"],
                             resp["result"]["receipt_id"])
            self.assertEqual(recorded["recipient"], "alex@example.invalid")
            self.assertEqual(recorded["service"], "mail")

            receipts = _read_receipts(store)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["status"], "delivered")
            self.assertIn("outbox_delivered", _control_events(store))

            # The host kept no copy: the runtime outbox dir must be empty.
            self.assertEqual(
                sorted(os.listdir(os.path.join(self.tmp, "outbox"))), [])
        finally:
            rt.close()
            self._stop_proc(proc)

    def test_service_side_idempotency_never_double_delivers(self):
        proc, store, port, key = _start_outbox(self.tmp)
        try:
            link = OutboxLink("127.0.0.1", port, key)
            link.start()
            _wait_link_ok(link)
            ack1 = link.deliver("dlv-1", "mail", "a@example.invalid",
                                "digest-a", "idem-key-1")
            ack2 = link.deliver("dlv-2", "mail", "a@example.invalid",
                                "digest-a", "idem-key-1")
            self.assertEqual(ack1["status"], "delivered")
            self.assertEqual(ack2["status"], "duplicate")
            self.assertEqual(ack1["receipt_id"], ack2["receipt_id"])
            self.assertEqual(len(_delivered_files(store)), 1)
            self.assertEqual(len(_read_receipts(store)), 1)
            self.assertIn("outbox_duplicate", _control_events(store))
            link.stop()
        finally:
            self._stop_proc(proc)

    def test_dropped_ack_host_uncertain_service_proves_delivery(self):
        proc, store, port, key = _start_outbox(self.tmp, drop_ack=True)
        try:
            rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.outbox_accounting)

            resp = approve(rt, envelope(rt, "external.send_mock"))
            self.assertEqual(resp["decision"], "UNKNOWN")
            self.assertEqual(resp["reason_code"], "unknown")

            # The service ledger + delivered file independently prove the
            # delivery happened even though the host may not believe it.
            self.assertEqual(len(_delivered_files(store)), 1)
            receipts = _read_receipts(store)
            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["status"], "delivered")
            self.assertEqual(receipts[0]["recipient"], "alex@example.invalid")
            self.assertIn("outbox_dropped_ack", _control_events(store))
        finally:
            rt.close()
            self._stop_proc(proc)

    def test_refusing_service_fails_closed_no_effect(self):
        proc, store, port, key = _start_outbox(self.tmp, refuse=True)
        try:
            rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.outbox_accounting)

            resp = approve(rt, envelope(rt, "external.send_mock"))
            self.assertEqual(resp["decision"], "UNKNOWN")
            self.assertEqual(resp["reason_code"], "denied")
            self.assertEqual(_delivered_files(store), [])
            self.assertEqual(_read_receipts(store), [])
        finally:
            rt.close()
            self._stop_proc(proc)

    def test_unreachable_service_fails_closed_but_reads_still_work(self):
        rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
            "127.0.0.1", 1, os.urandom(32)))
        self.addCleanup(rt.close)
        time.sleep(0.4)
        self.assertFalse(rt.outbox_accounting.health()["ok"])

        resp = approve(rt, envelope(rt, "external.send_mock"))
        self.assertEqual(resp["decision"], "UNKNOWN")
        self.assertEqual(resp["reason_code"], "denied")

        # The accounting service is NOT a global gatekeeper: a plain read that
        # needs no accounting still works while the service is unavailable.
        with open(os.path.join(rt.workspace_root, "notes.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("readable")
        read_resp = submit(rt, envelope(rt, "workspace.read", path="notes.txt"))
        self.assertEqual(read_resp["decision"], "ALLOW")

    def test_link_loss_after_valid_session_fails_next_delivery_closed(self):
        proc, store, port, key = _start_outbox(self.tmp)
        rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
            "127.0.0.1", port, key))
        self.addCleanup(rt.close)
        _wait_link_ok(rt.outbox_accounting)

        first = approve(rt, envelope(rt, "external.send_mock"))
        self.assertEqual(first["decision"], "ALLOW")
        self.assertEqual(len(_delivered_files(store)), 1)

        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        second = approve(rt, envelope(rt, "external.send_mock"))
        self.assertEqual(second["decision"], "UNKNOWN")
        self.assertIn(second["reason_code"],
                      ("denied", "unknown"))
        self.assertEqual(len(_delivered_files(store)), 1)  # no redelivery

        self.assertTrue(_wait(
            lambda: not rt.outbox_accounting.health()["ok"]),
            "outbox loss was never detected by the link")
        self.assertTrue(rt.outbox_accounting.health()["failed"])

    def test_unauthenticated_probe_refused_and_logged(self):
        proc, store, port, key = _start_outbox(self.tmp)
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=3)
            self.assertEqual(_read_frame(probe).get("type"), "challenge")
            probe.sendall(_frame({"type": "hello",
                                  "version": "voss.outbox.1",
                                  "challenge": "", "nonce": new_id("p-"),
                                  "mac": "0" * 64}))
            reply = _read_frame(probe)
            probe.close()
            self.assertEqual(reply.get("type"), "ack")
            self.assertEqual(reply.get("status"), "error")
            self.assertEqual(reply.get("reason"), "denied_outbox_auth")
            self.assertIn("outbox_denied_hello", _control_events(store))

            rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.outbox_accounting)
            resp = approve(rt, envelope(rt, "external.send_mock"))
            self.assertEqual(resp["decision"], "ALLOW")
            self.assertEqual(len(_delivered_files(store)), 1)
        finally:
            rt.close()
            self._stop_proc(proc)

    def test_replayed_hello_nonce_is_refused(self):
        proc, store, port, key = _start_outbox(self.tmp)
        try:
            first = socket.create_connection(("127.0.0.1", port), timeout=3)
            challenge = _read_frame(first)
            assert challenge.get("type") == "challenge", challenge
            nonce = new_id("ob-")
            hello = {"type": "hello", "version": "voss.outbox.1",
                     "challenge": challenge["challenge"], "nonce": nonce,
                     "mac": _sign_outbox_hello(key, nonce,
                                               challenge["challenge"])}
            first.sendall(_frame(hello))
            self.assertEqual(_read_frame(first).get("type"), "hello_ok")
            first.close()
            time.sleep(0.2)

            replay = socket.create_connection(("127.0.0.1", port), timeout=3)
            self.assertEqual(_read_frame(replay).get("type"), "challenge")
            replay.sendall(_frame(hello))
            reply = _read_frame(replay)
            replay.close()
            self.assertEqual(reply.get("status"), "error")
            self.assertEqual(reply.get("reason"), "denied_outbox_auth")
            self.assertTrue(any("replayed" in d
                                for d in _control_details(store, "outbox_denied_hello")))

            # A legitimate fresh-session host still delivers.
            rt = make_runtime(self.tmp, outbox_accounting=OutboxLink(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.outbox_accounting)
            resp = approve(rt, envelope(rt, "external.send_mock"))
            self.assertEqual(resp["decision"], "ALLOW")
            self.assertEqual(len(_delivered_files(store)), 1)
        finally:
            rt.close()
            self._stop_proc(proc)


class OutboxStorageTest(unittest.TestCase):
    def test_recorded_delivery_without_effect_file_is_uncertain(self) -> None:
        tmp = tempfile.mkdtemp(prefix="voss-outbox-uncertain-")
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, True))
        key = os.urandom(32)
        server = OutboxServer(tmp, key)
        self.addCleanup(server.stop)
        os.rmdir(server.delivered_dir)
        with open(server.delivered_dir, "w", encoding="utf-8") as handle:
            handle.write("blocked")
        server.start()
        link = OutboxLink("127.0.0.1", server.port, key, timeout=2.0)
        link.start()
        self.addCleanup(link.stop)
        deadline = time.time() + 5
        while time.time() < deadline and not link.health()["connected"]:
            time.sleep(0.05)
        self.assertTrue(link.health()["connected"])
        digest = "ab" * 32
        with self.assertRaises(OutboxUncertain):
            link.deliver("dlv-1", "mail", "a@b.invalid", digest, "req-1")
        with self.assertRaises(OutboxUncertain):
            link.deliver("dlv-2", "mail", "a@b.invalid", digest, "req-1")
        with open(server.ledger_path, encoding="utf-8") as handle:
            ledger = handle.read()
        self.assertEqual(ledger.count("req-1"), 1)
        self.assertNotIn("refused", ledger)


if __name__ == "__main__":
    unittest.main()
