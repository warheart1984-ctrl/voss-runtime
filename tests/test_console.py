"""Tests for the separate operator approval console (RFC 5.3, Binding 3.3).

The human consent gesture lives in its OWN OS process (``python -m
voss.console``), not the worker and not the trusted host.  The host only
pushes approval *views* over the authenticated link; votes and the kill
switch arrive back over the same link.  These tests prove:

- auto-approve from the console subprocess actually executes the effect
  (outbox file appears) and the transcript shows what the human saw;
- auto-deny is terminal with no effect, and is never cached;
- a lost console after a valid session makes the runtime fail closed on
  consequential actions (``denied_approval_unavailable``) while reads stay
  ALLOW - and it never auto-grants;
- an unauthenticated probe is refused and logged without disturbing either
  the console or a legitimate host;
- a ``kill <reason>`` directive from the console is the kill switch: the
  worker process is terminated and the watchdog suspends it.
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
from voss.console import ConsoleClient, _sign_console_hello
from voss.relay import _frame, _read_frame, frame_is_authed

from tests._support import (
    envelope, make_runtime, outbox_files, submit,
)

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _start_console(tmp, auto=None, transfer_key=None, delay=0.2):
    transfer_key = transfer_key or os.urandom(32)
    store = os.path.join(tmp, "console_store")
    os.makedirs(store, exist_ok=True)
    port_file = os.path.join(tmp, "console_port.txt")
    argv = [sys.executable, "-m", "voss.console",
            "--store", store, "--port-file", port_file,
            "--transfer-key", transfer_key.hex(), "--delay", str(delay)]
    if auto:
        argv += ["--auto", auto]
    proc = subprocess.Popen(
        argv, cwd=PKG_ROOT, text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"console died early: {proc.stderr.read()}")
        if os.path.exists(port_file):
            with open(port_file, encoding="utf-8") as handle:
                raw = handle.read().strip()
                if raw:
                    port = int(raw)
                    break
        time.sleep(0.05)
    assert port is not None, "console port never published"
    return proc, store, port, transfer_key


def _wait(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _wait_link_ok(link):
    assert _wait(lambda: link.health()["ok"]), "console link never established"


def _read_transcript(store, kind):
    records = []
    path = os.path.join(store, "console-transcript.jsonl")
    if not os.path.exists(path):
        return records
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            rec = json.loads(line)
            if rec["kind"] == kind:
                records.append(rec)
    return records


def _control_details(store, event_prefix):
    path = os.path.join(store, "console-control.jsonl")
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


class ConsoleTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name


class OperatorConsoleTest(ConsoleTestBase):
    def test_auto_approve_from_console_executes_effect(self):
        proc, store, port, key = _start_console(self.tmp, auto="approve")
        try:
            link = ConsoleClient("127.0.0.1", port, key)
            rt = make_runtime(self.tmp, operator_console=link)
            self.addCleanup(rt.close)
            _wait_link_ok(link)

            env = envelope(rt, "external.send_mock")
            resp = submit(rt, env)
            self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
            flow_id = resp["approval_request_id"]

            self.assertTrue(_wait(
                lambda: len(outbox_files(os.path.join(self.tmp, "outbox"))) == 1),
                "auto-approve never executed the effect")

            outbox_dir = os.path.join(self.tmp, "outbox")
            outbox = json.loads(
                open(os.path.join(outbox_dir, outbox_files(outbox_dir)[0]),
                     encoding="utf-8").read())
            self.assertEqual(outbox["recipient"], "alex@example.invalid")

            views = _read_transcript(store, "view")
            self.assertTrue(views, "no view was shown to the operator")
            view = views[-1]
            self.assertEqual(view["flow_id"], flow_id)
            self.assertEqual(view["action"], "external.send_mock")
            self.assertEqual(view["resource"]["service"], "mail")
            self.assertEqual(view["resource"]["recipient"], "alex@example.invalid")
            self.assertTrue(view["reversible"] in (True, False))
            self.assertIn("risk_class", view)
            self.assertIn("consequences", view)

            votes = _read_transcript(store, "vote")
            self.assertTrue(votes, "no vote came back from the console")
            self.assertEqual(votes[-1]["decision"], "APPROVE")
            self.assertTrue(votes[-1]["approver_ref"].startswith("operator@console"))
        finally:
            rt.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_auto_deny_is_terminal_and_not_cached(self):
        proc, store, port, key = _start_console(self.tmp, auto="deny")
        try:
            rt = make_runtime(self.tmp, operator_console=ConsoleClient(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.operator_console)

            env = envelope(rt, "external.send_mock")
            first = submit(rt, env)
            self.assertEqual(first["decision"], "REQUIRE_APPROVAL")
            flow_id = first["approval_request_id"]

            self.assertTrue(_wait(
                lambda: rt.approvals.get(flow_id).state == "DENIED_OR_EXPIRED"),
                "console deny never resolved the flow")
            self.assertEqual(
                len(outbox_files(os.path.join(self.tmp, "outbox"))), 0)

            second = submit(rt, env)
            self.assertEqual(second["decision"], "REQUIRE_APPROVAL")
            self.assertNotEqual(second["approval_request_id"], flow_id)
            self.assertEqual(
                len(outbox_files(os.path.join(self.tmp, "outbox"))), 0)
        finally:
            rt.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_lost_console_fails_closed_consequential_reads_allowed(self):
        proc, store, port, key = _start_console(self.tmp, auto="approve")
        rt = make_runtime(self.tmp, operator_console=ConsoleClient(
            "127.0.0.1", port, key))
        self.addCleanup(rt.close)
        _wait_link_ok(rt.operator_console)

        env = envelope(rt, "external.send_mock")
        first = submit(rt, env)
        self.assertEqual(first["decision"], "REQUIRE_APPROVAL")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        self.assertTrue(_wait(
            lambda: not rt.operator_console.health()["ok"]),
            "console loss was never detected by the client")

        second = submit(rt, env)
        self.assertEqual(second["decision"], "DENY")
        self.assertEqual(second["reason_code"], "denied_approval_unavailable")

        with open(os.path.join(rt.workspace_root, "notes.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("readable")
        read_env = envelope(rt, "workspace.read", path="notes.txt")
        read_resp = submit(rt, read_env)
        self.assertEqual(read_resp["decision"], "ALLOW")

    def test_console_never_reachable_fails_closed(self):
        rt = make_runtime(self.tmp, operator_console=ConsoleClient(
            "127.0.0.1", 1, os.urandom(32)))
        self.addCleanup(rt.close)
        time.sleep(0.4)
        resp = submit(rt, envelope(rt, "external.send_mock"))
        self.assertEqual(resp["decision"], "DENY")
        self.assertEqual(resp["reason_code"], "denied_approval_unavailable")

        with open(os.path.join(rt.workspace_root, "notes.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write("readable")
        read_resp = submit(rt, envelope(rt, "workspace.read", path="notes.txt"))
        self.assertEqual(read_resp["decision"], "ALLOW")

    def test_unauthenticated_probe_refused_and_logged(self):
        proc, store, port, key = _start_console(self.tmp, auto="approve")
        try:
            probe = socket.create_connection(("127.0.0.1", port), timeout=3)
            self.assertEqual(_read_frame(probe).get("type"), "challenge")
            probe.sendall(_frame({"type": "hello", "version": "voss.console.1",
                                  "challenge": "", "nonce": new_id("p-"),
                                  "mac": "0" * 64}))
            reply = _read_frame(probe)
            probe.close()
            self.assertEqual(reply.get("type"), "ack")
            self.assertEqual(reply.get("status"), "error")
            self.assertEqual(reply.get("reason"), "denied_console_auth")

            control_path = os.path.join(store, "console-control.jsonl")
            events = []
            with open(control_path, encoding="utf-8") as handle:
                for line in handle:
                    events.append(json.loads(line)["event"])
            self.assertIn("console_denied_hello", events)

            rt = make_runtime(self.tmp, operator_console=ConsoleClient(
                "127.0.0.1", port, key))
            self.addCleanup(rt.close)
            _wait_link_ok(rt.operator_console)
            resp = submit(rt, envelope(rt, "external.send_mock"))
            self.assertEqual(resp["decision"], "REQUIRE_APPROVAL")
            self.assertTrue(_wait(
                lambda: len(outbox_files(os.path.join(self.tmp, "outbox"))) == 1),
                "legitimate console never recovered after the probe")
        finally:
            rt.close()
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_replayed_hello_nonce_is_refused(self):
        proc, store, port, key = _start_console(self.tmp, auto="approve")
        try:
            first = socket.create_connection(("127.0.0.1", port), timeout=3)
            challenge = _read_frame(first)
            assert challenge.get("type") == "challenge", challenge
            nonce = new_id("console-")
            hello = {"type": "hello", "version": "voss.console.1",
                     "challenge": challenge["challenge"], "nonce": nonce,
                     "mac": _sign_console_hello(key, nonce,
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
            self.assertEqual(reply.get("reason"), "denied_console_auth")
            self.assertTrue(any("replayed" in d
                                for d in _control_details(store, "console_denied_hello")))
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_terminate_directive_is_the_kill_switch(self):
        proc, store, port, key = _start_console(self.tmp)
        rt = make_runtime(self.tmp, operator_console=ConsoleClient(
            "127.0.0.1", port, key))
        self.addCleanup(rt.close)
        _wait_link_ok(rt.operator_console)

        worker = rt.spawn_worker()
        proc.stdin.write("kill stop-all\n")
        proc.stdin.flush()

        self.assertTrue(_wait(
            lambda: worker.poll() is not None),
            "console terminate directive never killed the worker")
        self.assertFalse(rt.watchdog.accepts_work(rt.worker_principal))
        events = [rec["kind"]
                  for rec in _read_transcript(store, "terminate")]
        self.assertTrue(events, "no terminate gesture recorded")
        self.assertEqual(events[-1], "terminate")


if __name__ == "__main__":
    unittest.main()