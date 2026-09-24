"""Tests for the separate watch-guard process (RFC 7.4, Binding 4.7).

The kill authority lives OUTSIDE the trusted host: the guard process holds
the worker's OS pid and terminates it when authenticated heartbeats stop or
an explicit terminate directive arrives.  These tests prove:

- heartbeats keep the worker alive across idle-timeout windows;
- stopping heartbeats makes the guard kill the worker *itself* (no host);
- an explicit terminate directive kills immediately and the guard then
  refuses any further session;
- unauthenticated hellos and malformed/regressive tick streams are refused
  and logged, and never touch a guarded worker;
- exclusivity: one host connection at a time;
- fail-closed host integration: if the guard is lost after a valid session,
  the runtime's broker stops accepting work.
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
from voss.keys import KeyRing
from voss.relay import (
    _frame, _read_frame, derive_session_key, frame_is_authed, frame_signed,
)
from voss.watchguard import (
    GUARD_PROTOCOL, WatchGuardLink, WatchGuardServer, _sign_guard_challenge,
    _sign_guard_hello,
)

from tests._support import envelope, make_runtime, submit

PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _start_guard(tmp, timeout=1.0, transfer_key=None):
    transfer_key = transfer_key or os.urandom(32)
    store = os.path.join(tmp, "guard_store")
    os.makedirs(store, exist_ok=True)
    port_file = os.path.join(tmp, "guard_port.txt")
    proc = subprocess.Popen(
        [sys.executable, "-m", "voss.watchguard",
         "--store", store, "--port-file", port_file,
         "--transfer-key", transfer_key.hex(), "--timeout", str(timeout)],
        cwd=PKG_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 30
    port = None
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"guard died early: {proc.stderr.read()}")
        if os.path.exists(port_file):
            with open(port_file, encoding="utf-8") as handle:
                raw = handle.read().strip()
                if raw:
                    port = int(raw)
                    break
        time.sleep(0.05)
    assert port is not None, "guard port never published"
    return proc, store, port, transfer_key


def _spawn_worker():
    """A long-lived process standing in for the unprivileged worker."""
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _stop_proc(proc) -> None:
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _wait_killed(proc, timeout=6.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return True
        time.sleep(0.05)
    return False


def _control_events(store):
    path = os.path.join(store, "guard-control.jsonl")
    try:
        with open(path, encoding="utf-8") as handle:
            return [json.loads(line)["event"] for line in handle if line.strip()]
    except FileNotFoundError:
        return []


def _control_details(store, event_prefix):
    path = os.path.join(store, "guard-control.jsonl")
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


def _raw_link(port, transfer_key, extra=None):
    """Low-level authenticated socket. Returns socket, hello reply, session key."""
    s = socket.create_connection(("127.0.0.1", port), timeout=5.0)
    challenge = _read_frame(s)
    assert challenge.get("type") == "challenge", challenge
    nonce = new_id("guard-")
    s.sendall(_frame({"type": "hello", "version": GUARD_PROTOCOL,
                      "challenge": challenge["challenge"], "nonce": nonce,
                      "mac": _sign_guard_hello(
                          transfer_key, nonce,
                          challenge["challenge"])}))
    frame_key = derive_session_key(
        GUARD_PROTOCOL, transfer_key, challenge["challenge"], nonce)
    reply = _read_frame(s)
    assert frame_is_authed(reply, GUARD_PROTOCOL, frame_key), reply
    assert reply.get("seq") == 1, reply
    return s, reply, frame_key


class WatchGuardProcessTests(unittest.TestCase):

    def test_heartbeats_keep_worker_alive_past_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, store, port, key = _start_guard(tmp, timeout=1.0)
            worker = _spawn_worker()
            link = WatchGuardLink("127.0.0.1", port, key, tick=0.1, timeout=1.0)
            try:
                link.start()
                link.register_worker(worker.pid)
                self._wait_registered(link)
                time.sleep(2.5)  # well past idle_timeout while heartbeat flows
                self.assertIsNone(worker.poll(), "worker must survive heartbeats")
                self.assertTrue(link.health()["ok"])
                self.assertNotIn("guard_kill", _control_events(store))
            finally:
                link.terminate("test teardown")
                link.stop()
                _stop_proc(worker)
                _stop_proc(proc)

    def test_guard_kills_worker_when_heartbeats_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=1.0)
            worker = _spawn_worker()
            link = WatchGuardLink("127.0.0.1", port, key, tick=0.1, timeout=1.0)
            link.start()
            link.register_worker(worker.pid)
            self._wait_registered(link)
            self.assertIsNone(worker.poll())
            link.stop()  # the host goes silent; no more heartbeats
            self.assertTrue(
                _wait_killed(worker),
                "guard must terminate the worker after heartbeats stop")
            details = " ".join(_control_details(store, "guard_kill"))
            self.assertIn("idle timeout", details)
            self.assertIsNone(guard.poll(), "guard process survives the kill")
            _stop_proc(guard)

    def test_terminate_directive_kills_worker_then_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=2.0)
            worker = _spawn_worker()
            link = WatchGuardLink("127.0.0.1", port, key, tick=0.1, timeout=1.0)
            link.start()
            link.register_worker(worker.pid)
            self._wait_registered(link)
            reply = link.terminate("operator")
            self.assertEqual(reply.get("status"), "triggered")
            self.assertTrue(_wait_killed(worker))
            self.assertTrue(link.health()["triggered"])
            self.assertFalse(link.health()["ok"])
            self.assertIn("explicit terminate directive",
                          " ".join(_control_details(store, "guard_kill")))
            # A fresh host session is refused after the trigger.
            link2 = WatchGuardLink("127.0.0.1", port, key,
                                   tick=0.1, timeout=1.0,
                                   on_failure=lambda r: None)
            link2.start()
            deadline = time.time() + 5.0
            while time.time() < deadline and link2.health()["connected"]:
                time.sleep(0.05)
            self.assertFalse(link2.health()["ok"])
            link2.stop()
            link.stop()
            _stop_proc(worker)
            _stop_proc(guard)

    def test_unauthenticated_hello_refused_worker_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=2.0)
            worker = _spawn_worker()
            # No legitimate host connected yet: the bad hello must be the
            # only frame the guard sees and it must be refused.
            stranger = socket.create_connection(("127.0.0.1", port), 5.0)
            self.assertEqual(_read_frame(stranger).get("type"), "challenge")
            stranger.sendall(_frame({"type": "hello", "version": GUARD_PROTOCOL,
                                     "challenge": "", "nonce": "x",
                                     "mac": "00" * 32}))
            reply = _read_frame(stranger)
            self.assertEqual(reply.get("reason"), "denied_guard_auth")
            stranger.close()
            self.assertIn("guard_denied_hello", _control_events(store))
            # A legitimate host can still register and guard the worker.
            link = WatchGuardLink("127.0.0.1", port, key,
                                  tick=0.1, timeout=1.0)
            link.start()
            link.register_worker(worker.pid)
            self._wait_registered(link)
            self.assertIsNone(worker.poll(), "worker untouched by bad hello")
            link.terminate("test teardown")
            link.stop()
            _stop_proc(worker)
            _stop_proc(guard)

    def test_tick_regression_is_anomaly(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=5.0)
            link, hello, frame_key = _raw_link(port, key)
            self.assertEqual(hello.get("status"), "ok")
            link.sendall(_frame(frame_signed(
                GUARD_PROTOCOL, frame_key, 1,
                {"type": "register", "pid": os.getpid() + 1})))
            self.assertEqual(_read_frame(link).get("status"), "ok")
            link.sendall(_frame(frame_signed(
                GUARD_PROTOCOL, frame_key, 2, {"type": "heartbeat", "tick": 5})))
            self.assertEqual(_read_frame(link).get("status"), "ok")
            link.sendall(_frame(frame_signed(
                GUARD_PROTOCOL, frame_key, 3, {"type": "heartbeat", "tick": 3})))
            reply = _read_frame(link)
            self.assertEqual(reply.get("reason"), "tick_regression")
            link.close()
            self.assertIn("guard_anomaly", _control_events(store))
            _stop_proc(guard)

    def test_replayed_hello_nonce_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=5.0)
            # Capture a valid hello then replay it on a fresh connection.
            first = socket.create_connection(("127.0.0.1", port), 5.0)
            first_challenge = _read_frame(first)
            assert first_challenge.get("type") == "challenge", first_challenge
            nonce = new_id("guard-")
            hello = {"type": "hello", "version": GUARD_PROTOCOL,
                     "challenge": first_challenge["challenge"],
                     "nonce": nonce,
                     "mac": _sign_guard_hello(
                         key, nonce, first_challenge["challenge"])}
            first.sendall(_frame(hello))
            self.assertEqual(_read_frame(first).get("status"), "ok")
            first.close()
            time.sleep(0.2)

            replay = socket.create_connection(("127.0.0.1", port), 5.0)
            self.assertEqual(_read_frame(replay).get("type"), "challenge")
            replay.sendall(_frame(hello))
            reply = _read_frame(replay)
            self.assertEqual(reply.get("status"), "error")
            self.assertEqual(reply.get("reason"), "denied_guard_auth")
            replay.close()
            self.assertTrue(any("replayed" in d
                                for d in _control_details(store, "guard_denied_hello")))
            # A legitimate host with a fresh nonce is still accepted.
            link = WatchGuardLink("127.0.0.1", port, key,
                                  tick=0.1, timeout=1.0)
            link.start()
            self._wait_guard_ok(link, "legit host refused after a replay")
            link.stop()
            _stop_proc(guard)

    def test_restart_with_same_key_refuses_a_captured_hello(self):
        # The nonce cache dies with the process. A restarted guard holding the
        # same transfer key would accept a captured hello and re-arm a stale
        # (possibly reused) pid; the per-process challenge forbids it.
        with tempfile.TemporaryDirectory() as tmp:
            key = os.urandom(32)
            store = os.path.join(tmp, "guard_store")
            os.makedirs(store, exist_ok=True)
            first = WatchGuardServer(store, key, idle_timeout=5.0)
            first.start()
            self.addCleanup(first.stop)
            sock = socket.create_connection(("127.0.0.1", first.port), 5.0)
            challenge = _read_frame(sock)
            assert challenge.get("type") == "challenge", challenge
            nonce = new_id("guard-")
            hello = {"type": "hello", "version": GUARD_PROTOCOL,
                     "challenge": challenge["challenge"], "nonce": nonce,
                     "mac": _sign_guard_hello(key, nonce,
                                              challenge["challenge"])}
            blob = _frame(hello)
            sock.sendall(blob)
            self.assertEqual(_read_frame(sock).get("status"), "ok")
            sock.close()
            first.stop()

            second = WatchGuardServer(store, key, idle_timeout=5.0)
            second.start()
            self.addCleanup(second.stop)
            replay = socket.create_connection(("127.0.0.1", second.port), 5.0)
            self.assertEqual(_read_frame(replay).get("type"), "challenge")
            replay.sendall(blob)
            reply = _read_frame(replay)
            self.assertEqual(reply.get("status"), "error")
            self.assertEqual(reply.get("reason"), "denied_guard_auth")
            replay.close()
            # Legit host still registers with a fresh challenge.
            link = WatchGuardLink("127.0.0.1", second.port, key,
                                  tick=0.1, timeout=1.0)
            link.start()
            self._wait_guard_ok(link, "legit host refused after restart")
            link.stop()

    def test_forged_post_hello_frame_without_mac_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=5.0)
            link, _hello, frame_key = _raw_link(port, key)
            # A valid hello, then a register frame whose MAC is forged (correct
            # seq, wrong mac): the guard must refuse it, connection included.
            forged = frame_signed(
                GUARD_PROTOCOL, frame_key, 1,
                {"type": "register", "pid": os.getpid() + 1})
            forged["mac"] = "0" * 64
            link.sendall(_frame(forged))
            self.assertEqual(_read_frame(link).get("reason"),
                             "denied_guard_auth")
            self.assertTrue(any("unauthenticated" in d
                                for d in _control_details(store, "guard_anomaly")))
            link.close()
            _stop_proc(guard)

    def test_guard_is_exclusive_one_host_connection(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=5.0)
            first, hello, _frame_key = _raw_link(port, key)
            self.assertEqual(hello.get("status"), "ok")
            time.sleep(0.2)
            second = socket.create_connection(("127.0.0.1", port), 5.0)
            reply = _read_frame(second)
            self.assertEqual(reply.get("type"), "busy")
            self.assertIn("guard_busy", _control_events(store))
            first.close()
            second.close()
            _stop_proc(guard)

    def test_guard_loss_fails_runtime_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            guard, store, port, key = _start_guard(tmp, timeout=5.0)
            link = WatchGuardLink("127.0.0.1", port, key,
                                  tick=0.1, timeout=1.0)
            rt = make_runtime(tmp, watchdog_guard=link)
            try:
                self._wait_guard_ok(link, "runtime must start guard-connected")
                self.assertTrue(rt.watchdog_health().ok)
                read_path = os.path.join(rt.workspace_root, "read.txt")
                with open(read_path, "w", encoding="utf-8") as handle:
                    handle.write("ok")
                env = envelope(rt, "workspace.read", path="read.txt")
                self.assertEqual(submit(rt, env)["decision"], "ALLOW")

                _stop_proc(guard)  # guard process vanishes
                deadline = time.time() + 8.0
                while time.time() < deadline and rt.watchdog_health().ok:
                    time.sleep(0.05)
                self.assertFalse(rt.watchdog_health().ok,
                                 "watchdog must fail closed on guard loss")
                report = rt.health_report()
                self.assertFalse(report["watchdog_guard"]["ok"])
                resp = submit(rt, envelope(rt, "workspace.read",
                                           path="read.txt"))
                self.assertEqual(resp["decision"], "DENY")
                self.assertEqual(resp["reason_code"],
                                 "denied_worker_suspended")
                events = [r["record"]["event_type"]
                          for r in rt.audit.records()]
                self.assertIn("guard_failure", events)
            finally:
                rt.close()

    # ------------------------------------------------------------ helpers

    def _wait_registered(self, link, timeout=5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if link.health()["registered"]:
                return
            time.sleep(0.05)
        self.fail(f"link never registered with the guard: {link.health()}")

    def _wait_guard_ok(self, link, message, timeout=5.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if link.health()["ok"]:
                return
            time.sleep(0.05)
        self.fail(f"{message}: {link.health()}")


if __name__ == "__main__":
    unittest.main()
