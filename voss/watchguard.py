"""Watch-guard: kill authority OUTSIDE the trusted host (RFC 7.4, Binding 4.7).

The prototype's in-host ``watchdog.py`` is a thread: a host that is dead,
hung, or compromised owns its own kill switch.  The RFC requires the
watchdog/kill path not depend on the worker *or its host*.  This module
emulates that on stdlib sockets, mirroring the audit relay architecture:

- ``WatchGuardServer`` runs as its own process (``python -m voss.watchguard``),
  binds 127.0.0.1 and requires an HMAC-authenticated handshake (per-launch
  transfer key) before it accepts a host connection.
- The host registers the worker's OS pid with the guard, then sends periodic
  authenticated heartbeats.
- The guard holds the pid and the kill decision.  If heartbeats stop for
  ``idle_timeout`` seconds — the host is gone, hung, or compromised — the
  guard terminates the worker process itself.  It also obeys an explicit
  ``terminate`` directive (the operator kill switch), executed in a process
  the host does not control.
- Once triggered the guard fails closed: it refuses further registrations and
  heartbeats; a new worker requires a new guard instance (per-launch).
- On the host side, ``WatchGuardLink`` fails closed too: once the guard
  becomes unreachable after a successful session, or reports ``triggered``,
  the link's health stays bad and the runtime broker stops accepting work.

The guard cannot forge or grant anything; its only authority is the kill.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import signal
import socket
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from .canonical import new_id
from .relay import (
    _frame, _read_frame, frame_signed, frame_is_authed, derive_session_key,
    graceful_close,
)

GUARD_PROTOCOL = "voss.watchguard.1"
_IDLE_TIMEOUT = 3.0
_HEARTBEAT_TICK = 0.5


def _sign_guard_hello(transfer_key: bytes, nonce: str, challenge: str) -> str:
    # Domain-separated from the relay protocol string so a leaked or shared
    # transfer key cannot authenticate a hello against the wrong service.
    return hmac.new(
        transfer_key,
        GUARD_PROTOCOL.encode("ascii")
        + b":" + challenge.encode("ascii")
        + b":" + nonce.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _sign_guard_challenge(transfer_key: bytes, challenge: str) -> str:
    return hmac.new(
        transfer_key,
        GUARD_PROTOCOL.encode("ascii") + b":challenge:" + challenge.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _write_control(path: str, event: str, detail: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                '{"ts": %s, "event": "%s", "detail": "%s"}\n'
                % (time.time(), event, detail.replace('"', "'"))
            )
            handle.flush()
    except OSError:
        pass


class GuardAnomaly(RuntimeError):
    pass


class WatchGuardServer:
    """Separate-process kill authority. Per-launch; one worker per instance."""

    def __init__(
        self,
        store_dir: str,
        transfer_key: bytes,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        idle_timeout: float = _IDLE_TIMEOUT,
    ):
        if not transfer_key or len(transfer_key) < 16:
            raise ValueError("transfer key must be at least 16 bytes")
        self.store_dir = os.path.realpath(os.path.abspath(store_dir))
        os.makedirs(self.store_dir, exist_ok=True)
        self.control_path = os.path.join(self.store_dir, "guard-control.jsonl")
        self._transfer_key = transfer_key
        self._idle_timeout = max(float(idle_timeout), 0.2)
        # Fresh per-process challenge: a restart mints a new one, so a hello
        # captured against a previous guard process cannot re-arm the guard
        # against a (possibly reused) pid even with the same transfer key.
        self._challenge = new_id("challenge-")
        self._seen_nonces: set = set()  # hello nonces, this process only
        self._frame_key = b""
        self._reply_seq = 0

        self._lock = threading.RLock()
        self._pid: Optional[int] = None
        self._registered = False
        self._triggered = False
        self._last_heartbeat: Optional[float] = None
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._active_conn: Optional[socket.socket] = None
        self._serve_thread: Optional[threading.Thread] = None
        self._monitor_thread: Optional[threading.Thread] = None

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(4)
        self.host, self.port = self._listener.getsockname()[:2]

    @property
    def triggered(self) -> bool:
        with self._lock:
            return self._triggered

    def start(self) -> None:
        if self._serve_thread is not None:
            return
        self._serve_thread = threading.Thread(
            target=self._serve_loop, name="voss-watch-guard", daemon=True)
        self._serve_thread.start()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, name="voss-watch-guard-monitor",
            daemon=True)
        self._monitor_thread.start()
        _write_control(self.control_path, "guard_started", f"pid={os.getpid()}")

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._listener is not None:
                self._listener.close()
        except OSError:
            pass
        for thread in (self._serve_thread, self._monitor_thread):
            if thread is not None:
                thread.join(timeout=5.0)

    # --------------------------------------------------------------- monitor
    # The kill decision lives in this process: independent of any connection.

    def _monitor_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(0.1)
            self._maybe_trigger("idle timeout")

    def _maybe_trigger(self, reason: str) -> bool:
        with self._lock:
            if self._triggered or not self._registered:
                return False
            last = self._last_heartbeat
            now = time.monotonic()
            if last is not None and now - last <= self._idle_timeout:
                return False
            self._triggered = True
            pid = self._pid
        if pid is None:
            detail = "no heartbeat before registration completed"
            _write_control(self.control_path, "guard_triggered_no_pid", detail)
            return True
        self._kill_pid(
            pid, "guarded worker", f"{reason}: no heartbeat for "
            f"{self._idle_timeout:.1f}s")
        return True

    # ------------------------------------------------------------- connection

    def _serve_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            with self._lock:
                if self._triggered:
                    _write_control(self.control_path, "guard_refused_triggered",
                                   "connection after trigger")
                elif self._active_conn is not None:
                    _write_control(self.control_path, "guard_busy",
                                   "another host is connected")
                    self._reply(conn, {"type": "busy"})
                    graceful_close(conn)
                    continue
                else:
                    self._active_conn = conn
            threading.Thread(
                target=self._serve_conn, args=(conn,),
                name="voss-watch-guard-conn", daemon=True,
            ).start()

    def _serve_conn(self, conn: socket.socket) -> None:
        try:
            self._handle(conn)
        finally:
            with self._lock:
                if self._active_conn is conn:
                    self._active_conn = None
            graceful_close(conn)

    def _handle(self, conn: socket.socket) -> None:
        # The monitor owns the heartbeat-timeout kill; this loop only serves
        # the wire protocol and knows the current trigger state.
        conn.settimeout(min(0.5, self._idle_timeout / 2))
        # Speak first with this process's challenge; hello must MAC over it.
        self._reply(conn, {"type": "challenge",
                           "challenge": self._challenge,
                           "mac": _sign_guard_challenge(
                               self._transfer_key, self._challenge)})
        phase = "hello"
        conn_tick: Optional[int] = None
        auth_seq = 1
        self._reply_seq = 0
        self._frame_key = b""
        while not self._stop.is_set():
            if self.triggered:
                self._reply(conn, {"type": "ack", "status": "triggered"})
                return
            try:
                msg = _read_frame(conn)
            except socket.timeout:
                continue
            except Exception as exc:
                if not isinstance(exc, (ConnectionResetError,
                                        ConnectionAbortedError)):
                    self._write_guard_issue(str(exc)[:120])
                return

            if phase == "hello":
                reason = self._claim_hello(msg)
                if reason:
                    _write_control(self.control_path, "guard_denied_hello",
                                   f"{reason}:{str(msg)[:120]}")
                    self._reply(conn, {"type": "ack", "status": "error",
                                       "reason": "denied_guard_auth"})
                    return
                self._frame_key = derive_session_key(
                    GUARD_PROTOCOL, self._transfer_key, self._challenge,
                    str(msg["nonce"]),
                )
                _write_control(self.control_path, "guard_hello_ok", "guard")
                self._reply_session(conn, {"type": "ack", "status": "ok"})
                phase = "guard"
                conn_tick = None
                with self._lock:
                    self._last_heartbeat = time.monotonic()
                continue

            if not frame_is_authed(msg, GUARD_PROTOCOL, self._frame_key):
                _write_control(self.control_path, "guard_anomaly",
                               "unauthenticated frame")
                self._reply_session(conn, {"type": "ack", "status": "error",
                                           "reason": "denied_guard_auth"})
                return
            if msg.get("seq") != auth_seq:
                _write_control(self.control_path, "guard_anomaly",
                               f"sequence_error expected {auth_seq} "
                               f"got {msg.get('seq')}")
                self._reply_session(conn, {"type": "ack", "status": "error",
                                           "reason": "sequence_error"})
                return
            auth_seq += 1

            if msg.get("type") == "register":
                if self._registered:
                    self._reply_session(conn, {"type": "ack", "status": "error",
                                               "reason": "guard_already_registered"})
                    return
                pid = msg.get("pid")
                if not isinstance(pid, int) or pid <= 0:
                    self._reply_session(conn, {"type": "ack", "status": "error",
                                               "reason": "invalid_pid"})
                    return
                with self._lock:
                    self._pid, self._registered, self._last_heartbeat = (
                        pid, True, time.monotonic())
                _write_control(self.control_path, "guard_register", f"pid={pid}")
                self._reply_session(conn, {"type": "ack", "status": "ok"})
                continue

            if msg.get("type") == "heartbeat":
                tick = msg.get("tick")
                if not isinstance(tick, int) or tick < 0:
                    self._reply_session(conn, {"type": "ack", "status": "error",
                                               "reason": "invalid_tick"})
                    return
                if conn_tick is not None and tick <= conn_tick:
                    _write_control(self.control_path, "guard_anomaly",
                                   f"heartbeat tick regressed "
                                   f"{conn_tick}->{tick}")
                    self._reply_session(conn, {"type": "ack", "status": "error",
                                               "reason": "tick_regression"})
                    return
                conn_tick = tick
                with self._lock:
                    self._last_heartbeat = time.monotonic()
                self._reply_session(conn, {"type": "ack", "status": "ok"})
                continue

            if msg.get("type") == "terminate":
                with self._lock:
                    self._triggered = True
                    pid = self._pid
                reason = str(msg.get("reason", "") or "operator")
                _write_control(self.control_path, "guard_terminate_directive",
                               reason)
                if pid is not None:
                    self._kill_pid(pid, "guarded worker",
                                   f"explicit terminate directive ({reason})")
                self._reply_session(conn, {"type": "ack", "status": "triggered"})
                return

            self._reply_session(conn, {"type": "ack", "status": "error",
                                       "reason": "unknown_guard_frame"})
            return

    def _valid_hello(self, msg: Dict[str, Any]) -> bool:
        if msg.get("type") != "hello":
            return False
        if msg.get("version") != GUARD_PROTOCOL:
            return False
        challenge = msg.get("challenge")
        nonce, mac = msg.get("nonce"), msg.get("mac")
        return (
            isinstance(challenge, str) and challenge == self._challenge
            and isinstance(nonce, str) and isinstance(mac, str)
            and mac == _sign_guard_hello(self._transfer_key, nonce, challenge)
        )

    def _claim_hello(self, msg: Dict[str, Any]) -> str:
        """Refuse a bad hello, or a replayed single-use nonce (reason string)."""
        if not self._valid_hello(msg):
            return "denied_guard_auth"
        nonce = msg.get("nonce")
        with self._lock:
            if nonce in self._seen_nonces:
                return "replayed_hello_nonce"
            self._seen_nonces.add(nonce)
        return ""

    def _kill_pid(self, pid: int, subject: str, detail: str) -> None:
        terminated = False
        try:
            os.kill(pid, signal.SIGTERM)
            terminated = True
        except OSError as exc:
            detail = f"{detail}; os.kill failed: {exc}"
        _write_control(self.control_path, "guard_kill",
                       f"terminated={terminated} {subject}: {detail}")

    def _write_guard_issue(self, detail: str) -> None:
        _write_control(self.control_path, "guard_stream_issue", detail)

    def _reply(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        try:
            conn.sendall(_frame(msg))
        except OSError:
            pass

    def _reply_session(self, conn: socket.socket,
                       msg: Dict[str, Any]) -> None:
        self._reply_seq += 1
        self._reply(conn, frame_signed(
            GUARD_PROTOCOL, self._frame_key, self._reply_seq, msg))


class WatchGuardLink:
    """Trusted-host client to the separate watch-guard process.

    Heartbeats keep the guard from tripping.  The link fails closed: after a
    successful session, if the guard becomes unreachable or reports
    ``triggered``, ``on_failure`` is called and the link's health stays bad,
    so the runtime broker stops accepting work.
    """

    def __init__(
        self,
        host: str,
        port: int,
        transfer_key: bytes,
        *,
        tick: float = _HEARTBEAT_TICK,
        timeout: float = 2.0,
        on_failure=None,
    ):
        self._host = host
        self._port = port
        self._transfer_key = transfer_key
        self._tick = max(tick, 0.05)
        self._timeout = timeout
        self._on_failure = on_failure

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._io_lock = threading.RLock()
        self._pid: Optional[int] = None
        self._registered = False
        self._connected = False
        self._ever_connected = False
        self._triggered = False
        self._failed = False
        self._last_error = ""
        self._send_seq = 0
        self._frame_key = b""
        self._expect_seq = 0

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="voss-watch-guard-link", daemon=True)
            self._thread.start()

    def set_on_failure(self, callback) -> None:
        with self._io_lock:
            self._on_failure = callback
            if self._failed and callback is not None:
                try:
                    callback(self._last_error or "guard lost")
                except Exception:
                    pass

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        with self._io_lock:
            if self._sock is not None:
                sock, self._sock = self._sock, None
                graceful_close(sock)

    def register_worker(self, pid: int) -> None:
        """Set the worker pid; the heartbeat loop registers it on its socket."""
        with self._io_lock:
            self._pid = pid

    def terminate(self, reason: str = "operator") -> Dict[str, Any]:
        with self._io_lock:
            if self._sock is None:
                return {"status": "error", "reason": "guard not connected"}
            self._send_seq += 1
            try:
                self._sock.sendall(_frame(frame_signed(
                    GUARD_PROTOCOL, self._frame_key, self._send_seq,
                    {"type": "terminate", "reason": reason})))
                reply = self._read_session_reply(self._sock)
            except Exception as exc:
                self._record_error(f"guard link lost: {exc}")
                return {"status": "error", "reason": "link_lost"}
            if reply.get("status") == "triggered":
                self._set_triggered("terminate directive acked")
            return reply

    def health(self) -> Dict[str, Any]:
        ok = (
            self._connected and not self._triggered and not self._failed
        )
        return {
            "ok": ok,
            "connected": self._connected,
            "registered": self._registered,
            "triggered": self._triggered,
            "registered_pid": self._pid,
            "error": self._last_error or None,
        }

    # ------------------------------------------------------------------- run

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._triggered:
                return
            try:
                self._session()
            except Exception as exc:
                self._record_error(f"guard session failed: {exc}")
            self._stop.wait(self._tick)

    def _session(self) -> None:
        with self._io_lock:
            self._send_seq = 0
            self._expect_seq = 0
            sock = self._connect()
            self._sock = sock
        try:
            tick = 0
            while not self._stop.is_set():
                with self._io_lock:
                    if self._pid is not None and not self._registered:
                        self._send_seq += 1
                        self._send(sock, frame_signed(
                            GUARD_PROTOCOL, self._frame_key, self._send_seq,
                            {"type": "register", "pid": self._pid}))
                        reply = self._read_session_reply(sock)
                        if reply.get("status") != "ok":
                            raise GuardAnomaly(f"register refused: {reply!r}")
                        self._registered = True
                    tick += 1
                    self._send_seq += 1
                    self._send(sock, frame_signed(
                        GUARD_PROTOCOL, self._frame_key, self._send_seq,
                        {"type": "heartbeat", "tick": tick}))
                    reply = self._read_session_reply(sock)
                if reply.get("status") == "triggered":
                    self._set_triggered("guard reported triggered")
                    return
                if reply.get("status") != "ok":
                    raise GuardAnomaly(f"guard replied: {reply!r}")
                self._stop.wait(self._tick)
        finally:
            with self._io_lock:
                if self._sock is sock:
                    self._sock = None
            graceful_close(sock)
            self._connected = False

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self._host, self._port),
                                        timeout=self._timeout)
        sock.settimeout(self._timeout)
        challenge = self._read(sock)
        if (challenge.get("type") != "challenge" or
                not isinstance(challenge.get("challenge"), str)):
            sock.close()
            raise GuardAnomaly(f"no challenge: {challenge!r}")
        if challenge.get("mac") != _sign_guard_challenge(
                self._transfer_key, challenge["challenge"]):
            sock.close()
            raise GuardAnomaly("challenge failed authentication")
        nonce = new_id("guard-")
        self._frame_key = derive_session_key(
            GUARD_PROTOCOL, self._transfer_key,
            challenge["challenge"], nonce,
        )
        self._send(sock, {"type": "hello", "version": GUARD_PROTOCOL,
                          "challenge": challenge["challenge"],
                          "nonce": nonce,
                          "mac": _sign_guard_hello(
                              self._transfer_key, nonce,
                              challenge["challenge"])})
        reply = self._read_session_reply(sock)
        if reply.get("status") != "ok":
            sock.close()
            raise GuardAnomaly(f"hello refused: {reply!r}")
        self._ever_connected = True
        self._connected = True
        self._last_error = ""
        return sock

    def _read_session_reply(self, sock: socket.socket) -> Dict[str, Any]:
        reply = self._read(sock)
        expected = self._expect_seq + 1
        if (not frame_is_authed(reply, GUARD_PROTOCOL, self._frame_key) or
                reply.get("seq") != expected):
            raise GuardAnomaly(
                f"guard reply failed authentication (expected seq {expected})")
        self._expect_seq = expected
        return reply

    def _send(self, sock: socket.socket, msg: Dict[str, Any]) -> None:
        sock.sendall(_frame(msg))

    def _read(self, sock: socket.socket) -> Dict[str, Any]:
        return _read_frame(sock)

    def _record_error(self, error: str) -> None:
        self._connected = False
        self._last_error = error
        if self._ever_connected and not self._failed:
            self._failed = True
            self._notify_failure(error)

    def _set_triggered(self, reason: str) -> None:
        self._triggered = True
        self._connected = False
        self._last_error = reason
        if not self._failed:
            self._failed = True
            self._notify_failure(reason)

    def _notify_failure(self, reason: str) -> None:
        if self._on_failure is None:
            return
        try:
            self._on_failure(reason)
        except Exception:
            pass


def serve_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="voss.watchguard")
    parser.add_argument("--store", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--transfer-key", required=True)
    parser.add_argument("--timeout", type=float, default=_IDLE_TIMEOUT)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    server = WatchGuardServer(
        args.store, bytes.fromhex(args.transfer_key),
        port=args.port, idle_timeout=args.timeout,
    )
    with open(args.port_file, "w", encoding="utf-8") as handle:
        handle.write(str(server.port) + "\n")
    server.start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve_main())
