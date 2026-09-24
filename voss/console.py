"""Separate operator approval console (RFC 3, 5.3, 7.2, Binding 3.3).

Human sovereignty means the *human's* consent gesture must not live inside the
untrusted worker's process.  The prototype already routes approval through the
trusted host CLI; this module goes further and detaches the approval surface
into its own OS process, mirroring the audit relay and the watch-guard:

- ``ConsoleServer`` runs as its own process (``python -m voss.console``), binds
  127.0.0.1 and requires an HMAC-authenticated handshake (per-launch transfer
  key) before accepting the trusted host.
- The host pushes approval *views* (flow id, action, resource, risk class,
  consequences, remaining validity) to the console over the authenticated
  link; the console is where the human decides.
- The human gesture (approve / deny / cancel, or a ``terminate`` kill switch)
  flows console -> host over the same authenticated connection.  The worker
  has no path to the console and cannot forge a vote: the console is a
  separate process with its own credential.
- Fail closed: consequential approvals require a live console.  If the console
  cannot be reached, the runtime denies such requests (``denied_approval_unavailable``)
  instead of silently queuing them; it never auto-grants.
- ``--auto`` is a dev/demo-only mode that scripted the gesture with a fixed
  delay; interactive mode reads gestures from the operator's stdin.

The console holds no keys and can grant nothing by itself; every vote still
round-trips the runtime, which re-validates identity, binding, expiry, and
policy before any capability is issued.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
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

CONSOLE_PROTOCOL = "voss.console.1"


def _sign_console_hello(transfer_key: bytes, nonce: str, challenge: str) -> str:
    # Domain-separated from relay/watch-guard protocol strings.
    return hmac.new(
        transfer_key,
        CONSOLE_PROTOCOL.encode("ascii")
        + b":" + challenge.encode("ascii")
        + b":" + nonce.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _sign_console_challenge(transfer_key: bytes, challenge: str) -> str:
    return hmac.new(
        transfer_key,
        CONSOLE_PROTOCOL.encode("ascii") + b":challenge:" + challenge.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


class _Transcript:
    """Append-only operator transcript: what the human was shown and decided."""

    def __init__(self, path: str):
        self._path = path

    def append(self, kind: str, **fields: Any) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {"ts": time.time(), "kind": kind, **fields},
                        sort_keys=True,
                    )
                    + "\n"
                )
                handle.flush()
        except OSError:
            pass


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


class ConsoleAnomaly(RuntimeError):
    pass


class ConsoleServer:
    """Separate-process approval surface. Per-launch; one host connection."""

    def __init__(
        self,
        store_dir: str,
        transfer_key: bytes,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        auto: Optional[str] = None,
        delay: float = 0.2,
    ):
        if not transfer_key or len(transfer_key) < 16:
            raise ValueError("transfer key must be at least 16 bytes")
        if auto is not None and auto not in ("approve", "deny", "cancel"):
            raise ValueError("--auto must be approve|deny|cancel")
        self.store_dir = os.path.realpath(os.path.abspath(store_dir))
        os.makedirs(self.store_dir, exist_ok=True)
        self.control_path = os.path.join(self.store_dir, "console-control.jsonl")
        self.transcript_path = os.path.join(self.store_dir, "console-transcript.jsonl")
        self._transcript = _Transcript(self.transcript_path)
        self._transfer_key = transfer_key
        self._auto = auto
        self._delay = max(float(delay), 0.0)

        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._active_conn: Optional[socket.socket] = None
        self._serve_thread: Optional[threading.Thread] = None
        self._approver_ref = f"operator@console:{os.getpid()}"
        self._conn: Optional[socket.socket] = None
        # Fresh per-process challenge: a restarted console mints a new one, so
        # a captured hello cannot re-open a session after a restart that keeps
        # the same transfer key.
        self._challenge = new_id("challenge-")
        self._seen_nonces: set = set()  # hello nonces, this process only
        self._auth_seq = 0  # per-connection post-hello frame seq (server side)
        self._frame_key = b""

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(4)
        self.host, self.port = self._listener.getsockname()[:2]

    def start(self) -> None:
        if self._serve_thread is not None:
            return
        self._serve_thread = threading.Thread(
            target=self._serve_loop, name="voss-operator-console", daemon=True)
        self._serve_thread.start()
        _write_control(self.control_path, "console_started",
                       f"pid={os.getpid()} auto={self._auto or 'interactive'}")

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._listener is not None:
                self._listener.close()
        except OSError:
            pass
        if self._serve_thread is not None:
            self._serve_thread.join(timeout=5.0)

    # ------------------------------------------------------------- connection

    def _serve_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            with self._lock:
                if self._active_conn is not None:
                    _write_control(self.control_path, "console_busy",
                                   "another host is connected")
                    self._reply(conn, {"type": "busy"})
                    graceful_close(conn)
                    continue
                self._active_conn = conn
            threading.Thread(
                target=self._serve_conn, args=(conn,),
                name="voss-operator-console-conn", daemon=True,
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
        conn.settimeout(60.0)
        # Speak first with this process's challenge; hello must MAC over it.
        self._reply(conn, {"type": "challenge",
                           "challenge": self._challenge,
                           "mac": _sign_console_challenge(
                               self._transfer_key, self._challenge)})
        try:
            msg = _read_frame(conn)
        except Exception:
            _write_control(self.control_path, "console_stream_closed",
                           "before hello")
            return
        reason = self._claim_hello(msg)
        if reason:
            _write_control(self.control_path, "console_denied_hello",
                           f"{reason}:{str(msg)[:120]}")
            self._reply(conn, {"type": "ack", "status": "error",
                               "reason": "denied_console_auth"})
            return
        _write_control(self.control_path, "console_accepted_hello", "host")
        self._frame_key = derive_session_key(
            CONSOLE_PROTOCOL, self._transfer_key, self._challenge,
            str(msg["nonce"]),
        )
        self._send_seq = 1
        self._reply(conn, frame_signed(
            CONSOLE_PROTOCOL, self._frame_key, self._send_seq,
            {"type": "hello_ok"}))
        self._conn = conn
        self._auth_seq = 0
        self._send_seq = 1  # hello_ok is the first server frame in this session

        if self._auto is not None:
            auto_thread = None
        else:
            threading.Thread(
                target=self._command_loop, name="voss-operator-console-input",
                daemon=True,
            ).start()

        while not self._stop.is_set():
            try:
                msg = _read_frame(conn)
            except socket.timeout:
                continue
            except Exception as exc:
                if not isinstance(exc, (ConnectionResetError,
                                        ConnectionAbortedError)):
                    _write_control(self.control_path, "console_stream_closed",
                                   str(exc)[:120])
                return
            if not frame_is_authed(msg, CONSOLE_PROTOCOL, self._frame_key):
                _write_control(self.control_path, "console_anomaly",
                               "unauthenticated frame")
                return
            self._auth_seq += 1
            if msg.get("seq") != self._auth_seq:
                _write_control(self.control_path, "console_anomaly",
                               f"sequence_error expected {self._auth_seq} "
                               f"got {msg.get('seq')}")
                return
            kind = msg.get("type")
            if kind == "approval_view":
                self._transcript.append(
                    "view", flow_id=str(msg.get("flow_id", "")),
                    **{k: (msg.get("view") or {}).get(k)
                       for k in ("action", "resource", "risk_class",
                                 "consequences", "reversible",
                                 "expires_in_seconds", "payload_digest")},
                )
                _write_control(self.control_path, "console_view",
                               f"flow={msg.get('flow_id')}")
                self._show_view(str(msg.get("flow_id", "")))
                if self._auto is not None:
                    threading.Thread(
                        target=self._auto_vote,
                        args=(str(msg.get("flow_id", "")),),
                        name="voss-operator-console-auto", daemon=True,
                    ).start()
            elif kind == "approval_result":
                self._transcript.append(
                    "result", flow_id=str(msg.get("flow_id", "")),
                    decision=str(msg.get("decision", "")),
                    approver_ref=str(msg.get("approver_ref", "")),
                )
                _write_control(self.control_path, "console_result",
                               f"flow={msg.get('flow_id')} "
                               f"decision={msg.get('decision')}")
            else:
                _write_control(self.control_path, "console_anomaly",
                               f"unknown frame {kind!r}")
                return

    def _valid_hello(self, msg: Dict[str, Any]) -> bool:
        if msg.get("type") != "hello":
            return False
        if msg.get("version") != CONSOLE_PROTOCOL:
            return False
        challenge = msg.get("challenge")
        nonce, mac = msg.get("nonce"), msg.get("mac")
        return (
            isinstance(challenge, str) and challenge == self._challenge
            and isinstance(nonce, str) and isinstance(mac, str)
            and mac == _sign_console_hello(self._transfer_key, nonce, challenge)
        )

    def _claim_hello(self, msg: Dict[str, Any]) -> str:
        """Refuse a bad hello, or a replayed single-use nonce (reason string)."""
        if not self._valid_hello(msg):
            return "denied_console_auth"
        nonce = msg.get("nonce")
        with self._lock:
            if nonce in self._seen_nonces:
                return "replayed_hello_nonce"
            self._seen_nonces.add(nonce)
        return ""

    # ------------------------------------------------------- human gestures

    def _show_view(self, flow_id: str) -> None:
        print(f"[approval] flow={flow_id} "
              f"-> type approve|deny|cancel or 'kill <reason>'", flush=True)

    def _command_loop(self) -> None:
        for line in sys.stdin:
            if self._stop.is_set():
                return
            parts = line.strip().split(None, 1)
            if not parts:
                continue
            if parts[0].lower() == "kill":
                reason = parts[1] if len(parts) > 1 else "operator"
                self._send({"type": "terminate", "reason": reason})
                _write_control(self.control_path, "console_terminate_directive",
                               reason)
                self._transcript.append("terminate", reason=reason)
                continue
            if len(parts) != 2:
                continue
            flow_id, gesture = parts[0], parts[1].lower()
            if gesture not in ("approve", "deny", "cancel"):
                continue
            self._vote(flow_id, gesture.upper())

    def _auto_vote(self, flow_id: str) -> None:
        time.sleep(self._delay)
        self._vote(flow_id, str(self._auto).upper())

    def _vote(self, flow_id: str, decision: str) -> None:
        self._send({"type": "vote", "flow_id": flow_id,
                    "decision": decision, "approver_ref": self._approver_ref})
        _write_control(self.control_path, "console_vote",
                       f"flow={flow_id} decision={decision}")
        self._transcript.append("vote", flow_id=flow_id,
                                decision=decision,
                                approver_ref=self._approver_ref)

    def _send(self, msg: Dict[str, Any]) -> None:
        conn = self._conn
        if conn is None:
            return
        with self._send_lock:
            self._send_seq += 1
            try:
                conn.sendall(_frame(frame_signed(
                    CONSOLE_PROTOCOL, self._frame_key, self._send_seq, msg)))
            except OSError:
                pass

    def _reply(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        try:
            conn.sendall(_frame(msg))
        except OSError:
            pass


class StopConsole(Exception):
    pass


class ConsoleClient:
    """Trusted-host side: pushes approval views, receives human votes.

    Fail closed: once the console is unreachable after a valid session, or was
    never reached, ``health()`` is not ok and the runtime denies consequential
    approvals (never auto-grants).
    """

    def __init__(
        self,
        host: str,
        port: int,
        transfer_key: bytes,
        *,
        timeout: float = 2.0,
        on_vote=None,
        on_terminate=None,
    ):
        self._host = host
        self._port = port
        self._transfer_key = transfer_key
        self._timeout = timeout
        self._on_vote = on_vote
        self._on_terminate = on_terminate

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._io_lock = threading.RLock()
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._ever_connected = False
        self._failed = False
        self._last_error = ""
        self._send_seq = 0  # host -> console view/result frames
        self._expect_seq = 0  # console -> host vote/terminate frames
        self._frame_key = b""

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="voss-operator-console-client",
                daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._close_sock()

    def set_on_vote(self, callback) -> None:
        self._on_vote = callback

    def set_on_terminate(self, callback) -> None:
        self._on_terminate = callback

    def health(self) -> Dict[str, Any]:
        return {
            "ok": self._connected and not self._failed and not self._stop.is_set(),
            "connected": self._connected,
            "failed": self._failed,
            "error": self._last_error or None,
        }

    # --------------------------------------------------------------- io

    def publish_view(self, flow_id: str, view: Dict[str, Any]) -> None:
        self._send_best_effort({"type": "approval_view",
                                "flow_id": flow_id, "view": view})

    def publish_result(self, flow_id: str, decision: str,
                       approver_ref: str) -> None:
        self._send_best_effort({"type": "approval_result",
                                "flow_id": flow_id,
                                "decision": decision,
                                "approver_ref": approver_ref})

    def _send_best_effort(self, msg: Dict[str, Any]) -> None:
        with self._io_lock:
            sock = self._sock
            if sock is None:
                return
            self._send_seq += 1
            try:
                sock.sendall(_frame(frame_signed(
                    CONSOLE_PROTOCOL, self._frame_key, self._send_seq, msg)))
            except Exception as exc:
                self._record_error(f"console link lost: {exc}")

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._failed:
                return  # fail closed once a live console was lost
            try:
                self._session()
            except Exception as exc:
                self._record_error(f"console session failed: {exc}")
            self._stop.wait(0.2)

    def _session(self) -> None:
        with self._io_lock:
            self._send_seq = 0
            self._expect_seq = 0
            sock = socket.create_connection((self._host, self._port),
                                            timeout=self._timeout)
            sock.settimeout(self._timeout)
            challenge = _read_frame(sock)
            if (challenge.get("type") != "challenge" or
                    not isinstance(challenge.get("challenge"), str)):
                sock.close()
                raise ConsoleAnomaly(f"no challenge: {challenge!r}")
            if challenge.get("mac") != _sign_console_challenge(
                    self._transfer_key, challenge["challenge"]):
                sock.close()
                raise ConsoleAnomaly("challenge failed authentication")
            nonce = new_id("console-")
            frame_key = derive_session_key(
                CONSOLE_PROTOCOL, self._transfer_key,
                challenge["challenge"], nonce,
            )
            sock.sendall(_frame({"type": "hello", "version": CONSOLE_PROTOCOL,
                                 "challenge": challenge["challenge"],
                                 "nonce": nonce,
                                 "mac": _sign_console_hello(
                                     self._transfer_key, nonce,
                                     challenge["challenge"])}))
            reply = _read_frame(sock)
            if reply.get("type") != "hello_ok":
                sock.close()
                raise ConsoleAnomaly(f"hello refused: {reply!r}")
            if (not frame_is_authed(reply, CONSOLE_PROTOCOL, frame_key) or
                    reply.get("seq") != 1):
                sock.close()
                raise ConsoleAnomaly("hello_ok failed authentication")
            self._connected = True
            self._ever_connected = True
            self._last_error = ""
            self._sock = sock
            self._frame_key = frame_key
            self._send_seq = 0  # per-connection frames are numbered from 1
            self._expect_seq = 1
        try:
            while not self._stop.is_set():
                msg = _read_frame(sock)
                kind = msg.get("type")
                with self._io_lock:
                    expected = self._expect_seq + 1
                    valid = (
                        frame_is_authed(msg, CONSOLE_PROTOCOL,
                                        self._frame_key)
                        and msg.get("seq") == expected
                    )
                if not valid:
                    self._record_error(
                        f"console frame failed authentication "
                        f"(seq {msg.get('seq')}, expected {expected})")
                    return
                with self._io_lock:
                    self._expect_seq = expected
                if kind == "vote":
                    self._dispatch(self._on_vote, msg.get("flow_id", ""),
                                   msg.get("decision", "DENY"),
                                   msg.get("approver_ref", ""))
                elif kind == "terminate":
                    self._dispatch(self._on_terminate,
                                   msg.get("reason", "operator"))
                elif kind == "busy":
                    raise ConsoleAnomaly("console busy")
                elif kind != "ack":
                    self._record_error(f"unexpected console frame {kind!r}")
        finally:
            with self._io_lock:
                if self._sock is sock:
                    self._sock = None
            self._close_sock(sock)
            self._connected = False

    def _dispatch(self, callback, *args: Any) -> None:
        if callback is None:
            return
        try:
            callback(*args)
        except Exception:
            pass

    def _record_error(self, error: str) -> None:
        self._connected = False
        self._last_error = error
        if self._ever_connected and not self._failed:
            self._failed = True

    def _close_sock(self, sock: Optional[socket.socket] = None) -> None:
        sock = sock or self._sock
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass


def serve_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="voss.console")
    parser.add_argument("--store", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--transfer-key", required=True)
    parser.add_argument("--auto", choices=("approve", "deny", "cancel"),
                        default=None)
    parser.add_argument("--delay", type=float, default=0.2)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    server = ConsoleServer(
        args.store, bytes.fromhex(args.transfer_key),
        port=args.port, auto=args.auto, delay=args.delay,
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
