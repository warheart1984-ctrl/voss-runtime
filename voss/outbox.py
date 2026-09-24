"""External action transport with independent accounting (RFC 12).

``external.send_mock`` today writes a local outbox file inside the trusted
process.  This module detaches the *external* side of that effect into its
own OS process, exactly like the audit relay, the watch-guard, and the
operator console:

- ``OutboxServer`` runs as a separate process (``python -m voss.outbox``),
  binds 127.0.0.1 and requires an HMAC-authenticated handshake (per-launch
  transfer key) before a single delivery is accepted.
- The trusted host keeps no copy of the external event.  To perform an
  external action it must *deliver* over the authenticated link and receive a
  service-side **receipt** (``delivery_id`` -> ``receipt_id``).  The server
  records every delivery in its own append-only accounting ledger and writes
  the delivered message into its own store - independent of the host.
- Service-side idempotency: the same ``idempotency_key`` (the request id) is
  delivered at most once regardless of how many times the host asks; a retry
  is answered with the original receipt and no second effect.
- Fail closed: no receipt -> no effect.  If the service rejects a delivery
  (``refused``, e.g. simulated outage) or cannot be reached at all, the tool
  raises a hard failure and the runtime resolves the flow ``UNKNOWN``
  (``denied_tool_failure``) without marking the effect complete.  If a
  delivery was sent but the acknowledgement never arrived (the link dropped
  mid-flight), the outcome is *uncertain* (``outcome_uncertain``): the host
  cannot claim completion, but the service-side ledger - readable
  independently - proves whether the delivery actually happened.
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
    RelayStreamClosed, _frame, _read_frame, frame_signed, frame_is_authed,
    derive_session_key, graceful_close,
)

OUTBOX_PROTOCOL = "voss.outbox.1"

_MAX_DIGEST_CHARS = 128


def _sign_outbox_hello(transfer_key: bytes, nonce: str, challenge: str) -> str:
    # Domain-separated from relay/watch-guard/console protocol strings.
    return hmac.new(
        transfer_key,
        OUTBOX_PROTOCOL.encode("ascii")
        + b":" + challenge.encode("ascii")
        + b":" + nonce.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _sign_outbox_challenge(transfer_key: bytes, challenge: str) -> str:
    return hmac.new(
        transfer_key,
        OUTBOX_PROTOCOL.encode("ascii") + b":challenge:" + challenge.encode("ascii"),
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


class OutboxUnavailable(RuntimeError):
    """The service cannot be reached or refused delivery; no effect occurred."""


class OutboxUncertain(RuntimeError):
    """A delivery was sent but never acknowledged; outcome is unknowable."""


def _check_deliver(msg: Dict[str, Any]) -> Dict[str, str]:
    required = {
        "delivery_id": str,
        "service": str,
        "recipient": str,
        "payload_digest": str,
        "idempotency_key": str,
    }
    for field, field_type in required.items():
        if not isinstance(msg.get(field), field_type) or not msg.get(field):
            raise ValueError(f"missing or invalid field {field!r}")
    if msg["service"] != "mail":
        raise ValueError("unsupported external service")
    if len(msg["payload_digest"]) > _MAX_DIGEST_CHARS:
        raise ValueError("oversize payload_digest")
    return {field: str(msg[field]) for field in required}


class OutboxServer:
    """Separate-process external-action accounting service (one host)."""

    def __init__(
        self,
        store_dir: str,
        transfer_key: bytes,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        drop_ack: bool = False,
        refuse: bool = False,
    ):
        if not transfer_key or len(transfer_key) < 16:
            raise ValueError("transfer key must be at least 16 bytes")
        self._transfer_key = transfer_key
        self.store_dir = os.path.realpath(os.path.abspath(store_dir))
        os.makedirs(self.store_dir, exist_ok=True)
        self.delivered_dir = os.path.join(self.store_dir, "delivered")
        os.makedirs(self.delivered_dir, exist_ok=True)
        self.control_path = os.path.join(self.store_dir, "outbox-control.jsonl")
        self.ledger_path = os.path.join(self.store_dir,
                                        "outbox-receipts.jsonl")
        self._drop_ack = drop_ack
        self._refuse = refuse

        self._lock = threading.RLock()
        self._receipts: Dict[str, Dict[str, Any]] = self._load_receipts()
        self._stop = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._active_conn: Optional[socket.socket] = None
        self._serve_thread: Optional[threading.Thread] = None
        self._conn: Optional[socket.socket] = None
        self._send_lock = threading.Lock()
        # Fresh per-process challenge: a restarted service mints a new one, so
        # a hello captured against a previous process cannot be replayed even
        # when the same transfer key is retained across restarts.
        self._challenge = new_id("challenge-")
        self._seen_nonces: set = set()  # hello nonces, this process only
        self._auth_seq = 0  # per-connection host -> server frame seq
        self._reply_seq = 0  # per-connection server -> host reply seq
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
            target=self._serve_loop, name="voss-outbox", daemon=True)
        self._serve_thread.start()
        _write_control(self.control_path, "outbox_started",
                       f"pid={os.getpid()}")

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._listener is not None:
                self._listener.close()
        except OSError:
            pass
        if self._serve_thread is not None:
            self._serve_thread.join(timeout=5.0)

    def _load_receipts(self) -> Dict[str, Dict[str, Any]]:
        """Restore idempotency state; malformed ledgers prevent startup."""
        receipts: Dict[str, Dict[str, Any]] = {}
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, 1):
                    try:
                        record = json.loads(line)
                    except (json.JSONDecodeError, UnicodeError) as exc:
                        raise RuntimeError(
                            f"invalid outbox ledger at line {line_number}") from exc
                    if not isinstance(record, dict):
                        raise RuntimeError(
                            f"invalid outbox ledger at line {line_number}")
                    idem = record.get("idempotency_key")
                    if (not isinstance(idem, str) or not idem
                            or record.get("status") != "delivered"
                            or not isinstance(record.get("receipt_id"), str)
                            or not record["receipt_id"]):
                        raise RuntimeError(
                            f"invalid outbox ledger at line {line_number}")
                    if idem in receipts:
                        raise RuntimeError(
                            f"duplicate idempotency key in outbox ledger at line {line_number}")
                    required = ("service", "recipient", "payload_digest",
                                "delivery_id", "delivered_at")
                    if any(field not in record for field in required):
                        raise RuntimeError(
                            f"incomplete outbox ledger at line {line_number}")
                    self._recover_delivery_file(record)
                    receipts[idem] = record
        except FileNotFoundError:
            return receipts
        except OSError as exc:
            raise RuntimeError("cannot read outbox receipt ledger") from exc
        return receipts

    def _recover_delivery_file(self, record: Dict[str, Any]) -> None:
        """Rebuild the demo effect file from the fsynced ledger after a crash."""
        path = os.path.join(self.delivered_dir,
                            record["receipt_id"] + ".json")
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    if json.load(handle) != record:
                        raise RuntimeError("outbox effect disagrees with receipt ledger")
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError("cannot verify outbox effect file") from exc
            return
        self._write_delivered(record)

    # ------------------------------------------------------------- connection

    def _serve_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                return
            with self._lock:
                if self._active_conn is not None:
                    _write_control(self.control_path, "outbox_busy",
                                   "another host is connected")
                    self._reply(conn, {"type": "busy"})
                    graceful_close(conn)
                    continue
                self._active_conn = conn
            threading.Thread(
                target=self._serve_conn, args=(conn,),
                name="voss-outbox-conn", daemon=True,
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
                           "mac": _sign_outbox_challenge(
                               self._transfer_key, self._challenge)})
        try:
            msg = _read_frame(conn)
        except Exception:
            _write_control(self.control_path, "outbox_stream_closed",
                           "before hello")
            return
        reason = self._claim_hello(msg)
        if reason:
            _write_control(self.control_path, "outbox_denied_hello",
                           f"{reason}:{str(msg)[:120]}")
            self._reply(conn, {"type": "ack", "status": "error",
                               "reason": "denied_outbox_auth"})
            return
        _write_control(self.control_path, "outbox_accepted_hello", "host")
        self._frame_key = derive_session_key(
            OUTBOX_PROTOCOL, self._transfer_key, self._challenge,
            str(msg["nonce"]),
        )
        self._auth_seq = 0
        self._reply_seq = 0
        self._reply_signed(conn, {"type": "hello_ok"})
        self._conn = conn

        while not self._stop.is_set():
            try:
                msg = _read_frame(conn)
            except socket.timeout:
                continue
            except Exception as exc:
                if not isinstance(exc, RelayStreamClosed):
                    _write_control(self.control_path, "outbox_stream_closed",
                                   str(exc)[:120])
                return
            if not frame_is_authed(msg, OUTBOX_PROTOCOL, self._frame_key):
                _write_control(self.control_path, "outbox_anomaly",
                               "unauthenticated frame")
                return
            self._auth_seq += 1
            if msg.get("seq") != self._auth_seq:
                _write_control(self.control_path, "outbox_anomaly",
                               f"sequence_error expected {self._auth_seq} "
                               f"got {msg.get('seq')}")
                return
            kind = msg.get("type")
            if kind == "deliver":
                try:
                    fields = _check_deliver(msg)
                except ValueError as exc:
                    _write_control(self.control_path, "outbox_anomaly",
                                   str(exc))
                    return
                ack, dropped = self._deliver(conn, fields)
                if dropped:
                    return
                self._reply_signed(conn, ack)
            else:
                _write_control(self.control_path, "outbox_anomaly",
                               f"unknown frame {kind!r}")
                return

    def _valid_hello(self, msg: Dict[str, Any]) -> bool:
        if msg.get("type") != "hello":
            return False
        if msg.get("version") != OUTBOX_PROTOCOL:
            return False
        challenge = msg.get("challenge")
        nonce, mac = msg.get("nonce"), msg.get("mac")
        return (
            isinstance(challenge, str) and challenge == self._challenge
            and isinstance(nonce, str) and isinstance(mac, str)
            and mac == _sign_outbox_hello(self._transfer_key, nonce, challenge)
        )

    def _claim_hello(self, msg: Dict[str, Any]) -> str:
        """Refuse a bad hello, or a replayed single-use nonce (reason string)."""
        if not self._valid_hello(msg):
            return "denied_outbox_auth"
        nonce = msg.get("nonce")
        with self._lock:
            if nonce in self._seen_nonces:
                return "replayed_hello_nonce"
            self._seen_nonces.add(nonce)
        return ""

    # ------------------------------------------------------------ accounting

    def _deliver(self, conn: socket.socket,
                 fields: Dict[str, str]) -> tuple[Dict[str, Any], bool]:
        idem = fields["idempotency_key"]
        with self._lock:
            prior = self._receipts.get(idem)
            if prior is not None:
                if (prior.get("service") != fields["service"]
                        or prior.get("recipient") != fields["recipient"]
                        or prior.get("payload_digest") != fields["payload_digest"]):
                    _write_control(self.control_path, "outbox_idempotency_conflict", idem)
                    return ({"type": "delivered", "delivery_id": fields["delivery_id"],
                             "status": "refused",
                             "reason": "idempotency key reused for different request"}, False)
                try:
                    self._recover_delivery_file(prior)
                except OSError as exc:
                    self._fail_storage(exc)
                    return self._uncertain(fields, prior)
                _write_control(self.control_path, "outbox_duplicate", idem)
                return ({"type": "delivered", "delivery_id": fields["delivery_id"],
                         "status": "duplicate",
                         "receipt_id": prior["receipt_id"],
                         "delivered_at": prior["delivered_at"]}, False)
            if self._refuse:
                _write_control(self.control_path, "outbox_refused", idem)
                return ({"type": "delivered", "delivery_id": fields["delivery_id"],
                         "status": "refused",
                         "reason": "service refusing all deliveries"}, False)
            receipt_id = new_id("rcpt-")
            delivered_at = time.time()
            record = {
                "ts": delivered_at,
                "receipt_id": receipt_id,
                "delivery_id": fields["delivery_id"],
                "service": fields["service"],
                "recipient": fields["recipient"],
                "payload_digest": fields["payload_digest"],
                "idempotency_key": idem,
                "status": "delivered",
                "delivered_at": delivered_at,
            }
            self._append_ledger(record)
            self._receipts[idem] = record
            try:
                self._write_delivered(record)
            except OSError as exc:
                # The ledger already holds the receipt. A later retry of this
                # key must not be told the delivery was refused.
                self._fail_storage(exc)
                return self._uncertain(fields, record)
            _write_control(self.control_path, "outbox_delivered",
                           f"{receipt_id} key={idem}")
            ack = {"type": "delivered", "delivery_id": fields["delivery_id"],
                   "status": "delivered", "receipt_id": receipt_id,
                   "delivered_at": delivered_at}
            if self._drop_ack:
                _write_control(self.control_path, "outbox_dropped_ack", idem)
                return (ack, True)  # delivered, but reply withheld/connection dies
            return (ack, False)

    def _uncertain(self, fields: Dict[str, str], record: Dict[str, Any]) -> tuple[Dict[str, Any], bool]:
        return ({
            "type": "delivered",
            "delivery_id": fields["delivery_id"],
            "status": "uncertain",
            "reason": "delivery recorded, response uncertain",
            "receipt_id": record["receipt_id"],
            "delivered_at": record["delivered_at"],
        }, False)

    def _append_ledger(self, record: Dict[str, Any]) -> None:
        try:
            with open(self.ledger_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            self._fail_storage(exc)
            raise

    def _write_delivered(self, record: Dict[str, Any]) -> None:
        path = os.path.join(self.delivered_dir, record["receipt_id"] + ".json")
        temp_path = path + ".tmp"
        try:
            with open(temp_path, "x", encoding="utf-8") as handle:
                json.dump(record, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        except OSError:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise

    def _fail_storage(self, exc: OSError) -> None:
        self._refuse = True
        _write_control(self.control_path, "outbox_storage_failure", str(exc)[:120])

    def _reply(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        try:
            conn.sendall(_frame(msg))
        except OSError:
            pass

    def _reply_signed(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        with self._send_lock:
            self._reply_seq += 1
        try:
            conn.sendall(_frame(frame_signed(
                OUTBOX_PROTOCOL, self._frame_key, self._reply_seq, msg)))
        except OSError:
            pass


class OutboxLink:
    """Trusted-host side: preserve one authenticated session, deliver+receipt.

    The server never sends unsolicited frames, so there is no reader thread;
    a maintenance thread keeps the authenticated session alive and
    ``deliver()`` performs a synchronous request/response on it.  After a
    valid session is lost, the link fails closed and stops reconnecting.
    """

    def __init__(
        self,
        host: str,
        port: int,
        transfer_key: bytes,
        *,
        timeout: float = 2.0,
    ):
        self._host = host
        self._port = port
        self._transfer_key = transfer_key
        self._timeout = timeout
        self._stop = threading.Event()
        self._io_lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._sock: Optional[socket.socket] = None
        self._connected = False
        self._ever_connected = False
        self._failed = False
        self._last_error = ""
        self._send_seq = 0  # host -> server request frames
        self._expect_seq = 0  # server -> host reply frames
        self._frame_key = b""

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="voss-outbox-link", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        self._close_sock()

    def health(self) -> Dict[str, Any]:
        return {
            "ok": (self._connected and not self._failed
                   and not self._stop.is_set()),
            "connected": self._connected,
            "failed": self._failed,
            "error": self._last_error or None,
        }

    def deliver(
        self,
        delivery_id: str,
        service: str,
        recipient: str,
        payload_digest: str,
        idempotency_key: str,
    ) -> Dict[str, Any]:
        with self._io_lock:
            sock = self._sock
            if sock is None:
                raise OutboxUnavailable(
                    "outbox accounting service unreachable")
            self._send_seq += 1
            try:
                sock.settimeout(self._timeout)
                sock.sendall(_frame(frame_signed(
                    OUTBOX_PROTOCOL, self._frame_key, self._send_seq,
                    {"type": "deliver", "delivery_id": delivery_id,
                     "service": service, "recipient": recipient,
                     "payload_digest": payload_digest,
                     "idempotency_key": idempotency_key})))
                reply = _read_frame(sock)
            except Exception as exc:
                self._connected = False
                self._last_error = f"outbox link lost: {exc}"
                self._drop_session(sock)
                if self._ever_connected and not self._failed:
                    self._failed = True
                # The delivery may have reached the service even though the
                # acknowledgement did not: the outcome is unknowable here.
                raise OutboxUncertain(self._last_error) from exc
            with self._io_lock:
                expect = self._expect_seq + 1
            if not frame_is_authed(reply, OUTBOX_PROTOCOL, self._frame_key):
                self._connected = False
                self._last_error = "outbox reply failed authentication"
                self._drop_session(sock)
                if self._ever_connected and not self._failed:
                    self._failed = True
                raise OutboxUncertain(self._last_error) from None
            # hello_ok is reply seq 1; each deliver ack advances from there.
            if reply.get("type") != "delivered":
                self._connected = False
                self._last_error = f"outbox unexpected reply: {reply!r}"
                self._drop_session(sock)
                if self._ever_connected and not self._failed:
                    self._failed = True
                raise OutboxUncertain(self._last_error) from None
            if reply.get("seq") != expect:
                self._connected = False
                self._last_error = (
                    f"outbox reply sequence error: expected {expect} "
                    f"got {reply.get('seq')}")
                self._drop_session(sock)
                if self._ever_connected and not self._failed:
                    self._failed = True
                raise OutboxUncertain(self._last_error) from None
            self._expect_seq = expect
            status = reply.get("status")
            if status in ("delivered", "duplicate"):
                return {
                    "receipt_id": str(reply.get("receipt_id", "")),
                    "status": status,
                    "delivered_at": reply.get("delivered_at"),
                }
            if status == "uncertain":
                raise OutboxUncertain(
                    str(reply.get("reason") or "delivery recorded, response uncertain"))
            raise OutboxUnavailable(f"outbox refused delivery: {reply!r}")

    def _run(self) -> None:
        while not self._stop.is_set():
            with self._io_lock:
                if self._sock is None and not self._failed:
                    try:
                        self._open_session()
                    except Exception as exc:
                        self._connected = False
                        self._last_error = f"outbox connect failed: {exc}"
            self._stop.wait(0.2)

    def _open_session(self) -> None:
        sock = socket.create_connection((self._host, self._port),
                                        timeout=self._timeout)
        sock.settimeout(self._timeout)
        try:
            challenge = _read_frame(sock)
            if (challenge.get("type") != "challenge" or
                    not isinstance(challenge.get("challenge"), str)):
                raise OutboxUnavailable(f"no challenge: {challenge!r}")
            if challenge.get("mac") != _sign_outbox_challenge(
                    self._transfer_key, challenge["challenge"]):
                raise OutboxUnavailable("challenge failed authentication")
            nonce = new_id("ob-")
            frame_key = derive_session_key(
                OUTBOX_PROTOCOL, self._transfer_key,
                challenge["challenge"], nonce,
            )
            sock.sendall(_frame({"type": "hello", "version": OUTBOX_PROTOCOL,
                                 "challenge": challenge["challenge"],
                                 "nonce": nonce,
                                 "mac": _sign_outbox_hello(
                                     self._transfer_key, nonce,
                                     challenge["challenge"])}))
            reply = _read_frame(sock)
            if reply.get("type") != "hello_ok":
                raise OutboxUnavailable(f"hello refused: {reply!r}")
            if not frame_is_authed(reply, OUTBOX_PROTOCOL, frame_key):
                raise OutboxUnavailable("hello_ok failed authentication")
            if reply.get("seq") != 1:
                raise OutboxUnavailable(
                    f"unexpected hello_ok seq {reply.get('seq')}")
            self._sock = sock
            self._connected = True
            self._ever_connected = True
            self._last_error = ""
            with self._io_lock:
                self._send_seq = 0
                self._expect_seq = 1  # hello_ok consumed reply seq 1
                self._frame_key = frame_key
        except Exception:
            try:
                sock.close()
            except OSError:
                pass
            raise

    def _drop_session(self, sock: socket.socket) -> None:
        with self._io_lock:
            if self._sock is sock:
                self._sock = None
        try:
            sock.close()
        except OSError:
            pass

    def _close_sock(self, sock: Optional[socket.socket] = None) -> None:
        sock = sock or self._sock
        if sock is None:
            return
        try:
            sock.close()
        except OSError:
            pass


def serve_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="voss.outbox")
    parser.add_argument("--store", required=True)
    parser.add_argument("--port-file", required=True)
    parser.add_argument("--transfer-key", required=True)
    parser.add_argument("--drop-ack", action="store_true",
                        help="deliver but withhold/close before the ack")
    parser.add_argument("--refuse", action="store_true",
                        help="refuse every delivery (simulated outage)")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    server = OutboxServer(
        args.store, bytes.fromhex(args.transfer_key),
        port=args.port, drop_ack=args.drop_ack, refuse=args.refuse,
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
