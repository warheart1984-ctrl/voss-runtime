"""Remote audit relay (RFC 9.1 emulation of a write-only aggregator store).

The trusted runtime's audit log is local (append-only, MAC-chained).  This
module adds the RFC's wider requirement: an audit *store* in a separate
process an attacker running as the worker cannot reach or silently edit.

Architecture (prototype, stdlib only):

- ``AuditRelayServer`` runs as its own process (``python -m voss.relay``),
  binds 127.0.0.1, and requires an HMAC-authenticated handshake with a
  per-launch transfer key before it accepts anything.
- The trusted host runs ``AuditRelayClient``, which tails the local audit
  file and forwards each record to the relay.
- The relay does NOT trust the host's claim: it re-computes every HMAC and
  chain hash itself from its own stored head and a copy of the audit MAC
  key.  Records are only appended after they verify; duplicate redeliveries
  of the *same* content are idempotently acked, a contradictory redelivery
  or a sequence gap is a ``relay_violation`` and the store fails closed
  (stops ingesting further records until an operator intervenes).
- A worker/ap<->pipe actor without the transfer key is refused at the
  handshake and can never append anything.

The relay store is byte-identical to the audit file when every record was
relayed (same genesis, same payloads, same chaining), so an independent
verifier can diff the two and detect any host-side rewrite.

Key note (prototype scope): the relay holds a copy of the audit MAC key
because it must re-verify authenticity independently.  In production each
independent verifier would be enrolled with a verification key by a signing
service / HSM rather than sharing the writer's key (RFC 7.2 / 10).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import socket
import threading
import time
from typing import Any, Dict, List, Optional

from .audit import GENESIS as AUDIT_GENESIS
from .canonical import canonical_bytes, loads_strict, new_id, sha256_hex
from .keys import KeyRing

RELAY_PROTOCOL = "voss.relay.1"
MAX_FRAME = 1 << 22  # 4 MiB; audit lines are tiny, frame header bounds the read

GENESIS = AUDIT_GENESIS          # start the relay chain at the audit genesis
STALE_TIMEOUT = 15.0             # default idle threshold before stale is flagged
_IDLE_CLOSE_AFTER = 8            # 8 consecutive idle timeouts => close conn


class RelayViolationError(RuntimeError):
    pass


class RelayStreamClosed(RuntimeError):
    """Peer ended the stream cleanly (or the connection died mid-flight).

    A lost connection is not a forgery: it must not poison the store, or a
    crash of the trusted host would take the audit store down with it.
    """

    pass


def _sign_hello(transfer_key: bytes, nonce: str, challenge: str) -> str:
    return hmac.new(
        transfer_key,
        RELAY_PROTOCOL.encode("ascii")
        + b":" + challenge.encode("ascii")
        + b":" + nonce.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _sign_challenge(transfer_key: bytes, challenge: str) -> str:
    # Binds the server's per-process challenge frame to transfer-key
    # possession, so an observer cannot substitute a challenge: every hello
    # must MAC over the challenge THIS process issued.
    return hmac.new(
        transfer_key,
        RELAY_PROTOCOL.encode("ascii") + b":challenge:" + challenge.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def _challenge_frame(transfer_key: bytes, challenge: str) -> Dict[str, Any]:
    return {"type": "challenge", "challenge": challenge,
            "mac": _sign_challenge(transfer_key, challenge)}


def _frame_mac(protocol: str, transfer_key: bytes, seq: int,
               body: Dict[str, Any]) -> str:
    """HMAC over protocol-tag + monotonic seq + canonical body bytes.

    Every post-hello frame on every link protocol (relay, watch-guard,
    console, outbox) is domain-separated the same way the hello is: the tag
    pins the MAC to the protocol, and ``seq`` binds the MAC to one position
    in the stream so a captured frame cannot be spliced in elsewhere.
    """
    return hmac.new(
        transfer_key,
        protocol.encode("ascii")
        + b":" + str(seq).encode("ascii")
        + b":" + canonical_bytes(body),
        hashlib.sha256,
    ).hexdigest()


def frame_signed(protocol: str, transfer_key: bytes, seq: int,
                 msg: Dict[str, Any]) -> Dict[str, Any]:
    """Return ``msg`` with a monotonic ``seq`` and per-frame ``mac`` attached."""
    body = dict(msg)
    body["seq"] = seq
    body["mac"] = _frame_mac(protocol, transfer_key, seq, body)
    return body


def derive_session_key(protocol: str, transfer_key: bytes,
                       challenge: str, nonce: str) -> bytes:
    """Derive a fresh frame key from the authenticated process challenge and hello nonce."""
    fields = (b"voss.session-key.v1", protocol.encode("ascii"),
              challenge.encode("ascii"), nonce.encode("ascii"))
    material = b"".join(len(field).to_bytes(4, "big") + field
                       for field in fields)
    return hmac.new(transfer_key, material, hashlib.sha256).digest()


def frame_is_authed(msg: Any, protocol: str, transfer_key: bytes) -> bool:
    """A frame only authenticates if its MAC covers every field but itself."""
    if not isinstance(msg, dict):
        return False
    seq = msg.get("seq")
    mac = msg.get("mac")
    if not isinstance(seq, int) or seq < 0 or not isinstance(mac, str):
        return False
    body = {key: value for key, value in msg.items() if key != "mac"}
    try:
        expected = _frame_mac(protocol, transfer_key, seq, body)
    except Exception:
        return False
    return hmac.compare_digest(expected, mac)


def _verify_record(record: Dict[str, Any], prev: str, keyring: KeyRing):
    payload_bytes = canonical_bytes(record)
    mac = keyring.mac_audit(prev.encode("ascii") + payload_bytes)
    chain = sha256_hex({"prev": prev, "record": payload_bytes.decode("ascii")})
    return mac, chain


def _write_control(path: str, event: str, detail: str) -> None:
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {"ts": time.time(), "event": event, "detail": detail},
                    sort_keys=True,
                )
                + "\n"
            )
            handle.flush()
    except OSError:
        pass


def graceful_close(conn: socket.socket) -> None:
    """Drain then FIN so Windows doesn't RST away an already-sent reply.

    Closing a TCP socket that still has unread received data triggers an RST
    on Windows, destroying anything we just sent (e.g. a refusal).  Reading
    the peer's remaining bytes first lets the stack send a clean FIN.
    """
    try:
        conn.settimeout(3.0)
        while True:
            if not conn.recv(65536):
                break
    except (socket.timeout, OSError):
        pass
    try:
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass
    try:
        conn.close()
    except OSError:
        pass


class AuditRelayServer:
    """Separate-process audit store. Verify-then-append, idempotent redelivery."""

    def __init__(
        self,
        store_dir: str,
        keyring: KeyRing,
        transfer_key: bytes,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        timeout: float = STALE_TIMEOUT,
    ):
        if not transfer_key or len(transfer_key) < 16:
            raise ValueError("transfer key must be at least 16 bytes")
        self.store_dir = os.path.realpath(os.path.abspath(store_dir))
        os.makedirs(self.store_dir, exist_ok=True)
        self.store_path = os.path.join(self.store_dir, "relay-audit.jsonl")
        self.control_path = os.path.join(self.store_dir, "relay-control.jsonl")
        self._keyring = keyring
        self._transfer_key = transfer_key
        self._timeout = timeout
        self._stop = threading.Event()
        self._lock = threading.RLock()
        # Fresh per-process challenge: restarting the server mints a new one,
        # so a hello captured against a previous process cannot be replayed
        # even when the same transfer key is retained across restarts. The
        # hello MAC must cover this challenge; the single-use nonce set only
        # guards re-use within one process lifetime.
        self._challenge = new_id("challenge-")
        self._seen_nonces: set = set()  # single-use hello nonces, this process only
        self._frame_key = b""

        # Rebuild store head + event_id index so redeliveries are idempotent.
        # Compromised starts clear and is set only by load or a later violation.
        # It must not be reset after load: a bad store has to stay failed.
        self._head = GENESIS
        self._ids: Dict[str, Dict[str, Any]] = {}
        self._stored_count = 0
        self._compromised = False
        self._stale = False
        self._load_store()
        self._listener: Optional[socket.socket] = None
        self._active_conn: Optional[socket.socket] = None
        self._serve_thread: Optional[threading.Thread] = None

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(4)
        self.host, self.port = self._listener.getsockname()[:2]

    def _load_store(self) -> None:
        """Accept a recovered head only after every stored link verifies.

        A tampered line leaves the head at genesis and keeps the store
        compromised. The failure flag is not cleared by the caller.
        """
        try:
            with open(self.store_path, "r", encoding="utf-8") as handle:
                lines = [line.strip() for line in handle if line.strip()]
        except FileNotFoundError:
            return
        except Exception:
            self._compromised = True
            return

        prev = GENESIS
        ids: Dict[str, Dict[str, Any]] = {}
        for line in lines:
            try:
                stored = loads_strict(line)
                payload = stored.get("record")
                chain_prev = stored.get("chain_prev")
                chain_mac = stored.get("chain_mac")
                chain_hash = stored.get("chain_hash")
                event_id = payload.get("event_id") if isinstance(payload, dict) else None
                if (
                    not isinstance(payload, dict)
                    or not isinstance(chain_prev, str)
                    or not isinstance(chain_mac, str)
                    or not isinstance(chain_hash, str)
                    or not isinstance(event_id, str)
                    or not event_id
                    or not hmac.compare_digest(chain_prev, prev)
                ):
                    self._compromised = True
                    return
                mac, chain = _verify_record(payload, prev, self._keyring)
                if (
                    not hmac.compare_digest(mac, chain_mac)
                    or not hmac.compare_digest(chain, chain_hash)
                ):
                    self._compromised = True
                    return
                existing = ids.get(event_id)
                if existing is not None and existing != payload:
                    self._compromised = True
                    return
                ids[event_id] = payload
                prev = chain
            except Exception:
                self._compromised = True
                return
        self._ids = ids
        self._head = prev
        self._stored_count = len(ids)

    @property
    def compromised(self) -> bool:
        return self._compromised

    @property
    def stale(self) -> bool:
        return self._stale

    def start(self) -> None:
        if self._serve_thread is None:
            self._serve_thread = threading.Thread(
                target=self._serve_loop, name="voss-audit-relay", daemon=True)
            self._serve_thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._listener is not None:
                self._listener.close()
        except OSError:
            pass
        if self._serve_thread is not None:
            self._serve_thread.join(timeout=5.0)

    def _serve_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except OSError:
                break
            try:
                with self._lock:
                    if self._active_conn is not None:
                        _write_control(
                            self.control_path, "relay_busy",
                            "another host is connected")
                        try:
                            conn.sendall(_frame({"type": "busy"}))
                        except OSError:
                            pass
                        conn.close()
                        continue
                    self._active_conn = conn
                self._handle(conn)
            finally:
                with self._lock:
                    self._active_conn = None
                graceful_close(conn)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(self._timeout)
        # Speak first: the client must echo this process's challenge in its
        # hello MAC, so a captured hello from a previous process lifetime
        # (same transfer key, different process) cannot open a session.
        self._reply(conn, _challenge_frame(self._transfer_key, self._challenge))
        idle = 0
        phase = "hello"
        expected_seq = 0
        auth_seq = 1  # post-hello stanzas are numbered 1..; replays/gaps clamp
        self._reply_seq = 0
        self._frame_key = b""
        try:
            while not self._stop.is_set():
                if self._compromised:
                    refused = {"type": "refused", "reason": "relay_compromised"}
                    if self._frame_key:
                        self._reply_session(conn, refused)
                    else:
                        self._reply(conn, refused)
                    return
                try:
                    msg = _read_frame(conn)
                except socket.timeout:
                    idle += 1
                    if not self._stale:
                        self._stale = True
                        _write_control(self.control_path, "relay_stale",
                                       "no records within timeout")
                    if idle >= _IDLE_CLOSE_AFTER:
                        _write_control(self.control_path, "relay_idle_closed",
                                       "connection closed after idle timeout")
                        return
                    continue
                except RelayStreamClosed:
                    # Clean peer close / connection death: not a violation.
                    _write_control(self.control_path, "relay_stream_closed",
                                   "host stream ended")
                    return
                except RelayViolationError as exc:
                    self._violate(conn, str(exc))
                    return
                except (OSError, UnicodeDecodeError, ValueError) as exc:
                    self._violate(conn, f"malformed_frame:{exc}")
                    return

                idle = 0
                if self._stale:
                    self._stale = False
                    _write_control(self.control_path, "relay_recovered",
                                   "records resumed after idle")

                if phase == "hello":
                    reason = self._claim_hello(msg)
                    if reason:
                        _write_control(self.control_path, "relay_denied_hello",
                                       f"{reason}:{msg!r:.120}")
                        self._reply(conn, {"type": "violation",
                                           "reason": "denied_hello_auth"})
                        return
                    nonce = str(msg.get("nonce", ""))
                    self._frame_key = derive_session_key(
                        RELAY_PROTOCOL, self._transfer_key, self._challenge,
                        nonce,
                    )
                    _write_control(self.control_path, "relay_accepted_hello",
                                   "authenticated host connected")
                    self._reply_session(conn, {
                        "type": "hello_ok", "nonce": msg.get("nonce", "")})
                    phase = "stream_begin"
                elif phase == "stream_begin":
                    if msg.get("type") != "stream_begin":
                        self._violate(conn, "expected_stream_begin")
                        return
                    if not frame_is_authed(msg, RELAY_PROTOCOL,
                                           self._frame_key):
                        self._violate(conn, "stream_begin_auth")
                        return
                    if msg.get("seq") != auth_seq:
                        self._violate(
                            conn,
                            f"sequence_gap expected {auth_seq} got {msg.get('seq')}",
                        )
                        return
                    auth_seq += 1
                    self._reply_session(conn, {
                        "type": "stream_ready",
                        "chain_len": self._stored_count,
                        "head": self._head})
                    expected_seq = 1
                    phase = "records"
                else:
                    if not frame_is_authed(msg, RELAY_PROTOCOL,
                                           self._frame_key):
                        self._violate(conn, "record_auth")
                        return
                    expected_seq += 1
                    if msg.get("seq") != expected_seq:
                        self._violate(
                            conn,
                            f"sequence_gap expected {expected_seq} got {msg.get('seq')}",
                        )
                        return
                    self._ingest_record(conn, msg)
        except OSError:
            # peer vanished; reconnect is handled by the client
            return

    def _valid_hello(self, msg: Dict[str, Any]) -> bool:
        if msg.get("type") != "hello":
            return False
        if msg.get("version") != RELAY_PROTOCOL:
            return False
        challenge = msg.get("challenge")
        nonce = msg.get("nonce")
        mac = msg.get("mac")
        if not (isinstance(challenge, str) and
                isinstance(nonce, str) and isinstance(mac, str)):
            return False
        if challenge != self._challenge:
            return False
        return hmac.compare_digest(
            _sign_hello(self._transfer_key, nonce, challenge), mac)

    def _claim_hello(self, msg: Dict[str, Any]) -> str:
        """Return a reason string if this hello must be refused, else ''.

        The hello authenticates with the transfer key, but a transfer-key
        capable replay of a captured hello (same nonce+MAC) must not open a
        second session: the nonce is single-use for this process only.
        """
        if not self._valid_hello(msg):
            return "denied_relay_auth"
        nonce = msg.get("nonce")
        with self._lock:
            if nonce in self._seen_nonces:
                return "replayed_hello_nonce"
            self._seen_nonces.add(nonce)
        return ""

    def _ingest_record(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        record = msg.get("record")
        if not isinstance(record, dict):
            self._violate(conn, "record_missing_payload")
            return
        event_id = record.get("event_id")
        if not isinstance(event_id, str):
            self._violate(conn, "record_missing_id")
            return
        existing = self._ids.get(event_id)
        if existing is not None:
            if existing != record:
                self._violate(conn, f"duplicate_contradiction:{event_id}")
                return
            self._reply_session(conn, {
                "type": "ack", "request_seq": msg.get("seq"),
                "dup": True, "chain_len": self._stored_count})
            return
        mac, chain = _verify_record(record, self._head, self._keyring)
        line_record = {
            "chain_prev": self._head,
            "chain_mac": mac,
            "chain_hash": chain,
            "record": record,
        }
        with self._lock:
            self._ids[event_id] = record
            self._head = chain
            self._stored_count += 1
            with open(self.store_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(line_record, sort_keys=True) + "\n")
                handle.flush()
        self._reply_session(conn, {
            "type": "ack", "request_seq": msg.get("seq"),
            "dup": False, "chain_len": self._stored_count})

    def _violate(self, conn: socket.socket, reason: str) -> None:
        with self._lock:
            self._compromised = True
        _write_control(self.control_path, "relay_violation", reason)
        if self._frame_key:
            self._reply_session(conn, {"type": "violation", "reason": reason})
        else:
            self._reply(conn, {"type": "violation", "reason": reason})

    def _reply_session(self, conn: socket.socket,
                       msg: Dict[str, Any]) -> None:
        self._reply_seq += 1
        self._reply(conn, frame_signed(
            RELAY_PROTOCOL, self._frame_key, self._reply_seq, msg))

    def _reply(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        try:
            conn.sendall(_frame(msg))
        except OSError:
            pass


class AuditRelayClient:
    """Trusted-host side: tails the local audit file, forwards to the relay.

    The client keeps its own read cursor.  On every (re)connect it re-reads
    the whole file so records that a connection loss may have stranded are
    redelivered; the relay idempotently acks already-stored records.
    """

    def __init__(
        self,
        audit_path: str,
        host: str,
        port: int,
        transfer_key: bytes,
        *,
        timeout: float = 5.0,
        tick: float = 0.05,
    ):
        self._audit_path = audit_path
        self._host = host
        self._port = port
        self._transfer_key = transfer_key
        self._timeout = timeout
        self._tick = tick
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._cursor = 0
        self._seq = 0
        self.connected = False
        self.last_error = ""
        self.violation = ""
        self.records_relayed = 0
        self.last_ack_dup_count = 0
        self._on_violation = None

    def set_on_violation(self, handler) -> None:
        self._on_violation = handler

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._run, name="voss-audit-relay-client", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
        if not self.violation:
            # Best-effort synchronous final drain: relay anything the tailer
            # had not yet forwarded (records after the last read tick), on a
            # fresh connection, idempotently.
            try:
                self._session(one_pass=True)
            except Exception as exc:
                if not self.violation:
                    self.last_error = f"stop-drain: {exc}"

    def health(self) -> Dict[str, Any]:
        return {
            "ok": not self.violation and self.last_error == "",
            "connected": self.connected,
            "violation": self.violation or None,
            "error": self.last_error or None,
            "records_relayed": self.records_relayed,
            "dup_redeliveries": self.last_ack_dup_count,
        }

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._session(one_pass=False)
            except (OSError, RelayViolationError, RelayStreamClosed, ValueError) as exc:
                self.connected = False
                self.last_error = str(exc)
                if isinstance(exc, RelayViolationError) and not self.violation:
                    self.violation = str(exc)
                    if self._on_violation is not None:
                        self._on_violation(self.violation)
            self._stop.wait(self._tick)

    def _session(self, one_pass: bool) -> None:
        with socket.create_connection((self._host, self._port), timeout=self._timeout) as conn:
            conn.settimeout(self._timeout)
            challenge = _read_frame(conn)
            if (challenge.get("type") != "challenge" or
                    not isinstance(challenge.get("challenge"), str)):
                raise RelayViolationError(f"no challenge: {challenge!r}")
            if challenge.get("mac") != _sign_challenge(
                    self._transfer_key, challenge["challenge"]):
                raise RelayViolationError("challenge failed authentication")
            nonce = new_id("relay-")
            frame_key = derive_session_key(
                RELAY_PROTOCOL, self._transfer_key,
                challenge["challenge"], nonce,
            )
            self._frame_send(conn, {
                "type": "hello", "version": RELAY_PROTOCOL,
                "challenge": challenge["challenge"], "nonce": nonce,
                "mac": _sign_hello(self._transfer_key, nonce,
                                   challenge["challenge"]),
            })
            reply = _read_frame(conn)
            if reply.get("type") != "hello_ok":
                raise RelayViolationError(f"hello rejected: {reply!r}")
            reply_seq = 1
            if (not frame_is_authed(reply, RELAY_PROTOCOL, frame_key) or
                    reply.get("seq") != reply_seq):
                raise RelayViolationError("hello_ok failed authentication")
            self._frame_send(conn, frame_signed(
                RELAY_PROTOCOL, frame_key, 1,
                {"type": "stream_begin"}))
            ready = _read_frame(conn)
            if ready.get("type") != "stream_ready":
                raise RelayViolationError(f"stream rejected: {ready!r}")
            reply_seq += 1
            if (not frame_is_authed(ready, RELAY_PROTOCOL, frame_key) or
                    ready.get("seq") != reply_seq):
                raise RelayViolationError("stream_ready failed authentication")

            # Re-deliver everything from the start (idempotent); cursor is 0
            # on every connect so a connection loss can never strand records.
            self._cursor = 0
            self._seq = 1
            self.connected = True
            self.last_error = ""
            while True:
                for line in self._tail_once():
                    self._seq += 1
                    record = loads_strict(line).get("record")
                    self._frame_send(conn, frame_signed(
                        RELAY_PROTOCOL, frame_key, self._seq,
                        {"type": "record", "record": record}))
                    ack = _read_frame(conn)
                    reply_seq += 1
                    if (not frame_is_authed(ack, RELAY_PROTOCOL, frame_key) or
                            ack.get("seq") != reply_seq):
                        raise RelayViolationError("relay ack failed authentication")
                    if ack.get("type") == "violation":
                        raise RelayViolationError(f"relay: {ack.get('reason')}")
                    if ack.get("type") != "ack":
                        raise RelayViolationError(f"unexpected relay reply: {ack!r}")
                    if ack.get("request_seq") != self._seq:
                        raise RelayViolationError("relay ack request sequence mismatch")
                    if ack.get("dup"):
                        self.last_ack_dup_count += 1
                    else:
                        self.records_relayed += 1
                if one_pass or self._stop.is_set():
                    return
                self._stop.wait(self._tick)

    def _tail_once(self) -> List[str]:
        try:
            with open(self._audit_path, "r", encoding="utf-8") as handle:
                handle.seek(self._cursor)
                data = handle.read()
        except FileNotFoundError:
            return []
        if not data:
            return []
        chunks = data.split("\n")
        if data.endswith("\n"):
            complete = chunks[:-1]
            advance = len(data)
        else:
            trailing = chunks[-1]
            complete = chunks[:-1]
            advance = len(data) - len(trailing)
        self._cursor += advance
        return [ln for ln in complete if ln.strip()]

    def _frame_send(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        conn.sendall(_frame(msg))
        conn.settimeout(self._timeout)


def _frame(msg: Dict[str, Any]) -> bytes:
    body = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_FRAME:
        raise RelayViolationError("oversize_frame")
    return len(body).to_bytes(4, "big") + body


def _read_frame(conn: socket.socket) -> Dict[str, Any]:
    header = _recv_exact(conn, 4)
    if header is None:
        raise RelayStreamClosed("peer closed")
    length = int.from_bytes(header, "big")
    if length > MAX_FRAME:
        raise RelayViolationError("oversize_frame")
    body = _recv_exact(conn, length)
    if body is None:
        raise RelayStreamClosed("peer closed")
    decoded = loads_strict(body.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RelayViolationError("malformed_frame")
    return decoded


def _recv_exact(conn: socket.socket, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (ConnectionResetError, ConnectionAbortedError) as exc:
            raise RelayStreamClosed(f"connection_lost: {exc}") from exc
        if not chunk:
            return None
        buf += chunk
    return buf


def serve_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="voss.relay")
    parser.add_argument("--store", required=True, help="relay store directory")
    parser.add_argument("--keyring-dir", required=True,
                        help="directory holding keys.json (audit MAC key)")
    parser.add_argument("--port-file", required=True,
                        help="file to write the bound port into")
    parser.add_argument("--transfer-key", required=True, help="hex transfer key")
    parser.add_argument("--timeout", type=float, default=STALE_TIMEOUT,
                        help="idle-timeout in seconds before stale is flagged")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)

    keyring = KeyRing.load_or_create(args.keyring_dir)
    server = AuditRelayServer(
        args.store, keyring, bytes.fromhex(args.transfer_key),
        port=args.port, timeout=args.timeout,
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
