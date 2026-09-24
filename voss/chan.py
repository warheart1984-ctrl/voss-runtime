"""Authenticated adapter<->host channel protocol (Voss RFC 9.2, Binding 4.1).

The transport is the untrusted model adapter's only way to reach the trusted
runtime.  Shape of a message (both directions):

    {"mac": "<HMAC-SHA256 hex>", "body": {"chan": "voss.chan.v1",
     "sid": "<channel session id>", "dir": "a2h"|"h2a", "seq": <int>,
     "type": "<message type>", "msg": {...}}}

The MAC covers the canonical JSON of ``body`` with a per-spawn key that is
provisioned out-of-band (one-time bootstrap file) and never rides in the
adapter's environment as a secret-named variable.  Every side tracks the peer's
monotonic sequence per direction, so a replayed, skipped, or forged message is
rejected with a precise reason code and (host side) suspends the worker.

This module is *shared*: the untrusted adapter imports it too (like
``canonical``), which lets the adapter verify the host's messages rather than
blindly trusting whichever process happens to own its pipes.  It imports
nothing privileged.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Dict, Tuple

from .canonical import canonical_bytes, loads_strict, new_id

SCHEMA = "voss.chan.v1"
MAX_LINE = 65536

ADAPTER_TO_HOST_TYPES = frozenset({"hello", "proposal", "goodbye_ok"})
HOST_TO_ADAPTER_TYPES = frozenset({"hello_ok", "prompt", "denied"})

_DIR_ADAPTER = "a2h"
_DIR_HOST = "h2a"


class ChannelError(Exception):
    """A channel verification failure that must never be ignored."""

    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


class ChannelTimeoutError(RuntimeError):
    """Peer did not produce a complete line within the deadline."""


def mac(key: bytes, body: Dict[str, Any]) -> str:
    return hmac.new(key, canonical_bytes(body), hashlib.sha256).hexdigest()


def wire_line(key: bytes, sid: str, direction: str, seq: int,
              msg_type: str, msg: Dict[str, Any]) -> str:
    body = {"chan": SCHEMA, "sid": sid, "dir": direction,
            "seq": seq, "type": msg_type, "msg": msg}
    import json
    return json.dumps({"mac": mac(key, body), "body": body}, sort_keys=True)


def parse_wire(text: str) -> Tuple[Dict[str, Any], str]:
    try:
        line = loads_strict(text)
    except Exception as exc:
        raise ChannelError("denied_channel_auth") from exc
    if not isinstance(line, dict):
        raise ChannelError("denied_channel_auth")
    body = line.get("body")
    wire_mac = line.get("mac")
    if not isinstance(body, dict) or not isinstance(wire_mac, str):
        raise ChannelError("denied_channel_auth")
    return body, wire_mac


def chan_bootstrap(key: bytes, sid: str) -> Dict[str, Any]:
    return {"v": 1, "schema": SCHEMA, "sid": sid,
            "key_hex": key.hex(), "issued_at": round(time.time(), 6)}


def read_bootstrap_file(path: str) -> Tuple[bytes, str]:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise ChannelError("denied_channel_bootstrap") from exc
    return read_bootstrap(text)


def read_bootstrap(text: str) -> Tuple[bytes, str]:
    try:
        data = loads_strict(text)
        if not isinstance(data, dict) or data.get("v") != 1 or data.get("schema") != SCHEMA:
            raise ValueError("unsupported bootstrap schema or version")
        sid = str(data["sid"])
        key = bytes.fromhex(str(data["key_hex"]))
    except Exception as exc:
        raise ChannelError("denied_channel_bootstrap") from exc
    if len(key) < 16 or not sid:
        raise ChannelError("denied_channel_bootstrap")
    return key, sid


def unlink_quiet(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


class ChannelSession:
    """One side of an authenticated hop.

    ``role`` is ``"host"`` (trusted runtime) or ``"adapter"`` (untrusted
    worker).  ``receive()`` verifies MAC, session, direction, allowed type, and
    monotonic sequence before returning ``(type, msg)``.
    """

    def __init__(self, key: bytes, sid: str, role: str):
        if role not in ("host", "adapter"):
            raise ValueError("role must be 'host' or 'adapter'")
        self._key = key
        self._sid = sid
        self._role = role
        self._peer_dir = _DIR_ADAPTER if role == "host" else _DIR_HOST
        self._send_dir = _DIR_HOST if role == "host" else _DIR_ADAPTER
        self._allowed_send = (HOST_TO_ADAPTER_TYPES if role == "host"
                              else ADAPTER_TO_HOST_TYPES)
        self._allowed_peer = (ADAPTER_TO_HOST_TYPES if role == "host"
                              else HOST_TO_ADAPTER_TYPES)
        self._send_seq = 0
        self._recv_seq = 1

    @property
    def role(self) -> str:
        return self._role

    def send(self, msg_type: str, msg: Dict[str, Any]) -> str:
        if msg_type not in self._allowed_send:
            raise ChannelError("denied_channel_wrong_direction")
        self._send_seq += 1
        return wire_line(self._key, self._sid, self._send_dir,
                         self._send_seq, msg_type, msg)

    def receive(self, text: str) -> Tuple[str, Dict[str, Any]]:
        body, wire_mac = parse_wire(text)
        if body.get("chan") != SCHEMA:
            raise ChannelError("denied_channel_auth")
        if body.get("sid") != self._sid:
            raise ChannelError("denied_channel_bad_session")
        if body.get("dir") != self._peer_dir:
            raise ChannelError("denied_channel_wrong_direction")
        if not isinstance(body.get("seq"), int):
            raise ChannelError("denied_channel_auth")
        msg_type = body.get("type")
        if not isinstance(msg_type, str) or msg_type not in self._allowed_peer:
            raise ChannelError("denied_channel_wrong_direction")
        if not isinstance(body.get("msg"), dict):
            raise ChannelError("denied_channel_auth")

        if not _hmac_eq(mac(self._key, body), wire_mac):
            raise ChannelError("denied_channel_auth")

        seq = body["seq"]
        if seq < self._recv_seq:
            raise ChannelError("denied_channel_replay")
        if seq > self._recv_seq:
            raise ChannelError("denied_channel_sequence")
        self._recv_seq += 1
        return msg_type, body["msg"]


def _hmac_eq(a: str, b: str) -> bool:
    try:
        expected = a.encode("ascii")
        supplied = b.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(expected, supplied)
