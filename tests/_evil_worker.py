"""Adversarial channel peer used by transport tests (Voss RFC 9.2).

Run as ``python -m tests._evil_worker`` with ``VOSS_CHANNEL_BOOTSTRAP`` set
(the runtime provisions it exactly like a real worker).  ``VOSS_EVIL_MODE``
selects the attack:

- handshake-forged-mac       bad HMAC on the hello record
- reply-forged-mac           bad HMAC on the proposal record
- reply-replay               resend the (valid) hello record: duplicate seq
- reply-skip-seq             jump the sequence forward
- reply-wrong-direction      send a host-bound record on the adapter link
- reply-oversize             a line longer than the transport cap

The trusted runtime must refuse every one of these with a precise reason and
contain the worker.
"""
from __future__ import annotations

import json
import os
import sys

import voss.chan as chan

MAX = chan.MAX_LINE


def _corrupt_mac(wire_line: str) -> str:
    record = json.loads(wire_line)
    record["mac"] = "0" * 64
    return json.dumps(record, sort_keys=True)


def main() -> int:
    mode = os.environ.get("VOSS_EVIL_MODE", "valid")
    try:
        key, sid = chan.read_bootstrap_file(os.environ["VOSS_CHANNEL_BOOTSTRAP"])
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    session = chan.ChannelSession(key, sid, "adapter")

    if mode == "handshake-forged-mac":
        print(_corrupt_mac(
            session.send("hello", {"adapter": "evil", "ready": True})),
            flush=True)
        return 0

    valid_hello = session.send("hello", {"adapter": "evil", "ready": True})
    print(valid_hello, flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg_type, msg = session.receive(line)
        except chan.ChannelError:
            return 3
        if msg_type != "prompt":
            continue

        if mode == "reply-forged-mac":
            print(_corrupt_mac(session.send("proposal", {"envelopes": []})),
                  flush=True)
        elif mode == "reply-replay":
            print(valid_hello, flush=True)  # duplicate a2h seq=1
        elif mode == "reply-skip-seq":
            print(chan.wire_line(
                key, sid, "a2h", 3, "proposal", {"envelopes": []}), flush=True)
        elif mode == "reply-wrong-direction":
            print(chan.wire_line(
                key, sid, "h2a", 1, "prompt",
                {"prompt": "", "session_id": "", "principal": ""}),
                flush=True)
        elif mode == "reply-oversize":
            print("x" * (MAX + 1), flush=True)
        else:  # valid
            print(session.send("proposal", {"envelopes": []}), flush=True)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())