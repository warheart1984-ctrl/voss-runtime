"""Adversarial worker variant for the temporal-oracle tests (Binding 4.4).

Behaves exactly like ``voss.worker`` (proposes over the authenticated
channel, never executes) but can be made to **stall** past the runtime's
declared response ceiling (``VOSS_STALL_SECONDS``), or to **flood** each
proposal line with an oversized volume (``VOSS_BIG_VOLUME=1``).  Either makes
the runtime's temporal oracle register anomalies and engage containment.
"""
from __future__ import annotations

import os
import sys
import time

from voss.canonical import new_id
from voss.chan import ChannelSession, read_bootstrap_file, unlink_quiet


class AdversarialModel:
    """Deterministic proposals; may stall or bloat on request."""

    @staticmethod
    def _env(action: str, session_id: str, principal: str,
             payload: dict) -> dict:
        return {
            "version": "1",
            "request_id": new_id("req-"),
            "session_id": session_id,
            "principal": principal,
            "action": action,
            "resource": {"path": "notes.txt"},
            "payload": payload,
            "constraints": {},
        }

    def propose(self, prompt: str, session_id: str, principal: str) -> list:
        stall = float(os.environ.get("VOSS_STALL_SECONDS", "0") or 0)
        time.sleep(stall)
        payload: dict = {}
        if os.environ.get("VOSS_BIG_VOLUME") == "1":
            # ~40 KiB line: under the 64 KiB channel cap but over the
            # temporal oracle's volume cap.
            payload = {"noise": "x" * 40000}
        return [self._env("workspace.read", session_id, principal, payload)]


def main() -> int:
    bootstrap_path = os.environ.get("VOSS_CHANNEL_BOOTSTRAP")
    if not bootstrap_path:
        print("error: no channel bootstrap; refusing unauthenticated mode",
              file=sys.stderr)
        return 2
    try:
        key, sid = read_bootstrap_file(bootstrap_path)
        unlink_quiet(bootstrap_path)
    except Exception as exc:
        print(f"error: cannot load channel bootstrap: {exc}",
              file=sys.stderr)
        return 2
    if not key or not sid:
        return 2

    session = ChannelSession(key, sid, "adapter")
    model = AdversarialModel()
    print(session.send("hello", {"adapter": "voss.adversarial-stall",
                                 "ready": True}), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg_type, msg = session.receive(line)
        except Exception as exc:
            print(f"error: host channel violation: {exc}", file=sys.stderr)
            return 3
        if msg_type == "prompt":
            envelopes = model.propose(
                str(msg.get("prompt", "")),
                str(msg.get("session_id", "")),
                str(msg.get("principal", "")),
            )
            if envelopes:
                print(session.send("proposal", {"envelopes": envelopes}),
                      flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())