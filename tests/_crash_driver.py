"""Crash-injection driver (RFC 5.5): run one op to its crashpoint, then die.

Invoked as ``python -m tests._crash_driver <root> <mode>``.  Each mode sets the
``VOSS_CRASHPOINT`` seam for exactly the boundary it wants to die at; the
process exits 86 exactly when that seam fires (a power-loss style kill with no
cleanup).  Exit code 86 is how the test proves the intended boundary, and not
some other failure, was reached.
"""
from __future__ import annotations

import os
import sys

from tests._support import envelope, make_runtime, submit

from voss.crashpoint import (
    CP_CAPABILITY_ISSUED,
    CP_EFFECT_DONE,
    CP_FLOW_REQUEST,
    CP_FLOW_REQUEST_PREWAL,
    CP_FLOW_RESOLUTION,
    CP_REQUEST_EXECUTED,
)

_MODES = {
    "flow_request_prewal": CP_FLOW_REQUEST_PREWAL,
    "flow_request": CP_FLOW_REQUEST,
    "flow_resolution": CP_FLOW_RESOLUTION,
    "capability_issued": CP_CAPABILITY_ISSUED,
    "request_executed": CP_REQUEST_EXECUTED,
    "effect_done": CP_EFFECT_DONE,
}


def main() -> int:
    root, mode = sys.argv[1], sys.argv[2]
    point = _MODES[mode]
    rt = make_runtime(root)
    env = envelope(
        rt, "workspace.write", path="draft.txt",
        request_id=f"crash-{mode}", payload={"content": "crash-test"},
    )
    if mode in ("flow_request_prewal", "flow_request"):
        os.environ["VOSS_CRASHPOINT"] = point
        submit(rt, env)
    else:
        resp = submit(rt, env)
        flow_id = resp["approval_request_id"]
        os.environ["VOSS_CRASHPOINT"] = point
        rt.resolve_approval(flow_id, "APPROVE", "crash-test")
    os._exit(0)  # seam never fired: surface as a non-86 exit so the test fails


if __name__ == "__main__":
    raise SystemExit(main())