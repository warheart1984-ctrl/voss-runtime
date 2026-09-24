"""Deterministic crash-injection points for fault-injection tests (RFC 5.5).

A real crash can land at any byte offset of program progress.  These seams let
a test driver die (``os._exit`` == power loss) at exactly the moments where the
write-ahead ledger boundary matters:

- voss_cp_flow_request_prewal     flow created in memory, nothing recorded yet
- voss_cp_flow_request            flow_request record appended
- voss_cp_flow_resolution         approval granted, flow_resolution appended
- voss_cp_capability_issued       capability_issued appended
- voss_cp_request_executed        request_executed appended (before effect)
- voss_cp_effect_done             tool effect materialized, result not logged

Only active when ``VOSS_CRASHPOINT`` names the point; a worker can never set
it (the trusted process owns its environment).  No effect otherwise.
"""
from __future__ import annotations

import os

CP_FLOW_REQUEST_PREWAL = "voss_cp_flow_request_prewal"
CP_FLOW_REQUEST = "voss_cp_flow_request"
CP_FLOW_RESOLUTION = "voss_cp_flow_resolution"
CP_CAPABILITY_ISSUED = "voss_cp_capability_issued"
CP_REQUEST_EXECUTED = "voss_cp_request_executed"
CP_EFFECT_DONE = "voss_cp_effect_done"

_EXIT_CODE = 86  # distinctive: means "the intended crashpoint fired"


def maybe_crash(point: str) -> None:
    if os.environ.get("VOSS_CRASHPOINT") == point:
        os._exit(_EXIT_CODE)  # no cleanup, no flush guarantees beyond emit()