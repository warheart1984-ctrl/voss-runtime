"""Trusted operator console for the Voss prototype.

Run:  python -m voss.cli [--root DIR] [--auto]

The operator console is the trusted control path: it owns the approval
gesture (approve once / deny / cancel) and the watchdog kill switch.  The
model worker proposes; the console decides what reaches the broker.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from typing import Dict, List

from .approval import ApprovalView
from .keys import KeyRing
from .policy import package_policy
from .runtime import VossRuntime, default_dev_policy

DEMO = [
    ("read-forwarded-file", "propose:read", "A0 observe, policy grant, logged"),
    ("write-draft", "propose:write", "A1 workspace edit, human approval required"),
    ("send-project-update", "propose:email", "A2 external effect, one-time human approval"),
    ("uncertain-send", "propose:uncertain", "A2 ambiguous outcome -> UNKNOWN, no retry"),
    ("malicious-delete", "propose:delete", "unknown tools -> default deny"),
    ("path-escape", "propose:escape", "traversal -> default deny"),
    ("identity-forge", "propose:admin", "principal forgery -> identity deny"),
]


def _ask(view: ApprovalView, auto: bool) -> str:
    print("\n=== APPROVAL REQUESTED (trusted console) ===")
    print(view.describe())
    if auto:
        print("[auto] APPROVE")
        return "APPROVE"
    print("Choices: [1] Approve once  [2] Deny  [3] Cancel  [k] KILL worker")
    while True:
        choice = input("> ").strip().lower()
        if choice in ("1", "approve"):
            return "APPROVE"
        if choice in ("2", "deny"):
            return "DENY"
        if choice in ("3", "cancel"):
            return "CANCEL"
        if choice in ("k", "kill"):
            return "KILL"


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Voss Human Sovereign Runtime (prototype CLI)")
    parser.add_argument("--root", default=None, help="runtime directory (default: temp)")
    parser.add_argument("--auto", action="store_true", help="auto-approve (non-interactive demo)")
    args = parser.parse_args(argv)

    if args.root:
        base = os.path.realpath(args.root)
        os.makedirs(base, exist_ok=True)
    else:
        base = tempfile.mkdtemp(prefix="voss-demo-")

    workspace = os.path.join(base, "workspace")
    outbox = os.path.join(base, "outbox")
    audit_path = os.path.join(base, "audit.jsonl")
    os.makedirs(workspace, exist_ok=True)

    keyring = KeyRing.load_or_create(base)
    pkg = package_policy(default_dev_policy(workspace), keyring)

    rt = VossRuntime(workspace, outbox, audit_path, keyring=keyring, policy_package=pkg)

    with open(os.path.join(workspace, "notes.txt"), "w", encoding="utf-8") as handle:
        handle.write("Meeting notes: review the draft on Monday.\n")

    print(f"Runtime root : {base}")
    print(f"Worker       : {rt.worker_principal}")
    print(f"Policy       : v{rt.policy_version} (audit_required, human-gated actions present)")
    print(f"Tools        : {rt.tools.names()}")

    proc = rt.spawn_worker()
    print(f"Worker proc  : pid {proc.pid} (spawned with clean env)")

    try:
        for name, prompt, note in DEMO:
            print(f"\n--- step: {name} ({note}) ---")
            envelopes = rt.worker_propose(proc, prompt)
            for envelope in envelopes:
                response = rt.handle_envelope(json_dumps(envelope))
                print(f"proposal: {envelope.get('action')} -> {response.get('decision')} ({response.get('reason_code')})")
                if response.get("decision") == "REQUIRE_APPROVAL":
                    flow_id = response["approval_request_id"]
                    view = rt.approvals.view(flow_id)
                    decision = _ask(view, args.auto)
                    if decision == "KILL":
                        print(rt.kill_worker(reason="operator kill", proc=proc))
                        print("KILLED. Further steps will be denied.")
                        break
                    result = rt.resolve_approval(flow_id, decision, "operator@console")
                    print(f"resolution: {result.get('decision')} ({result.get('reason_code')}) result={result.get('result')}")
                elif response.get("decision") == "DENY":
                    print(f"  denied: {response.get('reason_code')}")
            else:
                continue
            break
    finally:
        rt.broker.revoke_all(rt.worker_principal, reason="console-exit")
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()

    print("\n=== AUDIT SUMMARY ===")
    for key, value in rt.audit_summary().items():
        print(f"{key}: {value}")
    print("=== HEALTH ===")
    for key, value in rt.health_report().items():
        print(f"{key}: {value}")
    print("=== DRIFT ===")
    for key, value in rt.drift_report().items():
        print(f"{key}: {value}")
    print("=== OUTBOX (simulated external effects) ===")
    for name in sorted(os.listdir(outbox)):
        print("  " + name)
    rt.close()
    return 0


def json_dumps(envelope: Dict) -> str:
    import json

    return json.dumps(envelope, sort_keys=True)


if __name__ == "__main__":
    raise SystemExit(main())