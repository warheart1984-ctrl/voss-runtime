"""Shared helpers for the Voss test suite."""
from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

from voss.canonical import new_id
from voss.keys import KeyRing
from voss.policy import Rule, build_policy_body, package_policy
from voss.runtime import VossRuntime

EXPIRY = 60


def dev_policy_package(
    keyring: KeyRing,
    workspace: str,
    expiry: int = EXPIRY,
    approval_rules: tuple = ("workspace.write", "external.send_mock"),
) -> Dict[str, Any]:
    rules = [
        Rule(principal="*", action="workspace.read",
             resource_prefix={"path_prefix": workspace},
             decision="ALLOW", approval_required=False, expiry_limit_seconds=expiry),
        Rule(principal="*", action="workspace.write",
             resource_prefix={"path_prefix": workspace},
             decision="ALLOW", approval_required="workspace.write" in approval_rules,
             expiry_limit_seconds=expiry),
        Rule(principal="*", action="external.send_mock",
             resource_prefix={"service": "mail"},
             decision="ALLOW", approval_required="external.send_mock" in approval_rules,
             expiry_limit_seconds=expiry),
    ]
    body = build_policy_body(rules, version="1.0.0", signer="operator-test")
    return package_policy(body, keyring)


def make_runtime(
    tmp: str,
    *,
    expiry: int = EXPIRY,
    policy_package: Optional[Dict[str, Any]] = None,
    policy_approval_rules: tuple = ("workspace.write", "external.send_mock"),
    keyring: Optional[KeyRing] = None,
    audit_relay=None,
    watchdog_guard=None,
    operator_console=None,
    outbox_accounting=None,
) -> VossRuntime:
    workspace = os.path.join(tmp, "workspace")
    outbox = os.path.join(tmp, "outbox")
    audit_path = os.path.join(tmp, "audit.jsonl")
    os.makedirs(workspace, exist_ok=True)
    os.makedirs(outbox, exist_ok=True)
    keyring = keyring or KeyRing.load_or_create(tmp)
    if policy_package is None:
        policy_package = dev_policy_package(keyring, workspace, expiry, policy_approval_rules)
    rt = VossRuntime(workspace, outbox, audit_path, keyring=keyring,
                     policy_package=policy_package, audit_relay=audit_relay,
                     watchdog_guard=watchdog_guard,
                     operator_console=operator_console,
                     outbox_accounting=outbox_accounting)
    return rt


def envelope(
    rt: VossRuntime,
    action: str,
    *,
    path: Optional[str] = None,
    recipient: Optional[str] = None,
    service: str = "mail",
    payload: Optional[Dict[str, Any]] = None,
    constraints: Optional[Dict[str, Any]] = None,
    principal: Optional[str] = None,
    request_id: Optional[str] = None,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    if action in ("workspace.read", "workspace.write"):
        resource: Dict[str, Any] = {"path": path or "file.txt"}
    else:
        resource = {"service": service, "recipient": recipient or "alex@example.invalid"}
    return {
        "version": "1",
        "request_id": request_id or new_id("req-"),
        "session_id": session_id or rt.worker_session,
        "principal": principal or rt.worker_principal,
        "action": action,
        "resource": resource,
        "payload": payload or {},
        "constraints": constraints or {},
    }


def submit(rt: VossRuntime, env: Dict[str, Any]) -> Dict[str, Any]:
    return rt.handle_envelope(json.dumps(env, sort_keys=True))


def approve(
    rt: VossRuntime,
    env: Dict[str, Any],
    decision: str = "APPROVE",
    ref: str = "test-human",
) -> Dict[str, Any]:
    resp = submit(rt, env)
    if resp.get("decision") == "REQUIRE_APPROVAL":
        return rt.resolve_approval(resp["approval_request_id"], decision, ref)
    return resp


def outbox_files(outbox_dir: str) -> list:
    return sorted(os.listdir(outbox_dir))