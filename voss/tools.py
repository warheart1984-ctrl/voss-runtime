"""Broker-owned tool executions (Voss RFC 6.3, 12).

Tools execute only inside the broker process, on requests the broker has
already validated, and they re-validate the canonical resource at the
boundary.  There are exactly three tools: workspace read/write and a
simulated external action.  There is deliberately no shell, network, or
delete capability anywhere in this prototype.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional

from .canonical import ProtocolError, new_id, sha256_hex
from .outbox import OutboxUnavailable, OutboxUncertain
from .protocol import CanonicalRequest, resolve_within_root

MAX_WORKSPACE_BYTES = 1_000_000


class ToolFailure(RuntimeError):
    pass


class UncertainOutcome(RuntimeError):
    """Execution happened but the result is ambiguous; no automatic retry."""


class ToolContext:
    """Enforces the resource boundary. Lives only in the trusted process."""

    def __init__(self, workspace_root: str, outbox_dir: str,
                 outbox_link=None):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))
        self.outbox_dir = os.path.realpath(os.path.abspath(outbox_dir))
        self._outbox_link = outbox_link
        os.makedirs(self.workspace_root, exist_ok=True)
        os.makedirs(self.outbox_dir, exist_ok=True)

    def _workspace_file(self, cr: CanonicalRequest) -> str:
        # Re-canonicalize at the execution boundary even though the normalizer
        # already validated: a caller between the two cannot change the path.
        return resolve_within_root(cr.resource["path"], self.workspace_root)

    def _max_bytes(self, cr: CanonicalRequest) -> int:
        return int(cr.constraints.get("size_max", MAX_WORKSPACE_BYTES))

    def read(self, cr: CanonicalRequest) -> Dict[str, Any]:
        path = self._workspace_file(cr)
        limit = self._max_bytes(cr)
        try:
            size = os.path.getsize(path)
            if size > limit:
                raise ToolFailure(f"file exceeds size constraint ({size} > {limit})")
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read(limit)
        except OSError as exc:
            raise ToolFailure(f"cannot read {path}: {exc}") from exc
        return {
            "bytes": len(content.encode("utf-8")),
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content": content,
        }

    def write(self, cr: CanonicalRequest) -> Dict[str, Any]:
        path = self._workspace_file(cr)
        limit = self._max_bytes(cr)
        payload_keys = set(cr.payload)
        if payload_keys - {"content"}:
            raise ToolFailure(f"unexpected write payload fields: {sorted(payload_keys)}")
        content = cr.payload.get("content", "")
        if not isinstance(content, str):
            raise ToolFailure("write content must be a string")
        data = content.encode("utf-8")
        if len(data) > limit:
            raise ToolFailure(f"content exceeds size constraint ({len(data)} > {limit})")

        parent = os.path.dirname(path)
        if not _contained(parent, self.workspace_root):
            raise ToolFailure("write target escapes the workspace")
        try:
            os.makedirs(parent, exist_ok=True)
            tmp = path + f".part-{new_id('')}"
            with open(tmp, "wb") as handle:
                handle.write(data)
            os.replace(tmp, path)
        except OSError as exc:
            raise ToolFailure(f"cannot write {path}: {exc}") from exc
        return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    def send_mock(self, cr: CanonicalRequest) -> Dict[str, Any]:
        """Simulated external action. Only writes a local outbox event.

        No real account, network, or delivery is involved.  The event is a
        record: recipient + digests of subject/body, so audit never stores
        the plaintext payload.
        """
        if cr.resource.get("service") != "mail":
            raise ToolFailure("unsupported service")
        recipient = cr.resource.get("recipient")
        if not isinstance(recipient, str):
            raise ToolFailure("invalid recipient")
        payload_keys = set(cr.payload)
        if payload_keys - {"subject", "body", "simulate_uncertain"}:
            raise ToolFailure(f"unexpected send payload fields: {sorted(payload_keys)}")
        subject = str(cr.payload.get("subject", ""))
        body = str(cr.payload.get("body", ""))

        if cr.payload.get("simulate_uncertain") is True:
            raise UncertainOutcome("mock delivery outcome is ambiguous")

        if self._outbox_link is not None:
            return self._deliver_via_accounting(cr, recipient, subject, body)

        effect = {
            "effect_id": new_id("effect-"),
            "request_id": cr.request_id,
            "session_id": cr.session_id,
            "principal": cr.principal,
            "recipient": recipient,
            "subject_sha256": sha256_hex({"subject": subject}),
            "body_sha256": sha256_hex({"body": body}),
            "delivered_at_utc": time.time(),
        }
        try:
            with open(
                os.path.join(self.outbox_dir, effect["effect_id"] + ".json"),
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump(effect, handle, sort_keys=True)
        except OSError as exc:
            raise ToolFailure(f"cannot record external event: {exc}") from exc
        return {
            "effect_id": effect["effect_id"],
            "recipient_sha256": sha256_hex({"recipient": recipient}),
            "subject_sha256": effect["subject_sha256"],
            "body_sha256": effect["body_sha256"],
            "delivered": True,
        }

    def _deliver_via_accounting(self, cr: CanonicalRequest, recipient: str,
                                subject: str, body: str) -> Dict[str, Any]:
        """External effect through the separate accounting service (RFC 12).

        No receipt -> no effect.  The tool raises a hard failure if the
        service is unreachable or refuses, and an uncertain-outcome if the
        delivery was sent but the acknowledgement never arrived (the service
        side owns the only verifiable record of what actually happened).
        """
        payload_digest = sha256_hex({"subject": subject, "body": body})
        try:
            ack = self._outbox_link.deliver(
                new_id("dlv-"), "mail", recipient, payload_digest,
                cr.request_id,
            )
        except OutboxUncertain as exc:
            raise UncertainOutcome(
                f"external delivery sent but never acknowledged: {exc}") from exc
        except OutboxUnavailable as exc:
            raise ToolFailure(
                f"external accounting service unavailable: {exc}") from exc
        return {
            "receipt_id": ack["receipt_id"],
            "recipient_sha256": sha256_hex({"recipient": recipient}),
            "subject_sha256": sha256_hex({"subject": subject}),
            "body_sha256": sha256_hex({"body": body}),
            "delivered": True,
            "accounting": "outbox-service",
        }


def _contained(path: str, root: str) -> bool:
    norm_path = os.path.normcase(os.path.normpath(path))
    norm_root = os.path.normcase(os.path.normpath(root)).rstrip(os.sep)
    return norm_path == norm_root or norm_path.startswith(norm_root + os.sep)


class ToolRegistry:
    """The only way tools get called. Unknown names default to denial."""

    def __init__(self, context: ToolContext):
        self._ctx = context
        self._tools: Dict[str, Any] = {
            "workspace.read": context.read,
            "workspace.write": context.write,
            "external.send_mock": context.send_mock,
        }

    def names(self) -> List[str]:
        return sorted(self._tools)

    def execute(self, action: str, cr: CanonicalRequest) -> Dict[str, Any]:
        fn = self._tools.get(action)
        if fn is None:
            raise ToolFailure(f"no such tool: {action}")  # default deny
        return fn(cr)