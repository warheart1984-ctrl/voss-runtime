"""Recoverable write-ahead ledger (Voss RFC 5.5 recovery support).

Flows, capabilities, and the replay-uniqueness markers that grant state
depends on must survive a trusted-host restart without granting anything
new.  The write-ahead ledger records every state mutation on the same
authenticated MAC chain as the audit log; on boot the runtime replays the
ledger and only restores what it can verify.  A tampered or unverifiable
ledger fails recovery closed (no grants are restored and the worker is
suspended).
"""
from __future__ import annotations

from .audit import AuditLog
from .canonical import loads_strict, sha256_hex


def _trim_partial_tail(path: str) -> None:
    """Drop an *incomplete* final record left by a crash mid-append.

    A record that never finished being written was never acknowledged, so
    discarding it is safe.  A structural parse failure mid-file is NOT
    trimmed: the chain check later fails closed instead.  Reads both a real
    crash and an unevidenced rollback of the newest record, which is the
    same undetectability class as truncation itself (RFC 9.1, write-only
    transport would remove it).
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return
    if not raw:
        return
    raw_lines = raw.splitlines(keepends=True)
    for index, raw_line in enumerate(raw_lines):
        if not raw_line.strip():
            continue
        try:
            loads_strict(raw_line.decode("utf-8", "replace").strip())
        except Exception:
            if index != len(raw_lines) - 1:
                return  # mid-file break: leave for verify_integrity to refuse
            with open(path, "wb") as handle:
                handle.write(b"".join(raw_lines[:index]))
            return


class WriteAheadLog(AuditLog):
    """Append-only recovery ledger sharing AuditLog's chaining semantics."""

    SCHEMA = "voss.wal.1"
    GENESIS = sha256_hex({"genesis": "voss-wal-chain"})

    def __init__(self, path: str, keyring):
        _trim_partial_tail(path)
        super().__init__(path, keyring)