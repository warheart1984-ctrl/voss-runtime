"""Trusted key material for the Voss prototype.

These keys live only in the trusted process.  They are never placed in the
worker environment, model context, tool output, or audit records.  In a
production deployment they would be held in an OS-backed secret store or
external signing service (Voss RFC 7.2 / 10).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os


class KeyRing:
    """Owns the policy signing key and the audit MAC key.

    Uses HMAC-SHA256 (RFC 2104) as the authenticated-origin mechanism;
    the RFC explicitly permits a keyed MAC where origin authentication is
    required (Binding section 4.3).
    """

    def __init__(self, policy_secret: bytes, audit_secret: bytes):
        if not policy_secret or not audit_secret:
            raise ValueError("key material must be non-empty")
        self._policy_key = policy_secret
        self._audit_key = audit_secret

    @classmethod
    def generate(cls) -> "KeyRing":
        return cls(os.urandom(32), os.urandom(32))

    @classmethod
    def load_or_create(cls, directory: str) -> "KeyRing":
        """Prototype secret store (RFC 7.2 / 10): keys persist across restarts
        so audit and write-ahead chains remain verifiable by the same runtime.

        Production would hold these in an OS-backed secret store or external
        signing service; the file is the prototype's stand-in and is chmod'd
        owner-only where the platform allows it.
        """
        import time

        path = os.path.join(directory, "keys.json")
        os.makedirs(directory, exist_ok=True)
        for _ in range(50):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                return cls(
                    bytes.fromhex(str(data["policy_key"])),
                    bytes.fromhex(str(data["audit_key"])),
                )
            except FileNotFoundError:
                pass
            except (OSError, ValueError, KeyError, TypeError) as exc:
                raise ValueError(f"cannot load key store at {path}: {exc}") from exc

            ring = cls.generate()
            try:
                with open(path, "x", encoding="utf-8") as handle:
                    json.dump(
                        {"policy_key": ring._policy_key.hex(),
                         "audit_key": ring._audit_key.hex()},
                        handle, indent=0,
                    )
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                return ring
            except FileExistsError:
                time.sleep(0.02)  # raced with another opener; read what won
        raise ValueError(f"cannot create key store at {path}")

    def sign_policy(self, policy_bytes: bytes) -> str:
        return hmac.new(self._policy_key, policy_bytes, hashlib.sha256).hexdigest()

    def verify_policy(self, policy_bytes: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or len(signature) != 64:
            return False
        expected = self.sign_policy(policy_bytes)
        return hmac.compare_digest(expected, signature)

    def mac_audit(self, payload_bytes: bytes) -> str:
        return hmac.new(self._audit_key, payload_bytes, hashlib.sha256).hexdigest()