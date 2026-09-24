//! Voss Human Sovereign Runtime — development-profile prototype.
//!
//! This crate is the Rust counterpart of the Python prototype. A model may
//! propose an action. It cannot sign policy, choose an approval nonce, or
//! hold the audit key. The loader denies missing, malformed, expired,
//! unsigned, and conflicting policy, and it rejects a bundle that removes
//! the last human approval gate.
//!
//! The profile is local and experimental. It brokers the three prototype
//! tools inside the trusted process. It does not claim Binding conformance:
//! the worker is a separate process with a scrubbed environment. On Windows
//! it is placed in a job that cannot create child processes and ends when
//! the host releases that job. It still runs as the host user, so the job is
//! not a file or network boundary. Suspend and revocation stay in the host. An
//! optional watch-guard process holds the worker pid and is the kill authority: it
//! terminates that process when authenticated heartbeats stop or a terminate
//! directive arrives, then refuses further sessions. If that link is lost,
//! the host fails closed. The pid is still the one the host registered.
//! Audit and the write-ahead ledger are local files. A verified ledger
//! restores approval and capability state. A tampered ledger restores
//! nothing and suspends the worker. A crash at a ledger boundary never
//! re-grants or double-executes; an incomplete trailing record is dropped,
//! and a mid-file break still fails closed. An optional relay process
//! re-verifies the audit chain and keeps a byte-identical copy; it shares
//! the audit MAC key only as a prototype stand-in. Drift includes a temporal
//! signal: each worker round-trip is timed against a 2 second ceiling and a
//! 16 KiB proposal-line cap, over a minimum 10-exchange window. Consequential
//! approval can be handed to a separate console process. If that console is
//! not live, those requests are denied and never queued or granted. Reads
//! that policy already allows still proceed. An optional outbox process
//! accounts for external sends. The host keeps no copy: a delivery counts
//! only when that process returns a receipt. A dropped acknowledgement
//! leaves the host outcome unknown. Refusal or an unreachable service fails
//! the effect closed, and reads that policy already allows still proceed.
//!
//! The worker speaks only on an authenticated channel. The per-spawn key
//! rides a one-time bootstrap file, which the worker deletes on first read.
//! A bad MAC, replay, sequence gap, wrong direction, oversized line, or
//! unknown session is audited and suspends the worker immediately. A peer
//! that never completes a line is audited at the read deadline and counts as
//! one temporal anomaly. A single timeout stays under the containment
//! threshold. That deadline is not a hard process kill.

#![deny(unsafe_code)]

pub mod approval;
pub mod audit;
pub mod broker;
pub mod canonical;
pub mod chan;
pub mod confine;
pub mod console;
pub mod crashpoint;
pub mod outbox;
pub mod keys;
pub mod policy;
pub mod protocol;
pub mod relay;
pub mod runtime;
pub mod tools;
pub mod watchdog;
pub mod watchguard;

pub use canonical::{ProtocolError, canonical_bytes, loads_strict, new_id, sha256_hex};
pub use keys::KeyRing;
pub use policy::{
    DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_APPROVAL, PolicyBundle, PolicyEngine,
    PolicyLoader, Rule, build_policy_body, package_policy,
};
pub use protocol::{CanonicalRequest, RequestNormalizer, action_class, bind};

pub const VERSION: &str = "0.1.0";
pub const RUNTIME_PROTOCOL_VERSION: &str = "1";
