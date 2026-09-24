# Voss Human Sovereign Runtime — Prototype Documentation

Version: 0.1.0 (prototype). Implements a reduced, runnable slice of the
normative requirements in `PROPOSED TECHNICAL STANDARD.docx` (RFC), with the
additional constraints from *The Voss Binding, revised edition 1.1.0*.

The prototype's goal is **demonstration and adversarial testing** of the
security boundary, not production deployment. Its job is to prove that a model
adapter with no direct OS/file/network/credential/tool access can only cause
effects that pass a signed default-deny policy and an explicit, bound,
single-use human approval — and to make every bypass attempt visible in an
authenticated audit trail.

---

## 1. Platform assumptions

These are the concrete platform facts the prototype relies on. Everything else
is implementation detail.

| Assumption | Value | Why it matters |
|---|---|---|
| OS | Windows 10/11 (win32) | `os.path` semantics, subprocess spawning, `os.replace` atomic writes; a production host would instead use AppContainer / integrity levels / job objects (see §6). |
| Interpreter | CPython 3.12 (or later 3.x) | Only toolchain present on the host. The RFC's production recommendation is a memory-safe compiled language (see §6). |
| Stdlib only | No third-party packages | The worker and broker both run without any external dependency (pypdf was used only offline, for spec extraction). |
| Process model | Worker = separate OS process; broker/runtime = trusted process | Enforces the "unprivileged worker / privileged mediator" boundary in the RFC. |
| Secrets | Policy signing key + audit MAC key live only in trusted process memory | Worker env is scrubbed before spawn; keys never appear in discussions, tool output, or audit. |
| Time | Wall clock used for approval/capability/policy expiry | Prototype failure mode: expiry is clock-dependent (see §6). |
| Logging | Append-only JSONL in the runtime's temp/`--root` dir | Simulates the RFC's append-only transport; not yet a hardware/remote store (see §6). |

---

## 2. Trust boundary

The prototype divides the system into **trusted** and **untrusted** components.
This boundary is enforced by construction (imports) as well as behavior.

### Trusted (inside the security perimeter)
- `canonical.py`, `protocol.py` — strict envelope parsing / canonicalization.
- `keys.py` — policy signing + audit MAC key material.
- `policy.py` — signed policy bundle loader, integrity checks, default-deny engine.
- `approval.py` — approval flow state machine and binding.
- `audit.py` — chained, MAC-authenticated audit log.
- `wal.py` — write-ahead recovery ledger (RFC 5.5), same chaining semantics.
- `crashpoint.py` — deterministic crash-injection seams for fault-injection
  tests (RFC 5.5). Trusted-process-side, trusted-only env variable, `os._exit`.
- `chan.py` — authenticated adapter<->host channel protocol (RFC 9.2),
  shared with the adapter for verification: per-spawn HMAC key + session id,
  MAC'd canonical records in both directions, per-direction monotonic
  sequence, handshake, 64 KiB line cap.
- `relay.py` — remote audit relay (RFC 9.1): a separate process that holds
  the audit MAC key, re-verifies every record's HMAC chain itself, stores a
  byte-identical independently verifiable audit copy, and fails closed on any
  integrity violation (sequence gap, contradictory redelivery, oversized
  frame, unauthenticated handshake).
- `broker.py` — capability broker; the **only** code path that calls tools.
- `tools.py` — exactly three tools; re-validates the resource at execution.
- `watchdog.py` — independent supervisor with suspend/revoke/terminate.
- `watchguard.py` — separate-process watchdog (RFC 7.4, Binding 4.7): the kill
  authority lives OUTSIDE the trusted host. The guard process holds the
  worker's OS pid and the kill decision; the host registers the pid and
  heartbeatts over an HMAC-authenticated link. If heartbeats stop, the guard
  terminates the worker itself; it also obeys an explicit `terminate`
  directive and refuses any session after triggering.
- `console.py` — separate-process operator console (RFC 5.3, Binding 3.3): the
  human consent surface lives OUTSIDE both the worker and the trusted host.
  The console process binds 127.0.0.1, requires an HMAC-authenticated
  handshake, receives approval *views* (action, resource, risk, consequences,
  remaining validity), and is where the human votes (approve / deny / cancel)
  or sends the `terminate` kill switch. The host pushes views best-effort and
  *fails closed*: if the console cannot be reached, consequential approvals
  are denied (`denied_approval_unavailable`) - never queued or auto-granted.
- `outbox.py` — separate-process external-action accounting service (RFC 12,
  Binding 4.8): the external accounting journey lives OUTSIDE the worker AND
  the trusted host. The outbox process binds 127.0.0.1, requires an
  HMAC-authenticated transfer-key handshake, receives a *simulated* external
  effect over an idempotency-keyed frame, self-records the event in its own
  append-only receipt ledger + delivered-file store, fsyncs each receipt
  before acknowledging, refuses reuse of an idempotency key against a
  different target/payload digest, and fails closed on any ledger storage
  failure. The trusted host keeps NO copy of the delivered event; delivery is
  proven only by the service-side receipt and the service's independently
  re-verifiable ledger. Remaining gap: this is a local stdlib demo of
  accounting, not real provider delivery or hardened remote accounting
  (`test_outbox.py`, §1 limitation #3).
- `runtime.py` — wiring, identity/session binding, drift containment.
- `cli.py` — trusted operator console (approval + kill switch); in the
  prototype the standalone `voss.console` process is the detached consent
  surface and `cli.py` is the interactive wrapper around `runtime`.

### Untrusted
- `worker.py` — the model adapter. Imports only `canonical` and `chan`. It
  **proposes** envelopes over an authenticated channel; it cannot execute,
  import broker/policy/keys/audit/tools, open sockets, spawn processes, or read
  creds. Without a provisioned channel credential it refuses to run (there is
  no unauthenticated mode).
- Worker responses to the broker are coarse (`decision`, coarse `reason_code`,
  capability/approval ids, result digests) and contain no payload plaintext.
- The model's own text (e.g. claims of approval) is never treated as consent.

Data crossing the boundary:
- Worker -> broker: canonical envelopes (action, resource, payload, constraints).
- Broker -> worker: coarse decision / reason / ids / digest results.
- Human -> broker: approval gesture binding `approval_request_id` + `(approve|deny|cancel)` + a chosen action + `worker_principal` + `approval_request_id` + `(approve|deny|cancel)` + approver_id, over the trusted console.
- Host <-> console: host pushes approval `view` (flow id, action, resource,
  payload digest, policy version, risk class, consequences, reversibility,
  remaining validity); console returns `vote` (flow id + decision +
  approver_ref) or `terminate` over its own HMAC-authenticated separate-process
  link. Every view/vote is recorded in the console's append-only transcript.

---

## 3. What the prototype demonstrates (mechanism -> evidence)

| Requirement (RFC) | Mechanism implemented | Verified by |
|---|---|---|
| Model adapter has no direct tool/credential access (RFC 6.1, 7, 8) | Worker spawns with scrubbed env; worker module bans broker/policy/keys/audit/tools/socket/subprocess imports; tools exist only in the broker | `test_worker_isolation.py`, `test_network_primitives_absent...` |
| Default-deny policy; deny on missing/conflicting/unsigned/expired/disabling-audit/removing-last-human-gate (RFC 4) | Signed policy bundle + strict loader fails closed on any of these; conflicting rules -> DENY | `test_policy.py` |
| Capability broker as sole tool-execution path (RFC 6.2) | `Broker.execute_action` is the only caller of `ToolRegistry`; single-use capability with binding = digest(request) + policy_version + nonce + expiry | `test_broker.py`, source architecture |
| Approval is bound to canonical action/target/payload digest + policy version + nonce + expiry, one-time, replay-proof (RFC 5, Binding 3.3) | `Flow` stores request_digest/binding_digest; `_validate_capability` re-checks identity, session, action, resource, payload digest, constraints, policy version, expiry, usage, revocation, replay, binding digest before use | `test_approval.py`, `test_broker.py`, `test_adversarial.py` |
| Reject changed/replayed/forged requests; fail closed (RFC 6.3) | Post-approval digest mismatch -> DENY(tamper) + flow cancelled; duplicate request_id -> DENY(replay); forged `capability_id`/`approval_request_id` -> DENY; unknown envelope fields -> DENY | `test_adversarial.py`, `test_broker.py` |
| Human consent is real and trusted (RFC 3) | Model text is never consent; only `runtime.resolve_approval`/CLI gestures bind a flow; DENY/CANCEL -> terminal | `test_adversarial.py::test_model_text_is_not_consent` |
| Audit with chain + denial trail (RFC 9.1) | HMAC-chained JSONL; payloads by digest only; schema/identity/policy denials all logged; integrity verifiable | `test_audit.py`, `test_broker.py`, `test_e2e.py` |
| Revocation (RFC 7.3) | `revoke_all` marks every cap revoked; `_validate_capability` refuses revoked | `test_broker.py::test_capability_revocation_blocks_use` |
| Independent watchdog / kill (RFC 7.4, Binding 4.7) | Host-side `Watchdog` owns suspend + capability revocation + OS process termination, independent of the worker; the broker consults watchdog health before every protected use. The *kill authority* is additionally externalized to a separate process (`watchguard.py`): the guard holds the worker pid and terminates it when authenticated heartbeats stop or an explicit `terminate` directive arrives; a host that dies, hangs, or is compromised cannot kill-switch itself, because the guard does not need the host to be healthy to act | `test_e2e.py::WatchdogKillDrillTest`, `test_watchdog.py`, `test_watchguard.py` |
| External watchdog process is fail-closed when the guard is lost (RFC 7.4) | If the guard becomes unreachable after a valid session, or reports `triggered`, `WatchGuardLink` calls the runtime's failure hook: the watchdog is suspended, audit emits `guard_failure`, and the broker denies all further work; guard state is one-shot (after triggering it refuses every new session) | `test_watchguard.py::test_guard_loss_fails_runtime_closed`, `test_terminate_directive_kills_worker_then_refuses` |
| Containment / drift (Binding 4.4) | Heuristic D>0.30 contain, D>0.50 fail-closed, min 10-event window | `test_adversarial.py::DriftContainmentTest` |
| Temporal drift oracle (Binding 4.4, latency/resource) | The runtime times every worker round-trip and caps proposal-line volume; a worker that stalls past the declared 2.0s response ceiling or floods an oversized line (>16 KiB) accumulates temporal anomalies, and over the declared min-10-exchange window pushes the drift score past containment — watchdog suspend + further work denied | `test_adversarial.py::TemporalDriftTest` |
| Separate operator console: consent surface is not in the host, and is fail-closed (RFC 3, 5.3, Binding 3.3) | `console.py` runs as its own process: HMAC-authenticated handshake, approval *views* pushed over the link, human votes (`approve`/`deny`/`cancel`) and the `terminate` kill switch returned over the same link. The host denies consequential actions (`denied_approval_unavailable`) whenever the console is unreachable after a valid session or was never reachable - never queued, never auto-granted - while policy-ALLOW reads continue to work; an unauthenticated probe is refused and logged (`console_denied_hello`) without disturbing a legitimate host; the console's append-only transcript records exactly what the human was shown (flow, action, resource, risk, consequences) and what they decided | `test_console.py` (6 tests: auto-approve executes the effect, auto-deny terminal, lost console fails closed, never-reachable fails closed, unauthenticated probe refused, terminate is the kill switch) |
| Safe local tools + simulated external action (RFC 12) | `workspace.read` (A0), `workspace.write` (A1), `external.send_mock` (A2). Default mode writes a local outbox record; with an explicitly configured `OutboxLink`, it sends a simulated delivery to a separate accounting process and requires a receipt. Neither mode contacts a real mail provider. No shell/delete exists | broker/e2e tests, CLI demo, `test_outbox.py` |
| Vendor-neutral model adapter (RFC 8) | `FakeModel` is a plain Python class that maps prompts to proposal envelopes; any vendor adapter speaking the stdin protocol slots in | `worker.py`, `test_worker_standalone_produces_only_proposals` |
| Grant state survives restart; tamper fails closed (RFC 5.5) | Write-ahead ledger (`wal.py`) chains every flow/capability/consumption mutation on the same HMAC chain as audit; on boot the runtime replays the verified ledger (`runtime._recover_state`) and, for identity/session + keys, reuses the persisted identity/`keys.json`; a tampered ledger is never trusted — no grants are restored and the worker is suspended | `test_wal.py` |
| Authenticated adapter<->host transport (RFC 9.2, Binding 4.1) | Every message both ways is HMAC-SHA256 over canonical JSON with a per-spawn key + channel session id; per-direction monotonic sequence; handshake (`hello`/`hello_ok`); 64 KiB line cap; worker refuses to run without a provisioned credential. Forgery/replay/out-of-sequence/wrong-direction/oversize -> audit `transport_denied` + immediate suspend/revoke | `test_chan.py`, `test_transport.py`, `test_worker_isolation.py` |
| Fresh session keys for local service links | Relay, console, outbox, and watch-guard derive a connection-scoped HMAC key from the transfer key, authenticated process challenge, protocol tag, and fresh hello nonce. Every post-hello frame in both directions, including hello acknowledgements, is MAC-checked with independent monotonic counters. The transfer key authenticates only challenge/hello setup. | Existing relay, console, outbox, and watch-guard protocol tests (updated; not run in this change) |
| Crash mid-flight never grants nor double-executes (RFC 5.5) | Crash-injection seams (`crashpoint.py`) kill the runtime at each ledger boundary via subprocess driver; reopen proves recovery restores exactly the right state: pending flow re-approvable, granted flow without capability grants nothing extra, issued-but-unused capability executes exactly once, request-executed marker blocks every replay, and an effect already performed is never re-run. A crash mid-append of a WAL record is tolerated by trimming the single incomplete last record; any mid-file break still fails closed | `test_crashpoints.py` |
| Audit survives in a separate write-only store (RFC 9.1) | `relay.py` re-verifies and independently re-chains each audit record in its own process; the relay store is byte-identical to the host audit copy, `verify_integrity()` passes on it, host restart redelivers idempotently (dup-acked), and any probe without the transfer key, oversized frame, sequence gap, or contradictory redelivery is refused and fails the store closed | `test_relay.py` |
| External action accounting process (RFC 12 prototype) | Optional `OutboxLink` sends simulated deliveries to a separate service. The service rebuilds idempotency state from its receipt ledger on restart, rejects reuse of an idempotency key with a different target or payload digest, fsyncs each receipt before acknowledging it, and refuses new deliveries on ledger storage failure. This remains a local stdlib demo, not real provider delivery or hardened remote accounting | `test_outbox.py` |

---

## 4. Tool surface (exactly three)

- `workspace.read`  — A0, policy-ALLOW, digest-logged, size-capped.
- `workspace.write` — A1, human approval required, atomic replace, size-capped.
- `external.send_mock` — A2, human approval required, single-use; records a
  simulated mail delivery locally or through the optional accounting service
  (recipient + digests of subject/body) and returns digests only (payload
  plaintext never crosses back to the worker or into audit).

Any other action string is not registered and is denied at the normalizer
(`denied_invalid_envelope`) or policy engine.

---

## 5. Threat model

### In scope (the prototype defends against these)
- A (possibly hostile/broken/drifted) model adapter trying to:
  - read/write/delete outside its workspace (traversal, absolute paths, `..`);
  - execute undeclared tools (`workspace.delete`, `shell.exec`, `network.send`,
    `secrets.read`, ...);
  - forge identity/session/capability/approval references;
  - replay an executed request;
  - tamper payload/resource after an approval was granted;
  - claim in its own text that a human approved;
  - smuggle strict-JSON violations (duplicate keys, control characters).
- A curious worker process that inspects its own environment for secrets.
- An adapter or pipe-level actor that forges, replays, desynchronizes,
  redirects, or drowns the channel: HMAC forgery, duplicate or skipped
  sequence numbers, host-bound messages on the adapter link, wrong session
  ids, oversized lines — each is refused with a precise reason, audited as
  `transport_denied`, and immediately suspends + revokes the worker.
- Log integrity: an attacker with file access who rewrites audit rows.

### Out of scope (accepted for the prototype; documented in §6)
- Native-code memory safety of CPython and its stdlib.
- OS-level confinement of the worker (AppContainer, WFP, seccomp, job objects).
- Compromise of the trusted runtime host process itself.
- Real network destinations, real credentials, key management at rest.
- Denial-of-service / resource exhaustion of the trusted process.
- Side channels (timing), hardware root of trust, anti-tamper of the process.

---

## 6. Known limitations and RFC gaps

### Unenforceable on this platform / in this prototype
1. **OS sandboxing of the worker.** The RFC would have the model adapter run
   under OS integrity mechanisms so it cannot touch files/network/sockets even
   if it wanted to. Windows AppContainer (WinRT) or WFP would be required;
   the prototype **simulates** this with process spawn + env scrubbing +
   import bans + absence of any privileged API in worker.py, and verifies the
   *behavioral* boundary with tests. A worker that exploited a Python-level
   escape is out of scope (§5).
2. **Independent watchdog outside the supervisor process.** The *kill* path is
   now genuinely external: `watchguard.py` is a separate process that holds the
   worker's OS pid and terminates it on heartbeat timeout or an explicit
   directive, and stays fail-closed after triggering. The worker has no
   dependency on the host's watchdog. Remaining gaps: the *pid* is asserted by
   the trusted host at registration (a compromised host could register a wrong
   pid); heartbeats only bound host liveness, not drift; and revocation +
   approval storage still live in the trusted process's memory, so a fully
   compromised host could in principle restore a revoked grant on the next
   boot — the external guard's terminate directive is the backstop that closes
   the worker process regardless.
3. **Real external action transport.** `external.send_mock` remains a
   simulation. An optional localhost accounting process records a delivery
   and returns a receipt; it does not contact SMTP, HTTP, or a model provider.
   Receipt/idempotency recovery is file-backed, and production still needs a
   hardened provider gateway and independently operated accounting store.
4. **Hardware/time/audit-store guarantees.** Audit is emulated across two
   components: the local JSONL (keyed MAC chaining) *and* a separate-process
   relay (`voss.relay`) that re-verifies and stores a byte-identical copy,
   so the worker cannot reach or silently edit the store, host restart
   redelivers idempotently, and integrity violations fail the store closed.
   Still absent: a real write-only hardware/remote transport, a hardware
   clock, TPM/HSM-held keys, and OS Event Tracing for Windows (ETW) as the
   collection channel — the relay demos the shape on stdlib sockets.
5. **Drift is heuristic.** The temporal (latency/resource) dimension is now
   measured: every worker round-trip is timed and proposal-line volume capped
   (declared bounds 2.0s / 16 KiB over a min-10-exchange window,
   `drift_report()["temporal"]`). Still per-session, in-process, host-side —
   not OS-enforced (no ETW/AppContainer resource counters); the baseline is
   "zero violations" over a min-10-event window.
6. **Durable state is file-based, not a hardened store.** A write-ahead ledger
   (`wal.jsonl`) records flow/capability/replay mutations on the audit MAC chain
   and is replayed (or fail-closed) on boot; keys and worker identity persist in
   local `keys.json` / `identity.json` (chmod-0600 where the platform allows).
   This is not an OS/key-store-backed datastore, not fsynced policies on every
   write. Crash windows (proved by `test_crashpoints.py`, which uses
   `os._exit` crash-injection seams):
   - crash between the in-memory mutation and the WAL append (`flow_request`)
     loses only that single pending proposal; the next boot has nothing to
     restore, but any replay or later grant is unaffected;
   - crash exactly when a record is mid-append is tolerated: the one incomplete
     trailing record is trimmed; a mid-file structural break is *not* trimmed,
     so chain verification still fails closed;
   - crash after approval, after capability issuance, or after
     `request_executed` was written restores flow/capability/replay state
     correctly and never double-executes an effect; the only anodyne gap is a
     crash after the effect ran but before `execution_result` was logged — the
     effect exists, exactly one `request_executed` record exists, replay is
     still refused, but that final audit event was lost in the window.
   Production needs an authenticated WAL with durable fsync ordering, OS/HSM key
   storage, and transactional snapshots (RFC 5.5).
7. **Language.** CPython is not the RFC's recommended memory-safe compiled
   language; the prototype chooses it for portability on the only available
   toolchain.
8. **Channel credential provisioning is a local file.** The per-spawn channel
   key rides in `worker-bootstrap.json` (chmod-0600 where allowed) and the
   adapter deletes it on first read. This models out-of-band key distribution;
   real enrollment would use a device key / TPM / IDS-issued credential. The
   64 KiB line cap bounds message size, but a persistently silent or streaming
   peer can still occupy the pipe until the read deadline; production needs
   non-blocking IO and OS-enforced quotas (see also §5 DoS scope).
9. **Local service-link session keys are process-local.** Relay, console,
   outbox, and watch-guard derive a distinct frame key for each accepted
   hello from the authenticated challenge and a fresh nonce. The transfer key
   remains a bootstrap credential used to authenticate that exchange; all
   post-hello frames, including server replies, use the derived key and a
   per-direction sequence. The key is not persisted. This limits cross-session
   frame replay, but does not replace OS ACLs, protect a compromised endpoint,
   or prove that the human saw an authentic display outside this prototype.

### Deliberate prototype simplifications (call-outs for reviewers)
- `_clean_env` scrubs variables whose *names* match secret-like fragments; it
  cannot detect secrets in arbitrarily named variables.
- Coarse responses intentionally withhold reason detail from the worker
  (defense in depth against probing).
- The CLI `--auto` mode auto-approves for demo purposes only; real operation
  uses the interactive console.
- `default_dev_policy` signs with `signer="operator-prototype"` and a throwaway
  key for demo; production policy signing keys live in an external signing
  service (RFC 10).
- The audit relay shares a copy of the audit MAC key so it can independently
  re-verify records; production would enroll each verifier with
  derive-only verification keys (HSM/signing service), so a relay compromise
  could not forge records (RFC 7.2/10).
- The watch-guard's transfer key is per-launch and the guard is started
  out-of-band, mirroring the relay's pattern; production would hand the guard
  the worker's pid at spawn via the OS (job objects / `WaitForSingleObject`
  process handles) rather than a host-sent register frame, so a compromised
  host could not mis-attribute a pid to the guard.
- The operator console is a separate process with its own HMAC credential and
  an append-only view/vote transcript, but consent *validation* and capability
  *issuance* still live in the trusted runtime; a fully compromised host could
  in principle ignore the console's gesture. The console's independent power
  is negative only: it holds no keys it could use to grant anything on its
  own, and when it cannot be reached at all the runtime denies consequential
  approvals (`denied_approval_unavailable`) instead of guessing.
- Console `--auto` votes with a fixed delay for demo/scripts; interactive mode
  reads the operator's stdin inside the console process. Votes are fire-and-
  forget sends over the authenticated socket (no per-vote ack), so an in-flight
  vote may be lost if the link drops mid-send; the runtime then fails closed on
  the next consequential request rather than double-grant, and the transcript
  still records what happened.
- Each separate-process link server (`relay`, `watchguard`, `console`,
  `outbox`) mints a fresh random challenge at startup and speaks first on every
  connection; the hello signature must MAC over the echoed challenge, so a
  captured hello from a *previous* process instance is refused even if the
  transfer key is unchanged across a restart (the per-process nonce cache dies
  with the process). The challenge is process-scoped, not connection-scoped:
  within one process lifetime the single-use nonce cache is the replay guard,
  and a restart keeps the key but not the ability to answer for the old
  challenge. A restarted guard/console/outbox holding the same key therefore
  refuses a stale captured hello instead of re-arming a stale (possibly reused)
  pid, and a legit fresh-session client still connects.

---

## 7. How to run

```powershell
# everything
python -m compileall -q voss tests
python -m unittest discover -s tests -v   # 140 tests

# remote audit relay (RFC 9.1 emulation), one process:
python -m voss.relay --store <dir> --keyring-dir <dir> --port-file <file> --transfer-key <hex>

# external watch-guard (RFC 7.4 kill authority), one process per worker:
python -m voss.watchguard --store <dir> --port-file <file> --transfer-key <hex> --timeout 3.0

# operator approval console (RFC 5.3), one separate process:
python -m voss.console --store <dir> --port-file <file> --transfer-key <hex>            # interactive
python -m voss.console --store <dir> --port-file <file> --transfer-key <hex> --auto approve --delay 0.2

# interactive/auto demo console (device-driver style, no network)
python -m voss.cli --auto
python -m voss.cli --root <dir>            # interactive approvals + kill switch
```

The CLI exercises: policy-allow read, human-gated write, human-gated mock send,
ambiguous-outcome handling, unknown-tool denial, traversal denial, identity
forgery denial, then prints audit summary, health, drift, and the outbox.
