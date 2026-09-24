# Voss Human Sovereign Runtime

A runnable prototype of a **governance engine for model adapters**: it routes
declared worker actions through a signed, default-deny policy and explicit,
bound human approval, and records them in an authenticated audit log with a
separate relay copy. The current worker boundary is behavioral; OS-level
confinement is still a production requirement.

This is a prototype for demonstration and adversarial testing, not production
deployment. Full design notes, threat model, known limitations, and RFC mapping
live in [`PROTOTYPE.md`](PROTOTYPE.md). The proposed provider gateway,
credential boundary, Windows isolation work, and independent approval/audit
authority are outlined in [`ARCHITECTURE-NEXT-STEPS.md`](ARCHITECTURE-NEXT-STEPS.md).

## Position against external frameworks

Voss is a proposed runtime governance specification and prototype, not a
certified system or a claim of conformance to the frameworks below. The
proposed Technical Standard is RFC-style, not an IETF RFC. The revised Voss
Binding v1.1.0 still requires explicit Operator ratification; its text says
v1.0.0 remains in effect until that approval is recorded.

| Framework | Voss relationship | Current limit |
|---|---|---|
| [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) | Voss requirements cover AI governance, declared risks, measurement, and containment at runtime. | A runtime specification does not establish an organization-wide AI risk program or deployment evidence. |
| [ISO/IEC 23894](https://www.iso.org/standard/77304.html) | Voss translates some AI risk treatments into runtime controls and evidence requirements. | It does not establish the full organizational risk-management process. |
| [ISO/IEC 42001](https://www.iso.org/standard/42001) | Operator authority, change control, and documented evidence support AI governance. | Voss alone is not an AI management system and has not been certified. |
| [NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final) | Voss specifies runtime security requirements. | Secure development, build, dependency, vulnerability, and release practices need a separate engineering process. |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | Voss addresses risks such as excessive agency, prompt injection, and unsafe tool execution. | This is partial coverage; each applicable risk needs its own implementation evidence. |
| [MITRE ATLAS](https://atlas.mitre.org/) | ATLAS can inform Voss red-team scenarios and adversarial tests. | ATLAS is a threat knowledge base, not a certification checklist. |

These are descriptive mappings, not framework assessments. A conformance claim
would require a clause-level crosswalk, implementation and deployment
evidence, documented exceptions, and independent review. See
[`PROTOTYPE.md`](PROTOTYPE.md) for current limits and
[`ARCHITECTURE-NEXT-STEPS.md`](ARCHITECTURE-NEXT-STEPS.md) for proposed work.

```
                    ┌────────────────────────────────────────────────┐
                    │              TRUSTED RUNTIME (host)            │
   model adapter   │                                                │
   (untrusted)     │   ┌──────────┐      ┌────────────┐            │
   ───────────▶    │   │  worker  │◀────▶│   broker   │            │
   proposals       │   │ (spawned │ env  │ (capability│── tools ──▶ effects
   over authed     │   │  subproc)|scrub│   broker)  │   (exactly  │
   channel         │   └────▲─────┘      └─────┬──────┘   3)        │
                    └────────┼──────────────────┼───────────────────┘
                             │ HMAC links (per-session key, monotonic seq)
              ┌──────────────┼───────────┬─────┴──────────┬──────────────┐
              │              │           │                │              │
       ┌──────┴─────┐ ┌──────┴─────┐ ┌───┴─────┐   ┌──────┴─────┐ ┌──────┴─────┐
       │  operator  │ │  kill      │ │ audit   │   │ external   │ │  WAL       │
       │  console   │ │  authority │ │ relay   │   │ accounting │ │  recovery  │
       │ (separate  │ │ (separate  │ │ (separate│  │  (separate │ │  ledger    │
       │  process)  │ │  process)  │ │ process) │  │  process)  │ │  (trusted) │
       └────────────┘ └────────────┘ └──────────┘   └────────────┘ └────────────┘
```

## What it demonstrates

- **No direct access** — the worker imports only `canonical` + `chan`; `broker`
  is the sole tool-execution path; anything else is banned by construction.
- **Default-deny policy** — signed policy bundle; denies on missing,
  conflicting, unsigned, expired, audit-disabling, or last-human-gate-removing
  states.
- **Replay-proof approval** — approval binds action/resource/payload digest +
  policy version + nonce + expiry; capabilities are single-use and revocable.
- **Human consent is real** — the model's own text is never consent; only the
  detached operator console binds a flow (`approve` / `deny` / `cancel`), and
  the runtime fails closed (`denied_approval_unavailable`) when the console is
  unreachable. Console `--auto` is demo-only.
- **External kill authority** — the watch-guard is a separate process holding
  the worker's OS pid; it kills the worker itself when heartbeats stop, obeys
  an explicit `terminate`, and refuses new sessions after triggering.
- **Tamper-evident audit** — HMAC-chained JSONL, mirrored byte-identically into
  a separate replay-verifying relay process; integrity violations fail closed.
- **Crash-safe, never double-executes** — write-ahead ledger with crash-point
  injection seams; recovery restores exactly the right grant state.
- **Safe tool surface** — exactly three tools (`workspace.read`,
  `workspace.write`, `external.send_mock`); no shell, no delete.

## Requirements

- Windows 10/11
- CPython 3.12+ (stdlib only — no third-party packages)

## Quick start

```powershell
# 1. Verify everything (compile + full test suite)
.\verify.ps1

# 2. Interactive/auto demo console (device-driver style, no network)
python -m voss.cli --auto
python -m voss.cli --root .\demo   # interactive approvals + kill switch
```

The CLI exercises: policy-allowed read, human-gated write, human-gated mock
send, ambiguous-outcome handling, unknown-tool denial, traversal denial.

## Running the separate-process services

Each link service is started out-of-band with its own transfer key:

```powershell
# operator approval console (RFC 5.3) — interactive, or auto for scripts
python -m voss.console --store <dir> --port-file <file> --transfer-key <hex>
python -m voss.console --store <dir> --port-file <file> --transfer-key <hex> --auto approve --delay 0.2

# external watch-guard (RFC 7.4 kill authority), one process per worker
python -m voss.watchguard --store <dir> --port-file <file> --transfer-key <hex> --timeout 3.0

# remote audit relay (RFC 9.1) — independent, re-verifying audit store
python -m voss.relay --store <dir> --keyring-dir <dir> --port-file <file> --transfer-key <hex>

# external-action accounting service (RFC 12 prototype) via --outbox-link
```

## Tests

```powershell
python -m compileall -q voss tests
python -m unittest discover -s tests -p "test_*.py"
```

140 tests covering: worker isolation and import bans, policy fail-closed
semantics, approval/capability binding and replay, adversarial forgery and
tamper, audit chain integrity, watchdog/kill drills, guard loss fail-closed,
crash-point recovery, channel/transport forgery, relay integrity, console
fail-closed behavior, WAL recovery, and temporal drift containment.

## Repository layout

| Path | Purpose |
|---|---|
| `voss/runtime.py`, `broker.py`, `worker.py`, `chan.py` | core runtime + adapter channel |
| `voss/policy.py`, `approval.py`, `keys.py`, `wal.py`, `audit.py` | policy, consent, secrets, recovery, audit |
| `voss/watchguard.py`, `console.py`, `outbox.py`, `relay.py` | separate-process services |
| `voss/tools.py` | exactly three safe tools |
| `tests/` | 140-test adversarial suite |
| `PROTOTYPE.md` | design, threat model, RFC mapping, limitations |

## License

[Apache License 2.0](LICENSE)
