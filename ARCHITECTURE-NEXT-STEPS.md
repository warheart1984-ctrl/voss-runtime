# Voss next architecture steps

Status: design proposal for review. This document does not change the Voss
Binding, policy constitution, or approval rules. Any change to those governing
rules remains an explicit human decision.

## Scope and claim

Voss can constrain and record effects that pass through its governed action
interfaces. It cannot prove that a model's internal goals, beliefs, or
interpretation are aligned with a person. Keep that limit explicit in product
claims and security reviews.

## 1. Bind local service frames to a fresh session key

The relay, console, outbox, and watch-guard links use this handshake:

1. The service sends a process-fresh challenge authenticated with its
   transfer key.
2. The client replies with a fresh nonce and a hello MAC over the protocol,
   challenge, and nonce.
3. Both sides derive a per-connection frame key using HMAC-SHA256 over
   length-prefixed fields: domain `voss.session-key.v1`, protocol, challenge,
   and nonce, keyed by the transfer key.
4. Every subsequent frame in each direction, including the successful hello
   reply, carries a MAC under that session key and a monotonic sequence number.
   Each direction maintains its own counter.

The transfer key authenticates setup only. It must not authenticate ordinary
post-hello frames. Python and Rust must use identical field encodings and
sequence rules. Failed MACs, replays, and gaps fail the connection closed.

Implementation status: this is wired into the four service links in the H:
Python and Rust trees; the Rust service files and matching protocol tests have
also been copied to the D: standalone tree. Existing protocol tests were
updated but not run during this change. The current nonce replay cache and
challenge remain process-local; a restart creates a fresh challenge.

## 2. Add a real, vendor-neutral model gateway

### Components and trust

```text
Untrusted model worker
        │ proposal channel; no network or provider key
        ▼
Trusted orchestration + Voss broker ───────► policy / approval / audit
        │ model request                         ▲
        ▼                                       │ normalized untrusted output
Provider gateway (credential + egress boundary)
        │ allowlisted HTTPS
        ▼
OpenAI / NVIDIA / OpenRouter / Anthropic / xAI / local provider
```

The gateway belongs on the trusted side of the worker boundary. It owns
provider credentials and network access. Provider adapters translate requests
and responses, but do not own policy, issue capabilities, or execute tools.
The gateway returns model text and proposed tool calls as untrusted data. The
host normalizes any proposed action into Voss's canonical envelope and routes
it through the existing default-deny policy and approval path.

### Provider adapter contract

Each adapter should implement a narrow interface:

- `capabilities`: supported API features, streaming, structured output, and
  tool-call format.
- `complete(request, credential_handle, limits)`: provider request and
  normalized response; it cannot call Voss tools.
- `validate_config`: provider identifier, model identifier, endpoint, and
  supported limits.

Keep vendor-specific request and response types inside adapters. The common
request should contain messages, generation limits, and a list of tool
*descriptions* only when needed. The normalized response should carry text,
untrusted proposed calls, finish status, usage if supplied, and provenance
metadata (provider, model, provider request ID, timestamp). Provider-reported
usage is evidence from the provider, not independently measured billing truth.

### Credential and network boundary

- Store keys in Windows Credential Manager/DPAPI-backed storage or a dedicated
  secret service; provide adapters a short-lived in-memory handle only.
- Never place keys in worker environment, arguments, prompts, model output,
  exception text, audit payloads, or debug logs. Redact authorization headers
  and provider error bodies before logging.
- Restrict gateway egress to configured HTTPS endpoints. Do not let the model
  choose an arbitrary base URL. Validate redirects and DNS/IP destinations so
  configuration cannot become an SSRF path.
- Use per-provider timeouts, request/response size limits, token ceilings,
  concurrency limits, and cancellation. Treat provider output, including
  purported tool calls, as untrusted input.
- Do not automatically retry a request that may have been accepted by the
  provider unless the provider supports a safe idempotency mechanism. Record
  an uncertain outcome when acceptance cannot be known.
- Audit provider/model/request identifiers, limits, latency, normalized action
  digests, and outcome. Do not audit prompts or responses by default; make any
  content retention explicit and policy-controlled.

The first implementation should support one provider behind this interface,
then add adapters without changing the broker protocol. OpenRouter is a
provider routing service, so preserve both the configured route and any
provider/model attribution it returns; do not assume the configured model name
fully identifies the serving backend.

## 3. Strengthen Windows OS isolation

Job Objects provide process lifetime and resource controls; they do not create
a separate security identity or stop same-user file/network access. The
production worker should run with a restricted token or AppContainer identity,
minimal filesystem ACLs, no inherited handles except the authenticated channel,
and no direct network access. Place provider egress in the gateway process and
allow only that process to reach configured HTTPS endpoints. Apply memory, CPU,
process-count, and wall-clock limits at the OS boundary.

The implementation sequence should be:

1. Make the worker's writable/readable directories explicit and test denied
   access outside them.
2. Launch with a restricted token/AppContainer and a Job Object; keep the
   broker and operator surfaces under separate identities.
3. Deny worker network egress at Windows Filtering Platform/firewall level;
   expose only a narrow local IPC endpoint if the worker needs orchestration.
4. Verify inherited handles, child-process creation, process escape attempts,
   resource limits, and cleanup on host/worker crash.

Do not describe a Job Object alone as a sandbox. The achievable boundary
depends on Windows edition, account privileges, and deployment policy, and
must be tested on the target system.

## 4. Move approval and audit authority outside the host

The current console is a separate consent surface, but the runtime validates
the gesture and issues capabilities. A compromised host can still ignore a
vote or fabricate local state. A stronger design should make the approval
service sign a one-time decision over a canonical request digest that binds:
request ID, action, resource, payload digest, policy version, worker identity,
expiry, and decision. The console must display those same bound fields and
sign only the human's explicit choice. The broker verifies the authority
signature and single-use state before executing an effect. That check alone
does not constrain a compromised broker: the effect executor must also verify
the signed grant before acting, or the approval service must be the only
component able to invoke the effect. For local file/process effects, enforce
that boundary with OS identities and ACLs so a host-side bypass cannot write
around the executor.

Keep human sovereignty explicit: the approval authority enforces policy and
records human choices; it does not change values or broaden a grant silently.
Constitution/policy changes need versioned proposals, preserved originals,
supporting evidence, dissent, and an explicit authorized signature.

For audit independence, replace the shared host/relay HMAC authority with a
writer signature and a relay verification key, or have a separately controlled
service append to an access-controlled remote/WORM store. A verifier that holds
the same HMAC secret as the writer can also forge records. Bind each approval
decision and each effect receipt to audit event IDs so an external reviewer can
reconcile request → policy → consent → capability → effect → receipt.

## 5. Acceptance evidence

Treat each stage as incomplete until the evidence exists:

- Cross-language known-answer vectors for key derivation, frame MACs, and
  sequence transitions.
- Replay, cross-session splice, downgrade, malformed-frame, and reconnect
  tests against both implementations.
- Provider contract tests with a fake HTTP server proving that credentials
  stay in the gateway, arbitrary endpoints are refused, and provider-returned
  tool calls only become proposals.
- Windows integration tests showing the worker cannot read secrets, access
  protected files, open network connections, or spawn uncontrolled children.
- Approval tests showing host-side fabrication or modification of a vote is
  rejected by the independent authority; audit verification works without the
  writer's secret.

These tests demonstrate specific boundaries under stated deployment
assumptions. They do not establish semantic alignment or prove that every
possible action is safe.
