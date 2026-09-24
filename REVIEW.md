# Voss — Merge Review Checklist (reasons NOT to merge)

This is the human's gate. The rules: **you are the only one who merges, you
read every diff, and a model-authored change does not land until a human says
it is clean.** This file exists so the review pass is the same every time
instead of a mood.

Scope applies: this repo is a security boundary (RFC 6/7/9/12, `PROTOTYPE.md`),
so the bar is higher than a normal project. Default posture: **when in doubt,
do not merge.**

---

## 1. Hard deny (any one of these → NO merge, no exception)

- Credentials, keys, seed material, or policy-signing/audit-MAC secrets in
  code, tests, fixtures, or logs — even "throwaway" or chmod-0600'd.
- A test was modified/added/skipped to make a failing change pass: conditionals
  like `skip`, `@expectedFailure`, `if not <env>` on a flake, relaxed assertions,
  `assert False`, or a test that no longer runs.
- A failure path was converted to a silent success: deleted `raise`, swallowed
  exception (`except Exception: pass`, bare `except:`), or a denial that no
  longer emits its audit/control-log event.
- Verification commands changed but the claim of passing did not: "still green"
  against a suite that no longer executes the affected path.
- Any file outside the stated task is edited, renamed, or deleted (scope creep
  is how injected bugs hide).
- Hard-coded paths, ports, pids, or nonces that only work on the author's
  machine.

## 2. Attack the change, then attack the file it touched

- **Replay the threat the change claims to fix.** If it hardens a link, prove
  the old exploit is refused. If it fixes a bug, show the failing case now
  fails the *right* way (correct reason code, event logged, process closed).
- **Red-team your own red-team.** A "rejection" test may be green for the wrong
  reason: wrong frame signed with the wrong key, `seq` compared against itself,
  nonce set shared across connections, reason string copy-pasted from another
  module (`denied_relay_auth` vs `denied_outbox_auth` — the exact class of bug
  found in this repo). If the test passes for the wrong reason, it is
  worse than no test.
- **Purview check.** Code that should be separate is now reachable, or a
  trusted module imports/trusts an untrusted one. Confirm the trust boundary
  in `PROTOTYPE.md` §2 still holds.
- **Per-connection state.** Any counter, nonce set, or credential that should
  reset per session is reset in code, not assumed from the previous run.
- **Failure closes the loop.** Set the link to fail (socket closed, service
  down, ledger full, guard triggered) and confirm the design says DENY/refuse
  — never queue, never silently retry forever, never auto-grant.

## 3. Read for the machine's tells

- `oldString`/`newString` style blind edits that replaced more than intended
  (identical blocks, `replaceAll` hits).
- Comments that describe a guarantee the code no longer provides, or deleted
  comments that explained a subtle invariant.
- "Fix" commits that are actually feature commits; message says one thing,
  diff does another.
- Odd duplications: two functions that should be one, or one function that
  grew three responsibilities mid-task.
- Blanket imports, ignored return values, unused variables that "might be
  needed later".
- A change that looks correct in isolation but interacts with state you know
  the author did not see (read `git diff` against the *whole* repo, not just
  the hunks).

## 4. The merge pass (before you press the button)

- `git diff` reviewed hunk-by-hunk; no binary diffs unaccounted for.
- `git status` shows exactly the files the task named; nothing staged that was
  not reviewed.
- Verification was run by you or reproducibly shown, **after** the final edit:
  `powershell -ExecutionPolicy Bypass -File .\verify.ps1`
  (this runs `compileall` then the full suite and exits 0 only on green).
  A merge must not proceed until this exit code tells you to.
- Any denials/rejections are coarse-coded correctly and reach the audit chain
  (`denied_*`, `*_denied_hello`, `*_anomaly`, `transport_denied`).
- Sanity: what did this change actually buy, and can you say it in one
  sentence? If you cannot, do not merge.

## 5. Log it (feeds future RAC)

Every merge and every rejected change gets one line in the running review
journal (see `JOURNAL` section below): what the model proposed, what you found,
what you did. This is the seed telemetry for governance — silent, undiscovered
injections are the failures you are already counting; write them down before
export, with repro steps.

---

## What "clean" looks like

- The diff is the smallest thing that does exactly the stated task.
- `.\verify.ps1` exits 0 on the final commit — run, not assumed.
- Tests changed only to match a real behavior change — and the old test *fails*
  against the new code, proving the assertion still bites.
- Refusals are loud: precise reason, audit/control event, session closed.
- The human can walk a colleague through every line in 60 seconds.