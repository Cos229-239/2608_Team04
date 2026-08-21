# Pass 3C — Durable Authority Reservation

## Objective

Add the smallest safe bridge from a prepared Pass B assignment to one exact
KeeperAuthority attempt. The local workspace, usage, session-capacity, and
one-winner launch claims must be durable before the external reservation call,
and any ambiguous reservation outcome must recover as `UNCERTAIN`.

This pass adds a supported one-assignment runner entry point, but does not add
multi-stage scheduling, automatic retry, cancellation orchestration, or broad
recovery policy.

## Allowed files

- `keeper/executive/authority_gateway.py`
- `keeper/pass_b/application.py`
- `keeper/pass_b/authority_reservation.py`
- `keeper/pass_b/control_room.py`
- `keeper/pass_b/models.py`
- `keeper/pass_b/orchestration.py`
- `keeper/pass_b/repository.py`
- `tests/keeper/executive/test_authority_gateway.py`
- `tests/keeper/pass_b/test_authority_reservation.py`
- `tests/keeper/pass_b/test_models.py`
- `docs/keeper/PASS_3_AUTHORITY_RESERVATION_CHARTER.md`
- `docs/keeper/KEEPER_COMPLETION_MATRIX.md`

## Invariants

- The current active Founder-approved charter is reloaded immediately before
  Authority plan preparation.
- The exact Pass B workflow, WorkItem, assignment, execution profile, provider
  selection, provider/account/session/model, workspace, usage reservation,
  role, and evidence requirements bind the reservation.
- Session capacity, usage, workspace, write scope, and one-winner launch state
  are claimed transactionally before the external Authority reservation call.
- A durable `RESERVATION_IN_FLIGHT` marker precedes that external call.
- A crash or exception after that marker is never treated as a safe pre-launch
  failure; the assignment, attempt, usage, session slot, and workspace recover
  conservatively as `UNCERTAIN`.
- No automatic retry executes an ambiguous Authority attempt.
- Production uses only the exact production Authority client and hardened
  production gateway. Test composition remains explicitly distinct.
- The production gateway receives the exact canonical reserved workspace; it
  cannot silently substitute the first charter workspace.
- Existing direct `run_assignment` callers remain fail-closed and retain their
  current exact Authority validation.
- Provider-generated code is never imported, evaluated, or executed in the
  trusted Keeper Executive process.

## Acceptance

- One dependency-ready prepared assignment can reserve one exact Authority
  attempt and execute through the existing launch gate.
- Missing usage, exhausted usage, unavailable session capacity, workspace
  mismatch, provider mismatch, stale charter, or duplicate preparation rejects
  before the external reservation call.
- Two contenders for one assignment produce one local claim and at most one
  external reservation.
- Side-effect-then-exception during Authority reservation becomes durable
  `UNCERTAIN` and cannot be automatically retried.
- Restart distinguishes safe local-only `RESERVED` attempts from ambiguous
  in-flight or externally reserved attempts.
- Test and production reservation composition cannot be interchanged.
- Focused tests, relevant Pass B and Executive regressions, strict typing,
  compilation, and repository checks pass.

## Prohibited scope

- KeeperAuthority source, installed service, protocol, credentials, ACLs, UAC,
  or machine configuration.
- Automatic retry of uncertain or non-idempotent work.
- Broad cancellation, timeout, pause/resume, or reconciliation redesign.
- Multi-stage scheduling and repair-loop automation.
- UI redesign; the Founder-provided visual reference is reserved for the
  later desktop-completion pass.
- Deployment, public release, spending, paid fallback, or live trading.
