# Pass 3B — Durable Provider Preparation

## Objective

Add the smallest safe prerequisite for product workflow execution: a durable
execution profile, policy-derived provider/session selection, and an atomic
dependency-ready assignment claim. This pass does not cross the external
provider launch boundary.

## Allowed files

- `keeper/pass_b/models.py`
- `keeper/pass_b/providers.py`
- `keeper/pass_b/repository.py`
- `keeper/pass_b/orchestration.py`
- `keeper/pass_b/control_room.py`
- `tests/keeper/pass_b/test_models.py`
- `tests/keeper/pass_b/test_provider_lifecycle.py`
- `docs/keeper/PASS_3_PROVIDER_SELECTION_CHARTER.md`
- `docs/keeper/KEEPER_COMPLETION_MATRIX.md`

## Invariants

- Current active Founder-approved charter remains authoritative.
- Automated provider selection and assignment consume active, scoped delegated
  grants.
- Paid providers and paid fallback remain prohibited.
- Workspace and write scopes are canonical and charter-contained.
- Reviewer selection excludes the producer provider, account, session, and
  independence identity.
- Dependency readiness, assignment insertion, provider selection persistence,
  and WorkItem transition have one durable transaction winner.
- Selection fairness is derived from durable selection history, not memory.
- No method introduced by this pass invokes a provider adapter or reserves an
  Authority attempt.

## Acceptance

- Exact current-charter, workflow, WorkItem, profile, provider, account,
  session, model, workspace, role, evidence, usage, effort, and delegation
  bindings are persisted.
- Incomplete dependencies and missing delegated scope fail closed.
- Concurrent preparation yields one assignment and one provider selection.
- Restart preserves the profile, selection, and READY assignment.
- Focused tests, Pass B regressions, strict typing, compilation, and
  repository checks pass.

## Prohibited scope

- Provider execution or provider-generated code execution.
- KeeperAuthority or service changes.
- Cancellation/retry/reconciliation redesign.
- Usage reset changes.
- UI redesign.
- Deployment, spending, push outside the ordinary reviewed branch workflow,
  or live trading.
