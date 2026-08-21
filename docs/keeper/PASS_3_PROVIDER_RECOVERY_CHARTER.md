# Pass 3 Provider Cancellation and Recovery Charter

## Objective

Complete the bounded provider-execution lifecycle by making cancellation
claim-before-effect, classifying every ambiguous cancellation as durable
`UNCERTAIN`, and providing one exact Founder-approved path to reconcile a
confirmed cancellation without permitting an automatic retry.

## Allowed files

- `keeper/app/workflow.py`
- `keeper/executive/service.py`
- `keeper/pass_b/application.py`
- `keeper/pass_b/models.py`
- `keeper/pass_b/orchestration.py`
- `keeper/pass_b/pilot.py`
- `keeper/pass_b/repository.py`
- focused Keeper workflow cancellation tests
- focused Pass B tests
- Keeper completion, recovery, testing, and hardening documentation

## Invariants

- Exactly one durable cancellation claimant may emit the external cancel effect.
- A cancellation exception or post-effect persistence failure becomes durable
  uncertainty while retaining session, usage, workspace, and write reservations.
- Restart never retries or releases ambiguous work.
- Reconciliation is limited to `CONFIRMED_CANCELED`.
- Reconciliation requires the existing native, one-use Founder
  `APPROVE_ACTION` flow. It binds the current active charter, workflow,
  WorkItem, assignment, attempt, provider, external execution, canonical
  workspace, and a canonical external-observation digest.
- The approval is consumed before the Pass B terminal transition. A failed
  transition remains fail-closed and requires a fresh approval.
- Reconciliation never marks provider work complete and never manufactures
  evidence.
- Workspace and write reservations become active again only so the existing
  explicit release/cleanup lifecycle can process the now-terminal assignment.
- No KeeperAuthority source, service, credential, ACL, machine, payment,
  deployment, publication, or live-trading state changes.

## Acceptance tests

- concurrent cancellation emits one external effect;
- cancel-side-effect then exception becomes durable `UNCERTAIN`;
- cancel success then persistence failure becomes durable `UNCERTAIN`;
- restart converts an interrupted cancellation claim to `UNCERTAIN`;
- uncertain cancellation retains the session slot and reservations;
- automatic rerun remains rejected;
- missing, stale, replayed, cross-assignment, wrong-attempt, wrong-provider,
  wrong-workspace, wrong-observation, and stale-charter approvals reject;
- one exact one-use Founder approval reconciles the exact attempt to
  `CANCELED`;
- successful reconciliation releases the session slot, consumes reserved
  usage, preserves workspace data, and leaves cleanup explicit;
- ordinary execution uncertainty cannot use the cancellation-reconciliation
  path.

## Prohibited scope

- KeeperAuthority or installed-service changes;
- automatic retry of uncertain work;
- completion without validated evidence;
- new delegated-mode authority;
- workspace, usage-reset, review, or provider-selection redesign;
- service, credential, ACL, machine, payment, deployment, publication, or
  live-trading changes.
