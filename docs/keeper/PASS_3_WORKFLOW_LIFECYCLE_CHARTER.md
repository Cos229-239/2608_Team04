# Pass 3D â€” Workflow Lifecycle Progression

## Objective

Connect the durable one-assignment Authority runner to deterministic workflow
stage progression. One call selects one dependency-ready, fully prepared and
reserved assignment. Accepted independent review completes its WorkItem, and
acceptance of the final WorkItem terminalizes the Workflow in the same
transaction.

## Allowed files

- `keeper/pass_b/orchestration.py`
- `keeper/pass_b/repository.py`
- focused Pass B lifecycle tests
- Keeper completion documentation

## Invariants

- The workflow must be active and bound to the current Founder-approved charter.
- Selection uses durable WorkItems, dependencies, execution profiles, provider
  selections, assignments, and reservations.
- Only one deterministic dependency-ready stage is attempted per call.
- The selected canonical workspace comes from Keeper's active reservation, not
  from caller input.
- Existing transactional session, usage, write, launch, Authority, evidence,
  and duplicate-effect controls remain authoritative.
- Concurrent calls may produce only one external Authority reservation and one
  provider execution for the selected assignment.
- Provider completion remains `REVIEW_REQUIRED`; it never self-approves.
- Only validated independent `ACCEPTED` review completes a WorkItem.
- The final accepted WorkItem and Workflow completion are one transaction.
- Repair-required, canceled, blocked, paused, uncertain, or incomplete work does
  not complete the workflow.
- Restart reconciliation may terminalize only an active workflow whose complete
  durable WorkItem set is already `COMPLETED`.

## Acceptance tests

- One prepared dependency-ready assignment runs through the existing Authority
  runner.
- Missing or incomplete dependencies produce no launch.
- Completed workflows reject new execution.
- Concurrent next-stage calls have one winner and one external reservation.
- A completed dependency unlocks its prepared successor.
- An intermediate accepted review leaves the Workflow active.
- The final accepted review atomically completes the Workflow.
- Repair-required review leaves the Workflow active.
- Completion reconciliation is idempotent and rejects incomplete work.

## Explicitly deferred

- In-flight provider cancellation beyond existing supported cancellation.
- Founder-directed reconciliation of `UNCERTAIN` external effects.
- Multi-stage desktop controls and visual workflow presentation.
- Automatic creation of reviews, implicit retries, or automatic repair loops.

## Prohibited scope

No KeeperAuthority or service changes, UI redesign, paid fallback, provider
switching, deployment, publication, credentials, UAC, ACLs, machine changes,
live trading, protected evidence changes, force push, or history rewrite.
