# Pass 3 Product Lifecycle Charter

## Objective

Connect the desktop product shell to Keeper's existing authoritative Executive
project and charter state. The pass makes project selection durable, prevents
cross-project presentation, exposes the complete Founder-reviewable charter, and
uses the existing production Founder approval flow before creating one atomic
charter-derived workflow plan.

## Allowed files

- `keeper/pass_b/application.py`
- `keeper/pass_b/control_room.py`
- `keeper/pass_b/orchestration.py`
- `keeper/pass_b/repository.py`
- `keeper/ui/desktop.py`
- `keeper/ui/view_models.py`
- focused Keeper product and Pass B tests
- Keeper completion and user documentation

## Invariants

- Conversation text and desktop buttons never create authority.
- Production approval uses `KeeperExecutive` and native Founder authentication.
- Current active Founder-approved charter state is reloaded before planning.
- A product snapshot contains at most one project's durable work.
- Workflow and work items are committed atomically.
- Existing KeeperAuthority, provider execution, workspace, evidence, usage,
  delegation, and recovery boundaries are unchanged.

## Acceptance tests

- Project selection persists across application restart.
- An unselected snapshot does not present one project's data as another's.
- Founder review exposes scope, constraints, budget, providers, tools,
  workspaces, privacy, delegation, and prohibited actions.
- Approval cancellation/failure creates no active charter or workflow.
- Successful native approval activates the exact proposed revision.
- One exact workflow plan is created atomically and idempotently.
- Stale or cross-project planning rejects.

## Prohibited scope

- No KeeperAuthority or Windows service changes.
- No provider execution, retry, recovery, usage, workspace, or evidence redesign.
- No credentials, ACLs, UAC, machine configuration, deployment, spending, or
  live-trading changes.
- No changes to protected workflow evidence.
