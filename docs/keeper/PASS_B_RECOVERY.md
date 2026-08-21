# Pass B Recovery and Concurrency

## Launch protocol

Keeper first validates the exact active charter, signed KeeperAuthority
attempt, active launch generation, canonical workspace reservation, protected
write scope, and usage reservation. Creating the durable `Attempt` atomically
claims the provider-session slot. Keeper then acquires the one-winner launch
claim and changes attempt and assignment to `LAUNCH_CLAIMED`. Production calls
KeeperAuthority's protected execution transition only after that commit.

On restart:

- `RESERVED` attempts are classified `FAILED` before launch and may be
  re-prepared with a new attempt identity.
- `LAUNCH_CLAIMED` or `RUNNING` attempts become `UNCERTAIN`.
- uncertain assignments, workspace records, write records, and their normalized
  claims remain uncertain and reserved;
- active usage reservations remain preserved;
- uncertain work is not automatically retried or released.

Completion consumes the active usage reservation in the same SQLite
transaction that records completed attempt, evidence, and assignment state.
The partial unique launch index prevents a second active, completed, or
uncertain launch for the assignment.

## Provider cancellation

Cancellation first claims the exact running assignment and attempt in one
transaction. Only that claimant may call the provider adapter. If the adapter
raises after the cancellation effect, or the terminal commit fails after the
adapter returns, Keeper records `CANCELLATION_OUTCOME_AMBIGUOUS` and keeps the
session slot, usage, workspace, write reservation, and launch claim reserved.
Restart classifies an interrupted cancellation claim the same way. Automatic
retry and automatic cleanup remain prohibited.

A confirmed cancellation can be reconciled only through the native one-use
Founder action-approval flow. The action binds the current Founder-approved
charter, workflow, WorkItem, assignment, attempt, Authority attempt, provider,
external execution, canonical workspace, and a SHA-256 digest of the external
observation. Reconciliation records that binding durably, changes only the exact
attempt and assignment to `CANCELED`, releases the session slot, consumes the
already reserved usage conservatively, and returns workspace/write reservations
to the existing explicit release lifecycle. It never marks work complete,
creates evidence, or authorizes a retry.

## Usage reset

Insufficient capacity is not failure. The reservation transaction changes the
assignment to `WAITING_FOR_USAGE_RESET` and writes a `PauseReason` and
`ResumeCheckpoint`. The checkpoint binds project, charter revision, assignment,
workspace reservation, usage pool, authority-envelope digest, and checkpoint
state.

Time passing is not a reset observation. A configured authenticated provider
observer must issue a one-use observation bound to provider, account, pool,
scheduled reset, observation time, and remaining capacity. The observation is
stored once for the next usage generation. Reset accounting preserves all
active reservations and computes remaining capacity after those reservations.

Resume requires that durable observation and revalidates assignment revision,
project, charter, authority digest, provider, account, session, model, usage
generation, exact workspace reservation and canonical identity, and the absence
of an uncertain launch. The checkpoint is one-use, the workspace is preserved,
and there is no automatic paid fallback.

## Workspace concurrency

SQLite `BEGIN IMMEDIATE` transactions and normalized claim tables provide:

- one active writer across equal, parent, or child canonical workspace paths;
- overlapping protected-scope exclusion based on physical canonical paths, not
  caller-selected workspace labels;
- concurrent reader allowance only through read-only reservations;
- owner-token lease renewal;
- explicit stale recovery after expiry;
- atomic propagation of renewal, release, stale, and uncertain state from a
  workspace to linked write records and claims.

Canonicalization resolves existing physical paths, case and alternate spelling
before claiming them. Primary repositories and `.ai-workflow/pw/` are rejected.
Cleanup requires explicit approval,
terminal assignment state, preserved evidence, a clean worktree, and no
untracked files.

## Operator recovery rule

Never infer a safe retry from process loss alone. Inspect the control-room
uncertainty prompt, reconcile external provider and Authority truth, preserve
evidence, and make an explicit recovery decision.
