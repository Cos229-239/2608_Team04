# Keeper Recovery

## Executive database backup and restore

SQLite is the authoritative Executive persistence boundary. Normal writes commit
once inside SQLite; they do not require a subsequent adjacent lineage-journal
append. The retired schema-v7 lineage table and any preserved `.keeper-lineage`
artifact are legacy evidence only and are not read or advanced by normal
operation.

`KeeperStore.backup()` creates a complete SQLite snapshot at a unique temporary
path, runs SQLite and foreign-key integrity checks, and atomically replaces the
requested backup artifact. Backups are outside the live business transaction
path.

`KeeperStore.restore_backup()` is an explicit production maintenance API, never a
normal startup action. It accepts only an exact
`ProductionRestoreAuthorization`, an exact
`ProductionFounderAuthenticator`, and an exact
`ProductionAuthorityServiceClient`; arbitrary confirmation or reconciliation
callbacks are not accepted. Preparation first uses SQLite backup semantics to copy
the selected source, including committed WAL state, into a unique immutable logical
artifact, closes the backup handles, and validates SQLite integrity and foreign keys.
The authorization binds the authenticated Founder SID, restore operation ID, backup
operation ID, canonical artifact path and SHA-256, source database ID, recovery epoch
and write generation, target canonical path, database ID, recovery epoch and write
generation, complete project scope, reason, issue time, expiry, and one-use
consumption identity. Later supported writes to the original source cannot enter the
authorized artifact. Tests use a separate exact test-only entry point and proof
types.

The enforced sequence is:

1. Acquire bounded exclusive locks for the target database and immutable artifact.
   Supported target connections hold the shared lock for their full transaction, so
   an active writer finishes first and a new writer cannot commit during restore.
2. Recheck the target database ID, recovery epoch, write generation, production mode,
   and authorization replay tables; capture the complete live monotonic safety ledger;
   and record an `ACTIVE` maintenance operation inside SQLite.
3. Revalidate the artifact path, hash, database identity, recovery epoch, source write
   generation, and production mode before and after staging, then migrate and
   integrity-check the staged database without changing live business state.
4. Open a bounded KeeperAuthority-signed project-scope fence tied to the restore and
   backup operation IDs, Founder-authorization digest, artifact identity/hash, source
   and target identities/generations, service key, protocol, requesting SID, Authority
   project versions, and complete attempt and launch-authorization snapshot.
5. Merge the live safety ledger into the staged database. Consumed one-time approvals,
   consumption timestamps and bindings, crossed budget state, immutable budget amount
   and scope, and safety-bound attempts are preserved even when absent from the older
   backup. Newer live facts win; conflicting identity, amount, project, charter, task,
   action, approval, budget, or attempt bindings reject restore. Preserved IDs and
   before/after ledger digests are written into durable reconciliation evidence.
6. Reconcile every fenced Authority attempt and launch authorization. New terminal
   truth becomes `UNCERTAIN` and non-retry-safe. Missing or conflicting authenticated
   Authority state rejects restore.
7. Compare-and-confirm the still-active fence immediately before replacement. Covered
   Authority cancellation, completion, revocation, attempt reservation, claim, start,
   or related launch-authority mutation is blocked while the fence is active; any
   digest/version mismatch or expiry aborts.
8. Pause every nonterminal project with `RESTORE_RECONCILIATION_REQUIRED`, consume the
   authorization, persist the signed fence and confirmation plus Executive safety
   evidence, advance the recovery epoch and generation, and complete the staged
   transaction.
9. Recheck the live boundary, replace live content through the SQLite backup API while
   holding the target lock and Authority fence, verify integrity, and only then mark
   the Authority fence `COMPLETED`.

Failure before replacement preserves live business state, recovery epoch, approval
consumptions, budgets, and Authority lifecycle state. A handled failure records a
failed Executive maintenance outcome and aborts its active Authority fence. Process
termination can leave either an Executive `ACTIVE` maintenance record or an
Authority `ACTIVE` fence. Executive recovery requires the exact operation ID,
unchanged generation, exclusive lock, and integrity check. Authority recovery is a
separate explicit signed operation. The fence ID is deterministically derived from
the durable restore operation ID, so it remains recoverable even if the begin-fence
response is lost. Recovery is allowed only after fence expiry, marks the fence
`EXPIRED`, and never completes the restore; until then covered mutations fail closed.

The empty `.keeper-lock` file carries only an operating-system advisory byte lock;
it contains no state and is not a second database-plus-file commit protocol. Manual
same-user replacement of the database outside this workflow remains outside the
Keeper 1.0 personal-use threat model.

The source candidate uses Authority protocol 7 and schema 6. This repair does not
install, restart, or update the Windows service. A separately authorized release or
installation step must deploy the matching KeeperAuthority build before production
restore can use the fence operations; an older installed service fails the protocol
identity check rather than falling back to unfenced restore.

Pass A continues to support multiple normal Executive runtime writers through
SQLite transactions, CAS, uniqueness constraints, and the shared lock. Restore is
the enforced exclusive maintenance operation.

## Provider process recovery

An in-process paused desktop run persists `interrupted` and the exact prior stage,
and may resume only to that stage. The desktop coordinator inspects incomplete
runs during startup and records a durable recovery decision before allowing any
selected-stage retry.

Critical JSON state is written to a temporary file, flushed, and atomically
replaced. Each process run has its own directory under `.ai-workflow/runs/` with
the prompt, stdout, stderr, and `run.json`.

At startup, `start` and `resume` inspect incomplete runs. `recover` can be run
directly:

```bash
python -m keeper recover
```

Provider ownership records bind the PID to process creation time, executable,
command identity, parent, provider identity, run and stage, launch nonce, and
evidence path. On Windows, recovery opens one native process handle and retains it
from the first identity check through the destructive boundary. It reloads the
protected ownership record and provider evidence, rechecks the full live identity
through that same handle, and terminates only that exact process object through the
retained handle. Every path closes the handle.

Process discovery is tri-state. Only an operating-system-confirmed missing PID or
a signaled retained process object is treated as absent/exited. Access denial,
insufficient privilege, and unexpected query failures remain indeterminate,
blocked, and non-retry-safe. Protected ownership is never bypassed after an
indeterminate query.

Recovery never uses a PID-only tree kill after validation. Descendants cannot be
rebound to the original job after a restart, so a detected or unenumerable
descendant tree is classified as uncertain and left untouched. An inaccessible
handle, exited process, reused PID, identity change, ownership change, ambiguous
tree, or uncertain termination outcome also remains blocked and is not retry-safe.
A missing process may be eligible for an explicitly authorized retry of the exact
interrupted stage. Unfinished work is never silently removed.

A durable `EXECUTION_STARTED` provider attempt remains authoritative even when its
filesystem `run.json` is missing or unreadable. Provider evidence is corroborating
evidence only. Missing, malformed, duplicated, inaccessible, or identity-mismatched
evidence is recorded as indeterminate and is never retry-safe.

Recovery reads only the exact canonical `run.json` path protected in the durable
attempt. It does not search sibling provider directories for a matching run ID.
The path must remain canonical and contained in the run evidence root. The record
must exactly match the Keeper run, task, stage, role, attempt and retry parent,
logical provider and instance, stable registration, executable and configuration,
endpoint and authentication, capability and policy identities, evidence path,
launch nonce, and ownership token. Missing fields are mismatches, not wildcards.

Provider status is canonicalized and checked against explicit nonterminal and
terminal sets. Unknown or missing states and incomplete terminal dispositions
remain indeterminate. `RECOVERED_TERMINAL` additionally requires consistent
protected ownership and an authoritative result showing the exact process exited.

Mutable provider `run.json` terminal fields are never completion authority.
Normal completion writes an immutable Keeper completion record containing the
exact attempt identity, result, executable/configuration identity, and digest of
the provider evidence before finalizing protected attempt state. Recovery requires
that record (or the same trusted crash-gap journal), validates its integrity and
evidence digest, and only then permits `RECOVERED_TERMINAL`. If a child exits before
the protected record is persisted, the attempt remains uncertain and
non-retry-safe even when `run.json` claims success.

Before provider launch, Keeper durably creates a cryptographically random,
attempt-specific completion challenge. The completion journal binds that
challenge, process ownership, lifecycle transaction, and evidence digest and is
authenticated with the installation authority key. A manually inserted database
row, literal writer label, copied record, reused challenge, or correctly recomputed
public digest remains unverified without a valid writer proof.

Inspect the recorded workspace and Git state before retrying a blocked task.
Keeper preserves dirty and failed worktrees. `cleanup-worktrees PATH` removes only
a clean registered worktree and refuses dirty work.
