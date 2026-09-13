# Keeper Security

Keeper 1.0 uses the versioned personal-use boundary in
[`THREAT_MODEL.md`](THREAT_MODEL.md). Installed Executive code is trusted;
provider output and provider processes are not. Arbitrary code already executing
inside the trusted interpreter is a post-compromise condition, not a claimed
Python object-isolation boundary.

Provider-generated code is never imported, evaluated, compiled, or executed in
the trusted Executive process. It runs only in Authority-managed provider
processes, isolated build/test processes, approved workspaces, deterministic
tools, or reviewed installed updates. Keeper 1.0 exposes no in-process third-party
plugin loader.

Keeper treats task definitions and process output as untrusted data.

- Paths are repository-relative, normalized, and checked for traversal.
- Changed files must match allowed paths and must not match blocked paths.
- Commands are argument arrays executed without a shell.
- Only commands in trusted task or workflow configuration are run.
- Freeform process output is never executed.
- Structured review output is schema-validated before use.
- Credential-like environment variables are filtered from child processes.
- Prompts and logs must not contain secrets.
- Dirty worktrees are never silently deleted.
- Final evidence is indexed by path, byte count, and digest, then its
  security-relevant report fields and provider-attempt identities are copied into
  an immutable finalization record. Export revalidates both layers.

Protected actions include force pushes, history rewrites, repository or backup
branch deletion, secret publication, purchases, paid resources, production
deployment, live trading, real trades, weakened security, disabled required tests,
and out-of-roadmap architecture changes. Keeper blocks these actions pending
explicit authorization.

The environment-name filter is defense in depth, not a secret manager. Operators
must use the repository's approved credential storage and inspect custom provider
configuration before execution.

## Local Founder confirmation

Production Founder approval uses the Windows credential UI and validates the
credential with `LogonUser`. The resulting token SID must equal the Windows SID
provisioned from the Keeper desktop process; a caller-supplied account, SID,
conversation speaker, or `LOCAL_FOUNDER` string has no authority. The packed
Credential UI buffer is zeroed over its complete returned byte length before
`CoTaskMemFree`; the unpacked user, domain, and password buffers are zeroed on
success, rejection, cancellation, and exceptions, and token handles are closed
exactly once.

The confirmation and final single-purpose Founder capability are signed with a
3072-bit RSA key in the Microsoft Software Key Storage Provider. The private key
is non-exportable and created with forced high-protection UI; KeeperAuthority is
provisioned only with the public modulus, exponent, issuer identity, and key ID.
The signer accepts only the strict capability schema and requires the exact fresh
signed confirmation. It binds project, charter revision, protected delegation,
action and approval digests, SID, session, event, approval, challenge and proof,
generation, revocation epoch, lifetime, usage, machine, and application identity.

The repository re-reads the complete challenge/session/event/approval chain in
the same transaction, consumes the one-use challenge and session, and only then
requests the capability. A same-user process cannot export the private key or
silently sign: every CNG use requires the protected Windows interaction, and a
replayed confirmation cannot be rebound to different claims. As with any
same-user desktop prompt, malware may attempt to display or invoke Windows UI;
the design does not claim to make a compromised interactive account trustworthy.
It does prevent key possession, configuration injection, a cached session, or
bare caller fields from silently minting Founder authority.

Production and test repositories are distinct exact concrete types. The
production facade exposes no mutable repository or authenticator, both
compositions are immutable after construction, populated unbound fixture state
fails closed, and each database is permanently marked `PRODUCTION` or `TEST` on
its first empty trusted open.

KeeperAuthority rejects bare Founder identifiers. It verifies the capability
signature and strict bindings, then atomically consumes it while creating the
exact next launch generation. Database uniqueness constraints make capability,
signature, approval record/event, session, challenge, approval digest, and proof
digest permanently one-use for the project across revocation, restart, and
package upgrade. Exact retries return the one existing canonical generation;
failed creation rolls back both generation and consumption.

## Restore authorization and reconciliation

Production restore does not accept callback success as authority. Before requesting
Founder confirmation, Keeper finalizes a unique logical SQLite artifact with the
SQLite backup API, thereby incorporating committed WAL content, closes its handles,
and validates integrity and foreign keys. The exact Windows Founder confirmation
covers the restore and backup operation IDs, canonical artifact path and SHA-256,
source database ID, recovery epoch and write generation, target path/identity/epoch/
generation, complete project scope, reason, and two-minute lifetime. A successful
restore consumes the authorization identity in SQLite; replay, artifact mutation,
source-identity mismatch, and stale target identity fail closed. Production rejects
all test proof, authenticator, and Authority-client concrete types.

Before staging, the Executive captures the current project-scoped approval and budget
safety ledger independently of the backup and Authority attempt list. One-time
approval consumption, its timestamp and project/charter/action/task binding, crossed
budget state, immutable amount/currency and binding, and related attempt identity are
monotonic. They are merged into the staged database, with newer live facts winning;
an ambiguous mismatch aborts. Preserved IDs and ledger digests are included in the
durable restore reconciliation record, so restart retains the same replay and budget
boundaries.

KeeperAuthority atomically opens a signed, bounded project-scope fence containing the
complete attempt and launch-authorization state plus monotonic project versions. The
fence is bound to the Founder-authorization digest, artifact, source and target
identities, service key, requesting SID, and restore operation. Queries remain
available, but covered reservations, claims, starts, completion, cancellation, and
launch revocation are blocked while the fence is active. The Executive validates and
reconciles that snapshot, then obtains a signed compare-and-confirm with the same
state/version digest immediately before replacement. Omitted or altered attempts,
terminal results, cancellations, or revocations invalidate the proof. New terminal
truth is retained as non-retry-safe `UNCERTAIN` state.

The target exclusive lock and Authority fence remain held through the SQLite live
replacement. The fence is completed only after replacement and integrity verification.
Failure before replacement aborts the fence and preserves live business state and
recovery epoch. The deterministic fence ID is recoverable from the durable restore
operation ID even if the begin response is lost. An interrupted active fence blocks
covered changes after expiry until an explicit operation-bound Authority recovery
marks it `EXPIRED`; recovery never completes the restore. There is no unfenced third-snapshot fallback.

Every supported database connection holds a shared OS advisory lock for its full
transaction. Restore holds the exclusive form from initial identity validation
through replacement and records in-database maintenance and fence identity. This
prevents an acknowledged supported write from being overwritten. A stale active
maintenance record blocks supported connections until explicit integrity- and
generation-checked recovery. The lock file contains no authority or commit metadata.

## Authenticated lifecycle authority

Keeper creates a 256-bit installation authority key with the operating system
cryptographic random source. On Windows the stored key blob is protected with
current-user DPAPI and kept under the Keeper data directory's dedicated
`authority/` folder, outside repositories, worktrees, provider evidence, and
qualification working directories. On non-Windows systems the key file must have
mode `0600`; broader permissions fail closed. Current-user DPAPI protects key
material at rest from other Windows accounts and offline access according to
DPAPI's guarantees. DPAPI alone does not isolate the key from arbitrary processes
running as the same user.

Keeper's same-user provider isolation therefore also depends on process
confinement. Before any provider instruction can execute, Keeper creates and
configures a Job Object with kill-on-close and no breakaway allowance, creates
the exact retained provider process suspended, assigns and confirms the process
in that Job, and only then resumes its retained primary thread. Only the explicit
standard-stream handles are inherited. The non-inheritable exclusive authority
blob handle remains held until the Job has terminated every descendant and all
process, thread, and Job handles are closed. Assignment, confirmation, or resume
failure terminates the suspended process or Job without executing provider code.
If atomic confinement cannot be established, provider execution fails closed.

The key is never placed in configuration, environment variables, command lines,
stdin, logs, reports, or provider working directories. Provider children receive
only public challenges and evidence paths. Qualification and completion records
carry a versioned key identifier and HMAC-SHA-256 writer proof over their complete
canonical payload. Verification uses constant-time comparison. Public SHA-256
digests remain useful for content reconciliation but never establish writer
authority.

Key loading, DPAPI unprotection, identifier mismatch, or authentication failure
blocks qualification and completion. There is no unkeyed fallback. Automatic key
rotation is intentionally disabled for the MVP. Rotation requires retaining the
old DPAPI-protected key for records that must remain verifiable; deleting or
replacing it makes old records unverifiable and therefore non-retry-safe.
Initial key publication writes and flushes a unique same-directory temporary
file, then atomically links it to the final path without overwrite. A concurrent
winner is loaded and validated; partial or corrupt final files fail closed.

Commit authorization and mutation are separate operating-system and Git
operations. Keeper revalidates the authorized staged-content digest immediately
before commit, but no cross-process transaction can make the final check and Git
mutation atomic. Operators must prevent concurrent writers during an authorized
commit.

## Local model assignment

`qwen2.5-coder:14b` is disabled for every role. `qwen3-coder:30b` is an approved
general-purpose provider for building, repair, review, tests, documentation,
analysis, exploration, and planning. It never reviews its own work. Every
Qwen-authored change passes normal verification and receives final review from a
different capable provider instance and context. High-risk changes require a
non-Qwen final reviewer. No Qwen model is an automatic fallback; if an approved
route is unavailable, the task becomes `BLOCKED`.
