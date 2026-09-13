# Keeper Executive Completion Pass A

## Audit authority

[`THREAT_MODEL.md`](THREAT_MODEL.md), version 1.0, is the authoritative threat
boundary for Completion Pass A. Supported-path failures remain release blockers.
Arbitrary code already executing in the trusted Executive interpreter, deliberate
same-process monkey-patching, and same-user manual database replacement are
post-compromise hardening scenarios and are not Critical/High Pass A blockers.

## Product boundary

Keeper Executive is the conversation-first project manager above the independently
protected Authority Service. It converts Founder conversation into a versioned
Project Charter, generates a workload-specific workflow, selects qualified
specialists, validates authority deterministically, reviews evidence, requests
repair, and resumes from durable state.

The executive never signs provider records, qualifies providers, fabricates
completion, reads Authority protected keys, or broadens Authority IPC. Production
composition uses an exact `ProductionExecutiveRepository` with an exact Windows
Founder authenticator; test composition uses structurally separate concrete
types. `KeeperExecutive` is a narrow immutable facade and does not expose either
trusted object. Databases are permanently mode-bound and populated unbound
fixture state cannot be adopted by production. Production runtime construction
accepts only the concrete Authority-backed gateway. Test and pilot transports
exercise the same lifecycle semantics but are explicitly non-production-authoritative.

## State machines

Projects move through intake, clarification, charter drafting and approval,
activation, planning, execution, review, waiting or blocked states, pause, and a
terminal completed, canceled, or failed state. Tasks move through proposed,
ready, launch claimed, execution started, running, completion pending, review,
repair, uncertain, completion, blocked, failed, canceled, or skipped states.
Explicit transition maps and optimistic revisions reject arbitrary or stale
completion.

Approval is one trusted transaction that reloads the exact proposed charter and
authenticated Founder interaction, binds identity, revision, canonical content
digest, source provenance, and expiry, then creates the immutable approval
history and approved lifecycle state together. Public repository writes cannot
create an approved charter. Activation reloads the durable charter, approval,
and source; rejects unresolved material questions, revoked or expired approval,
copied or stale binding, and superseded revisions; then atomically binds the
active revision. Approved content remains immutable. Material changes create a
new draft revision with exact differences, reason, authority basis, and a link
to the prior version.

## Conversation and charter model

Intake values retain one of four origins: explicit Founder statement, high
confidence inference, proposed assumption, or unresolved question. A future
desktop client can revise structured values without losing the source
interaction. Charter records include purpose, outcome, deliverables, non-goals,
criteria, constraints, assumptions, questions, timeline, budget, tools,
providers, workspaces, privacy, risk, delegation, authority, escalation, review,
evidence, completion, version, and Founder approval fields.

Charter and protected-action approval are not derived from conversation text.
Production confirmation uses the Windows credential UI and `LogonUser` to
authenticate the provisioned desktop principal SID. A non-exportable 3072-bit
Windows CNG RSA key with forced high-protection UI signs the resulting one-use
confirmation and the strict Founder authorization capability; KeeperAuthority
receives only its pinned public verifier. The capability issuer requires that
fresh confirmation and cannot sign arbitrary payload shapes. The repository
re-reads the durable charter, challenge, consumed session, event, and approval in
the same transaction before issuance. Test issuers, authenticators, confirmations,
repositories, algorithms, and database modes are distinct and rejected by the
production composition.

## Delegation and deterministic authority

Advisory mode permits analysis, planning, drafting, and reading. Delegated mode
permits routine actions explicitly listed by the charter. Full Delegation permits
bounded material work inside the same envelope. It is not unlimited authority.

Every launch action is derived again from the durable workflow task immediately
before claim. Classification includes objective, target, scope, provider, tool,
workspace, cost and canonical currency, reversibility, external effects,
publication, deployment, spending, Git mutation, security impact, and data
classification. Conflicts such as deployment disguised as writing fail closed.
Every non-goal is an explicit denial and is never added to allowed scope.
Ambiguity fails closed. Protected deletion, history rewrite,
credential access, security-boundary change, live trading, financial-authority
change, governance change, and irreversible destruction are non-delegable.
Push, production deployment, external publication, purchases, spending, and
commit authorization remain separately approvable. One-time approvals consume
in the execution claim transaction with one concurrent winner. Spending is
reserved atomically in canonical minor units against the cumulative
charter/approval limit, preventing split-action bypass; unknown cost, absent
budget, and implicit currency conversion are denied.

The Executive sends KeeperAuthority only the signed Founder capability, never
bare asserted Founder identity fields. KeeperAuthority independently checks the
pinned issuer/key, signature, strict schema, project, charter, action and approval
digests, principal/session/event/record/challenge, generation, revocation epoch,
expiry, and usage before signing launch authority.

Authority launch authorizations are stored by project and generation. Revoking
a generation leaves its record permanently revoked and cancels its unlaunched
attempts. Capability ID/digest/signature and every Founder approval, event,
session, challenge, approval digest, and proof digest are durably unique across
the entire project history, not only the adjacent generation. Consumption and
the exact next generation commit in one immediate transaction. Exact retries are
idempotent; concurrent requests yield one canonical record; revocation, restart,
or upgrade never makes an old identity reusable.

## Dynamic workflow and specialists

The planner has workload-aware strategies for software, research, video, music,
writing, and general projects. Each generated stage explains its purpose and
rationale and creates durable tasks with dependencies, inputs, outputs,
capabilities, authority class, evidence, review, and retry policy.

Selection starts from current authenticated Authority registration and
qualification records; caller-created profiles cannot establish qualification.
Before launch, the runtime persists a unique attempt binding covering project,
charter revision, workflow, task revision, provider registration and
qualification, executable digest, workspace, instruction digest, expected
outputs, and evidence requirements. Only then may the Authority Service launch
the provider. Mutable gateway strings have no completion authority.

Independent review creates a separate durable review attempt. It reserves and
executes a distinct Authority-qualified provider/session, binds the review to
the current author attempt and artifact/evidence digest, and accepts only an
authenticated reviewer completion. A relabeled author session, copied review,
missing execution, stale artifact revision, or unsigned completion cannot finish
the task.

## Persistence, restart, and surfaces

Executive schema version 6 adds the production/test repository-mode marker and
the signed Founder capability entity. Schema version 8 records the database
recovery identity and explicit recovery epoch wholly inside SQLite. Schema version
9 adds the write generation, durable restore-maintenance state, one-use restore
authorization consumption, and signed Authority reconciliation receipt. Schema
version 10 records the active Authority fence identity and expiry. Authority schema
version 4 adds the durable project-wide capability-consumption ledger; schema
version 5 adds project versions and signed restore-fence state. Authority protocol
version 3 carries begin, confirm, complete, abort, and expired-fence recovery.
Existing hash-checked execution, review, late-result, one-time approval-consumption,
and cumulative budget records remain intact. Project, charter, workflow, task, approval, execution, review, and
evidence ownership is checked at persistence boundaries. Project, charter, and
task updates use exact compare-and-swap state; approved content and authenticated
identity bindings cannot be rewritten. Migrations remain idempotent and do not
copy Authority signatures or protected state into the Executive database.
SQLite is the sole live Executive commit boundary; no adjacent lineage append is
required after a business transaction. Pass A supports multiple runtime writers
through SQLite transactions, CAS, uniqueness constraints, and a shared OS
transaction lock. Explicit restore first creates an immutable integrity-checked SQLite artifact and
requires an exact typed Founder authorization over its hash, identity, backup
operation and source generation. It takes the exclusive lock, captures and merges
the live monotonic approval/budget safety ledger, opens a signed project-scoped
Authority fence, validates the complete fenced snapshot, compare-and-confirms the
unchanged Authority version, pauses nonterminal projects, rechecks generation, and
advances the in-database recovery epoch only in the validated staged replacement.
The fence remains held through replacement and is closed only afterward.
Unkeyed local payload hashes are corruption/CAS aids only and never establish
approval, provider identity, execution, review, or completion authority.

The task claim and Authority attempt ID are durable before provider launch.
Restart reconciles the original attempt instead of creating a new one. A lost
response after the execution boundary becomes `UNCERTAIN` and is non-retry-safe.
Two workers yield one claim. Cancellation rechecks authority before launch,
requests service-owned cancellation, prevents new launches, and cannot be
overwritten by late completion. Late authenticated evidence is retained as
history while task and project state remain canceled.

The application view model exposes Keeper conversation, project summary, charter
history, delegation and limits, unresolved questions, workflow and stage status,
tasks, assignments, decisions, assumptions, review attempts, blockers, evidence,
uncertain work, and late results. Controls are advertised only when valid, and
active charter approvals are not mislabeled as pending. The desktop dashboard can consume this model while
keeping conversation as the primary interaction.

## Pass B extension points

- `SpecialistProfile.session_id` and the selector allow multiple sessions per
  provider without changing task records.
- Waiting states reserve provider reset, credential, external system, and usage
  reset transitions.
- Cost and provider fields allow shared usage-pool accounting.
- Workspace fields and readiness checks allow future write reservations and
  cross-worktree locking.
- `ProjectStatusView` is presentation-independent for the final black, gold,
  gray, and white desktop experience.

Pass A does not automatically purchase usage, wait for provider resets, publish,
deploy, enable live trading, or implement the final production desktop shell.
