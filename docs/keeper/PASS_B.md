# Keeper Completion Pass B

Pass B turns the approved Executive and Authority foundation into a
conversation-first personal project system. It adds durable provider sessions,
shared usage accounting, assignments, attempts, evidence, reviews, workspace
leases, write claims, recovery checkpoints, delegated-mode records, control-room
views, and the Sage presentation boundary.

## Product flow

1. The Founder describes a project in conversation.
2. Keeper extracts durable intake facts and proposes a versioned Project
   Charter.
3. Conversation text remains non-authoritative. The existing Founder
   authentication and charter activation boundary supplies authority.
4. Keeper selects an adaptive workflow from the active charter's project type,
   deliverables, evidence requirements, and review requirements.
5. Assignments bind immutable provider, account, session, role, model,
   workspace, charter revision, authority-envelope digest, expected evidence,
   and usage policy.
6. Keeper validates the active Founder-approved charter and signed
   KeeperAuthority attempt, then atomically claims usage, the exact workspace,
   protected write scope, and provider-session capacity before launch.
   Production execution crosses KeeperAuthority's protected execution
   transition; only explicit test composition calls a mock adapter directly.
7. Keeper validates returned evidence as untrusted data. Review acceptance is
   derived from a distinct completed reviewer attempt and validated reviewer
   evidence, never from a caller-supplied Boolean.
8. The control room presents durable state, blockers, uncertainty, recovery
   prompts, and Authority health.

The workflow designer has separate adaptive strategies for software, research,
video, music, writing, design, marketing, business operations, and general
projects. It does not impose one universal coding pipeline.

## Durable storage

Pass B records are stored in the existing Keeper SQLite database. Migration
version 3 is recorded in `pass_b_schema_migrations`. Migrations retain version
1 records while adding unique Authority-attempt identity, usage-window
generation, and authenticated reset-observation claims. Generic records use
revision-and-payload-hash compare-and-swap updates. Normalized claim tables
provide transactionally enforced uniqueness for workspace writers, protected
write scopes, usage reservations, and launch identity.

The inherited store configuration retains WAL mode, full synchronous behavior,
foreign keys, busy handling, integrity-checked backup behavior, recovery epoch,
and the Pass A restore fence. Adding Pass B tables does not introduce a
database-plus-file transaction protocol.

## Authority boundary

Pass B reuses `ProjectRecord`, `ProjectCharter`, workflows, Founder approvals,
and the production Executive facade. It does not create a second authority
system.

Provider adapters translate data only. They cannot approve, expand charters,
authorize side effects, or load provider-generated code into the Executive.
Launch calls must match the active project, Founder-approved charter revision,
assignment, work item, role, provider registration, session, workspace, and
authority-envelope digest. Production composition validates the signed attempt
and active launch generation, then asks KeeperAuthority to execute it. A bare
or replayed attempt string cannot authorize provider work.

## Reviewer-only repository checks

A reviewer still requires exact producer evidence. For a no-write repository
check, Keeper can atomically publish a clean Git snapshot as the producer: the
top-level repository path, HEAD commit, tree, and the SHA-256 and size of every
Git object are bound into one validated evidence bundle. This internal snapshot
does not launch a provider, consume usage, or claim that a model produced the
source evidence. The repository must remain clean and byte-identical when the
review reference is validated.

A READY assignment that has never created an attempt or launch claim may be
abandoned through the supported pre-launch operation. That atomic transition
cancels the assignment, releases workspace and write claims, and returns its
local usage reservation without recording consumption. Running, uncertain, or
otherwise launched assignments remain ineligible and require their existing
recovery paths.

## Supported entry points

- `scripts/keeper-pass-b-desktop.py` starts the conversation-first desktop
  shell with the production Executive and Authority client.
- `scripts/keeper-pass-b-pilot.py` runs the isolated deterministic DarkSage
  pilot and writes durable evidence.

The local/mock adapter is intended for diagnostics, tests, and isolated pilots.
Real remote transports are injected behind the stable adapter contract.
