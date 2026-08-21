# Keeper Completion Plan

## Current MVP inventory

Keeper already provides validated task/run/finding models, an explicit state
machine, atomic JSON persistence, deterministic worktree ownership, bounded
retries, structured provider output, independent review, protected capability
authorization, verification evidence, safe cleanup, process-tree termination,
CLI commands, documentation, and a deterministic pilot.

## Gap analysis

The MVP has no desktop interface, durable application database, first-run
experience, provider discovery catalogue, semantically bound verification
categories, reusable project/task records, notification centre, report
exporter, controlled Git commit/push service, or packaged launcher. Its real
command provider is generic rather than a stable provider-adapter protocol.

## Chosen architecture

Keeper Productization remains Python-first and local-only:

- Tkinter/ttk desktop UI, requiring no browser, server, or exposed port.
- In-process application service with no privileged IPC.
- SQLite transactional application store under the user's selected data path.
- Existing JSON evidence remains the immutable per-run record format.
- Provider-neutral adapter protocol with executable discovery and diagnostics.
- Existing orchestration engine remains authoritative for workflow execution.
- Standard-library zipapp packaging plus a single Windows launcher.

This is the smallest architecture compatible with the repository, Python 3.14,
offline mock operation, Windows packaging, and future macOS/Linux launchers.

## Staged implementation sequence

1. Versioned storage, migrations, application service, semantic verification,
   Git safety, reporting, and notification records.
2. Provider discovery/adapters, capability routing, and independence evidence.
3. Desktop shell, setup wizard, projects, tasks, workflow, findings,
   authorizations, history, and settings.
4. Threat controls, adversarial tests, evidence hashing, and recovery.
5. Packaging, launch scripts, documentation, full tests, packaged smoke test,
   and end-to-end mock pilot.

## Migration strategy

SQLite migrations are monotonic and transactional. The initial migration
creates versioned application tables. Existing `.ai-workflow/tasks`, `runs`,
pilot invocations, and cleanup registers can be imported as read-only legacy
evidence; source files are never changed or deleted.

## Test strategy

Unit tests cover storage, migrations, routing, verification semantics,
authorization, Git policy, redaction, and reporting. Integration tests exercise
complete mock workflows, failure/recovery, commit/push simulations, and process
trees. UI behaviour is tested through a display-independent view model and
diagnostic launch mode. Packaging produces a zipapp and runs its diagnostic
entry point.

## Packaging strategy

`scripts/build-keeper.ps1` creates `dist/keeper.pyz` reproducibly from tracked
sources. `scripts/keeper-launch.ps1` launches source or packaged mode with one
command. Installers remain release artifacts rather than committed binaries.

## Security boundaries

Keeper is local-only and fail-closed. It does not merge, rebase, reset, stash,
clean, force-push, deploy, trade, spend money, delete repositories/branches/
worktrees, or reveal secrets. Commit, push, network use, and protected actions
require explicit scoped authorization. Provider output and repository text are
untrusted. Commands use argument arrays, paths are canonicalized, logs are
bounded/redacted, evidence is hashed, and provider descendants are terminated.

## Definition of done

The desktop app launches; first-run diagnostics work; repositories and tasks can
be created; providers are discovered; mock workflow completes; routing and
independence are enforced; semantic verification is fail-closed; state,
evidence, reports, and notifications persist; commit/push require authorization;
packaging and packaged diagnostics pass; documentation matches behaviour; all
quality gates pass; and no Critical or High release blocker remains.
