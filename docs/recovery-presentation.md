# Recovery display and local worker safety

Desktop refresh reads `KeeperApplication.recovery_records()`; it must not invoke recovery, probe a process, terminate work, or rewrite durable run state. Startup and explicitly requested recovery remain separate operations.

Recovery records are global, independent of the selected project. Legacy nested `recovery.classification=uncertain` is displayed as UNCERTAIN and included in the global count. Authority-backed external uncertainty stays on its existing exact-disposition path.

The desktop distinguishes two actions:

- Resume: an existing paused worker is still alive.
- Retry stage: an interrupted, recoverable run has explicit retry-safe evidence, no previous live process, and a retryable stage.

Unknown, unsafe and uncertain records remain visible but offer neither action. These are presentation hints, not grants of authority. The execution path revalidates state and explicitly rejects uncertainty. Existing stage, provider, reroute and authorization checks remain in force.

Within one coordinator, recovery is serialized against start/retry publication and skips every registered worker, including workers not yet started and paused workers. Failed thread startup removes only the exact failed registry entry; durable state remains available for recovery. Duplicate retry is rejected before lifecycle mutation.

## Remaining boundary

The lock and registry are process-local. They do not prove ownership across two Keeper instances using the same data directory. Cross-instance startup recovery remains a known risk and needs separately reviewed single-instance or durable-ownership design. Do not run two instances against one profile or describe this change as cross-process confinement.

## Project scope display

The Projects page displays recorded request, outcome, deliverables, success criteria, exclusions, constraints and open questions as selectable plain text in a scrollable area. Missing fields say Not recorded, not approved or unrestricted. Intake recognizes explicit Success:/Success is wording and preserves combined negative clauses verbatim as constraints. This does not modify the approval dialog, delegation defaults, authentication or Founder approval handlers. A recorded constraint is not an execution grant or a claim that free text is mechanically enforced.

## Verification

- `test_audit_recovery_followups.py`: non-mutating/global reads, worker admission, serialization, failed launch cleanup, action gating, uncertainty rejection and recorded scope.
- `test_restart_recovery_retry.py`: existing restart/retry safety regression coverage.
- `test_project_scope_presentation.py`: real QML scope display at both supported sizes.
- `test_chat_recovery_integration.py`: real QML editor lifecycle and fault injection; see `chat-recovery.md`.

No test success substitutes for installed Authority/provider validation with the owner handling credentials.
