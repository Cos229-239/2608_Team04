# Changelog

## Unreleased

- Export the exact Windows server-auth root store into a deterministic Host-owned
  PEM bundle for restricted Codex launches, excluding every certificate present
  in the Windows Disallowed store and failing closed if that policy cannot be
  represented exactly. The Host scrubs caller trust-path
  overrides, injects only the hash- and file-identity-attested bundle, binds it
  into the signed environment contract, and holds a read-only/no-delete lock
  across setup and provider execution. Token restriction, Job confinement,
  filesystem ACLs, TLS verification, and zero-effect registration ordering are
  unchanged.
- Accept the exact subscription `plus` and `pro` runtime plan labels for the Codex
  subscription provider while preserving the observed plan through account
  discovery, the Founder replacement capability, signed successor lineage, Host
  registration probing, durable registration, and qualification. All other plan
  labels remain fail-closed, and API-key billing, paid fallback, account
  switching, and provider switching remain prohibited.
- Transfer the exact reviewed Codex executable into KeeperAuthority for
  registration and qualification as a client-opened, locked, read-only handle.
  A disposable worker uses only the already-authenticated client-process token
  for the single minimum-rights process open, reverts and proves clean, and only
  then publishes the retained process handle to Authority code. This avoids the
  incompatible restricted-service two-pass DACL grant while preserving the
  Restricted Code deny. Authority revalidates PID/SID/session/lifetime and
  handle rights, then binds final path, file identity, SHA-256, size, and
  Authenticode before any durable provider effect.
- Add a fail-closed recovery lifecycle for a Defender-quarantined selected
  Provider Host executable. Recovery requires the exact durable current record,
  an absent selected executable, byte-exact remaining selected package and
  Startup launcher, one intact Defender-clean retained rollback generation, and
  a different exact Defender-clean replacement before any drain or mutation.
- Grant the exact KeeperAuthority service SID query-only access to the attested
  Provider Host process token before pipe construction, and make Authority's
  Host-server measurement request only `TOKEN_QUERY`. This preserves exact
  SID/session/process/image/hash binding without granting token duplication.
- Treat canonical uppercase, lowercase, and mixed-case SHA-256 encodings as the
  same installed Authority package identity while rejecting malformed,
  non-string, or unequal upgrade digests.
- Bind every KeeperAuthority package upgrade to the exact authorized external
  manifest, package bytes, Git commit, and Git tree; persist those identities in
  the durable upgrade claim/event and atomically update or restore installed
  provenance across upgrade, interruption, retry, and rollback.
- Bootstrap the user-owned Provider Host process DACL before runtime or pipe
  construction, granting the exact KeeperAuthority service SID only
  `PROCESS_QUERY_LIMITED_INFORMATION` after signed installation, package,
  path, hash, file-identity, session, and protected-tree validation.
- Migrate and attest the exact Provider Host ACL policy on both the selected
  package and its retained rollback generation before an install lifecycle can
  clear its durable transaction. Same-version repair preserves the rollback
  generation, and interrupted ACL finalization remains fail-closed and
  recoverable.
- Bootstrap the restricted KeeperAuthority process DACL through an exact-rights
  duplicated self-handle and kernel-object security APIs, with exact read-back
  verification and sanitized service-specific startup failure stages.
- Split named-pipe client revalidation into non-filesystem process checks and
  retained-process-token executable observation, so neither the raw pipe token
  nor the service identity opens the protected Provider Host image.
- Bind Provider Host path observation to a minimum-access impersonation
  duplicate of the exact retained authenticated client-process token, including
  process creation and executable identity revalidation, instead of using the
  raw named-pipe token for filesystem access.
- Keep Provider Host enrollment path validation on a disposable read-only
  worker, then revert and positively verify the worker identity before
  Authority code can consume its observation. Restricted provider code remains
  denied by the exact Host ACL.
- Correct the Provider Host machine-key security-descriptor binding, validate
  the exact non-exportable CNG identity and protected owner/DACL policy, and
  reconcile an exact interrupted key without deleting or recreating it.
- Replace the default Keeper desktop with a PySide6/Qt Quick executive control center using the official lighthouse identity, 13 source-backed product areas, durable Keeper Assistant conversation, responsive layouts, and protected-path-redacted service health.
- Add a pinned standalone Windows build plus hashed per-user install, repair, upgrade, one-generation rollback, status, and data-preserving uninstall lifecycle.
- Require an authenticated Executive commit receipt before KeeperAuthority can bind
  typed reviewer input. The receipt proves the exact delivered-input record,
  reviewer attempt, session slot, usage reservation, and RESERVED launch claim were
  committed and conservatively launch-claimed before external execution; Authority
  protocol 6 carries this binding.

## 0.6.0

- Authorize restore against an integrity-checked immutable SQLite backup artifact,
  including WAL-backed source state captured at backup time, and bind the signed
  request to its artifact path and hash, backup operation ID, and source generation.
- Preserve consumed one-time approvals, consumption bindings and timestamps, crossed
  budget reservations, and related Executive attempt bindings monotonically when an
  older backup is restored; ambiguous bindings fail closed and preserved identities
  are recorded in the durable reconciliation evidence.
- Add a signed, bounded, project-scoped KeeperAuthority reconciliation fence. Covered
  attempt and launch-authority mutations are blocked until compare-and-confirm and
  live replacement complete; expiry and interruption require explicit conservative
  recovery. Executive schema 10, Authority schema 5, and Authority protocol 5 carry
  the new maintenance and fence state.

## 0.5.9

- Replace restore confirmation and reconciliation callbacks with exact typed
  production Founder authorization and a signed KeeperAuthority project-scope
  snapshot bound to the operation, backup, database identities, and generation.
- Preserve newer Authority terminal truth as non-retry-safe uncertainty, validate
  one-time approval consumption and budget reservations, and record the validated
  receipt before setting the reconciliation timestamp.
- Enforce restore exclusivity with a bounded OS shared/exclusive lock, durable SQLite
  maintenance state, write generations, final identity rechecks, and conservative
  interrupted-lease recovery.

## 0.5.8

- Adopt the versioned Keeper 1.0 single-Founder personal-use threat model for
  Completion Pass A and move same-process post-compromise scenarios to the
  hardening backlog.
- Make SQLite the only live Executive commit boundary and retire the external
  per-transaction lineage append.
- Add atomic integrity-checked backups, explicit Founder-approved restore with
  Authority reconciliation, and an in-database recovery epoch.

## 0.5.7

- Create Windows provider processes suspended and assign them to a configured
  kill-on-close Job Object before resuming the primary thread.
- Restrict inherited handles to the explicit standard streams and retain the
  process, primary-thread, Job, executable, script, and authority handles through
  descendant termination.
- Publish first-installation authority keys through a flushed same-directory
  temporary file and atomic no-overwrite hard link, loading a concurrent winner.
- Add pre-assignment, failure-cleanup, nested-descendant, cancellation,
  authority-access, and concurrent key-initialization regressions.

## 0.5.6

- Authenticate qualification and completion authority with installation-local
  HMAC-SHA-256 writer proofs and constant-time verification.
- Protect the Windows authority key with DPAPI, keep it outside provider evidence
  and repository roots, and fail closed when key loading is unavailable.
- Replace standalone raw qualification evidence with a protected evidence
  reference resolved from Keeper storage.
- Bind signed qualification and completion records to unpredictable pre-launch
  challenges and add forgery, wrong-key, cross-installation, and replay coverage.

## 0.5.5

- Separate provider registration from protected qualification; version metadata
  now comes only from an authorized retained-component qualification launch and
  immutable qualification evidence.
- Preserve registered capability and role restrictions through diagnostics,
  selection, routing evidence, and reports.
- Require an immutable Keeper completion journal before recovery can accept
  mutable provider evidence as terminal.
- Align standalone batch startup with qualified launcher/script composite
  registrations.

## 0.5.4

- Resolve recovery evidence only from the protected canonical `run.json` path
  and require complete execution identity plus an explicit provider status.
- Canonically digest the complete schema-versioned provider registration,
  including qualification and authorization metadata.
- Align standalone command startup with the current registration schema and
  exact invocation binding used by desktop routing.

## 0.5.3

- Require protected, pre-existing provider registration before command-provider
  discovery can report a provider as available.
- Preserve authoritative Windows launcher and batch-script component identities
  through adapter construction and launch evidence.
- Treat every unresolved durable execution-started attempt as indeterminate and
  non-retry-safe when provider evidence is missing, malformed, duplicated, or
  inconsistent.

## 0.5.2

- Added post-validation Windows replacement and junction-retarget integration
  coverage at the process-creation boundary.
- Retained registered batch scripts against replacement in addition to their
  immutable command launcher.
- Added spawned-process reroute races, committed-reservation crash recovery,
  execution-start crash recovery, and transactional rollback coverage.
- Persisted reroute reservation state in recovery and final-report evidence.

## 0.5.1

- Made recovery process discovery tri-state and fail closed on access denial and
  other indeterminate operating-system results.
- Bound command launch to mandatory immutable registration using retained
  deny-write/delete handles on Windows and post-launch image verification.
- Separated routing dispositions from actual provider execution attempts and
  reconciled reports against provider run evidence.
- Added atomic SQLite reroute consumption and destination-attempt reservation.

## 0.5.0

- Exercised controlled command executables through the complete author, independent
  review, repair, post-repair review, semantic verification, and evidence workflow.
- Added durable provider ownership checkpoints, incremental redacted logs, and
  retained-handle restart recovery that blocks ambiguous descendants.
- Added same-run selected-stage retries with stage-attempt identities, explicit
  authorization records, stable provider registration digests, truthful fresh
  instance identities, downstream invalidation, and irreversible-stage rejection.
- Added active waiver revocation and structured desktop evidence views for routing,
  provider identities, commands, verification, findings, logs, hashes, and Git results.
- Added rendered Windows Tk validation that navigates the real notebook, invokes the
  dashboard Refresh callback, verifies its status update, and records structured
  smoke evidence.

## 0.4.0

- Routed automatic and provider-specific desktop policies through discovered command
  and local-model adapters with independent review selection.
- Added startup interruption classification, immutable explicit retry attempts, and
  irreversible-stage retry rejection.
- Connected exact-scoped commit and push authority to durable lifecycle stages.
- Persisted live evidence roots, semantic command records, waiver details, Git
  results, retry history, and lifecycle notifications.
- Added a packaged rendered-Tk diagnostic mode with explicit unavailable reporting.

## 0.3.0

- Connected desktop tasks to the production orchestrator and durable lifecycle.
- Added approval/rejection, pause/resume, cancellation, live status polling,
  evidence actions, interactive setup, and lifecycle notifications.
- Added semantic command evidence, scoped waivers, and exact Git authorization.
- Added unified acceptance pilots and adversarial authorization coverage.

## 0.2.0

- Added versioned SQLite storage, migrations, backup/export, and legacy evidence import.
- Added full durable lifecycle, semantic verification binding, and tamper-evident reports.
- Added provider discovery, command adapters, deterministic independence routing, and
  loopback-only Ollama support.
- Added local desktop UI, first-run diagnostics, project/task/authorization workflows,
  notifications, history, and deterministic demonstration.
- Added dedicated Git safety, security controls, Windows packaging, documentation,
  and productization test coverage.
