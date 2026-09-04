# Known Limitations

## Provider Host artifact trust gate

- Provider Host release builds use exact SHA-256-pinned Python, MSVC, and
  Dependency Walker inputs. The build fails when the Git source is dirty, when
  an input differs, or when Nuitka attempts a download. Toolchain provenance is
  recorded beside (not inside) the deterministic package.
- Every release-candidate Host executable must pass the repository Defender
  verifier with real-time protection enabled. A detection, quarantine, changed
  hash, unavailable Defender boundary, or disabled protection blocks release;
  Keeper never adds an exclusion or changes endpoint-protection policy.
- Defender quarantine of a selected Host executable is recovered only through
  the explicit exact-hash `replace-quarantined-selection` lifecycle. Generic
  install, update, repair, rollback, and recovery continue to reject the
  incomplete selected package; no quarantined executable is restored or
  allowlisted.
- Authority-only process-DACL policy is kept outside the Provider Host import
  graph. This both minimizes the per-user executable and prevents unused
  service-side security mutation code from being compiled into the Host.

- Windows is the packaged and smoke-tested target; the standard-library code is
  portable, but macOS/Linux bundles are not produced.
- The final live protocol-6 smoke used a Founder-approved deterministic offline
  controlled provider. General authenticated Codex/Claude daily execution still
  requires its own supported Authority registration and qualification.
- OS toast delivery is best-effort; every notification is retained in-app.
- Discord remains a future notification-only adapter.
- Keeper does not automatically delete retained logs or evidence.
- The desktop provides structured textual evidence drill-down rather than an embedded
  side-by-side diff renderer.
- Authenticated external command-provider task execution remains unverified. Controlled
  executables exercise the complete production adapter and workflow path without
  external credentials.
- Startup recovery can terminate an exact owned Windows root through its retained
  native handle. It blocks if descendants exist or cannot be enumerated because a
  restarted process cannot safely recover the original job handle.
- The last staged-content revalidation and the Git commit operation are not one
  cross-process atomic transaction. Concurrent repository writers remain outside
  Keeper's trust boundary.
- Rendered Tk automation requires a Python runtime with matching Tcl/Tk libraries.
  The packaged diagnostic reports unavailable with exit 78 when that prerequisite is
  absent.
- Cross-process reroute reservation and storage races are covered directly. A
  dedicated separate-process test driving complete `WorkflowCoordinator.retry()`
  winner launch and loser exception handling remains deferred.
- An interrupted restore that leaves an Executive `ACTIVE` maintenance record
  intentionally blocks supported database access until the Founder runs
  exact-operation, integrity- and generation-checked recovery. An interrupted
  KeeperAuthority fence separately blocks covered project mutations until its bounded
  expiry and explicit operation-bound recovery; neither recovery path completes the
  restore automatically.
- The signed restore fence contains one project-scoped Authority snapshot and is
  bounded by the Authority protocol message limit. Extremely large personal-use
  attempt histories require a future paged signed-snapshot/fence protocol.
- This source requires KeeperAuthority 1.7.52, protocol 7, and schema 6. Application
  packaging never installs, restarts, updates, or reconfigures that service.
- The Codex subscription provider is authoring-only. Independent approval remains
  paused until a separately qualified reviewer provider is available.
- The Codex subscription provider accepts only exact ChatGPT `plus` and `pro`
  runtime plan labels. Every other or missing label fails closed. The observed
  label is bound through the Founder capability, signed replacement lineage,
  Host registration probe, registration, and qualification; no API-key, paid
  fallback, account switch, or provider switch is authorized.
- Codex registration and qualification require a live authenticated desktop
  client to hold the exact reviewed executable open with read-only sharing.
  KeeperAuthority duplicates and validates that handle from the retained client
  process; path-only production requests fail closed.
- Codex setup processes use only the exact per-attempt directory under the
  enrolled per-user `KeeperProviderExchange` root as their current directory.
  The exchange root is outside the protected Host installation and has a closed
  SYSTEM/Administrators/enrolled-user ACL that enrollment and Host startup both
  attest. The protected installation and state tree retain their Restricted
  Code deny and are never made traversable merely to launch a provider.
  Host-side canonical, profile, ACL, alias, emptiness, and replay checks fail
  closed before process creation.
- Provider Host installation and enrollment are mechanically separate. The
  1.7.52 Host is release-locked to KeeperAuthority 1.7.52, protocol 7, and schema 6;
  older or newer Authority releases fail closed before enrollment. Source 1.7.1
  added the Founder-authenticated protocol-7 enrollment proposal/grant/proof/
  receipt/revocation lifecycle and permits an enrolled Host to start without a
  provider binding. Installation before the Authority upgrade remains inert and
  reports `INSTALLED_UNENROLLED`. Lifecycle verification uses disposable roots;
  the live Phase 2 migration must use the canonical per-user install and Startup
  roots plus the supported Authority lifecycle. The currently reviewed Host
  artifact is not Authenticode-signed, so enrollment binds the exact `NotSigned`
  status together with its immutable package manifest, executable SHA-256, file
  identity, canonical path, ACL, and non-exportable Host key; it does not invent a
  signer. A future signed artifact will instead require and bind the exact valid
  publisher certificate. Live installation, Authority migration/restart, Founder
  enrollment, Codex registration/qualification, and model execution remain
  separately authorized operations.
- KeeperAuthority 1.7.52 requires the Host-signed durable launch journal to prove
  zero `CLAIMED`, `STARTED`, `RUNNING`, or `UNCERTAIN` work before registration,
  qualification, or active-enrollment revocation. `READY`/`IDLE` alone is not a
  zero-work proof. The supported reconciliation command is deliberately limited
  to an exact uncertain registration probe with conservative read-only-effect
  accounting; uncertain qualification and provider execution require separate
  Founder disposition and cannot be terminalized by this command.
- Provider Host 1.7.52 resolves and grants the exact KeeperAuthority service SID
  on its protected named pipe so the restricted Windows service token can connect.
  Restricted Code remains explicitly denied, and every connected client must still
  pass the signed protocol and exact Authority process measurement before any Host
  state is touched. After exact signed-installation attestation, the Host grants the
  service SID only process-query-limited access to its process object and query-only
  access to its process token. Authority does not request token duplication. Authority
  grants that same exact service SID only process-query-limited access to its own
  process object; the Host validates the impersonated restricted service thread token
  and never opens the Authority process token.
- Provider Host 1.7.52 authenticates the restricted service token under bounded
  client impersonation, positively reverts, and only then observes the exact
  Authority process through the enrolled-user QLI-only grant. The Authority
  installation remains protected from Host traversal, and the signed hello plus
  enrollment receipt bind the canonical image path, digest, and file identity.
  Provider Host 1.7.52 measures its packaged Windows process image with the
  operating-system process-image API. It does not trust Nuitka's bundled
  `sys.executable`, command-line arguments, or caller-supplied paths when binding
  the running Host to its signed installed executable. During every Authority
  RPC, the restricted service retains the exact pipe-server process and token
  handles and validates the OS-reported path, SID, session, process lifetime,
  and PID. The Host's enrolled key signs a nonce-bound executable digest and
  durable file identity measured under its own user context; Authority requires
  an exact match to the committed enrollment before sending any provider request.
- Provider qualification uses a durable pre-bind `UNCERTAIN` fence and the
  supported exact `reconcile_provider_qualification` operation. This recovery
  surface is intentionally limited to the already validated registration and
  qualification evidence; it cannot substitute a provider, executable,
  account, model, or Host binding.
  Operators invoke it through `keeper-authority
  codex-reconcile-qualification`; diagnostics keep the Host in
  `QUALIFICATION_UNCERTAIN` with a Founder action until recovery completes.
- Keeper 1.7.52 also persists stable Authority registration and qualification
  claims before Host setup work and retains signed terminal setup results in the
  Host journal. This closes the terminal-Host-result/Authority-crash duplicate
  window, including duplicate Medium-effort qualification requests. A crash
  before the Host can persist a terminal result remains deliberately
  fail-closed as visible Host launch uncertainty. Registration-probe ambiguity
  may use the bounded read-only reconciliation contract; qualification or
  provider-execution ambiguity is never automatically replayed and requires
  Founder disposition.
- A terminal `QUALIFICATION_FAILED` record is not silently replayable. Keeper
  1.7.52 permits one explicit Founder-authorized retry bound to the exact failed
  qualification digest, registration, client identity, and matching
  Authority/Host release. The failed record is retained, the retry identity is
  deterministic and atomically reserved, and failure of that retry is terminal.
  This path authorizes one additional subscription request; it is never an
  automatic retry or an API-key/paid-fallback authorization.
- Keeper 1.0 is a personal-use, single-Founder product. It does not claim to
  resist arbitrary code already executing in its trusted Executive interpreter,
  a malicious local administrator, manual same-user database replacement, or
  unsupported in-process plugins. Those are future service-isolation hardening
  scenarios, not supported-path release claims.
- Keeper 1.7.52 can terminalize a Host-signed failed registration probe without
  replaying it. The signed failure exposes only bounded stage/code and
  digest/byte-count process evidence. Legacy 1.7.39 failures remain
  recoverable but correctly report `DETAIL_UNAVAILABLE`. Founder disposition
  permits abandon or one exact new probe generation; there is no automatic or
  repeated retry.
- After that exact generation-2 retry fails with signed zero-effect accounting,
  KeeperAuthority 1.7.52 permits one separate Founder-authorized successor
  registration family. The predecessor remains permanently
  `REGISTRATION_EXHAUSTED`; one deterministic successor carries signed
  predecessor/failure/request/capability lineage plus an exact sanitized
  account-identity digest and exact Plus/Pro plan from a separately authorized
  read-only discovery. The successor rejects a different account or plan before
  registration persistence.
  Lost responses and restarts
  recover that same successor, while mismatches, concurrent alternate
  capabilities, and attempts to create another successor family fail closed.
- A signed replacement authorization remains bound to the exact release that
  created it until its first Host attempt starts. After activation, that release
  is retained as historical signed lineage rather than compared to every later
  service version. This permits a later matching Authority/Host release to
  recover, disposition, retry, persist, and qualify the already-attempted
  successor without rewriting evidence. Unactivated replacements cannot cross
  a release boundary, and all account/executable/client/failure bindings remain
  mandatory.
- Keeper 1.7.52 has one deliberately non-general recovery operation for the
  exact 1.7.47 Claude pre-dispatch defect. It is release-, artifact-, provider-,
  enrollment-, client-, request-, setup-, challenge-, process-termination-, and
  zero-effect-bound. The historical Host proposal and Authority grant and
  receipt must retain valid purpose-bound signatures and exact cross-envelope
  identity, runtime, enrollment, generation, and digest bindings. It atomically
  leaves a dormant generation-2 retry and a
  revoked generation-27 Host enrollment. It cannot migrate another provider,
  another release, an online Host, active/uncertain Host work, or a claim that
  already reached the Host. Remove this compatibility surface only in a later
  reviewed release after the historical evidence must no longer be recoverable.
  Its preserved offline-process evidence may outlive the generic freshness
  window only at one exact release-pinned canonical digest; no other stale
  termination evidence is accepted.
