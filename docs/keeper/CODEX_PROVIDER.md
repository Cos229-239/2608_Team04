# Codex subscription provider and Keeper Provider Host

Keeper 1.0 supports the official standalone Windows Codex CLI as an
authoring-only provider through KeeperAuthority 1.7.50, Authority protocol 7,
schema 6, and the per-user `keeper-provider-host/1` protocol. The Provider Host
is an unelevated execution deputy. It cannot register, qualify, reserve, approve,
spend, change policy, or fabricate Authority state.

The Host status response includes a Host-signed durable launch-journal summary.
KeeperAuthority treats `CLAIMED`, `STARTED`, `RUNNING`, and `UNCERTAIN` rows as
unresolved work, reports their exact sanitized identities and counts through
supported diagnostics, and rejects registration, qualification, or enrollment
revocation unless the signed unresolved count is exactly zero. Authority-local
serialization prevents a concurrent request from starting Host work between that
zero-work observation and a revocation transition.

The only supported Host-launch reconciliation is a Founder-authenticated,
generation-bound terminalization of an exact uncertain registration probe. It
records conservative read-only process and usage-observation accounting, is
durably idempotent after a lost response, and cannot reconcile qualification or
provider-execution work. Unknown, mismatched provider work and any cleanup whose
termination cannot be positively verified remain fail-closed.

The supported contract uses the Founder's existing ChatGPT subscription
authentication. OpenAI API keys, API billing, paid fallback, credit purchase,
automatic account switching, automatic provider switching, Low effort, and
self-review are prohibited.

Restricted Codex launches use a deterministic PEM export of the current Windows
server-auth root store after excluding every exact certificate in the Windows
Disallowed store; an unavailable or non-X.509 distrust record fails closed. The
Host ignores caller-provided certificate-bundle
environment variables, creates the bundle beneath the already-attested provider
exchange root, binds its exact path, SHA-256, size, and file identity into the
signed environment envelope, and holds it read-only without write/delete sharing
for the complete process launch. This preserves normal Windows trust policy and
TLS verification while making that policy available inside the restricted token.

The runtime account-plan allowlist is exactly ChatGPT Plus or ChatGPT Pro.
The observed plan is preserved in the account binding and must remain exact
through the Founder replacement capability, signed predecessor/successor
lineage, Host registration probe, registration persistence, and qualification.
Free, Team, Business, Enterprise, missing, and unknown labels fail closed. The
pricing declaration retains the Plus entitlement class for the existing
exhausted-registration request family; accepting Pro changes no API-billing,
fallback, account-switch, or cost authority.

Registration and qualification transfer a client-opened, read-only locked file
handle for the exact reviewed Codex executable. KeeperAuthority duplicates that
kernel object only from the retained authenticated named-pipe client process.
Because a `SERVICE_SID_TYPE_RESTRICTED` token cannot satisfy the required
two-pass process-object access check through a service-SID grant alone, one
disposable worker uses the already authenticated client-process token solely to
open that exact process for query and handle duplication. It reverts and proves
clean before publishing the handle to Authority code. Authority then revalidates
the exact PID, SID, session, process lifetime, canonical path, file identity,
SHA-256, size, and Authenticode signer before any durable provider effect. The
restricted service never traverses the Founder profile by pathname, and
restricted provider identities retain an explicit process-access deny.

The suspended-launch STARTED acknowledgement is signed and binds the exact
Authority identity, attempt, launch, and Host event digest. The Host validates
that closed schema and durably claims its nonce and sequence before resuming a
provider process; missing, mismatched, extra, stale, or replayed acknowledgements
fail closed while the process remains suspended.

## Production boundary

The production path is:

1. KeeperAuthority authenticates the local Executive client and owns provider
   registration, qualification, usage, session, workspace, and launch policy.
2. KeeperAuthority and the logged-on Provider Host mutually authenticate over a
   local-only named pipe using separate asymmetric identities and exact Windows
   peer identity checks. Authority retains the exact Host process/token handles,
   and the enrolled Host key signs a nonce-bound executable digest and durable
   file identity that must match the committed installation before any request.
3. KeeperAuthority signs one expiring, sequenced request bound to the complete
   project, charter revision, workflow, WorkItem, assignment, attempt,
   registration, qualification, executable, provider, model, effort, command,
   workspace, environment, network, usage, and cancellation declaration.
4. The host transactionally claims the sequence, nonce, launch, and canonical
   workspace before external execution. Replays and overlapping workspaces fail.
5. The host builds an allowlisted environment from its already-running user
   process. It never asks the service to reconstruct or export a user profile.
6. Registration and qualification use an exact SHA-derived directory beneath
   the enrolled per-user `KeeperProviderExchange` root as their current
   directory. That root is outside the protected Host installation, has a
   closed SYSTEM/Administrators/enrolled-user ACL, and is re-attested by the
   enrollment client and Host. The protected Host installation and state tree
   keep their explicit Restricted Code deny and are never used as a provider
   CWD; the Host rejects aliases, path substitutions, replays, and nonempty
   setup directories before launch.
7. The host locks and remeasures the executable, derives a restricted
   Medium-integrity token, creates the process suspended, persists `STARTED`,
   assigns the complete tree to a kill-on-close Job Object, and only then resumes.
8. The public account/model probe uses parent-owned anonymous pipes. The Host
   sends one bounded JSONL request and waits for its exact response identity
   before sending the next request. Only the child pipe ends are inherited;
   malformed, missing, duplicate, reordered, oversized, timed-out, or
   cleanup-uncertain exchanges terminate the Job and fail before registration.
9. The host signs a bounded completion receipt. KeeperAuthority verifies the
   exact envelope and provider-input digests before accepting completion.

`execute_provider(attempt_id)` remains ID-only. Provider input is immutable,
server-owned Authority state and cannot be replaced at execution time.

## Identity, transport, and replay

The pipe rejects remote clients and has an explicit DACL that denies the
Restricted Code SID carried by every supported provider token before allowing
SYSTEM and the exact interactive user. The Host uses a dedicated measured
`KeeperProviderHost.exe`; a shared Python interpreter or zipapp cannot satisfy
the Authority peer-executable binding. The Host's non-exportable per-user CNG
key and versioned installation tree use the same Restricted Code exclusion, so
a compromised supported provider cannot sign as, replace, or connect as the
Host merely because it retains the Founder's user-profile SID.
Both peers validate SID, session, executable path, SHA-256, process identity,
and key identity. Every signed message carries a nonce, monotonic sequence,
issue time, expiry, maximum TTL, and exact body digest. Future-issued, expired,
replayed, reordered, mismatched, test-composition, or identity-invalid messages
fail closed.

Host lifecycle state is durable and visible as `STARTING`, `READY`, `PREPARING`,
`CLAIMED`, `STARTED`, `RUNNING`, terminal, or `UNCERTAIN`, plus `LOCKED`,
`DRAINING`, `STOPPED`, and `STALE`. New work rejects outside the ready path.
Lock cancels active work; logoff cancels and stops. Restart converts unresolved
external-effect states to `UNCERTAIN`; non-idempotent work is never retried
automatically.

## Credentials and environment

Credentials never cross the service/host protocol. The host uses only the
official CLI's existing per-user ChatGPT session and exposes only a one-way
account identity digest plus public plan/model/usage observations.

The environment allowlist excludes API keys, access tokens, cookies, proxy
settings and credentials, paid-fallback controls, and mutable provider/model
overrides. Values are not logged. The Authority records only safe names,
classifications, and digests. Provider output remains untrusted structured data;
provider-generated code is never imported, evaluated, or executed inside the
trusted Executive process.

## Codex provider declaration

Registration pins the canonical executable path, SHA-256, size, file identity,
valid OpenAI Authenticode publisher/certificate, CLI version, one model,
Medium/High efforts, exact Windows SID/session/profile, ChatGPT subscription
account digest, capability observation, pricing authority, and conservative
usage policy. Qualification and every launch revalidate those values.

The Authority-owned invocation uses no command shell and fixes model, effort,
workspace, prompt, schema, output paths, timeout, and sandbox policy. Mutable
user configuration cannot widen it. A single Codex identity is authoring-only;
independent review waits for a separately qualified reviewer.

## Usage semantics

`INCLUDED_SUBSCRIPTION` is not `FREE`: it means zero authorized incremental API
charge under the existing subscription and bounded observed capacity. Unknown
capacity uses a conservative durable launch budget. Exhaustion becomes
`WAITING_FOR_USAGE_RESET`; no automatic retry, purchase, fallback, provider
switch, or account switch occurs. A durable wait clears only with a fresh
validated provider observation allowed by the existing reset policy.

## Per-user lifecycle

Provider Host artifacts are versioned beneath the canonical per-user
`%LOCALAPPDATA%\Programs\DarkSage\KeeperProviderHost` root. The lifecycle
accepts the dedicated `KeeperProviderHost.exe` only as part
of its complete standalone distribution. A SHA-256-bound package manifest names
every runtime file, size, and digest; missing, additional, changed, linked, or
escaping files fail closed. Installation copies and revalidates the entire
distribution, while the executable retains its separate Authority identity.
Current selection is atomic and retains one verified rollback generation.
Install, same-version repair, drain-before-update, rollback, crash recovery, and
data-preserving uninstall are supported by `keeper provider-host`. The at-logon
launcher stores no password and quotes every trusted path. Both its file and
containing Startup namespace deny the restricted provider token, preventing
delete-and-replace attacks through parent-directory rights.

If Defender has quarantined only the executable of the exact selected Host,
normal lifecycle commands remain fail closed. The separate
`replace-quarantined-selection` command requires the caller to bind the complete
durable `current.json` SHA-256, the absent selected executable recorded by that
exact selection, the byte-exact remaining selected package and launcher, one
named Defender-clean retained rollback version plus executable/package hashes,
and a different exact Defender-clean replacement package. It performs no drain
or lifecycle mutation until every identity and protected-tree check passes.

An installed Host with no signed enrollment receipt exits successfully in
`INSTALLED_UNENROLLED` bootstrap-only state. It does not open the runtime pipe,
accept requests, register or qualify providers, reserve usage, or execute a
model. A Founder-authenticated protocol-7 enrollment uses an exact Host-signed
proposal, one short-lived Authority-signed grant, one Host proof, and one
Authority-signed receipt. The proposal binds the service key, protocol/schema,
user SID/session/profile, canonical install and Startup selection, manifest,
executable path/hash/file identity, exact Authenticode status and signer identity
when present, non-exportable Host public key, pipe, nonce, expiry, and generation.
KeeperAuthority independently remeasures those values under the authenticated
named-pipe client before it persists a one-winner `PENDING` record.

Completion stores `ACTIVE` before the gateway is exposed. Lost responses use
exact, idempotent reconciliation; conflicts, expiry, replay, downgrade, and
ambiguous activation fail closed. Revocation first persists a durable
`UNCERTAIN` execution fence, disables the live gateway, and then persists
`REVOKED`; a lost response can retrieve the same signed denial after a fresh,
exact Founder authentication. A revocation-fenced `UNCERTAIN` record cannot be
reactivated by enrollment reconciliation after restart. Host enrollment never
creates a provider binding. Registration and qualification remain later
Authority-owned operations, and the Host reports `NO_QUALIFIED_PROVIDERS` until
exact qualification is durably bound.

Subscription registration first persists one deterministic
`REGISTRATION_STARTED` identity and challenge before the Host account probe.
The Host atomically retains the complete signed terminal probe result. A crash
after that terminal result but before Authority publication therefore resumes
the same probe identity and returns the retained result; it cannot launch a
second probe. Diagnostics expose the pending registration identity and block
unrelated provider work or Host revocation until it finishes.

Qualification begins against an enrolled, ready Host with no provider binding.
KeeperAuthority first atomically persists one deterministic qualification ID,
challenge, and `QUALIFICATION_STARTED` fence before any Host/model launch. The
Host atomically retains the complete signed terminal qualification result. A
crash after the single Medium subscription request but before Authority staging
resumes the same qualification and consumes that retained result, so it cannot
issue a second model request. KeeperAuthority then durably stages the qualified
observation as `UNCERTAIN` before requesting the exact Host binding, and
publishes registration and qualification as `QUALIFIED` atomically only after
the Host acknowledges the same binding. If the Host commits the binding but its response is lost,
`reconcile_provider_qualification(registration_id)` re-sends only the stored
Authority-owned binding and atomically completes the same records. It accepts no
replacement provider input and remains one-winner and idempotent.

An exact terminal response may be returned idempotently after the caller loses
the public registration or qualification response. If a Host crash leaves the
launch itself `UNCERTAIN` before a terminal signed result exists, diagnostics
report that uncertainty instead of advertising a resumable terminal result;
qualification cannot be automatically replayed.

An Authority-terminalized `QUALIFICATION_FAILED` result is also never retried by
the ordinary qualification endpoint. Keeper 1.7.50 adds one separate
Founder-authorized retry generation for the exact failed registration,
qualification evidence digest, client SID, and matching Authority/Host release.
The authorization is durably consumed before launch, the original failed
qualification remains permanent evidence, and only the dedicated retry
operation can activate it. Lost responses return the same retry result; a
failed retry cannot authorize another retry.

The supported shipped recovery command is:

```powershell
keeper-authority codex-reconcile-qualification `
  --registration-id <persisted-registration-id> `
  --output-directory <new-empty-response-directory> `
  --apply
```

The command exclusively claims its response directory, performs exactly one
reconciliation request, and persists the complete public Authority response
before extracting identifiers. Authority diagnostics report
`QUALIFICATION_UNCERTAIN` and `RECONCILE_PROVIDER_QUALIFICATION` until the exact
durable pair is reconciled. Re-running against an already claimed response
directory or an already reconciled registration fails closed.

The installed Host executable owns the supported production enrollment surface;
no protected configuration file is edited by hand. After the matching protocol-7
Authority update is healthy, the Founder runs:

```powershell
KeeperProviderHost.exe enrollment-status
KeeperProviderHost.exe enroll --generation 1
```

`enroll` displays the normal Windows Founder credential dialog and then performs
the proposal/grant/proof/receipt exchange through the authenticated Authority
pipe. Interrupted flows resume only through `resume-enrollment` or
`reconcile-enrollment`. Revocation requires the exact enrollment ID, receipt
digest, and next generation through `revoke-enrollment`; arbitrary receipt or
configuration input is not accepted.

All source verification uses disposable `C:\tmp` roots. Real installation,
Startup creation, Authority update/restart, Founder enrollment, Codex
registration/qualification, and any model execution remain distinct live
operations requiring their applicable Founder authorization. Disposable CLI
roots and no-op drain callbacks are test composition only; the Phase 2 runbook
uses the canonical roots and supported Authority lifecycle.

## Desktop truth

The Providers and Safety views project only read-only, redacted service state:
host installed/online state, lifecycle state, protocol compatibility, provider
registered/qualified state, execution/usage state, and any explicit Founder
action. Raw executable paths, account identities, credentials, and host keys are
not displayed. UI state grants no Authority effect.

Registration-probe failures are durable lifecycle outcomes. KeeperAuthority
records the exact Host-signed result digest and only bounded stage/code plus
output byte counts and SHA-256 digests; raw probe output, exception text,
credentials, and paths are not placed in Authority diagnostics. A legacy
terminal result without this bounded process detail is reported as
`DETAIL_UNAVAILABLE` rather than reconstructed.

`REGISTRATION_FAILED` blocks new provider work, Host revocation, and
qualification until a fresh Founder capability chooses one of two closed
dispositions: preserve-and-abandon, or one exact retry. The retry keeps the
stable registration identity, increments the attempt generation, and uses a
new deterministic setup identity. The authorization is first persisted as
`REGISTRATION_RETRY_AUTHORIZED`, which is a dormant, zero-effect state rather
than an active Host launch claim. This permits the exact version-bound Host
enrollment to be replaced before the matching registration request atomically
activates `REGISTRATION_STARTED`. The disposition is idempotent across response
loss and cannot be authorized a second time.

The signed successor lineage records the exact Authority/Host release that
created the replacement authorization. That release remains mandatory until
the successor attempt is activated. Once an exact attempt has started, the
lineage release becomes immutable historical evidence: a later matching
Authority/Host release may recover its terminal result, apply its one Founder-
authorized retry disposition, persist the recovered registration, and qualify
it without rewriting the original signature. Account, executable, client,
predecessor, failure, and capability bindings remain exact throughout.

If that one retry also reaches the exact terminal, zero-effect
`REGISTRATION_FAILED` state, KeeperAuthority 1.7.50 permits one distinct
Founder-authorized `NEW_REGISTRATION_AFTER_EXHAUSTION` transition. The
capability is bound to the generation-2 failure digest, unchanged Codex
executable/client request identity, an exact sanitized account-identity digest
obtained by a separately authorized read-only account discovery, exact
Authority and Host release,
and signed proof of zero registration, qualification, provider-binding, model,
or usage effects. One transaction permanently seals the predecessor as
`REGISTRATION_EXHAUSTED` and creates one deterministic successor in
`REGISTRATION_REPLACEMENT_AUTHORIZED`. The signed successor lineage binds the
predecessor, terminal failure, request identity, Founder authorization, and
successor identity. The successor Host probe uses that digest as an exact
account binding rather than `DISCOVER`, and any account switch fails before a
registration can persist. Response loss and restart recover that same successor;
concurrent or mismatched capabilities, replay with a different capability, and
another successor after the new family exhausts all fail closed.

The discovery command is `keeper-authority codex-discover-account-identity`.
It verifies the exact reviewed Codex path, SHA-256, size, version, and
Authenticode identity, sends only app-server `initialize`, `initialized`, and
`account/read`, and persists only the one-way account digest, plan, executable
measurement, bounded stream hashes, and explicit zero model/qualification/
registration/usage effects. It never persists the account email or raw probe
output and requires a separate exact-hash live authorization before `--apply`.
