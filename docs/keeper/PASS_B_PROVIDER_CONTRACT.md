# Pass B Provider Contract

Providers, accounts, and sessions have separate durable identities. Display
names are never keys.

An adapter descriptor declares:

- provider and model identity;
- capabilities;
- local or remote classification;
- session model and usage-pool identity;
- concurrency limit and cost mode;
- authentication readiness;
- tool and workspace support;
- cancellation and resume support;
- evidence format;
- health state.

Reattachment is exact for durable model, capability, tool, workspace,
usage-pool, cost, health, cancellation, and resume declarations. An adapter
with a widened declaration is rejected rather than silently expanding a
persisted provider.

An assignment request contains only the bounded project, charter revision,
assignment, attempt, role, model, workspace, authority attempt, global context,
task context, and expected-evidence data required by the provider.

Adapters do not make authority decisions. Production provider execution is
performed by KeeperAuthority against the qualified durable registration.
Explicit unit-test composition may launch the deterministic mock adapter
directly. Results are structured untrusted
data containing an external execution identity, summary, artifact descriptors,
usage, and an optional opaque resume-token digest. Keeper validates identity,
required evidence kinds, artifact paths, digests, and the prohibition on
trusted-process execution before evidence can become `VALIDATED`.

Session capacity is claimed transactionally with the Pass B attempt before any
provider call. Completion or confirmed cancellation releases it; ambiguous
post-claim outcomes retain the slot until explicit reconciliation.

Artifact dictionaries that request evaluation, execution, module import,
library loading, trusted plug-in loading, or any execution request are rejected.
Provider text and files are never imported or evaluated by Pass B.

## Implemented adapters

- Local deterministic adapter for tests, diagnostics, and isolated pilots.
- Codex-style resumable session adapter with an injected transport.
- Generic remote adapter with an injected structured-data transport.

These adapters define production-ready boundaries; provider-specific
authentication and transport automation remains explicit configuration work.

## Selection constraints

Provider substitution is denied unless the charter allows it. Candidates must
match approved provider identity, role capabilities, health, authentication,
privacy class, session concurrency, cost policy, and reviewer independence
exclusions.

Paid sessions are never selected without an explicit allowed-paid policy. Pass
B never buys credits and never changes account or provider when that would
silently change cost or privacy.
