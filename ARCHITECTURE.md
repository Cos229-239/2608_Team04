# Keeper Architecture

## Trust boundaries

1. **Founder/UI boundary** — captures intent and explicit authorization; the desktop is not itself an authority.
2. **Executive boundary** — owns projects, charters, workflow transitions, workspaces, findings, evidence, and recovery.
3. **KeeperAuthority boundary** — Windows service that owns provider identities, registrations, qualifications, durable claims, effect accounting, and signed state.
4. **Provider Host boundary** — per-user restricted process that performs only the exact enrolled provider operation.
5. **Provider boundary** — external/local AI executable whose output is untrusted until validated and bound to the initiating operation.

## Major modules

- `keeper/app/` — product service composition and durable application lifecycle.
- `keeper/executive/` — Founder authority, charters, plans, runtime, and specialist roles.
- `keeper/authority_service/` — protected service, IPC, provider state, registration, qualification, and recovery.
- `keeper/provider_host/` — enrollment, restricted process creation, protocol, replay protection, and install lifecycle.
- `keeper/providers/` — provider adapters and routing.
- `keeper/ui_qml/` — product desktop presentation and controller.
- `keeper/pass_b/` — completion workflow and compatibility surfaces retained from productization.
- `tests/keeper/` — unit, integration, Windows security, restart, fault-injection, and release-regression coverage.

## Invariants

- Request threads do not retain impersonation tokens.
- Provider processes run with restricted tokens, sanitized environments, Job containment, and exact executable identity checks.
- Registration/qualification persistence occurs only after exact identity and signed-result validation.
- Uncertain or pending external effects block conflicting work until supported reconciliation or Founder disposition.
- Founder disposition of an uncertain external execution is a separate high-risk, one-time authenticated action. A locked Provider Host recovery barrier rejects live workers and advances a durable generation before KeeperAuthority signs the initial exact-attempt inactivity observation. The Founder approval binds that proof, the original execution charter, the current approval charter, and every workspace/write claim released. At finalization KeeperAuthority validates the Executive database/recovery identity, records a same-identity barrier proof at an equal or newer generation, durably terminalizes the exact attempt, and returns a signed disposition before local claims can be released. It preserves possible-effect accounting, consumes reserved usage, accepts no result, authorizes no retry, and is projected globally rather than through only the selected project.
- Authenticated absence reconciliation is limited to synchronous reservation rejection in the same live operation, with no external execution identity; it records the Authority identity and observation digest before releasing local reservations.
- Retried operations reuse stable identities and cannot duplicate model/provider effects.
- Package provenance, ACL, Defender, version, schema, and protocol checks fail closed.

## Compatibility namespace

Keeper 1.7.50 uses historical Windows paths and CNG identifiers containing `DarkSage`. They are compatibility identifiers only. A future namespace migration must preserve installed state, keys, enrollment, rollback, and recovery through an explicitly reviewed release.
