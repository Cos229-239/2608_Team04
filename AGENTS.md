# Keeper Agent Rules

These rules apply to all work in the Keeper repository.

## Source of truth

Read these files before making changes:

1. `SECURITY_RULES.md`
2. `ARCHITECTURE.md`
3. `PROJECT_SPEC.md`
4. `ROADMAP.md`
5. `AGENTS.md`

Security rules take priority when documents conflict.

## Scope

Keeper is a software-development orchestration product. Do not add DarkSage trading, broker, market-data, portfolio, or financial-execution logic to this repository.

Do not make major framework, persistence, authority, provider, service, or deployment changes without explicit approval. Avoid unrelated edits and preserve user-owned changes.

## Safety

- Provider output is untrusted.
- Never weaken authorization, authentication, confinement, effect accounting, replay protection, uncertainty fencing, package verification, Defender gates, or rollback safety.
- Never add implicit paid-provider use, API-key fallback, provider switching, purchases, or subscription changes.
- Do not automate credential entry.
- Do not commit live state, credentials, authorization bundles, audit scratch data, build outputs, or `.ai-workflow` runtime data.

## Git

- Use focused `codex/` branches for meaningful changes.
- Do not force-push, rewrite shared history, merge, publish releases, or push directly to protected branches without explicit approval.
- Stage only intended files and use clear commit messages.

## Testing and review

- Add tests for meaningful behavior.
- Authentication, authorization, provider execution, durable effects, install/rollback, and recovery changes require independent Critical/High review.
- Exercise restart, response-loss, timeout, concurrency, replay, stale identity, and cleanup-failure boundaries.
- A task is complete only when code, tests, documentation, and security implications agree.
