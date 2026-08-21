# Keeper Security Rules

## Priority

Security, explicit Founder authority, effect accounting, and durable recovery take precedence over convenience and availability.

## Provider execution

- Provider output is untrusted data and must never be imported or executed by the trusted interpreter.
- Executables are bound by canonical path, file identity, size, SHA-256, signer requirements, client PID/SID/session/process lifetime, and enrolled Host identity.
- Restricted tokens, sanitized environments, Job containment, handle ownership, and cleanup must fail closed.
- No API key, credential, or raw authentication material may be logged or committed.
- No API billing, paid fallback, provider switching, or additional model request may occur without explicit authority.

## Durable effects

- Every operation that may create an external effect requires a stable durable claim before the effect.
- Restart, timeout, response loss, and concurrency must not duplicate registration, qualification, model, provider, usage, Git, or publication effects.
- `UNCERTAIN` and unresolved claims remain signed, visible, and blocking until supported reconciliation or exact Founder disposition.
- Diagnostics must not report READY/IDLE while hiding unresolved durable effects.

## Windows service and package security

- KeeperAuthority remains least-privilege and service-confined.
- Provider Host enrollment is generation-bound and mutually authenticated.
- Installed packages require exact manifests, provenance, protected ACLs, version/schema/protocol compatibility, and Defender verification.
- Do not disable or weaken Defender, firewall, filesystem ACLs, service isolation, credential protection, or signature checks to make a release pass.
- Rollback and recovery must verify the exact artifact being activated.

## Repository safety

- Never commit credentials, live evidence, `.ai-workflow` runtime state, local databases, build output, or machine-specific authorization bundles.
- Preserve unrelated user changes.
- Require independent review for authentication, authorization, provider execution, durable effect accounting, credential handling, install/rollback, and recovery changes.
