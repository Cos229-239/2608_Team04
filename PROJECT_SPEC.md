# Keeper Project Specification

## Purpose

Keeper is a local software-development orchestration product. It records Founder intent, creates isolated workspaces, delegates bounded work to approved AI providers, verifies results, requires independent review for security-sensitive changes, and preserves durable evidence for recovery.

## Product boundaries

Keeper:

- manages local Git repositories without becoming their product runtime;
- treats provider output as untrusted data;
- requires explicit provider registration and qualification;
- keeps authorization, provider execution, and durable state fail closed;
- does not merge, publish, deploy, purchase, or perform destructive actions without the applicable explicit authority;
- does not contain trading, broker, market-data, or financial execution logic.

## Core workflow

```text
BACKLOG -> READY -> BUILDING -> SELF_VERIFYING -> INDEPENDENT_AUDIT
        -> REPAIRING -> FINAL_VERIFY -> APPROVED -> COMPLETED
```

Exceptional states such as `BLOCKED`, `FAILED`, `PAUSED`, `CANCELLED`, and `RECOVERY_REQUIRED` are durable and visible.

## Provider principles

- Local and free providers are preferred.
- Cloud/subscription providers are opt-in.
- API keys and credentials are never bundled.
- Paid fallback and provider switching are never implicit.
- A provider operation is uniquely identified, durably claimed, and recoverable across restart or lost response.
- A prelaunch reservation synchronously rejected before Authority persistence can be reconciled only by an immediate authenticated exact-absence observation in that operation; every response-loss or restart uncertainty remains fenced.
- A stale uncertain external execution can be locally abandoned only after a signed KeeperAuthority/Provider Host exact-attempt inactivity observation and an exact one-time Founder disposition. The approval binds every released workspace and write claim, preserves possible-effect accounting, consumes reserved usage, accepts no result, grants no retry, and remains globally visible until resolved.
- External effects must be bounded, observable, and accounted before subsequent work is allowed.

## Supported environment

Keeper Desktop, KeeperAuthority, and Keeper Provider Host currently target Windows. Core orchestration and deterministic tests should remain portable where platform security APIs are not required.
