# Keeper

Keeper is a local software-development orchestration product for safely managing repo work, bounded AI-provider execution, verification, and durable evidence.

## What it does

- tracks founder intent and task state
- manages local Git projects and execution boundaries
- runs the Keeper desktop and provider-host flow
- enforces authorization, verification, and evidence before external effects
- packages and validates a release-ready `.pyz` build

## Main areas

- `keeper/` — core runtime, app service, desktop, executive flow, provider host, UI
- `scripts/` — build and smoke-test scripts for packaging and validation
- `tests/` — deterministic project and security-focused checks
- `docs/` — architecture, recovery, security, and install guidance

## Quick commands

```bash
python -m keeper.desktop --diagnostics
python -m keeper.desktop --mock-demo
pwsh ./scripts/test-keeper-package.ps1
```

## Notes

This repo is oriented around a secure local workflow and intentionally avoids trading, brokerage, or deployment-only logic outside the Keeper product boundary.
