# Team 04 - Keeper

Keeper is the project being developed by Team 04 for the class project.

## Team Members

- Dane Dabney

## Current Plan

- Maintain the Keeper project in the shared team repository.
- Use `dev` as the shared development branch.
- Use personal branches for individual development and testing.
- Continue developing, testing, and documenting Keeper.

## Prototype Pages

- `index.html` - roster editor prototype landing page
- `roster-v2-sample.json` - sample editable roster shape for future class setup work
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
