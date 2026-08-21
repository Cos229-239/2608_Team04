# Keeper

Keeper is a local-first executive control center for fail-closed software-development workflows. The desktop presents durable projects, charters, repositories, workflows, tasks, findings, authorizations, evidence, reviews, reports, providers, recovery state, and settings without becoming an authority boundary.

The product desktop is a PySide6/Qt Quick application with a black, charcoal, metallic-gold, gray, and white visual system. The Founder-provided lighthouse/helmet asset is the canonical application mark. The 13 product areas are **Overview**, **Projects**, **Repositories**, **Workflows**, **Tasks**, **Findings**, **Authorizations**, **Evidence**, **Reviews**, **Reports**, **Providers**, **Recovery**, and **Settings**. Keeper Assistant is the durable conversation surface; it records Founder intent and charter clarification rather than inventing chatbot state.

QML renders primitive redacted snapshots and sends user intent to `KeeperDesktopController`. Existing application, Executive, Pass B, and KeeperAuthority services remain authoritative. Unsupported provider registration, new authority creation, paid fallback, deployment, publication, destructive operations, force push, and live trading are absent or visibly disabled.

Launch development mode with:

```powershell
powershell -File scripts/keeper-desktop.ps1
```

Build and install the standalone local desktop using [`DESKTOP_INSTALLATION.md`](DESKTOP_INSTALLATION.md). The deterministic mock workflow remains available for offline diagnostics and demonstrations and is always labeled as non-production.

Keeper 1.0 release audits use the controlled personal-use boundary in [`THREAT_MODEL.md`](THREAT_MODEL.md). Provider output remains untrusted and is never loaded as code into the trusted Executive interpreter.
