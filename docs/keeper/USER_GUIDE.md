# Keeper User Guide

Keeper opens as a local executive control center. Its header identifies the current page, environment, active project, and read-only health state. The left navigation exposes 13 source-backed areas; the right Keeper Assistant rail records durable project conversation. Keeper, not Sage, is the product and head AI.

## First run

The seven-step setup wizard explains the safety boundary, validates an evidence directory with an exclusive random write probe, optionally records a protected Git repository, stores local routing preferences, reports provider qualification truthfully, checks KeeperAuthority through its read-only health boundary, and shows a final review. Setup never registers a provider, changes a service, handles credentials, enables paid fallback, deploys, or trades.

## From conversation to approved work

1. Describe the desired outcome and boundaries in Keeper Assistant.
2. Keeper records durable intake, creates a project, and drafts a proposed charter. Conversation is not approval.
3. Open **Projects** and review the exact current charter, constraints, exclusions, providers, workspaces, evidence, and delegation envelope.
4. Choose **Authenticate & Approve** only when the displayed revision is correct. Keeper invokes the existing native Windows Founder-authentication path and never reads or stores the password.
5. After one valid approval, Keeper atomically plans the charter-derived workflow and may advance routine work inside the durable delegation envelope.

Cancellation, rejection, unavailable authentication, stale charter state, exhausted usage, revoked delegation, missing independent capacity, protected-workspace conflict, or uncertainty fails closed and appears as durable state.

## Daily product areas

- **Overview:** current project, workflow/approval/provider counts, integrity state, and recent durable activity.
- **Projects:** project catalog, current proposed or approved charter, and exact Founder approval.
- **Repositories:** registered protected originals and source status.
- **Workflows:** charter-derived work items and the bounded delegated-completion control.
- **Tasks:** legacy and workflow tasks with source-backed status.
- **Findings:** durable audit and verification findings.
- **Authorizations:** existing grants, use, expiry, and revocation. New authority is created only through supported Founder/charter flows.
- **Evidence:** validated bundles and typed evidence-reference cards; protected local paths stay hidden.
- **Reviews:** independent reviewer assignment, evidence, and disposition bindings.
- **Reports:** finalized run reports backed by protected evidence.
- **Providers:** qualified provider/session truth and shared usage pools. Registration is intentionally unavailable in this UI phase.
- **Recovery:** interrupted and `UNCERTAIN` state. Unsafe automatic retry is unavailable.
- **Settings:** presentation, local paths, provider executable paths, and allowlisted read-only KeeperAuthority health.

The top search filters source-backed rows locally. Developer details reveal durable IDs but continue to redact protected evidence and Authority paths. The Assistant rail collapses automatically on smaller windows.

## Launch and lifecycle

Development launch:

```powershell
powershell -File scripts/keeper-desktop.ps1
```

Standalone install and lifecycle commands are in [`DESKTOP_INSTALLATION.md`](DESKTOP_INSTALLATION.md). Application files default to `%LOCALAPPDATA%\Programs\Keeper`; user state defaults to `%LOCALAPPDATA%\Keeper` and survives uninstall.
