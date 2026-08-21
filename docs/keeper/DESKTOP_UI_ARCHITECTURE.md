# Keeper Desktop UI Architecture

## Boundary

The desktop is a client. QML renders primitive immutable snapshots and emits
user intent. `KeeperDesktopController` validates each intent, calls the existing
Python application services, and publishes a new redacted snapshot. QML never
imports database, Executive, provider, or KeeperAuthority objects.

```text
Qt Quick/QML
  -> validated controller slots
  -> KeeperApplication / PassBApplication
  -> Executive and orchestration services
  -> KeeperAuthority (authority truth)
```

## Technology decision

- PySide6 6.10.1, pinned because it supports the repository's Python 3.14 runtime and supplies Qt Quick, QML tooling, accessibility, scaling, and deployment tooling.
- Qt Quick Controls with repository-owned QML components and no network-loaded assets.
- The official Founder-supplied 1254 x 1254 lighthouse/helmet PNG is the only source for application branding and Windows icon generation.
- Existing Tkinter modules remain temporarily for compatibility tests and headless legacy entry points, but the product entry point launches Qt.

## State and threading

- All domain calls execute in Python.
- Read-only refreshes are serialized and publish complete snapshots.
- Delegated completion runs through one bounded worker and reports busy, error, blocked, and completion states; short reads and validated settings calls remain serialized on the UI boundary.
- Project selection is persisted by `PassBApplication`; visual selection alone grants no authority.
- Sensitive actions receive exact durable identifiers, never table indices or caller-synthesized records.

## Security

- QML receives only primitive dictionaries/lists with redacted paths.
- Provider credentials are never accepted by this frontend.
- Provider configuration stores executable paths only and never silently registers or qualifies a provider.
- Founder approval calls the existing production authentication path and binds the exact displayed charter ID and revision.
- Unsupported actions are absent or visibly disabled with a stable reason.
- KeeperAuthority health is read-only; the desktop cannot install, restart, or reconfigure the service.
