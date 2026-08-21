# KeeperAuthority service package

KeeperAuthority uses one deterministic, service-only package construction and
verification contract. The desktop/general Keeper zipapp is not a valid
KeeperAuthority upgrade artifact.

## Build

Build into a new empty output directory:

```powershell
.\scripts\build-keeper-authority.ps1 -OutputDirectory C:\tmp\keeper-authority-release
```

The build emits:

- `keeper-authority.pyz` — the deterministic service package;
- `keeper-authority-package-manifest.json` — the external package hash, size,
  Git commit/tree identity, embedded archive manifest, and complete entry list.
  Manifest creation compares every packaged source entry byte-for-byte with that
  exact Git commit and rejects dirty or uncommitted runtime content.

The archive contains only the Python dependency closure reachable from
`keeper.authority_service.service_main`, plus an embedded
`keeper-authority-package.json`. Entry order, timestamps, permissions,
compression, content digests, and JSON serialization are deterministic. UI,
QML, assets, tests, caches, bytecode, protected workflow state, and unrelated
application modules are rejected.

## Non-mutating verification

```powershell
python -m keeper.authority_service.service_install verify-package `
  --package C:\tmp\keeper-authority-release\keeper-authority.pyz `
  --expected-sha256 <AUTHORIZED_SHA256>
```

Verification rejects a wrong package hash, unexpected or duplicate entries,
path traversal, malformed identity metadata, nondeterministic ZIP metadata,
missing closure entries, unsupported service/protocol/schema versions, and any
entry digest or size mismatch.

## Supported upgrade

The elevated upgrade takes the already frozen package and its separately
authorized digest. It does not rebuild from source:

```powershell
python -m keeper.authority_service.service_install upgrade-package `
  --package C:\tmp\keeper-authority-release\keeper-authority.pyz `
  --expected-sha256 <AUTHORIZED_NEW_SHA256> `
  --expected-current-sha256 <AUTHORIZED_INSTALLED_SHA256> `
  --recovery-preimage-manifest <AUTHORIZED_PREIMAGE_MANIFEST_PATH> `
  --external-manifest <AUTHORIZED_EXTERNAL_MANIFEST_PATH> `
  --expected-external-manifest-sha256 <AUTHORIZED_EXTERNAL_MANIFEST_SHA256>
```

The lifecycle verifies the candidate and exact canonical external manifest
before reading or replacing the installed
package, requires the installed package to match its separately authorized
current digest, captures and verifies those exact old bytes as rollback, copies the candidate to a
staging file, re-verifies the staged bytes, atomically replaces the installed
package. Before replacement it persists an exact claim binding the candidate,
current package, rollback artifact, release metadata, Provider Host identity, and
the revalidated stopped-state recovery preimage. A retry reconciles only those
recorded identities and safely completes the same operation; the exact
claim-recorded backup remains eligible for supported rollback. It then records the
exact package, Git commit, Git tree, and packaged source-tree identities. The
top-level installed-source identity and the upgrade event are updated together;
rollback restores the corresponding prior source identity. The service
must already be stopped through the separately authorized lifecycle.

The compatible Founder-verifier configuration transition is independently
claim-bound before its atomic file replacement. A lost return after either the
config replacement or manifest completion is reconciled by the same exact upgrade.
Rollback from an interrupted package upgrade first finalizes that exact config
claim, preserving both the backward-compatible schema-3 bytes and their lifecycle
provenance before restoring the prior package.

Rollback restores the exact captured installed byte stream. Release handoffs
must authorize only the service-package digest produced by this construction
path; the legacy general Keeper zipapp is never an Authority upgrade input.

With KeeperAuthority stopped through a separately authorized lifecycle, restore
the exact manifest-recorded rollback generation with:

```powershell
python -m keeper.authority_service.service_install rollback-package `
  --package <MANIFEST_RECORDED_BACKUP_PATH> `
  --expected-sha256 <AUTHORIZED_ROLLBACK_SHA256>
```

Rollback rejects an unrecorded backup, a backup not belonging to the latest
upgrade, a changed current package, any service state not confirmed exactly as
stopped, a wrong digest, and a mismatched staging file. It stages and
re-verifies the exact rollback bytes,
atomically restores them, and records the restored and replaced identities.
Before replacement it persists an exact rollback claim. Reinvoking the same
authorized rollback after interruption either completes the same verified
staging operation or records an already-restored package; any other on-disk
identity fails closed as uncertain.
