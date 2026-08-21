# KeeperAuthority 1.7.4 startup recovery

KeeperAuthority 1.7.4 is the bounded recovery release for a protocol-7 upgrade
that may have committed Authority schema 6 before Provider Host machine-key
initialization failed. Protocol 7 and schema 6 are unchanged.

## Corrected boundary

The Windows service start callback now constructs the Authority core, reports
`RUNNING`, and then performs Provider Host identity initialization on a dedicated
daemon worker. CNG provider/key opening and creation are never performed in the
service start callback. If the worker cannot open the exact machine identity,
the Authority IPC service remains available for diagnostics while every Provider
Host enrollment, qualification, and execution operation fails closed.

The elevated package lifecycle provisions or verifies the exact non-exportable
machine identity before installing a protocol-7/schema-6 package. Provisioning
uses the fixed key name `DarkSage.KeeperAuthority.ProviderHost.v1` and an exact
protected DACL: deny Restricted Code, then allow Local System, Administrators,
and the `NT SERVICE\KeeperAuthority` service SID. Runtime code opens this identity
only; it cannot create or replace it.

## Supported recovery preparation

No recovery command is self-authorizing. KeeperAuthority must already be stopped,
and a separate Founder-approved elevated recovery window must bind the exact old
package hash, candidate package hash, preimage destination, and expected service
identity.

Before package replacement, capture a new exclusive preimage with:

```powershell
python -m keeper.authority_service.service_install `
  backup-recovery-preimage C:\path\to\new-exclusive-preimage
```

The command refuses an existing destination, rejects reparse points, and creates
the empty destination with a protected inheritable DACL allowing only Local
System, Administrators, and the KeeperAuthority service SID before copying any
protected byte. If that exact ACL cannot be applied and verified, the empty
destination is removed and the operation fails closed. It then hashes every copied
file, compares the copy to the stopped protected source, writes a sibling manifest,
and records the public manifest/tree identities in the lifecycle manifest. A retry
must use a new destination; it never overwrites a preimage.

The authorized upgrade then uses `upgrade-package` with the exact candidate and
current-package SHA-256 values plus the exact sibling preimage-manifest path and
the exact build-generated external package manifest and its SHA-256. The
lifecycle re-hashes that manifest and both stopped-state trees, requires the
preimage to be canonically disjoint from protected state, and binds its manifest,
tree, and destination identities into a durable package-upgrade claim before
replacement. It captures the exact package rollback artifact,
provisions/verifies the Provider Host identity, installs frozen candidate bytes,
and records the public identity. Any identity or lifecycle mismatch rejects before
package replacement.

Beginning with 1.7.21, the external package manifest is also verified against
the exact Git commit and tree before mutation. That identity is persisted in
the durable upgrade claim and event and atomically becomes the installed
top-level provenance identity. This closes the legacy omission where package
bytes could be correct while the installed manifest still named an older source
commit.

The one legacy 1.7.3 orphan state is reconciled through a separate durable
identity claim. Its provider, key name, public key, owner, exact closed DACL,
descriptor controls, and observed policy hash are bound before the only missing
primary-group normalization is written. No other unclaimed mismatch is repaired.
Claim retry opens existing-only and revalidates the claimed public identity and
pre-write policy; it cannot recreate a missing key or write a substituted key.

If execution is interrupted after the claim, invoking the same exact authorized
upgrade reconciles only the recorded old or candidate digest and completes the
same operation. The exact claim-recorded backup is also accepted by the supported
rollback command before an upgrade event exists. Any third digest fails closed as
uncertain. Upgrade event creation and claim removal are one atomic manifest write.

The schema-2 to schema-3 Founder-verifier configuration migration uses a second
durable claim before replacing `service.json`. It binds the old and target config
digests, exact backup, schema transition, and verifier identity. Retry accepts only
the exact old or target bytes and atomically records completion while removing the
claim. A rollback requested during this boundary first reconciles the compatible
schema-3 configuration provenance before restoring package bytes, so neither the
upgrade nor rollback path can strand a manifest/config mismatch.

## Post-start acceptance

After the one separately authorized start, supported diagnostics must show all of
the following before Phase 2 continues:

- service version 1.7.4, protocol 7, schema 6;
- the expected service-key identity;
- the expected registration, qualification, and attempt counts;
- no active or uncertain provider work;
- Provider Host state `NOT_CONFIGURED`, `INITIALIZING`, `UNAVAILABLE`, or the
  expected enrolled state, without any provider execution;
- package and lifecycle provenance matching the authorized hashes.
- no outstanding `package_upgrade_claim` or `package_rollback_claim`.
- no outstanding `configuration_migration_claim`.

`UNAVAILABLE` with `IDENTITY_INITIALIZATION_FAILED` is a safe diagnostic state,
not permission to enroll, register, qualify, retry, or execute. Those operations
remain separately authorized.
