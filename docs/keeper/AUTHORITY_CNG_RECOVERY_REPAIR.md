# KeeperAuthority 1.7.4 CNG policy recovery repair

KeeperAuthority 1.7.4 repairs the Windows machine-key policy comparison used by
the elevated Provider Host Authority-identity provisioning step. The repair is
bounded to protocol 7 and schema 6; it does not change provider execution,
enrollment, registration, qualification, or pricing authority.

The lifecycle now:

- resolves `GetSecurityDescriptorLength` from `advapi32.dll` with an explicit
  Windows signature;
- opens only the Microsoft Software Key Storage Provider and the exact durable
  machine-key name;
- rejects an existing object unless its name, unique name, RSA algorithm,
  3072-bit length, non-exportable policy, and security-descriptor support agree;
- assigns the exact Administrators owner and primary group plus the protected
  DACL granting only
  SYSTEM, Administrators, and the KeeperAuthority service SID while denying the
  Restricted Code SID first;
- reads the owner, group, DACL, descriptor control flags, trustees, ACE flags,
  ACE types, and rights back through documented Windows security APIs;
- maps the Microsoft Software KSP's normalized generic rights to their exact
  specific-rights form and compares a closed semantic authorization set rather
  than comparing SDDL strings;
- rejects null or empty DACLs, inherited ACEs, noncanonical deny/allow order,
  unresolved trustees, broader or missing rights, unexpected trustees, and any
  owner, group, or control mismatch before exposing the public identity; and
- closes every opened handle and fails closed on unavailable APIs, inaccessible
  properties, ambiguous identity, policy mismatch, interruption, or read-back
  failure.

A disposable persisted-key reproduction showed that the Microsoft Software KSP
returns a full-control ACE as `0xD01F01FF` even when the requested SDDL uses
generic-all. Those encodings are equivalent after the KSP's generic mapping but
are not textually equal. Only this documented normalization is accepted; the
result must still equal the exact full-control mask for every intended trustee.

A finalized same-name key left by an interruption after the 1.7.3 lifecycle
wrote owner and DACL but before it persisted an identity record has one narrowly
recognized recovery state: every provider, key, owner, DACL, control, trustee,
and right property must match exactly, with only the primary group allowed to
differ from the new explicit Administrators group. The lifecycle reads only the
public key, records its exact identity plus a sanitized hash of the observed
legacy policy in a durable claim, and only then writes the final exact policy.
Retry reopens the key without creation and must match that public identity and
either the claimed legacy-policy hash or the already-exact target policy before
reconciliation. A missing, substituted, or differently secured key is never
created or modified by the legacy-claim path.

All other existing identities are read-only. An exact already-secured identity
may be adopted; a mismatched or inaccessible identity is rejected without a
claim or write. Private key material is never exported, inspected, deleted,
replaced, or recreated. The final public identity record is persisted only after
the exact policy read-back verifies, and retry is idempotent.

No service lifecycle or live CNG mutation is performed by the offline repair
and verification process. Installation remains a separately authorized,
exact-artifact recovery operation.
