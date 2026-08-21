# Keeper Provider Host 1.7.14 protected-tree observation repair

KeeperAuthority and Provider Host 1.7.14 retain protocol 7 and schema 6. This
bounded repair resolves an enrollment deadlock between two correct controls:
the Host installation denies `S-1-5-12` (Restricted Code), while Authority
must remeasure that same user-owned protected installation.

The authenticated named-pipe SID, process, Windows session, canonical profile,
package, executable, manifest, and Host identity bindings remain mandatory.
After those bindings are established, Authority revalidates the retained pipe
peer process handle, creation time, executable path and file identity, SID, and
session. It rejects restricted or ambiguous process tokens, then creates a
minimum-access impersonation duplicate from that exact retained process token.
A disposable Authority worker uses only that duplicate while it reads the
deterministic per-user Host installation derived from the canonical profile. It
reverts immediately after that fixed read-only body and positively proves that
it no longer has a thread token before publishing any result. The process
binding is revalidated before duplication, after observation, and before the
result is accepted. Core process revalidation uses only the retained process
handle, token, pipe metadata, creation time, and reported image path. It never
opens the protected image through either the raw pipe token or the service
identity. Exact executable path canonicalization and file identity are first
bound, and subsequently remeasured, only inside the same retained-process-token
read worker. This closes the access-denied self-deadlock without expanding the
Host DACL.
Authority storage, signing, callbacks, enrollment mutation, and provider
execution are unreachable from the impersonated body. A failed impersonation,
reversion, or clean-identity verification returns no observation and fails
closed on the non-impersonating service thread.

Before and after package measurement, Authority verifies every protected Host
installation and state path against the exact closed policy installed by
Keeper: the Founder SID owns the path; Restricted Code is denied full access;
only SYSTEM and that Founder SID receive full access; the DACL and inheritance
shape are exact; and the medium-integrity no-write-up label is intact. Reparse
points, junctions, symlinks, unexpected trustees, broader rights, ownership
changes, policy changes, tree changes, and package changes fail closed. The
separately controlled provider-output exchange is not treated as Host program
or state storage.

The raw named-pipe impersonation token is never used for Host filesystem
observation. Restricted provider processes remain unable to read or replace the Host
program, state, launcher, or lifecycle metadata. Installing this source and
retrying enrollment remain separate exact-artifact Founder-authorized live
actions.

The 1.7.13 follow-up applies the same boundary to Authority-to-Host runtime
activation. Authority retains the exact process serving the connected Host
pipe using the documented server PID and session APIs. It duplicates only that
authenticated Host process token, and a new disposable worker resolves,
file-identity-binds, and hashes the Host executable while impersonating that
token. The gateway constructor performs no filesystem read of the user-owned
Host tree. The worker reverts and proves a clean thread before Authority sends
the first protocol frame; PID, creation time, SID, session, canonical path,
file identity, and digest disagreements fail closed. This permits supported
activation and reconciliation without granting the service account access to
the protected per-user Host tree or weakening its closed ACL.

The 1.7.14 reciprocal repair removes the Host's pre-connection read of the
protected Authority runtime. The signed enrollment receipt remains the source
of the expected Authority path, digest, file identity, SYSTEM SID, and session.
After reading and cryptographically verifying the signed hello in memory, but
before claiming it, signing, writing a response, or touching Host runtime
state, a disposable Host worker impersonates only that connected named-pipe
client. While impersonating it binds the exact client process, creation time,
session, SID, canonical image path, file identity, and digest, then revalidates
the binding. The worker reverts and positively verifies a clean thread before
publishing the observation. Any impersonation, reversion, path, identity, or
digest failure rejects the connection without a protocol response. The
Authority installation ACL remains closed and unchanged.
