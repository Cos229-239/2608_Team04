# Keeper Provider Host 1.7.15 online-handshake repair

KeeperAuthority and Provider Host 1.7.15 retain protocol 7 and schema 6. This
release repairs the Authority-to-Host status handshake after a durable Host
enrollment without changing provider authority, enrollment semantics, or the
Provider Host filesystem boundary.

## Failure and repair

The Authority previously impersonated the authenticated user Host process to
measure the Host executable. The per-user Host installation already has a
closed ACL that grants exact read access to SYSTEM and the enrolled user while
denying Restricted Code. Impersonating the Host was therefore unnecessary and
could strand the post-enrollment handshake before the signed hello.

The Authority now performs that exact measurement as clean LocalSystem on a
bounded disposable worker. It retains and revalidates the pipe-server process,
SID, session, creation identity, canonical executable path, executable file
identity, and SHA-256 before sending the first protocol frame. The generation's
durable executable file identity is supplied to the gateway and must match the
live observation.

The reciprocal Host-to-Authority observation is unchanged: because the
per-user Host cannot read the protected Authority installation, a disposable
Host worker impersonates only the authenticated Authority named-pipe client,
measures the exact Authority image, reverts immediately, and publishes no
result until clean reversion is proven.

## Failure behavior

- Identity measurement is bounded. A timeout is `UNCERTAIN`, not success.
- Authority-side uncertainty disables the gateway; there is no automatic retry.
- Host-side timeout or reversion uncertainty fail-stops the Host accept loop.
- No signed hello, replay claim, callback, provider action, or response occurs
  before the applicable peer observation succeeds.
- Public diagnostics preserve the durable `ENROLLED_OFFLINE` state and expose
  only a sanitized failure category.
- Pipe and Host-tree ACLs continue to deny Restricted Code. No ACL is widened.

The installed 1.7.14 Authority and Host are not changed by building this source.
A separately authorized exact-artifact lifecycle is required before any live
update, Host restart, or enrollment recovery.
