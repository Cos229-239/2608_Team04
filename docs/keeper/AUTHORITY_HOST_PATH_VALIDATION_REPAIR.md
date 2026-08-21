# KeeperAuthority 1.7.7 bounded Host path-validation impersonation repair

KeeperAuthority 1.7.7 keeps protocol 7 and schema 6 unchanged. It repairs the
read-only Windows path validation used before Provider Host enrollment.

The authenticated user environment was already obtained through the exact
named-pipe client token. The remaining enrollment observer then attempted to
resolve and read the user's profile and per-user Host installation as the
LocalSystem service identity. A correctly protected user profile can deny that
access before enrollment persistence.

The repaired path uses two fixed disposable workers. The first canonicalizes
only the authenticated `USERPROFILE`. The second reads only the exact per-user
Host install root, startup registration, current package selection, state and
output roots, executable identity and digest, and Authenticode binding. Both
workers impersonate only the authenticated named-pipe client token. The service
caller thread never impersonates.

Each worker proves a clean starting identity, impersonates immediately before
its fixed read-only operation, reverts immediately afterward, and positively
verifies that no thread token remains before returning any result. Failure to
impersonate, read, revert, or verify identity fails closed. No Authority store,
database, signing, enrollment mutation, provider execution, service callback,
or unrelated work is reachable from either impersonated body.

All proposal, SID, process, session, package, executable, path-alias, file-ID,
digest, signature, and stable Host identity comparisons remain outside the
impersonated worker or are fixed read-only measurements. Provider Host 1.7.7 is
still exact-version locked to KeeperAuthority 1.7.7, protocol 7, and schema 6.
Installing either candidate remains a separate Founder-authorized live action.
