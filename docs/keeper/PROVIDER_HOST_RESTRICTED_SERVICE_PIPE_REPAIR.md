# Provider Host restricted-service pipe repair

KeeperAuthority 1.7.19 and its exact-version Provider Host repair both Windows
restricted-service authorization deadlocks observed during Host connection and
authenticated Authority-process measurement.

KeeperAuthority runs with `SERVICE_SID_TYPE_RESTRICTED`. Windows performs the
restricted-token access check against the unique KeeperAuthority service SID as
well as the normal SYSTEM identity. The 1.7.16 Host pipe DACL allowed SYSTEM and
the enrolled interactive user but did not allow the unique service SID. The Host
therefore reached local `READY` while Authority failed closed with
`OSError:PIPE_UNAVAILABLE`.

The repaired pipe policy is an exact closed DACL:

- deny `S-1-5-12` (Restricted Code) full access first;
- allow SYSTEM full access;
- allow only the resolved `NT SERVICE\KeeperAuthority` service SID full access;
- allow only the enrolled interactive user SID full access; and
- disable inherited ACEs.

The Host resolves the service SID through the supported Windows account lookup
and requires the `S-1-5-80-...` service-SID namespace. Missing, unresolved, or
malformed service identity fails before pipe creation. No wildcard, service-logon
group, Administrators grant, inherited grant, or permissive fallback is used.

The explicit Restricted Code deny remains in force, so the restricted provider
token cannot open the Host pipe. After connection, the existing signed protocol,
exact Authority process SID/session/path/hash/file-identity measurement, replay
protection, and active-enrollment check remain mandatory before any request can
affect Host state.

Windows applies the same two-pass restricted-token check when the Host opens the
Authority process for identity observation. At service startup, Authority 1.7.19
therefore adds one exact `PROCESS_QUERY_LIMITED_INFORMATION` allow ACE for its
resolved unique service SID to its own process object. It preserves the owner,
group, descriptor control flags, and every existing allow and deny ACE, then
reads the descriptor back and requires that exact one-ACE delta. An ambiguous,
inherited, duplicate, or broader service-SID ACE fails startup closed.

Because the service token is already restricted at startup, an ordinary access
check cannot bootstrap a security-descriptor handle before that exact ACE exists.
Authority duplicates its own process pseudo-handle into one real, non-inheritable
handle carrying only `READ_CONTROL | WRITE_DAC`. It reads and writes the kernel
object descriptor through `GetKernelObjectSecurity` and
`SetKernelObjectSecurity`, closes the handle before server construction, and
fails startup closed if duplication, descriptor access, write, read-back, or
handle cleanup cannot be verified. Stable service-specific exit codes identify
only the failed process-security stage; descriptors and private state are never
reported.

KeeperAuthority is configured as the virtual account
`NT SERVICE\KeeperAuthority`, not LocalSystem. KeeperAuthority 1.7.22 therefore
requires its exact service SID as both TokenUser and a restricting SID, plus
session zero, a restricted token, and no Restricted Code SID. While
impersonating the authenticated pipe client on a disposable worker, the Host
requires that same exact TokenUser and restricting-SID identity. It opens the
bound process with query-limited rights only; it never opens or duplicates the
Authority process token. Reversion is positively verified before the result is
published.

The 1.7.22 Host installation policy also grants that exact service SID only
read/execute access to the protected Host tree. SYSTEM and the enrolled owner
retain their prior access, Restricted Code remains denied, inherited or extra
trustees remain prohibited, and the service receives no write/delete/ownership
authority.

The user-owned Host process object is a separate Windows authorization
boundary from its executable and pipe. Before constructing the Host runtime,
opening its replay database, or creating any pipe listener, the Host now
reloads the exact committed enrollment checkpoint and Authority-signed receipt,
then revalidates their proposal digest and the signed Host identity against the
exact per-user installation selection, complete package, executable path and
hash, stable file identity, user/session binding, byte-exact startup launcher,
and protected-tree attestation. It then
uses the same exact descriptor primitive to add one allow ACE for the resolved
KeeperAuthority service SID with only `PROCESS_QUERY_LIMITED_INFORMATION`
(`0x1000`) and flags zero. Owner, group, control, revision, defaulting state,
canonical ACE order, and all existing ACEs must survive exact read-back.

The Host bootstrap duplicates only its own pseudo-handle into a
non-inheritable `READ_CONTROL | WRITE_DAC` handle. It never opens another
process and does not grant terminate, synchronization, VM, token, thread,
ownership, or DACL authority to the service. A missing, inherited, denied,
duplicate, broader, noncanonical, or unverifiable service grant fails before
pipe readiness. Restricted Code remains unable to query the Host process.

An update retains one prior Host package as its rollback generation. That
retained package is executable product state and is covered by the same closed
tree policy. Update, repair, rollback, and interrupted-lifecycle recovery now
byte-verify both retained packages, apply the exact current ACL policy to both,
verify their package bytes again, and attest the complete protected tree before
clearing the lifecycle transaction. A same-version repair retains the prior
rollback version instead of pruning it. Any ACL write or read-back failure
leaves the transaction durable and the Host fail-closed until supported
recovery completes the same verification.

This offline repair does not update or restart the installed Authority, alter the
live Host enrollment, register or qualify a provider, or execute a model. A live
update requires a separate exact-artifact authorization.
