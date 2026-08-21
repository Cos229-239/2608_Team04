# Authorization

Commit, push, network use, and worktree creation are separate capabilities. An
authorization records the exact repository/task scope, approving identity,
timezone-aware issue/expiry timestamps, reuse policy, revocation, and consumption.
Malformed, naive, expired, revoked, mismatched, or replayed authority fails closed.

Commit authority is bound to authorization ID, task, run, repository, worktree,
branch, HEAD, exact staged paths, and the digest of the exact staged content. Push
authority also binds the remote name and URL, source and destination refs, expected
commit, and non-force operation.

Provider reroute authority binds the run, task, retry stage, exact source attempt,
next destination attempt number, prior and proposed stable registration digests,
policy, capabilities, and independence requirements. It is timezone-aware,
expiring, and consumed once. It cannot carry forward to an arbitrary later retry.

Keeper never accepts authorization for merge, rebase, reset, stash, clean,
force-push, branch/worktree deletion, deployment, trading, or spending.
