# Provider Host pipe-startup repair

KeeperAuthority 1.7.16 and its exact-version Provider Host repair a fail-closed
availability defect in the Windows named-pipe listener startup path.

In 1.7.15, failure while creating the first Host listener terminated only its
daemon accept thread. The main Host process could remain alive without a pipe,
so Authority observed `PIPE_UNAVAILABLE` while the operating system still
reported a running Host process.

The repaired Host now:

- publishes readiness only after `CreateNamedPipeW` returns a valid handle;
- propagates first-listener and successor-listener startup failures to the main
  Host loop;
- fails closed after a bounded startup interval rather than remaining alive
  without a listener;
- closes a newly created handle when readiness publication or connection fails;
- preserves the original exception when pipe cleanup also fails; and
- binds the directly used Win32 named-pipe functions with explicit argument and
  return types.

The pipe authorization policy is unchanged. Restricted provider processes are
still denied access, and only SYSTEM and the enrolled interactive user retain
the existing permitted access. Authority identity, session, executable,
manifest, hash, and enrollment checks remain unchanged.

This offline repair does not update or restart the installed Authority, start or
enroll a Host, register or qualify a provider, or execute a model. Live migration
requires a separate exact-artifact authorization.
