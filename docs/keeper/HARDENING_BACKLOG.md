# Hardening Backlog

Nonblocking future work:

- Signed Windows installer and code-signing pipeline.
- Native macOS and Linux bundles.
- Rich diff/log widgets and accessibility testing with assistive technology.
- Optional operating-system notification adapters beyond Windows toast.
- Explicit evidence retention/deletion UI with preview and backup enforcement.
- Authenticated external-provider qualification matrix in a disposable test
  repository; command-adapter and controlled-provider paths are covered, but
  credentialed provider sessions are not claimed as release-verified.
- Optional Discord notification-only integration with OS credential storage.
- Expand the completed rendered Windows Tk smoke into broader accessibility and
  long-duration interaction coverage.
- Make next-stage selection skip an earlier dependency-ready assignment whose
  active usage, write, or lease prerequisites are incomplete when a later
  fully reserved independent assignment is runnable. Current behavior fails
  closed before external reservation but can reduce availability.
- Close the current-charter bookkeeping window between orchestration validation
  and transactional review/workflow completion if the Executive and Pass B
  stores gain a shared atomic validation boundary. Production Authority launch
  remains independently current-charter-bound.
- If Executive and Pass B records move into one transaction domain, make
  Founder reconciliation approval consumption and the terminal Pass B
  cancellation transition atomic. Today a rare Pass B commit failure consumes
  the one-use approval but leaves the attempt safely `UNCERTAIN`, requiring a
  fresh approval.
- If Keeper becomes public, multi-user, or accepts unknown plugins, isolate the
  Executive as a separate service between the Desktop/UI and KeeperAuthority.
  That version requires a new threat model for hostile same-user clients and
  plugin compromise; Python object sealing is not a substitute for the process
  boundary.
