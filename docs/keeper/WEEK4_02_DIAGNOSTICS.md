# Update 2 - actionable provider path diagnostics

Integrated Dane's `941698e` guidance and `538dfe0` Windows/UNC/POSIX error
redaction regression tests. Added input validation for malformed provider names,
empty paths, web/network addresses, and filesystem resolution errors. Existing
paths and file-picker URLs with spaces are accepted; directories are rejected.
Invalid input preserves previously saved settings and is not executed.

Saving an executable path does not register, qualify, authenticate, or run it.
Qualification remains an explicit supported Authority operation. Error messages
do not expose the submitted local path. Tests use inert local fixture files.

Dane's `c17b5bd` approval-renewal repair is already equivalent in shared dev:
one duplicate-request guard and `reuse_pending=True`. No older implementation
was imported over the current atomic renewal logic.
