# Testing

Run:

- `python -m pytest tests/keeper -q`
- `python -m pytest -q`
- `python -m mypy --strict keeper tests/keeper`
- `python -m compileall -q keeper tests/keeper`
- `git diff --check`
- `scripts/verify-foundation.sh` from Git Bash
- `powershell -File scripts/test-keeper-package.ps1`

Desktop behavior is tested through `KeeperViewModel` so tests remain headless.
Packaging smoke initializes fresh data, runs diagnostics and a complete mock pilot,
and exits cleanly.

Controller tests exercise first-run navigation and real application-service actions
without a display. Controlled command executables exercise complete workflows,
selected-stage retries, timeout/cancellation recovery, live redacted logging, and
restart-time retained-handle recovery. Adversarial coverage exercises post-validation
PID reuse, exited retained objects, parent and ownership changes, ambiguous
descendants, executable replacement, registration changes, truthful retry instance
IDs, actual-execution-only reporting, independent-connection authorization races,
and exact one-use reroute authority.

Pass B provider-recovery tests deterministically synchronize concurrent
cancellation claims and prove one external effect. Fault injection covers
cancel-side-effect-then-exception, terminal-commit failure, and restart during a
claimed cancellation. The suite verifies durable uncertainty, retained session,
usage, workspace, write and launch claims, blocked automatic retry, exact
one-use Founder action approval, current-charter and observation binding,
conservative usage consumption, explicit cleanup, composition separation, and
rejection of ordinary execution uncertainty. The controlled-provider workflow
regression also proves a cancelled author stage is durably stopped before retry.

Release-gate tests use Windows `spawn` workers with independent database
connections. Executable race tests pause after validation and retained-handle
acquisition but before `CreateProcess`, then attempt same-path, same-size, and
junction retarget attacks. Directory symlinks are used when the current token
permits them; otherwise the integration uses an unprivileged Windows junction.
Linux fallback execution uses a sealed in-memory file descriptor and has a
capability-gated substitution regression; other non-Windows kernels fail closed
when sealed descriptor execution is unavailable.

Provider-discovery regressions use marker-writing configured commands and verify
that diagnostics and first-run discovery never invoke content before immutable
registration validation. Batch registration tests separately corrupt launcher and
script digests and sizes. Recovery tests delete, corrupt, duplicate, and mismatch
provider evidence after durable execution-start persistence.

Canonical-registration mutation tests alter endpoint, authentication, capability,
policy, independence, qualification, component, authorization, revocation,
expiration, path, size, and field shape authority while retaining the old digest;
every mutation blocks discovery. Exact-attempt recovery tests prove wrong paths,
instances, runs, tasks, stages, roles, attempts, registrations, executable or
configuration identities, and statuses cannot finalize execution. A complete
exact-path terminal record is the positive control.

Qualification tests prove ordinary registration is non-executing and unqualified,
then exercise successful and failed protected batch qualification using actual
version output. Capability/role tests cover disabled reviewer and repair
capabilities, empty and single-role eligibility, unknown/duplicate roles, and
truthful diagnostics. Completion tests mutate only provider terminal evidence and
verify it cannot finalize without a matching immutable completion journal; forged
digests and wrong attempt or instance identities remain blocked.

Authenticated-authority regressions remove writer proofs, recompute all public
digests, insert completion rows manually, sign with another installation key,
copy records across registrations and attempts, mutate signed versions and
component identities, and replay challenges. Standalone tests prove raw evidence
and missing protected references fail closed. Secret-isolation tests confirm the
authority key is outside provider roots and absent from inherited environment
state.

Windows suspended-launch regressions delay Job assignment and prove the provider's
first instruction cannot run, inject configuration/creation/assignment/resume
failures, check retained-handle cleanup, and exercise immediate cancellation,
timeouts, standard executables, registered batch launchers, and nested descendants.
The nested fixture confirms descendant start, parent exit, full Job termination,
no surviving process, and no post-lifecycle authority-blob access. Authority-key
tests race independent first-installation processes and interrupt publication to
prove one valid no-overwrite winner and no partial final key.

`python -m keeper.desktop --ui-smoke --data-dir <fresh-isolated-profile> --screenshot-dir <path>` now launches the Qt product shell and renders all 13 pages. `python -m keeper.ui_qml` is the direct Qt entry. `--mock-demo`, `--ui-smoke`, and `--test-ui-fixture` require an explicit empty or previously marked QA profile and refuse the normal Founder profile and protected workflow paths. Release evidence uses the normal Windows platform so system fonts and high-DPI behavior match the installed product; the Qt offscreen backend is retained only for structural CI smoke.

`tests/keeper/test_qml_desktop.py` verifies canonical navigation, primitive/redacted state, durable Keeper Assistant conversation, fail-closed actions, absent Sage surfaces, disabled unsupported authority/provider controls, safe Authority health, source-backed search, and narrow-window Assistant behavior. `tests/keeper/test_desktop_package_lifecycle.py` verifies manifest path confinement, install, repair, rollback, and data-preserving uninstall.

Package verification runs `Keeper.exe --diagnostics --data-dir <isolated-profile>`, `Keeper.exe --mock-demo --data-dir <isolated-qa-profile>`, the 13-page rendered UI smoke with the same isolated QA contract, manifest hashes, protected-content/secret/private-path scans, and the isolated install/repair/upgrade/rollback/uninstall lifecycle. The legacy Tk classes remain covered by compatibility tests but are neither the default product shell nor included in the Qt package.
