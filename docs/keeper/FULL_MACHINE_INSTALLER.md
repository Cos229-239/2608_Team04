# Full-machine Windows installer

The full-machine setup is the administrator-facing release path. It installs
KeeperAuthority for the computer, then returns to the signed-in Windows user to
install the Provider Host, complete Founder-confirmed enrollment, and install
Keeper Desktop. Provider credentials are never copied into the package.

Provider Host setup and enrollment must use the same compatibility directory,
`%LOCALAPPDATA%\Programs\DarkSage\KeeperProviderHost`. This historical directory
name is not product branding; changing it requires a separately reviewed
identity/state migration. The installer path regression test compares setup's
destination with the production enrollment client's actual destination.

Setup supports initial installation and conservative reinstalls. An existing
Authority must have the exact bundled archive bytes. An existing same-version
Host is retained only after package, protected ACL, signed committed enrollment,
live Authority enrollment, current user/session, and executable file identity
checks. The enrolled Host may be an earlier build of that same version; setup
explicitly retains it, rather than claiming to replace it with the bundled Host.
The desktop then uses its existing verified repair/upgrade lifecycle.

Generation 1 is requested only for a genuinely unenrolled Host with no prior
enrollment/database state, and still requires interactive Founder confirmation.
Pending transactions, revoked/stale enrollment, changed sessions/identities, and
different component versions stop setup and require the supported recovery or
upgrade procedure. Setup never deletes protected history to simulate a fresh PC.

Each component's exit code is checked in Inno Setup's `PrepareToInstall` hook.
An Authority failure prevents the user phase, and any user-phase failure prevents
the successful completion page. Setup does not automatically retry failed phases
or claim to roll back earlier successful component operations. Diagnostic logs
are retained as `Keeper-machine-authority-*.log`, `Keeper-machine-user-*.log`, and
the Inno Setup log in Windows temporary folders (the administrator's temp folder
may differ from the signed-in user's). Close setup and resolve the reported error
before rerunning it. First-time enrollment cancellation may need reconciliation,
not a new enrollment attempt.

End-to-end clean-machine validation is still required; preflight checks and a
successful reinstall are not evidence of a completed fresh-PC installation.

Build inputs are exact, prebuilt Desktop, Authority, and Provider Host packages:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-keeper-machine-installer.ps1 `
  -PythonPath C:\path\to\python.exe `
  -AuthorityPackageRoot C:\path\to\authority-package `
  -ProviderHostRoot C:\path\to\KeeperProviderHost.dist
```

Without `-CertificateThumbprint`, the output name contains `Unsigned`. A public
release must use an organization-controlled Authenticode certificate that has a
private key and builds to a trusted Windows root. The signing script timestamps
with SHA-256, verifies the resulting signature, and fails closed if the
certificate or Windows SDK signing tool is unavailable. Certificate passwords
and private keys are not stored in the repository or installer payload.

## Fresh-computer release gate

Test the final signed bytes on a separate supported Windows computer or a clean,
reverted VM snapshot. Record the installer SHA-256 and Windows version, then
verify in order:

1. New installation and Founder-confirmed Provider Host enrollment.
2. Desktop and Start-menu shortcuts open the installed executable.
3. KeeperAuthority is running under its restricted service identity.
4. Provider Host starts for the enrolled user and reports `READY`.
5. Repair preserves protected Authority data, enrollment, and desktop data.
6. Upgrade preserves data and retains the approved rollback package.
7. Rollback restores the prior executable generation without rolling back data.
8. Uninstall removes executables, shortcuts, and service registration while
   preserving protected audit/history data according to Keeper policy.
9. First run discovers only configured providers and performs no execution
   before Founder approval.

Do not label a release fresh-PC tested based only on another profile or folder on
the development computer. A different physical machine or clean VM image is
required.
