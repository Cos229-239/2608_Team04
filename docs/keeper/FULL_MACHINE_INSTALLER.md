# Full-machine Windows installer

The full-machine setup is the administrator-facing release path. It installs
KeeperAuthority for the computer, then returns to the signed-in Windows user to
install the Provider Host, complete Founder-confirmed enrollment, and install
Keeper Desktop. Provider credentials are never copied into the package.

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
