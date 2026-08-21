# Keeper Desktop Local Release Checklist

1. **Create package:** build from a clean reviewed commit with `scripts/build-keeper-desktop.ps1` and the pinned UI requirements. Preserve the generated installer release descriptor and verify its source commit/tree and script/package hashes.
2. **Approve hashes:** retain the SHA-256 of `Keeper.exe` and `keeper-package-manifest.json`; pass the approved manifest hash to every install, repair, upgrade, or rollback and verify exact manifest coverage.
3. **Install location:** default to `%LOCALAPPDATA%\Programs\Keeper`; never require elevation or machine-wide configuration.
4. **Migrate configuration:** preserve `%LOCALAPPDATA%\Keeper`; startup migrations remain owned by Keeper storage services.
5. **First launch:** complete the seven-step wizard and confirm the environment/composition label is truthful.
6. **Provider setup:** configure executable paths only; register and qualify providers through separately authorized supported Authority operations.
7. **KeeperAuthority health:** confirm READY/UNAVAILABLE, version, protocol, schema, identity, provenance, and check time through the read-only projection.
8. **Safe demonstration:** run packaged diagnostics and the deterministic mock workflow only with an explicit isolated QA profile; confirm the UI labels the result non-production and the Founder profile is unchanged.
9. **Production readiness:** require complete tests, strict mypy, compilation, package scans, Windows UI smoke, pilot, and independent Critical/High and product/UI audits.
10. **Rollback/uninstall:** verify one-generation rollback, manifest validation, shortcut replacement, and data-preserving uninstall before daily use.

No checklist item authorizes a service change, provider mutation, credential operation, paid-provider fallback, deployment, publication, or live trading.
