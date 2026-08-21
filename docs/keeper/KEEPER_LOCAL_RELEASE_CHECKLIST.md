# Keeper Local Release Checklist

This checklist prepares a local Keeper package without installing, deploying,
publishing, or changing KeeperAuthority.

1. Create the package with the repository-supported build command from a clean
   approved commit.
2. Record the SHA-256 of the completed package beside the release record.
3. Propose a user-owned local installation directory outside source repositories
   and protected Keeper evidence trees.
4. Back up configuration, then validate the supported schema migration from the
   approved baseline without replacing the backup.
5. Perform the first launch with an isolated data directory and complete the
   protected-tree-safe evidence-directory probe.
6. Configure only Founder-selected provider accounts; keep local/free routing as
   the default and do not enable paid fallback.
7. Confirm the desktop reports read-only KeeperAuthority health, version,
   protocol, schema, identity, provenance, and last-check state without changing
   the service.
8. Run packaged diagnostics and the packaged mock demonstration; confirm no
   push, deployment, spending, credential access, or live trading is available.
9. Mark production readiness only after package, upgrade, desktop, diagnostics,
   mock workflow, pilot, secret scan, and protected-path scan all pass.
10. Preserve the prior package and configuration backup, and document local
    uninstall and rollback commands before any separately approved installation.
