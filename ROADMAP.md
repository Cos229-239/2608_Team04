# Keeper Roadmap

## Current baseline

- Local Keeper Desktop and durable Executive workflow
- KeeperAuthority Windows service
- Restricted per-user Provider Host
- Exact provider registration, qualification, recovery, and effect accounting
- ChatGPT-subscription Codex provider qualification without API-key fallback
- Deterministic packaging, provenance, Defender, and rollback gates

## Next priorities

1. Complete the repository separation and make this repository the sole Keeper source of truth.
2. Replace historical DarkSage compatibility identifiers through a versioned live migration only after full recovery testing.
3. Add repository-native CI for Keeper-focused tests, static checks, packaging, and Windows security tests.
4. Extend the reviewed subscription-provider boundary to additional opt-in providers without weakening the common authority contract; Claude reviewer support is the first multi-provider implementation.
5. Improve Desktop provider diagnostics and supported recovery UX.
6. Reduce retained protected diagnostic output where hashes are sufficient.

## Non-goals

- Trading, broker execution, market data, portfolio management, or financial logic
- Silent cloud-provider selection
- Automatic purchases or subscription changes
- Automatic deployment, publication, force push, or destructive Git operations
