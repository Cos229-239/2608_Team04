# Keeper Provider Host 1.7.8 session-rollover repair

KeeperAuthority and Provider Host 1.7.8 retain protocol 7 and schema 6. This
bounded repair lets the supported enrollment client durably supersede one stale
Founder-authorized proposal after the Founder signs in to a new interactive
Windows session.

Supersession remains fail closed. Authority must prove that no Host enrollment
exists, the Provider Host package must have changed, and the old checkpoint must
contain no grant, proof, receipt, or Authority enrollment effect. The prior and
current bindings must have the exact same user SID and canonical profile path;
only the numeric interactive-session ID may differ.

The complete old proposal and Founder capability are archived as `SUPERSEDED`
with both session bindings and package identities before the active checkpoint
is removed. Neither the old proposal nor its capability is resumed or reused.
The client creates a new proposal bound to the current session and requires a
fresh production Founder authentication before contacting KeeperAuthority.

Cross-user, cross-profile, same-package, granted, proved, committed, revoked,
ambiguous, malformed, mismatched-Authority, or replayed state continues to
reject. An interruption after archive persistence is idempotent: retry verifies
the exact archive before removing the unchanged stale checkpoint.
