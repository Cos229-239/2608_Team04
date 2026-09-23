# September 13 dev integration repair

The unreviewed Keeper-password approval path introduced in `8f0559d` is withdrawn. It allowed replacement without previous authentication and emitted a method not accepted by production capability validation. Approval again uses the existing Windows credential UI, provisioned SID validation, signed one-use confirmation and exact charter binding. No validator is relaxed to accept the incomplete method.

The QML password-account form and configuration entry points are removed. Any existing `keeper-account.json` file is ignored, not migrated, opened or deleted by this repair. No user credential entry is automated. A separate Keeper-account design needs reviewed protected storage, enrollment/rotation, migration and consistent Authority verification before release.

The malformed controller approval worker is restored together with its async completion signal and presentation-only refresh helper. Production composition retains its exchange-root validator import. The navigation grouping from the teammate update is preserved.

Automatic desktop reboot is withdrawn: its implementation launched a replacement before the first process exited and bypassed close-time draft saving. Close normally and wait for the desktop to exit before reopening. Cross-instance ownership is still a known limitation; never run two copies against the same profile.

The five audit follow-ups are merged separately with their existing commit history. Mock, source and fault-injection test results do not certify installed Authority/provider operation.
