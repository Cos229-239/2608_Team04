# Data and Retention

Keeper stores versioned SQLite records in `%LOCALAPPDATA%\Keeper` by default and
uses WAL transactions. It stores projects, worktrees, tasks, policies, providers,
runs, stages, commands, authorizations, findings, dispositions, artifacts,
verification records, approvals, notifications, and settings.

The default log-retention preference is 90 days, but deletion is never silent or
automatic in this release. Use database backup or JSON export before manual
retention actions. Existing `.ai-workflow/runs/*/run.json` evidence can be imported;
source evidence is preserved and its path recorded.
