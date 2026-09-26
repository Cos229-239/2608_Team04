# Update 3 - bounded local refresh timing

Adapted Ace's performance-check idea (`4a384d3`) without importing its subprocess
launches, automatic assistant requests, or misleading startup/restart labels.
Ace's later `_asyncFinished` addition (`c99810b`) already exists in dev.

Settings now shows timing for the initial snapshot and manual refreshes. Each
refresh runs the existing snapshot operation once. Last outcome, successful
average/maximum, and sample count are shown. At most 32 measurements are retained
in memory; restart clears them. Failed refreshes are marked failed and excluded
from successful averages. Clear timings does not alter warnings or durable data.

This measures snapshot refresh, not complete application startup, restart,
rendering, or provider performance. It adds no provider request, subprocess,
benchmark loop, persisted record, or automatic optimization. The existing manual
refresh remains synchronous; this update does not claim to fix UI responsiveness.
