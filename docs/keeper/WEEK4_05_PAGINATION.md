# Update 5 - predictable task pagination

Reproduced a real QML defect: when a task list shrank, only its displayed page
was clamped; the old page number remained stored and reappeared when results
grew. Task paging now clamps the stored page on result-count changes, starts at
page one on project/charter scope changes, and resets for sort/filter changes.
The page helper also bounds negative indexes. Search already reset the page.

The change is presentation-only and does not write task state, switch projects,
start work, or alter authorization. Real QML regression covers shrinking and
regrowing results, switching project, sort/order/filter/search changes, negative
indexes, unchanged records, and rendering at 1600x960 and 1120x700.

The task panel now fits the supported window height with a scrollable list and
visible pagination controls. Geometry assertions guard against controls being
clipped by the footer. UI tests allow explicit Windows rendering and inject the
test Authority client, so visual checks need no live Authority diagnostics.
