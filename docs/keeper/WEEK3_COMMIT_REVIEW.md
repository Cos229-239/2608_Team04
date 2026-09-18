# Week 3 local commit review — September 17, 2026

These changes are prepared for Devon's review before any push or Trello publication. They describe five work items, not five separate working days. No live credentials or runtime databases are included.

## 1. Prevent duplicate Keeper approval renewal requests

Builds on Dane's unchanged-charter expiry renewal (`37136e2`), included as a required prerequisite with its lifecycle tests. New opt-in atomic lookup/create reuses one valid request under concurrent renewal, cancellation or restart without extending expiration or bypassing authentication. Invalid, stale or duplicate bindings fail closed. Ten new atomic-renewal cases and six teammate-integration boundary cases cover the behavior. Independent security review found no Critical/High issues.

Provider-diagnostics integration and shared-setup tests are outside this five-item commit series and remain separately pending.

## 2. Fix Keeper search routing and no-results feedback

Actual loaded-record matches take priority over exact page shortcuts. Added missing searchable collections, plain-text result feedback, Escape and clear-search controls. Usage results route to Providers. Real-QML regression covers keyword collisions, routing, normalization and no-match behavior without changing authority or calling providers.

## 3. Distinguish filtered Keeper lists from empty records

Fourteen lists distinguish hidden matches from genuinely empty data. Explicit reset clears search and only the current page's filters; selector labels stay synchronized. Recovery uncertainty remains globally visible and unchanged. Real-QML tests cover all lists, reset behavior and record immutability.

## 4. Keep long Keeper approval details scrollable and controls visible

Bound approval details to the window, keep action buttons in a fixed footer, render dynamic values literally and reset scroll on reopening. Retains Dane's expiry/retry explanation and regression (`6f5b996`), credited as imported work. Adds long-text geometry/scrolling tests at two window sizes. Authentication and controller action remain unchanged; independent review found no Critical/High issues.
