# Report format and structured output

Machine-readable output follows [audit-report.schema.json](schemas/audit-report.schema.json). Evidence fragments follow [audit-fragment.schema.json](schemas/audit-fragment.schema.json).

## Required human report

1. Scope, mode, artifact/revision, policy retrieval time, platforms, storefront assumptions, and limitations.
2. Readiness verdict: `GO`, `CONDITIONAL_GO`, or `NO_GO` with the top reasons.
3. Product and reviewer-access map.
4. Coverage table by source, policy, build, unit test, UI test, archive, runtime, and App Store Connect.
5. P0/P1 blockers.
6. Complete deduplicated finding table.
7. Privacy/permissions/SDK and archive summaries when applicable.
8. Build/test/archive results with exact actions and statuses.
9. Five-minute reviewer path when runtime or submission scope applies.
10. App Store Connect unknowns and draft review notes.
11. Ordered next actions; do not implement them unless asked.

## Finding presentation

For each important finding show ID, disposition, verification, severity, category, title, authority, evidence, trigger path, consequence, remediation direction, and unresolved assumptions. Keep raw logs in referenced artifacts rather than flooding the report.

## Coverage

Coverage is `resolved applicable checks / discovered applicable checks`. `PASS`, `FAIL`, and a justified `N/A` are resolved. `NOT_RUN`, `NEEDS_VERIFY`, and `BLOCKED` are unresolved. Report counts per layer; do not combine them into a probability of Apple approval.

## Language

Write in the user's language. Preserve Apple product names and exact rule identifiers. Clearly distinguish tool output, direct observation, inference, developer assertion, and current official policy.
