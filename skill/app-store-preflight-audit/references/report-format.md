# Report format and structured output

Machine-readable output follows [audit-report.schema.json](schemas/audit-report.schema.json). Evidence fragments follow [audit-fragment.schema.json](schemas/audit-fragment.schema.json). Eval metrics follow [eval-report.schema.json](schemas/eval-report.schema.json).

Schema `0.2.0` readers accept `0.1.0` fragments. Producers always emit the current schema. Breaking field removals, type changes, or semantic redefinitions require a major schema version; additive optional fields are permitted in a minor version. See [schema-versioning.md](schema-versioning.md).

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

## CI formats

- Stable JSON is the source of truth and retains evidence, coverage, scope, and compatibility metadata.
- SARIF 2.1.0 maps finding IDs to rules and P0/P1/P2 to error/warning levels without claiming compiler certainty.
- JUnit maps `FAIL` to failures and `N/A`, `NOT_RUN`, `NEEDS_VERIFY`, and `BLOCKED` to skipped tests. CI consumers must not reinterpret skipped checks as passes.
