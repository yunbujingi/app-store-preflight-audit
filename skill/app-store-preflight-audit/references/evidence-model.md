# Evidence, severity, and conclusion model

Keep these dimensions independent.

## Disposition

- `PASS`: the applicable check was executed or directly inspected and no issue was found within its stated scope.
- `FAIL`: evidence demonstrates the check does not meet a technical, submission, or policy requirement.
- `N/A`: product discovery demonstrates the check does not apply.
- `NOT_RUN`: an optional executable check was not performed. State why.
- `NEEDS_VERIFY`: evidence is incomplete or a current policy/product fact remains unresolved.
- `BLOCKED`: the check is required for the selected scope but a missing prerequisite prevents it.

Absence of a keyword is not enough for `N/A`. For example, absence of `StoreKit` imports does not prove the product has no paid digital entitlement.

## Verification state

- `CONFIRMED`: directly observed in source, configuration, bundle, tool output, runtime, or supplied App Store Connect evidence.
- `INFERRED`: supported by evidence but dependent on interpretation, reachability, packaging, backend, or policy applicability.
- `UNRESOLVED`: competing explanations remain or required evidence is unavailable.

## Severity

- `P0`: prevents building, packaging, upload, launch, or review of a core path; submission must stop.
- `P1`: strong, evidence-backed rejection or material privacy/safety risk; fix before submission.
- `P2`: meaningful review risk or material ambiguity; fix or explain before submission.
- `P3`: product-quality defect unlikely to reject alone.
- `P4`: optimization with no expected impact on this submission.

Severity describes impact, not confidence. A confirmed typo can be P3; an inferred privacy mismatch can be P1.

## Readiness verdict

- `NO_GO`: at least one unresolved P0, or a confirmed P1 that makes submission unreasonable.
- `CONDITIONAL_GO`: no P0, but P1/P2 or required blocked evidence remains.
- `GO`: no material blocker found and all required layers for the declared scope have sufficient coverage.

`GO` is scoped. Source-mode `GO` means no source-level blocker was found; it is not permission to say the complete submission will pass.

## Finding requirements

Each finding needs:

- stable ID and category;
- disposition, verification state, and severity;
- short title and explanation;
- evidence with relative path, line/location, command, bundle path, or runtime route;
- authority type and current official URL when policy-dependent;
- reviewer/user trigger path when relevant;
- remediation direction and affected surface;
- unresolved assumptions and storefront/platform applicability.

Accepted authority types are `APP_REVIEW_GUIDELINE`, `APP_STORE_CONNECT_REQUIREMENT`, `PRIVACY_REQUIREMENT`, `HIG`, `PLATFORM_TECHNICAL_REQUIREMENT`, and `QUALITY_ONLY`. Use `QUALITY_ONLY` rather than inventing an Apple clause.

## Deduplication and false-positive control

- One root cause should produce one primary finding with multiple evidence records.
- Static API patterns create `INFERRED` leads until target membership and actual use are established.
- Test code, previews, samples, generated sources, vendored code, comments, and dead feature flags must be identified before raising user-facing risk.
- A third-party framework without its own privacy manifest is not automatically a failure; establish that the SDK requires one or uses covered APIs.
- Do not infer backend data collection solely from a model name, endpoint string, or SDK import.
