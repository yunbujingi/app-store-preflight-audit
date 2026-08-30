# Sample App Store Preflight Audit

Verdict: **CONDITIONAL_GO**

This synthetic example demonstrates report shape only. It contains no real project, account, signing, or App Store Connect data.

## Scope

- Mode: archive
- Platforms: iOS
- Storefront assumptions: US, DE
- Policy source status: recorded by URL, retrieval time, and SHA-256

## Coverage

| Layer | Resolved | Applicable | Coverage |
| --- | ---: | ---: | ---: |
| archive | 4 | 5 | 80% |
| policy | 1 | 1 | 100% |
| runtime | 0 | 5 | 0% |

## Findings

| ID | Severity | Disposition | Verification | Title |
| --- | --- | --- | --- | --- |
| ARCHIVE-REASON-1 | P1 | NEEDS_VERIFY | INFERRED | Packaged binary API signal lacks a direct declaration |

Runtime scenarios remain `NOT_RUN`; this report does not claim Simulator or App Store Connect coverage.

> Synthetic example. This is not an Apple review decision or legal advice.
