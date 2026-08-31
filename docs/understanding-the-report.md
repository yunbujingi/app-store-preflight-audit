# Understanding the report

[简体中文](understanding-the-report.zh-CN.md) | [Quick Start](quick-start.md)

The report separates three questions: how strong the evidence is, what an individual check concluded, and what the combined preflight verdict is. Do not collapse them into a single pass/fail signal.

## Evidence verification

| State | Meaning | Example |
| --- | --- | --- |
| `CONFIRMED` | Direct evidence supports the statement within the recorded scope. | A packaged Info.plist contains a specific bundle ID. |
| `INFERRED` | Evidence is indirect or heuristic and requires human confirmation. | A Mach-O string or undefined symbol suggests a required-reason API category. |
| `UNRESOLVED` | Available evidence cannot establish the statement. | Target membership depends on an unresolved Xcode condition. |

Static symbol or byte evidence does not prove that code is reachable, executed, or used for a particular purpose. It must not be used to select an approved Privacy Manifest reason automatically.

## Check dispositions

| Disposition | Meaning | Release interpretation |
| --- | --- | --- |
| `PASS` | The check passed for the recorded evidence and scope. | Positive, but not a statement about untested layers. |
| `FAIL` | Evidence confirms the check did not meet its requirement. | Review and normally resolve before submission. |
| `N/A` | The check was determined not to apply. | Confirm that the applicability decision is sound. |
| `NOT_RUN` | The check was not attempted. | No result exists; do not count it as a pass. |
| `NEEDS_VERIFY` | A lead, ambiguity, or incomplete cross-check requires review. | Obtain stronger evidence or make a documented human decision. |
| `BLOCKED` | The check could not run because a required tool, artifact, authorization, state, or environment was unavailable. | Not a failure, but never a pass. Remove the blocker or accept the coverage gap explicitly. |

`PASS` means only “passed this check within this evidence boundary.” For example, a source Privacy Manifest parse can pass while Archive packaging remains unverified.

## Overall verdict

| Verdict | Meaning |
| --- | --- |
| `GO` | No active finding currently prevents proceeding within the audited scope. Coverage limitations may still exist and must be read. |
| `CONDITIONAL_GO` | Proceed only after reviewing stated conditions, unresolved evidence, or lower-severity risks. |
| `NO_GO` | Active high-impact evidence indicates the candidate should not be submitted without remediation or a deliberate, documented decision. |

No verdict is an Apple approval promise. Apple can evaluate behavior, metadata, policy applicability, account state, regional rules, or reviewer context that this audit did not observe.

## Coverage is not approval probability

Coverage measures how many applicable checks in each audit layer have resolved evidence. It does not estimate the probability of App Review approval. A report can have high source coverage and zero runtime coverage; a single confirmed submission blocker can matter more than many passed low-risk checks.

The canonical report calculates coverage from the fragments supplied to `assemble`. If no fragment/check exists for a layer, that layer may be absent from `coverage`; absence means “outside this assembled scope,” never `PASS` or 100%. CI should assert the expected collector names in `fragments`, while the Skill or human report records unavailable expected checks as `NOT_RUN` or `BLOCKED`.

Always read coverage by layer:

- source and target graph;
- build/unit/UI test;
- Archive and signing;
- runtime and reviewer path;
- App Store Connect;
- current policy/storefront applicability.

## Findings, baseline, and suppression

A finding combines severity, disposition, verification, authority, evidence, assumptions, and remediation. In recurring CI, the report also distinguishes new, changed, unchanged, suppressed, and resolved findings.

A suppression does not rewrite a finding as `PASS`. It records a reviewed, accountable, expiring decision and removes that finding from selected CI noise/verdict input while preserving it in canonical JSON. Never suppress missing evidence or `BLOCKED` state merely to make a gate green.

## Before sharing a report

Canonical JSON can contain bundle identifiers, filenames, SDK inventory, metadata values, finding details, and hashes. Redaction reduces obvious secrets and local paths but cannot understand every project-specific identifier. Follow the [safe execution and public evidence guide](safe-execution-and-public-evidence.md) before publishing any fragment, report, screenshot, Archive, or App Store Connect export.
