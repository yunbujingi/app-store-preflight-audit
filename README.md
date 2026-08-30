# App Store Preflight Audit / App Store 上架前审计

[English](README.md) | [简体中文](docs/README.zh-CN.md)

An unofficial, evidence-driven Codex skill for auditing Apple-platform apps before App Store submission.

Latest published release: `v0.2.0-beta`.

It separates source inspection, isolated Xcode execution, archive inspection, runtime review, and App Store Connect verification. It produces machine-readable evidence and a concise human report without treating a successful build as proof of approval.

> This project is not affiliated with, endorsed by, or sponsored by Apple Inc. It does not guarantee App Store approval and does not provide legal advice.

## What is included

- Progressive skill instructions that load only applicable policy and workflow references.
- Source, build, archive, and submission audit modes with explicit coverage states.
- A stable target graph from PBX source/resource phases plus optional `xcodebuild` list/build-setting evidence.
- A two-axis evidence model: verification state and impact severity.
- Isolated Xcode command planning/execution with Git before/after checks.
- Privacy manifest and required-reason API evidence collection.
- Archive-level `.xcarchive`, exported bundle, and safety-limited `.ipa` inspection.
- Mach-O, dynamic dependency, signature, and bundle-local required-reason cross-checks without executing app code.
- Parent/child ID, version, platform, architecture, embedded-profile, debug-resource, static-library, and Xcode Privacy Report evidence.
- Stable JSON Schema plus Markdown, SARIF 2.1.0, and JUnit output.
- A rule-level Apple policy registry with stable IDs, applicability, fingerprints, review versions, and related evals.
- Read-only local App Store Connect export import and archive identity comparison.
- Baseline finding diffs and accountable, expiring suppressions that remain visible in canonical JSON.
- Non-mutating Simulator scenario plans and normalized direct observations.
- Reproducible fixtures, per-rule TP/TN/FP/FN metrics, and zero-regression CI gates.
- Deterministic Skill packaging and a dry-run-first, no-overwrite installer.

## Install

Create and inspect a deterministic package:

```bash
python3 skill/app-store-preflight-audit/scripts/package_skill.py \
  --skill skill/app-store-preflight-audit \
  --output /tmp/app-store-preflight-audit.zip \
  --checksum-output /tmp/app-store-preflight-audit.zip.sha256
python3 skill/app-store-preflight-audit/scripts/install_skill.py \
  --source /tmp/app-store-preflight-audit.zip --destination-root /path/to/skills
```

The installer is a dry run until `--install` is supplied and never overwrites an existing Skill.

## Use

```text
$app-store-preflight-audit perform a source-only App Store readiness audit of this repository.
```

```text
$app-store-preflight-audit perform a full preflight audit. Do not modify the repository; mark unavailable device and App Store Connect checks as blocked.
```

The skill does not submit builds, change App Store Connect metadata, purchase products, reset simulators, or repair findings unless separately authorized.

This beta is intentionally being released for community validation. Please use the dedicated issue forms for [false positives](.github/ISSUE_TEMPLATE/false-positive.yml), [false negatives](.github/ISSUE_TEMPLATE/false-negative.yml), [Apple rule changes](.github/ISSUE_TEMPLATE/apple-rule-change.yml), and [new project shapes](.github/ISSUE_TEMPLATE/new-project-shape.yml). Submit only synthetic or fully redacted evidence.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 skill/app-store-preflight-audit/scripts/run_evals.py \
  --cases evals/cases.json --output /tmp/app-store-preflight-evals.json
python3 /path/to/quick_validate.py skill/app-store-preflight-audit
```

The test suite uses Python's standard library and does not require Xcode. Xcode-specific execution is guarded and dry-run by default.

See the [sample report](examples/sample-report.md), [compatibility policy](COMPATIBILITY.md), [disclaimer](DISCLAIMER.md), [security policy](SECURITY.md), and [contribution guide](CONTRIBUTING.md).

## License

Apache-2.0. Apple, App Store, Xcode, iOS, iPadOS, macOS, watchOS, tvOS, and visionOS are trademarks of Apple Inc. Their use here is descriptive.
