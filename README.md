# App Store Preflight Audit

An unofficial, evidence-driven Codex skill for auditing Apple-platform apps before App Store submission.

Current release: `v0.1.0-beta`.

It separates source inspection, isolated Xcode execution, archive inspection, runtime review, and App Store Connect verification. It produces machine-readable evidence and a concise human report without treating a successful build as proof of approval.

> This project is not affiliated with, endorsed by, or sponsored by Apple Inc. It does not guarantee App Store approval and does not provide legal advice.

## What is included

- Progressive skill instructions that load only applicable policy and workflow references.
- Source, build, archive, and submission audit modes with explicit coverage states.
- A two-axis evidence model: verification state and impact severity.
- Isolated Xcode command planning/execution with Git before/after checks.
- Privacy manifest and required-reason API evidence collection.
- Archive-level bundle, extension, framework, entitlement, and manifest inventory.
- JSON Schema definitions and Markdown report rendering.
- Reproducible fixtures and tests focused on false-positive controls.

## Install

Copy `skill/app-store-preflight-audit` into your Codex skills directory, or package that directory as a zip for a compatible skill uploader.

## Use

```text
$app-store-preflight-audit perform a source-only App Store readiness audit of this repository.
```

```text
$app-store-preflight-audit perform a full preflight audit. Do not modify the repository; mark unavailable device and App Store Connect checks as blocked.
```

The skill does not submit builds, change App Store Connect metadata, purchase products, reset simulators, or repair findings unless separately authorized.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 /path/to/quick_validate.py skill/app-store-preflight-audit
```

The test suite uses Python's standard library and does not require Xcode. Xcode-specific execution is guarded and dry-run by default.

See [the Chinese guide](docs/README.zh-CN.md), [disclaimer](DISCLAIMER.md), [security policy](SECURITY.md), and [contribution guide](CONTRIBUTING.md).

## License

Apache-2.0. Apple, App Store, Xcode, iOS, iPadOS, macOS, watchOS, tvOS, and visionOS are trademarks of Apple Inc. Their use here is descriptive.
