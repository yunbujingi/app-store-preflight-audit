# App Store Preflight Audit / App Store 上架前审计

[English](README.md) | [简体中文](docs/README.zh-CN.md)

An unofficial, evidence-driven Codex skill for auditing Apple-platform apps before App Store submission.

Latest published release: `v0.3.0-beta`.

`v0.3.0-beta` deepens target/archive truth, adds cautious runtime evidence, ships a standalone scanner CLI with verified distribution, and provides a GET-only App Store Connect inventory adapter.

It separates source inspection, isolated Xcode execution, archive inspection, runtime review, and App Store Connect verification. It produces machine-readable evidence and a concise human report without treating a successful build as proof of approval.

> This project is not affiliated with, endorsed by, or sponsored by Apple Inc. It does not guarantee App Store approval and does not provide legal advice.

## Start here

- New user: [ten-minute Quick Start](docs/quick-start.md)
- Reading results: [understanding the report](docs/understanding-the-report.md)
- Final artifact: [Archive and IPA recipe](docs/recipes/archive-and-ipa-audit.md)
- CI adoption: [baseline and suppression recipe](docs/recipes/ci-baseline-and-suppression.md)
- Before `--execute` or sharing evidence: [safe execution and public evidence](docs/safe-execution-and-public-evidence.md)
- Output example: [synthetic sample report](examples/sample-report.md)

## Choose the evidence you have

| Input | What it can establish | Extra environment |
| --- | --- | --- |
| Source repository | Product signals, Privacy Manifests, target graph leads, configuration and policy risks. | Python 3.9+; Xcode optional. |
| `.xcarchive` | Final archived bundles, Mach-O, frameworks, entitlements/signing metadata, packaged manifests. | macOS/Xcode improves binary and signing coverage. |
| `.ipa` or exported `.app` | Exported payload closest to submission; inspected as untrusted input without launching binaries. | Python works cross-platform; macOS tools add evidence. |
| Simulator screenshots/`.xcresult` | Direct runtime evidence for an explicit device/OS/locale/appearance matrix. | Designated Simulator and test state; automation remains opt-in. |
| App Store Connect export/API inventory | Build, metadata, age-rating, IAP/subscription, screenshot, and privacy-answer comparisons. | Export preferred; API adapter is allowlisted GET-only. |

Use source first when that is all you have. Use the exact `.ipa` or `.xcarchive` intended for submission when packaging truth matters. Missing evidence is never counted as passed. A CLI report covers only the fragments supplied to `assemble`, so CI must also assert that every expected collector ran.

## Three-minute setup

From a trusted checkout:

```bash
python3 -m pip install --upgrade .
app-store-preflight-audit --version
```

Run the [Quick Start](docs/quick-start.md) for tested source, Archive, and GitHub Actions paths. CLI `--help` is the single source of truth for all parameters.

## First use with the Codex Skill

Start read-only and add stronger evidence progressively:

```text
$app-store-preflight-audit

Perform a read-only source audit first.
Do not build, run scripts, launch Simulator, or access App Store Connect.
Report coverage, every BLOCKED item, and the next evidence needed.
```

For a final artifact:

```text
Audit this .ipa at Archive level.
You may read Mach-O metadata, Info.plist, Privacy Manifest, and signing metadata,
but do not execute any packaged binary or modify signing state.
```

## Interfaces and boundaries

| Interface | Intended user | Responsibility |
| --- | --- | --- |
| CLI | Developers and CI | Deterministic collection, structured output, input/tool error status. |
| Codex Skill | Codex users | Select mode, orchestrate evidence, explain findings and missing coverage. |
| Python package | Integrators | Reuse scanner modules and parsers. |
| GitHub Actions | CI projects | Baseline diffs, canonical JSON, SARIF, and JUnit retention/gating. |

The project never guarantees Apple approval. Default collectors do not modify the audited repository or execute packaged binaries. Xcode execution is dry-run by default and requires explicit risk acknowledgement; App Store Connect access in this Skill is permanently read-only. Reports are not automatically safe to publish—redaction cannot recognize every proprietary identifier or personal detail.

Current beta limitations: complex Xcode project shapes may remain unresolved; real signing/runtime/ASC coverage depends on supplied tools and evidence; static symbol matches remain inferred; Apple rules and storefront exceptions must be checked at audit time.

## Community validation

Use the dedicated forms for [false positives](.github/ISSUE_TEMPLATE/false-positive.yml), [false negatives](.github/ISSUE_TEMPLATE/false-negative.yml), [Apple rule changes](.github/ISSUE_TEMPLATE/apple-rule-change.yml), and [new project shapes](.github/ISSUE_TEMPLATE/new-project-shape.yml). Public reports and artifacts may contain private metadata—submit only synthetic or manually verified, fully redacted evidence.

Verified Skill packaging, checksum/provenance, installation, and backed-up upgrade commands are documented in [installation and packaging](skill/app-store-preflight-audit/references/installation-and-packaging.md).

## Development

```bash
python3 -m unittest discover -s tests -v
python3 skill/app-store-preflight-audit/scripts/run_evals.py \
  --cases evals/cases.json --output /tmp/app-store-preflight-evals.json
python3 /path/to/quick_validate.py skill/app-store-preflight-audit
```

The test suite uses Python's standard library and does not require Xcode. Xcode-specific execution is guarded and dry-run by default.

See the [documentation path](docs/quick-start.md), [compatibility policy](COMPATIBILITY.md), [disclaimer](DISCLAIMER.md), [security policy](SECURITY.md), and [contribution guide](CONTRIBUTING.md).

## License

Apache-2.0. Apple, App Store, Xcode, iOS, iPadOS, macOS, watchOS, tvOS, and visionOS are trademarks of Apple Inc. Their use here is descriptive.
