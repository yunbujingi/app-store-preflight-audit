# Quick Start: your first audit in ten minutes

[简体中文](quick-start.zh-CN.md) | [Project README](../README.md)

App Store Preflight Audit is an unofficial readiness scanner. It does not submit an app, modify App Store Connect, or predict Apple's decision. Start with the least invasive evidence you have, then add stronger evidence only when a finding or coverage gap needs it.

## Install and verify

Requirements: Python 3.9 or later. Xcode is optional for source-only collection and required only for Xcode metadata, signing tools, builds, or Simulator evidence.

From a trusted checkout:

```bash
python3 -m pip install --upgrade .
app-store-preflight-audit --version
```

The examples below write only to `/tmp/app-store-preflight`. Create it once:

```bash
mkdir -p /tmp/app-store-preflight
```

## Path A: you only have source code

Use this first. It reads repository files and Git metadata; it does not build, resolve packages, execute scripts, or launch Simulator.

```bash
app-store-preflight-audit inventory \
  --root /path/to/repository \
  --output /tmp/app-store-preflight/inventory.json

app-store-preflight-audit privacy \
  --root /path/to/repository \
  --output /tmp/app-store-preflight/privacy.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/inventory.json \
  --input /tmp/app-store-preflight/privacy.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md
```

Generated files:

- `inventory.json` and `privacy.json`: collector fragments;
- `audit.json`: canonical structured report;
- `audit.md`: human-readable report.

The run is complete for this declared source scope when both collector fragments and both reports exist, and every included check has a disposition. The assembler does not invent checks for fragments you did not supply: absent Archive, runtime, or App Store Connect layers are outside this CLI report, not passed. Record them as `NOT_RUN` or `BLOCKED` in the Skill/human review, and make CI assert its expected collector list. Source-only completion does not mean submission readiness is fully proven.

Recommended Skill prompt:

```text
$app-store-preflight-audit

Perform a read-only source audit first.
Do not build, run scripts, launch Simulator, or access App Store Connect.
Report coverage, every BLOCKED item, and the next evidence needed.
```

## Path B: you have an `.xcarchive`, `.ipa`, or exported `.app`

Archive evidence is closer to the submitted product because it contains final bundles, executables, Info.plists, embedded frameworks, and packaged Privacy Manifests.

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.ipa \
  --output /tmp/app-store-preflight/archive.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/archive.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md \
  --sarif-output /tmp/app-store-preflight/audit.sarif \
  --junit-output /tmp/app-store-preflight/audit.xml
```

The default Archive command never launches packaged binaries. On macOS it uses available read-only binary metadata tools; add `--read-entitlements` or `--verify-signatures` only when you intend to use local signing tools. See the [Archive/IPA recipe](recipes/archive-and-ipa-audit.md) for Privacy Reports, Link Maps, and evidence limits.

Recommended Skill prompt:

```text
Audit this .ipa at Archive level.
You may read Mach-O metadata, Info.plist, Privacy Manifest, and signing metadata,
but do not execute any packaged binary or modify signing state.
```

## Path C: you want GitHub Actions

First produce and review a stable local report. Store it as a CI baseline only after confirming that it represents the intended revision and audit scope. Then use the assembler's `--baseline` and reviewed `--suppressions` inputs to highlight new or changed findings.

Follow the [CI baseline and suppression recipe](recipes/ci-baseline-and-suppression.md). CI should retain canonical JSON, SARIF, and JUnit artifacts; it must not silently treat `BLOCKED` as `PASS`.

## What to read next

- [Understanding the report](understanding-the-report.md): evidence, dispositions, verdict, and coverage.
- [Safe execution and public evidence](safe-execution-and-public-evidence.md): `--execute`, project hooks, redaction limits, and an Issue checklist.
- [Archive and IPA audit](recipes/archive-and-ipa-audit.md): final-artifact evidence.
- [CI baseline and suppression](recipes/ci-baseline-and-suppression.md): actionable PR diffs without hiding findings.
- [Synthetic sample report](../examples/sample-report.md).
