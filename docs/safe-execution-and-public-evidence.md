# Safe execution and public evidence

[简体中文](safe-execution-and-public-evidence.zh-CN.md) | [Quick Start](quick-start.md)

This guide explains operational risk for users. [SECURITY.md](../SECURITY.md) remains the vulnerability-reporting and maintainer security policy.

## Default capability boundary

Source, privacy, Archive, local App Store Connect import, report assembly, and runtime-plan generation are read-only with respect to the audited project. They may write requested report files outside the project. Archive inspection never executes packaged binaries. The App Store Connect adapter sends allowlisted `GET` requests only and cannot upload, modify, price, submit, or message App Review.

Read-only does not mean “safe to publish.” Reports can still contain project metadata.

## What `--execute` changes

The `xcode` command is a dry-run plan unless `--execute` is supplied:

```bash
app-store-preflight-audit xcode \
  --root /path/to/repository \
  --project /path/to/repository/App.xcodeproj \
  --scheme App \
  --action build \
  --output-root /tmp/app-store-preflight-xcode \
  --evidence-output /tmp/app-store-preflight/xcode-plan.json
```

Inspect the capability/side-effect preview first. Execution also requires `--acknowledge-execution-risk`. Depending on the project, separate acknowledgements may be required for:

- `--allow-run-scripts`;
- `--allow-build-hooks` for Swift Package plugins, custom build tools/rules, or dependency hooks;
- `--allow-dependency-resolution`, which can access the network and change caches;
- `--allow-signing`, which can access signing identities or keychain-backed operations.

An executing Xcode build can run repository-controlled code. A Run Script, Package Plugin, custom build tool, CocoaPods hook, or dependency tool may access the network, developer caches, credentials available to the process, or paths outside the isolated build directory. The runner isolates build outputs and compares Git state before/after, but it cannot sandbox every side effect of arbitrary project code.

Never add acknowledgement flags merely to make a check pass. Inspect the detected capability, use a trusted revision, minimize credentials/network access, and run on a disposable CI host when possible.

## Other explicit tool access

- `target-graph --use-xcodebuild` runs Xcode metadata commands with automatic package resolution disabled. It does not build the app, but still invokes Xcode on the project.
- `archive --read-entitlements` and `archive --verify-signatures` invoke local read-only signing metadata commands.
- `runtime-plan --use-xcresulttool` reads a supplied `.xcresult`; runtime-plan generation alone does not boot or mutate Simulator.
- StoreKit, permission, and weak-network runtime observations require explicit authorization and a named dedicated test state. The tool does not create that state automatically.
- `asc-read` reads a pre-generated JWT from an environment variable. Never pass a token on the command line or save it in a report.

## What can appear in fragments and reports

Depending on supplied evidence, JSON/Markdown/SARIF/JUnit can contain:

- bundle identifiers, product/target/scheme names, and relative filenames;
- SDK/framework/library names and dependency versions;
- entitlement keys and sanitized values;
- App Store Connect app names, SKU, build/version inventory, age-rating answers, IAP/subscription metadata, and screenshot filenames;
- finding explanations, assumptions, reviewer-path details, and test-state descriptions;
- hashes and stable fingerprints that may correlate repeated reports;
- screenshot or `xcresult` inventory when imported.

Raw Archives, provisioning profiles, screenshots, ASC exports, and runtime observations can contain substantially more sensitive data than the normalized report.

## What redaction protects—and what it does not

Automatic redaction replaces recognized secret/token patterns and common absolute user/temp paths. Collectors prefer relative paths or path tokens, and signing fixtures sanitize common team identifiers.

Redaction cannot reliably recognize:

- a proprietary bundle ID, app/feature codename, server hostname, or customer name;
- custom credential formats or secrets embedded in arbitrary binary/text fields;
- personal information visible inside screenshots or review notes;
- sensitive meaning inferred from filenames, entitlement combinations, IAP identifiers, or hashes;
- data copied into free-form evidence by a custom integration.

Redaction reduces accidental disclosure; it never replaces manual review.

## Public Issue checklist

Before opening a public false-positive, false-negative, rule-change, or project-shape Issue:

- Reproduce with the smallest synthetic fixture whenever possible.
- Do not attach a real `.ipa`, `.xcarchive`, `.app`, `.xcresult`, provisioning profile, certificate, App Store Connect export, JWT, screenshot, or full audit report.
- Replace bundle IDs, team IDs, product names, domains, account names, paths, commit IDs, and review credentials with synthetic values.
- Remove source code unrelated to the reproduction.
- Inspect every JSON value, Markdown paragraph, SARIF property, JUnit message, filename, and embedded archive member.
- Confirm hashes/fingerprints are safe to disclose or regenerate them from synthetic content.
- State the tool version, schema version, platform/Xcode version, expected outcome, actual outcome, and why the evidence is synthetic or fully redacted.
- Use private vulnerability reporting for credential exposure, code execution, traversal, unsafe archive handling, or redaction bypasses.

When in doubt, describe the shape and state transition without uploading the original evidence.
