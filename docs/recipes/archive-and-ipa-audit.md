# Recipe: Archive and IPA audit

[简体中文](archive-and-ipa-audit.zh-CN.md) | [Quick Start](../quick-start.md)

Use this recipe when you have the candidate that will be distributed: an `.xcarchive`, exported `.app`, or `.ipa`. Archive evidence is stronger than source inference for packaging questions, but it still cannot prove runtime behavior or Apple approval.

## Choose the artifact

| Input | Best use | Important limitation |
| --- | --- | --- |
| `.xcarchive` | Inspect Xcode's archived products, bundles, signing metadata, and archive context. | It may not be the exact export later uploaded. |
| `.ipa` | Inspect the exported payload closest to the upload artifact. | Some archive context is absent; ZIP contents are treated as untrusted. |
| exported `.app` | Inspect one final app bundle during local investigation. | It may omit export packaging and sibling products. |
| source repository | Explain origin and target membership. | It cannot prove final packaging. |

Prefer the exact artifact intended for submission and record how it was produced. Do not attach a real artifact to a public Issue.

## Basic read-only audit

```bash
mkdir -p /tmp/app-store-preflight

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

The scanner validates ZIP traversal, symlinks, compression ratios, file counts, and size budgets before reading an IPA. It parses bundles, Info.plists, Privacy Manifests, Mach-O metadata, embedded frameworks/dylibs, XCFramework containers, versions, platform/deployment information, and obvious debug/test resources. It never executes packaged binaries.

## Entitlements and signatures

On macOS, opt into read-only local signing tools:

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.xcarchive \
  --read-entitlements \
  --verify-signatures \
  --output /tmp/app-store-preflight/archive.json
```

`--read-entitlements` uses `codesign` display mode and, when available, read-only profile decoding. `--verify-signatures` checks the supplied artifact but never imports certificates, changes profiles, or re-signs code. Missing tools or unsigned fixtures produce limitations or blockers, not a pass.

Sanitized signing fixtures exist for reproducible tests only. They validate comparison logic and never prove a real signature.

## Xcode Privacy Report

If Xcode generated a Privacy Report for the exact candidate, import it:

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.xcarchive \
  --privacy-report /path/to/PrivacyReport.json \
  --output /tmp/app-store-preflight/archive.json
```

The scanner normalizes known report shapes and compares bundle identities, SDK names, and required-reason categories with packaged evidence. Supply the report when SDK aggregation or Xcode's view is needed to resolve a gap; do not assume a report from another build applies. Unknown schema fields remain inferred or unresolved.

## Target graph and Link Map

An Archive can show that a final executable contains a symbol or library identity, but static-library source ownership requires linker/project evidence. Add a target graph and Link Map fragment:

```bash
app-store-preflight-audit target-graph \
  --root /path/to/repository \
  --workspace App.xcworkspace \
  --configuration Release \
  --link-map /path/to/App-LinkMap-normal-arm64.txt \
  --output /tmp/app-store-preflight/target-graph.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/archive.json \
  --input /tmp/app-store-preflight/target-graph.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md
```

Without a Link Map, final executable ownership for linked static-library members remains unresolved. The scanner must not guess from filenames alone.

## Interpret symbol findings correctly

Mach-O byte strings and undefined symbols are static leads. They may include dead, unreachable, compatibility, or wrapper code and therefore use `INFERRED` evidence. Confirm reachability and purpose before changing a Privacy Manifest. A symbol match cannot choose an approved reason for you.

## Completion checklist

- The artifact is the intended submission/export.
- Every packaged app, extension, App Clip, Watch product, framework, and dylib appears in inventory.
- Malformed packaged manifests and confirmed bundle/signing mismatches are resolved.
- `NEEDS_VERIFY` symbol/SDK leads have a documented human decision.
- Missing Link Map, signing tools, Privacy Report, runtime, or App Store Connect evidence is visible as a limitation—not silently treated as passed.
- Reports have been manually reviewed before sharing.
