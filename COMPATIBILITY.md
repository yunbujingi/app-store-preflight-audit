# Compatibility

## Schema

The `v0.2.0-beta` tools emit schema `0.2.0`. `assemble_report.py` accepts both `0.1.0` and `0.2.0` fragments so existing collectors can migrate incrementally. Consumers must treat unknown major schema versions as unsupported.

Additive optional fields may appear in minor releases. Removing or renaming fields, changing field types, tightening required fields, or redefining disposition/verification semantics requires a major schema version.

## Runtime

- Python 3.9 or later; helper scripts use only the standard library.
- Archive metadata works cross-platform at the plist/byte level. `file`, `lipo`, `otool`, `nm`, `codesign`, `xcrun`, and `xcodebuild` evidence is conditional on macOS/Xcode availability.
- `run_isolated_xcode.py` remains dry-run by default.
- `simulator_review.py` never mutates Simulator state.

## Pre-1.0 policy

Beta CLI flags may change with a changelog entry. Safety boundaries, schema changes, and evidence-state semantics are never changed silently.
