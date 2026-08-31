# Compatibility

## Schema

The `v0.3.0-beta` development tools emit schema `0.3.0`. `assemble_report.py`, eval loading, and policy-registry validation accept `0.1.0`, `0.2.0`, and `0.3.0` inputs so existing collectors can migrate incrementally. Consumers must treat unknown major schema versions as unsupported.

Additive optional fields may appear in minor releases. `v0.3.0-beta` adds target-graph, archive, runtime-evidence, read-only ASC, and provenance fields while preserving prior input schemas. After the beta line stabilizes, removing or renaming fields, changing field types, tightening required fields, or redefining disposition/verification semantics requires a major schema version.

## Runtime

- Python 3.9 or later; helper scripts use only the standard library.
- The scanner is distributed as a pure-Python wheel and the Skill zip contains the same source files. A `setup.py` compatibility shim supports the older setuptools bundled with macOS Python 3.9.
- Archive metadata works cross-platform at the plist/byte level. `file`, `lipo`, `otool`, `nm`, `codesign`, `xcrun`, and `xcodebuild` evidence is conditional on macOS/Xcode availability.
- `.ipa` extraction rejects symlinks/traversal and enforces configurable file and size budgets.
- `run_isolated_xcode.py` remains dry-run by default; execution requires capability acknowledgement and separate build-hook acknowledgement when applicable.
- `simulator_review.py` never mutates Simulator state; generated XCTest plans require human review and do not imply execution.

## Pre-1.0 policy

Beta CLI flags may change with a changelog entry. Safety boundaries, schema changes, and evidence-state semantics are never changed silently.
