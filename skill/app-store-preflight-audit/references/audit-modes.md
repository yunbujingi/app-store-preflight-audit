# Audit modes and coverage

Choose the narrowest mode that satisfies the user's request. A higher mode includes the evidence layers below it only when their prerequisites are available.

## Source

Read-only repository inspection. Inventory products, targets, capabilities, dependencies, data flows, permissions, account/payment/AI/UGC signals, release flags, metadata files, and reviewer paths inferable from code.

Prerequisites: readable source repository.

Never claim: successful compilation, final bundle contents, runtime behavior, server availability, signing validity, or App Store Connect state.

## Build

Source mode plus isolated dependency resolution when authorized, Debug/Release build, unit tests, and explicitly requested UI tests.

Prerequisites: macOS, compatible Xcode/toolchain, a known project/workspace and scheme, safe build-script review, and an output directory outside the repository. UI tests also require a disposable simulator/device and destination.

Never claim: App Store-valid signing or archive state from an unsigned build.

## Archive

Inspect an existing archive or create one when separately authorized. Audit final bundles, extensions, embedded frameworks, manifests, versions, architectures, signatures, entitlements, and packaged resources.

Prerequisites: supplied `.xcarchive`/`.app`, or Build prerequisites plus archive/signing inputs. Unsigned and signed archive results must be distinguished.

Never claim: upload acceptance unless an actual upload validation result is supplied.

## Submission

Archive mode plus reviewer-path runtime checks and App Store Connect evidence. Review metadata, screenshots, privacy answers, age rating, IAP/subscription items, review credentials, review notes, storefront availability, agreements, and server access.

Prerequisites vary. Read-only App Store Connect access, screenshots, reviewer account, sandbox products, real hardware, or backend access may be needed. Missing access is `BLOCKED`, not `PASS`.

## Capability matrix

Record each layer independently:

| Layer | Example prerequisite | If absent |
| --- | --- | --- |
| Source | readable repository | `BLOCKED` |
| Policy | current official Apple page | `NEEDS_VERIFY` for time-sensitive conclusions |
| Build | Xcode + scheme | `NOT_RUN` |
| Unit test | runnable test plan | `NOT_RUN` |
| UI test | disposable destination | `NOT_RUN` |
| Archive | archive/signing inputs | `NOT_RUN` or `BLOCKED` |
| Runtime | launchable build and controllable state | `NOT_RUN` |
| App Store Connect | supplied export or authorized read access | `BLOCKED` |

## Exit criteria

An audit is complete for its declared scope when:

1. Every discovered applicable check has one disposition.
2. Every `FAIL`, `NEEDS_VERIFY`, and `BLOCKED` item names the evidence or authority needed next.
3. Commands actually run, commands only planned, and user-supplied assertions are distinguishable.
4. Repository state was checked before and after any executable step.
5. Coverage is reported per layer. Do not turn coverage into an Apple approval probability.
