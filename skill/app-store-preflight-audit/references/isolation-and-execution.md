# Isolation and executable checks

Builds and tests are allowed only as evidence collection, not remediation.

## Before execution

1. Record `git status --porcelain`, current revision, submodule state, and relevant lockfile hashes.
2. Identify project/workspace, exact scheme, configuration, destination, and test plan. Do not guess a scheme when multiple plausible choices exist.
3. Inspect `PBXShellScriptBuildPhase`, Swift package plugins, generators, CocoaPods phases, and custom wrappers. Treat them as untrusted code.
4. Select a new output root outside the repository. Do not use or delete the user's existing DerivedData.
5. State whether dependency downloads, signing, network calls, simulators, devices, Keychain, iCloud, notifications, IAP sandbox, or backend mutations may occur.

## Execution tiers

- Tier 0 — plan only: render the command, make no changes. Default for the bundled runner.
- Tier 1 — unsigned build: isolated DerivedData and source packages; signing disabled where compatible.
- Tier 2 — tests: dedicated simulator/device state; no simulator reset unless explicitly authorized.
- Tier 3 — archive/signing: requires explicit signing scope and must distinguish unsigned from distribution-representative output.
- Tier 4 — external validation: uploads, App Store Connect mutations, purchases, account creation/deletion, and reviewer messages require separate explicit authorization and are outside the default audit.

## Invariants

- Use argument arrays, not shell interpolation, for paths, schemes, and destinations.
- Keep all result bundles, logs, archives, package clones, and DerivedData under the isolated output root.
- Do not run `git clean`, `git reset`, destructive simulator commands, Keychain deletion, or broad filesystem cleanup.
- Apply timeouts and preserve the exact exit status.
- After execution, compare Git status and lockfile hashes. If the repository changed, raise a P0 safety finding and stop. Do not revert automatically.
- Report build, unit test, UI test, archive, signing, and upload validation independently.

## Interpreting results

- `BUILD SUCCEEDED` proves only the invoked action and destination succeeded.
- A skipped test is not a pass.
- An unsigned archive does not validate signing or App Store upload acceptance.
- A simulator result does not establish behavior that depends on camera, Bluetooth, HealthKit, push delivery, StoreKit production state, or other hardware/service constraints.
- Warnings require classification; deprecation alone is not automatically a rejection risk.
