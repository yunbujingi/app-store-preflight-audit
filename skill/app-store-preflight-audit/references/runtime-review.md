# Runtime and five-minute reviewer review

Runtime claims require direct observation. Source inference alone cannot pass a runtime scenario.

## Test-state discipline

Use disposable or explicitly designated test state. Do not reset the user's simulator/device, delete accounts, alter production data, trigger real purchases, or upload personal content without authorization.

Record device model, OS, orientation, appearance, content size category, locale, network condition, account/data fixture, permissions, build configuration, and result for each run.

`scripts/simulator_review.py` creates the matrix without mutating any Simulator. Device, OS, locale, appearance, and Dynamic Type must all be explicit or the matrix is `BLOCKED`. It can optionally generate a reviewable `.xctestplan`, inventory screenshots, semantically import an exported JSON or explicitly authorized `xcresulttool` read, and list `simctl` inventory. It does not boot, erase, install, launch, grant permissions, change appearance, or manipulate network state. Missing observations remain `NOT_RUN`.

The generated test-plan environment variables document requested appearance and Dynamic Type for a human-reviewed harness; they do not themselves change Simulator settings. Record screenshots and `.xcresult` from the exact matrix run. StoreKit, permission, and weak-network observations require `authorized=true` plus a named dedicated `test_state`; otherwise force `BLOCKED`, even if the supplied result says `PASS`.

The default matrix covers fresh install, permission denial, dark appearance plus largest supported Dynamic Type, long/empty/loading/error states, and offline/weak/timeout networking. Add product-specific routes rather than marking defaults passed from source inspection.

## Applicability-driven scenarios

Start with fresh install and the primary value path. Add only applicable states:

- all optional permissions denied;
- no data and large data;
- offline, weak network, timeout, and server error;
- sign-in failure, sign-out/re-entry, account deletion;
- background termination and relaunch;
- dark mode, largest supported Dynamic Type, reduced motion, VoiceOver sampling;
- smallest/largest declared device classes, iPad multitasking, and declared orientations;
- purchase failure, cancellation, pending, restore, and existing entitlement;
- extension, widget, watch, notification, deep-link, and share entry points.

If a state cannot be created through supported product/test interfaces, mark it `BLOCKED`; do not add hidden production code or fake data to make the audit pass.

## Five-minute reviewer path

Independently assess:

1. Can a new reviewer understand the value from the first screen?
2. Can they reach and complete the core function?
3. Are permission and login requests contextual and recoverable?
4. Are loading, empty, denial, and failure states clear?
5. Are non-obvious features, hardware, IAP, AI, or credentials explained in review notes?

List the five strongest first-impression risks, but classify product polish separately from policy failure.
