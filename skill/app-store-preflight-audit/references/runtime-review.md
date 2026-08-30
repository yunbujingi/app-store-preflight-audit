# Runtime and five-minute reviewer review

Runtime claims require direct observation. Source inference alone cannot pass a runtime scenario.

## Test-state discipline

Use disposable or explicitly designated test state. Do not reset the user's simulator/device, delete accounts, alter production data, trigger real purchases, or upload personal content without authorization.

Record device model, OS, orientation, appearance, content size category, locale, network condition, account/data fixture, permissions, build configuration, and result for each run.

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
