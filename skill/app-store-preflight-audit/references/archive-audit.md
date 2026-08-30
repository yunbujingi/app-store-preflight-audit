# Archive-level audit

Repository inspection cannot establish final packaging. Use this reference for `.xcarchive`, exported `.app`, `.appex`, embedded framework, watch, widget, and other shipped bundles.

## Provenance

Record archive path fingerprint, creation time when available, Xcode/toolchain metadata, scheme/configuration if present, signing state, and whether the archive was supplied or created during this audit. Do not assume it corresponds to the current source revision without evidence.

## Bundle graph

Enumerate every shipped executable container:

- main `.app`;
- `.appex` extensions;
- watch apps/extensions;
- app clips;
- frameworks and XCFramework slices actually embedded;
- other executable bundles.

For each record bundle ID, display name, short/build version, supported platforms/device families, minimum OS, executable name, privacy manifest presence, embedded provisioning presence, and parsed entitlements when safely available.

Check uniqueness and parent/child consistency of identifiers and versions. Separate missing evidence from confirmed mismatch.

## Privacy and SDK evidence

- Parse every packaged privacy manifest.
- Associate a manifest with the bundle that contains it.
- Do not assume the app manifest covers third-party frameworks.
- List frameworks without manifests as inventory. Raise a failure only when covered API/data behavior or an applicable SDK requirement is established; otherwise use `NEEDS_VERIFY`.
- Treat a malformed packaged manifest as more serious than an unused source manifest because it affects the submitted artifact.

## Signing and entitlements

Use platform tools only in read mode. Never import, delete, or alter certificates or profiles. Compare requested entitlements, archive entitlements, embedded profile entitlements, and product capabilities where evidence is available.

Unsigned archives must be labeled `UNSIGNED_OR_UNVERIFIED`. Do not extrapolate upload validity.

## Resources and release integrity

Inspect final Info.plist values, icons, launch resources, localizations, URL/document types, ATS settings, background modes, debug artifacts, environment endpoints, and packaged test/sample assets. Archive checks should prefer actual bundle contents over source-file presence.

Never execute binaries from the archive.
