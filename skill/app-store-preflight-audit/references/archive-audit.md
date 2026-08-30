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

Inspect each packaged executable without launching it. Record Mach-O detection, architectures when `lipo` is available, dynamic dependencies from `otool`, undefined-symbol evidence from `nm`, and read-only signature verification when explicitly requested. A tool failure is evidence limitation, not proof that a binary is invalid.

Check uniqueness and parent/child consistency of identifiers and versions. Separate missing evidence from confirmed mismatch.

## Privacy and SDK evidence

- Parse every packaged privacy manifest.
- Associate a manifest with the bundle that contains it.
- Do not assume the app manifest covers third-party frameworks.
- List frameworks without manifests as inventory. Raise a failure only when covered API/data behavior or an applicable SDK requirement is established; otherwise use `NEEDS_VERIFY`.
- Treat a malformed packaged manifest as more serious than an unused source manifest because it affects the submitted artifact.
- Compare binary required-reason API leads with the manifest in the same containing app or SDK bundle. Apple requires each executable or dynamic library that uses a covered API to be declared by its containing bundle; an app-level declaration must not silently cover an embedded SDK.
- Byte strings and undefined symbols remain `INFERRED` until reachability and actual purpose are established. Never select an approved reason from symbol evidence alone.
- Compare discovered framework names with Apple's current third-party SDK requirements at audit time. Do not freeze Apple's changing SDK list into the Skill.

## Signing and entitlements

Use platform tools only in read mode. Never import, delete, or alter certificates or profiles. Compare requested entitlements, archive entitlements, embedded profile entitlements, and product capabilities where evidence is available.

Unsigned archives must be labeled `UNSIGNED_OR_UNVERIFIED`. Do not extrapolate upload validity.

When entitlements are readable, cross-check `application-identifier` suffixes against bundle IDs and review parent/extension capability consistency. Never print signing identities, team member names, certificates, or provisioning payloads.

## Resources and release integrity

Inspect final Info.plist values, icons, launch resources, localizations, URL/document types, ATS settings, background modes, debug artifacts, environment endpoints, and packaged test/sample assets. Archive checks should prefer actual bundle contents over source-file presence.

Never execute binaries from the archive.
