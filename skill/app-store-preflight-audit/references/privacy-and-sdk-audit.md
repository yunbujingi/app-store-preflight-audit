# Privacy, permissions, tracking, AI, and SDK audit

Load this reference when any user data, system permission, network service, analytics, advertising, AI provider, or third-party SDK is present.

## Build the actual-data behavior map

For each data/API category identify:

| Field | Meaning |
| --- | --- |
| Producer | app target, extension, framework, SDK, backend |
| Trigger | user route or background event |
| Purpose | user-visible feature served |
| Destination | on-device, developer server, named third party |
| Retention | observed policy or `UNRESOLVED` |
| User control | consent, denial fallback, deletion/revocation |
| Declarations | purpose string, manifest, App Privacy, privacy policy, UI |

Compare behavior across all declarations. Do not treat PrivacyInfo, App Privacy labels, privacy policy, purpose strings, and consent UI as interchangeable.

## Privacy manifests and required-reason APIs

- Parse every packaged `PrivacyInfo.xcprivacy`, not only the source file with that name.
- Validate plist structure and expected key types.
- Map source API signals to target membership and declared approved reasons.
- Confirm reasons match the user-facing function; do not choose reasons merely to silence validation.
- For an embedded SDK, establish whether the SDK itself uses covered APIs or belongs to Apple's SDK list before declaring its absent manifest a failure.
- Archive evidence outranks repository layout for what is actually shipped.

Static patterns are leads. Comments, test fixtures, vendored samples, and unreachable code need filtering.

## Permissions

For each requested capability verify purpose, timing, accurate localized usage description, denial path, settings recovery, and whether the core app is improperly gated. Include photos/camera/microphone/location/contacts/calendar/Bluetooth/motion/health/local network/notifications/tracking and product-specific APIs.

Do not mark an unused plist key as a rejection solely because it exists; establish mismatch, misleading disclosure, or unexpected prompt risk.

## Tracking and SDKs

Inventory direct and transitive SDKs from source manifests and final archive. For each, record version, purpose, network behavior, data categories, manifest/signature evidence, tracking potential, and unresolved binary behavior.

An SDK name alone does not prove tracking. Determine actual configuration, domains, identifiers, data combination, and cross-company use. Conversely, developer responsibility is not limited to first-party source.

## Third-party AI

Identify data sent to each model/provider, including text, images, audio, identifiers, diagnostics, and contextual metadata. Verify pre-transfer disclosure, explicit permission when personal data is shared with a third-party AI, retention/training statements, revocation/deletion, failure behavior, safety boundaries, and reviewer accessibility.

Do not infer that using AI is itself a rejection risk.

## Secrets and report handling

Do not print full tokens, credentials, private keys, provisioning content, account passwords, user records, or signed request URLs. Evidence should contain relative path, line, secret type, and a redacted fingerprint only when necessary.
