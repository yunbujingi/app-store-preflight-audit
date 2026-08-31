# App Store Connect verification

App Store Connect checks in this Skill are permanently read-only. Upload, metadata mutation, pricing/availability changes, submission, and App Review messaging are outside this Skill even when another workflow may be separately authorized.

## Evidence sources

Use, in descending confidence: authorized read-only API/connector results, user-supplied App Store Connect export/screenshots, repository metadata files, then developer assertions. Label the source and observation time.

Prefer local, user-exported JSON/plist evidence first. `inspect_asc_export.py` fingerprints imported documents, records field presence without exposing review-note or demo credential values, and can compare bundle ID/version/build with an Archive fragment. Its capability record must remain read-only: no network, upload, edit, or submit.

`fetch_asc_readonly.py` is the optional API adapter. It accepts a pre-generated JWT only through an environment variable, fixes the origin to `https://api.appstoreconnect.apple.com`, sends `GET` only, disables redirects, bounds pagination/response size, and emits only resource IDs plus attributes listed in `asc-read-allowlist.json`. It supports offline response fixtures for evals. Never log the token or response fields outside the allowlist.

The allowlist covers app identity, build inventory, app info/age-rating declarations, IAP, subscription groups/subscriptions, App Store versions/localizations, and screenshot sets/screenshots. App Privacy answers do not have an enabled documented endpoint in this allowlist; import a user export and mark the API portion `BLOCKED` or `NEEDS_VERIFY` rather than scraping App Store Connect.

## App version

Verify selected build, platform version, name/subtitle/description/keywords/promotional text, screenshots/previews, category, age rating, privacy policy/support/marketing URLs, copyright, export compliance, availability, release method, and App Privacy answers.

Compare every claim with the exact submitted build. Missing App Store Connect access is `BLOCKED`; repository copy is not proof of live metadata.

## Submission items

Inventory each item submitted with or separately from the version: IAP, subscription, in-app event, custom product page, product page test, Game Center item, or other current item type. Verify reviewability and metadata independently.

## Review access

Confirm contact details, demo account, passwords/OTP path, special hardware, geography, backend availability, feature flags, IAP visibility, non-obvious entry points, and review instructions. Never put secrets in the public audit report.

## Review notes

Draft concise notes that describe how to reach core and hidden functionality, permission purposes, account/IAP/AI prerequisites, special hardware, and known environment constraints. Unknown facts use `[DEVELOPER INPUT REQUIRED: ...]`; never invent credentials or successful behavior.

## Manual checklist boundary

Only list facts that could not be verified. Do not duplicate completed checks in a generic manual checklist.
