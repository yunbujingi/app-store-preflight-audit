# App Store Connect verification

App Store Connect checks are read-only unless the user separately authorizes a specific mutation. Never submit, edit metadata, alter availability/pricing, or message App Review by implication.

## Evidence sources

Use, in descending confidence: authorized read-only API/connector results, user-supplied App Store Connect export/screenshots, repository metadata files, then developer assertions. Label the source and observation time.

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
