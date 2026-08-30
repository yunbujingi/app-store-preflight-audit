# Apple policy freshness and regional routing

Do not embed the full Apple rules. Retrieve applicable official pages at audit time and record the URL and retrieval date.

## Primary official routes

- App Review Guidelines: `https://developer.apple.com/app-store/review/guidelines/`
- App Review overview: `https://developer.apple.com/app-store/review/`
- App Store Connect Help: `https://developer.apple.com/help/app-store-connect/`
- Privacy manifests: `https://developer.apple.com/documentation/bundleresources/privacy-manifest-files`
- Required-reason APIs: `https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api`
- Human Interface Guidelines: `https://developer.apple.com/design/human-interface-guidelines/`
- Upcoming submission requirements: locate the current page under Apple Developer News or App Store Connect Help; do not reuse an old SDK/Xcode deadline.

Use only current `developer.apple.com` pages as authority for policy findings. Developer forums, blogs, issue trackers, and prior rejection anecdotes can suggest checks but cannot settle the rule.

## Freshness record

For each material rule conclusion record:

- official URL;
- retrieval date and timezone;
- guideline/section identifier when one exists;
- relevant platform and OS;
- storefront assumption;
- whether the page was successfully retrieved;
- any interpretation or exception that remains unresolved.

If network access is unavailable, disclose the latest locally verified date. Mark policy-sensitive claims `NEEDS_VERIFY`; technical facts directly observed may remain `CONFIRMED`.

## Regional and program variables

Never make a global commerce conclusion until these are known or explicitly marked unknown:

- storefronts selected for distribution;
- developer legal-entity country/region;
- app category and business model;
- whether goods/services are digital or consumed outside the app;
- reader, multiplatform, enterprise, education, marketplace, or other applicable category;
- StoreKit external-purchase or other entitlements;
- alternative distribution terms;
- age-rating and regulated-industry requirements.

US storefront, EU storefronts, and other storefronts may have different external-purchase/link rules. State the exact scope of any conclusion.

## Policy changes and maintenance

- Prefer stable rule IDs in findings, but never assume unchanged wording.
- Do not silently update a stored rule snapshot. Policy behavior changes require a project release note and eval coverage.
- Do not copy Apple documentation wholesale into this project.
- When current pages conflict with local references or model memory, current official pages win.

Use `scripts/record_policy_snapshot.py` to store URL, UTC retrieval time, content SHA-256, storefronts, platforms, HTTP metadata when available, and `NEW`/`UNCHANGED`/`CHANGED` status. It accepts only HTTPS pages on `developer.apple.com`, limits responses to 10 MB, and stores no copied page body. A changed hash requires human review because layout or navigation changes can also change the page.
