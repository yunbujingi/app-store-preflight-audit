# Security Policy

## Supported versions

Security fixes are applied to the latest release line. Pre-1.0 releases may receive breaking fixes when a safe audit boundary requires them.

## Report a vulnerability

Do not open a public issue for vulnerabilities that could expose credentials, execute untrusted repository code, modify audited repositories, or leak report contents. Use GitHub's private vulnerability reporting feature when enabled. If it is unavailable, contact the maintainers through a private channel listed in the repository profile.

Include the affected version, reproduction steps using non-sensitive fixtures, impact, and a proposed containment step. Never include real signing certificates, provisioning profiles, tokens, App Store Connect credentials, or user data.

## Security model

- Repository source and build scripts are untrusted audit inputs.
- Helper scripts never execute app binaries.
- Archive tools invoke only read-only metadata commands (`file`, `lipo`, `otool`, `nm`, and explicitly requested `codesign` inspection/verification) with timeouts.
- Xcode execution is dry-run by default and refuses output inside the audited repository.
- Detected Run Script phases, custom build rules, Swift Package plugins/build commands, and dependency hooks require explicit acknowledgement.
- Every executable Xcode request emits a tokenized capability/side-effect preview and requires explicit acknowledgement.
- Secret-like values and absolute user/temp paths are redacted from all JSON fragments and rendered reports.
- `.ipa`, plist, Mach-O, source, and App Store Connect import collectors enforce file-count and size budgets and reject symlink/path traversal.
- The App Store Connect API adapter obtains JWTs only from an environment variable, fixes requests to the official Apple HTTPS origin, disables redirects, sends GET only, bounds pagination, and emits only reviewed allowlist fields. Generated ASC fragments may still contain private app metadata and must not be committed or attached publicly.
- The skill never uploads, submits, purchases, deletes, resets, or remediates by implication.
- Policy snapshots accept only HTTPS `developer.apple.com` sources, cap response size, and retain hashes rather than copied page bodies.
- Simulator planning never boots, erases, installs, launches, grants permissions, or changes device state.
- The installer is dry-run-first, rejects archive traversal, verifies optional checksums/signatures, refuses implicit overwrite, and preserves the prior Skill as a timestamped backup for explicit upgrades. Release installation verifies embedded and detached provenance before writing.
- GitHub Actions are pinned to full commit SHAs; release asset upload refuses name collisions instead of clobbering existing files.
