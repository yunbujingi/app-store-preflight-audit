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
- Detected Run Script build phases require explicit acknowledgement.
- Secret-like values are redacted from rendered reports.
- The skill never uploads, submits, purchases, deletes, resets, or remediates by implication.
- Policy snapshots accept only HTTPS `developer.apple.com` sources, cap response size, and retain hashes rather than copied page bodies.
- Simulator planning never boots, erases, installs, launches, grants permissions, or changes device state.
- The installer is dry-run-first, rejects archive traversal, and refuses to overwrite an existing Skill.
