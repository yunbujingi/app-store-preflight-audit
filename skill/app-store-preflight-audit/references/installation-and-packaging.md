# Installation and deterministic packaging

Create a reproducible archive with:

```bash
python3 scripts/package_skill.py --skill /path/to/app-store-preflight-audit \
  --output /tmp/app-store-preflight-audit.zip \
  --checksum-output /tmp/app-store-preflight-audit.zip.sha256
```

The packager sorts entries, normalizes timestamps and permissions, excludes caches and symlinks, and prints SHA-256. Output must be outside the Skill directory.

Preview installation before allowing writes:

```bash
python3 scripts/install_skill.py --source /tmp/app-store-preflight-audit.zip \
  --destination-root /path/to/skills
```

Add `--install` only after inspecting the destination. The installer rejects path traversal, requires one top-level Skill folder and `SKILL.md`, and refuses to overwrite an existing Skill. Updating an installed copy requires a separate user-authorized backup/removal decision.
