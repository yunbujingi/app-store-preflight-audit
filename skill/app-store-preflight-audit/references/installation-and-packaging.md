# CLI, installation, and deterministic packaging

The scanner and Skill share one source tree. Install the Python package and its single CLI locally with:

```bash
python3 -m pip install --upgrade .
app-store-preflight-audit --version
```

The Skill remains the thin orchestration and progressive-reference layer; collector logic is callable through the `app-store-preflight-audit` CLI or directly from `scripts/`.

Create a reproducible archive with:

```bash
python3 scripts/package_skill.py --skill /path/to/app-store-preflight-audit \
  --output /tmp/app-store-preflight-audit.zip \
  --checksum-output /tmp/app-store-preflight-audit.zip.sha256 \
  --provenance-output /tmp/app-store-preflight-audit.provenance.json
```

The packager sorts entries, normalizes timestamps and permissions, excludes caches and symlinks, embeds a per-file `PROVENANCE.json`, emits an optional detached copy, and prints SHA-256. Output must be outside the Skill directory.

Preview installation before allowing writes:

```bash
python3 scripts/install_skill.py --source /tmp/app-store-preflight-audit.zip \
  --checksum-file /tmp/app-store-preflight-audit.zip.sha256 \
  --destination-root /path/to/skills
```

Add `--install` only after inspecting the destination. The installer rejects path traversal, requires one top-level Skill folder and `SKILL.md`, and refuses to overwrite an existing Skill. An explicit `--install --upgrade` moves the current installation to a timestamped, recoverable backup before replacing it. Optional `--minisign-signature` plus a trusted `--minisign-public-key` verifies maintainer signatures when a release supplies one.

After installing the scanner CLI, one command can download an immutable GitHub tag, verify checksum plus embedded/detached provenance, and preview or perform Skill installation:

```bash
app-store-preflight-audit install-release --repository OWNER/app-store-preflight-audit \
  --version v0.3.0-beta \
  --destination-root /path/to/skills
```

Add `--install` for a new install or `--install --upgrade` for a backed-up upgrade. The repository is explicit so forks do not silently contact the original maintainer. The command accepts only explicit v-prefixed tags and bounded HTTPS GitHub release assets; it never follows provenance to execute code.
