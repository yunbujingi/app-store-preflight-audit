#!/usr/bin/env python3
"""Safely install a Skill directory or packaged zip without overwriting an existing Skill."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination-root", required=True, type=Path)
    parser.add_argument("--install", action="store_true", help="Perform installation; default prints a dry-run plan")
    parser.add_argument("--upgrade", action="store_true", help="Replace an installed Skill after moving it to a timestamped backup")
    parser.add_argument("--checksum-file", type=Path, help="Verify a SHA-256 checksum file before installation")
    parser.add_argument("--minisign-signature", type=Path, help="Optionally verify a minisign signature for the source zip")
    parser.add_argument("--minisign-public-key", help="Trusted minisign public key used with --minisign-signature")
    return parser.parse_args()


def verify_checksum(source: Path, checksum_file: Path) -> str:
    if not source.is_file():
        raise ValueError("checksum verification requires a packaged file source")
    expected = checksum_file.read_text(encoding="utf-8").strip().split()[0].lower()
    if len(expected) != 64 or any(character not in "0123456789abcdef" for character in expected):
        raise ValueError("checksum file does not begin with a SHA-256 digest")
    actual = hashlib.sha256(source.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError("source SHA-256 does not match checksum file")
    return actual


def verify_minisign(source: Path, signature: Path, public_key: str) -> None:
    executable = shutil.which("minisign")
    if not executable:
        raise ValueError("minisign is unavailable")
    result = subprocess.run(
        [executable, "-Vm", str(source), "-x", str(signature), "-P", public_key],
        check=False, capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise ValueError("minisign verification failed")


def safe_zip(zip_path: Path, staging: Path) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        items = [item for item in archive.infolist() if not item.is_dir()]
        names = [PurePosixPath(item.filename) for item in items]
        if not names or any(path.is_absolute() or ".." in path.parts for path in names):
            raise ValueError("zip contains an unsafe path")
        if any(((item.external_attr >> 16) & 0o170000) == 0o120000 for item in items):
            raise ValueError("zip symlinks are not accepted")
        roots = {path.parts[0] for path in names}
        if len(roots) != 1:
            raise ValueError("zip must contain exactly one top-level Skill directory")
        archive.extractall(staging)
    return staging / next(iter(roots))


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    destination_root = args.destination_root.resolve()
    if args.upgrade and not args.install:
        raise SystemExit("--upgrade requires --install")
    if bool(args.minisign_signature) != bool(args.minisign_public_key):
        raise SystemExit("--minisign-signature and --minisign-public-key must be supplied together")
    verification = {"sha256": "NOT_REQUESTED", "minisign": "NOT_REQUESTED"}
    try:
        if args.checksum_file:
            verification["sha256"] = verify_checksum(source, args.checksum_file.resolve())
        if args.minisign_signature and args.minisign_public_key:
            if not source.is_file():
                raise ValueError("minisign verification requires a packaged file source")
            verify_minisign(source, args.minisign_signature.resolve(), args.minisign_public_key)
            verification["minisign"] = "VERIFIED"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error)) from error
    if source.is_dir():
        if any(path.is_symlink() for path in source.rglob("*")):
            raise SystemExit("source Skill contains a symlink; refusing installation")
        skill = source
        name = source.name
    elif source.is_file() and source.suffix == ".zip":
        with tempfile.TemporaryDirectory(prefix="skill-install-inspect-") as temporary:
            skill = safe_zip(source, Path(temporary))
            name = skill.name
            if not (skill / "SKILL.md").is_file():
                raise SystemExit("package does not contain SKILL.md")
    else:
        raise SystemExit("source must be a Skill directory or .zip")
    destination = destination_root / name
    backup = destination_root / f"{name}.backup-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    plan = {
        "source": source.name,
        "destination": str(destination),
        "will_install": args.install,
        "upgrade": args.upgrade,
        "backup": str(backup) if args.upgrade and destination.exists() else None,
        "verification": verification,
    }
    print(json.dumps(plan, ensure_ascii=False))
    if not args.install:
        return 0
    if destination.exists() and not args.upgrade:
        raise SystemExit(f"destination already exists; refusing to overwrite; pass --upgrade to preserve it as a backup: {destination}")
    if args.upgrade and not destination.exists():
        raise SystemExit(f"cannot upgrade a missing destination: {destination}")
    if backup.exists():
        raise SystemExit(f"backup destination already exists: {backup}")
    destination_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{name}-install-", dir=destination_root) as temporary:
        staging = Path(temporary)
        if source.is_dir():
            prepared = staging / name
            shutil.copytree(source, prepared, symlinks=False, ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"))
        else:
            prepared = safe_zip(source, staging)
        if not (prepared / "SKILL.md").is_file():
            raise SystemExit("prepared Skill is missing SKILL.md")
        moved_existing = False
        try:
            if destination.exists():
                destination.rename(backup)
                moved_existing = True
            prepared.rename(destination)
        except OSError:
            if moved_existing and not destination.exists() and backup.exists():
                backup.rename(destination)
            raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
