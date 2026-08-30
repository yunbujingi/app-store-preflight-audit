#!/usr/bin/env python3
"""Safely install a Skill directory or packaged zip without overwriting an existing Skill."""

from __future__ import annotations

import argparse
import json
import shutil
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination-root", required=True, type=Path)
    parser.add_argument("--install", action="store_true", help="Perform installation; default prints a dry-run plan")
    return parser.parse_args()


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
    plan = {"source": source.name, "destination": str(destination), "will_install": args.install}
    print(json.dumps(plan, ensure_ascii=False))
    if not args.install:
        return 0
    if destination.exists():
        raise SystemExit(f"destination already exists; refusing to overwrite: {destination}")
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
        prepared.rename(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
