#!/usr/bin/env python3
"""Create a deterministic Skill zip and optional SHA-256 checksum."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

EXCLUDED_NAMES = {".DS_Store", "__pycache__"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--checksum-output", type=Path)
    parser.add_argument("--provenance-output", type=Path)
    parser.add_argument("--version", default="0.3.0-beta")
    return parser.parse_args()


def inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def main() -> int:
    args = parse_args()
    skill = args.skill.resolve()
    output = args.output.resolve()
    if not (skill / "SKILL.md").is_file():
        raise SystemExit("skill directory must contain SKILL.md")
    if inside(output, skill):
        raise SystemExit("package output must be outside the skill directory")
    if args.checksum_output and inside(args.checksum_output.resolve(), skill):
        raise SystemExit("checksum output must be outside the skill directory")
    if args.provenance_output and inside(args.provenance_output.resolve(), skill):
        raise SystemExit("provenance output must be outside the skill directory")
    files = [
        path for path in skill.rglob("*")
        if path.is_file() and not path.is_symlink() and not any(part in EXCLUDED_NAMES for part in path.parts)
    ]
    file_records = [
        {
            "path": path.relative_to(skill).as_posix(),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }
        for path in sorted(files, key=lambda item: item.relative_to(skill).as_posix())
    ]
    provenance = {
        "format": "app-store-preflight-skill-provenance-v1",
        "name": skill.name,
        "version": args.version,
        "license": "Apache-2.0",
        "reproducible": True,
        "files": file_records,
    }
    provenance_bytes = (json.dumps(provenance, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(skill).as_posix()):
            relative = Path(skill.name) / path.relative_to(skill)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        provenance_info = zipfile.ZipInfo(f"{skill.name}/PROVENANCE.json", date_time=(1980, 1, 1, 0, 0, 0))
        provenance_info.compress_type = zipfile.ZIP_DEFLATED
        provenance_info.create_system = 3
        provenance_info.external_attr = (0o644 & 0xFFFF) << 16
        archive.writestr(provenance_info, provenance_bytes, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    temporary.replace(output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    if args.checksum_output:
        checksum = args.checksum_output.resolve()
        checksum.parent.mkdir(parents=True, exist_ok=True)
        checksum.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    if args.provenance_output:
        provenance_output = args.provenance_output.resolve()
        provenance_output.parent.mkdir(parents=True, exist_ok=True)
        provenance_output.write_bytes(provenance_bytes)
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
