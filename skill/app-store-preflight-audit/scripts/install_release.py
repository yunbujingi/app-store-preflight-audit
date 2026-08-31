#!/usr/bin/env python3
"""Download, verify, and install or upgrade an immutable GitHub Release Skill asset."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

from _common import sha256_bytes
try:
    from .install_skill import main as install_skill_main
except ImportError:  # Direct execution from the Skill scripts directory.
    from install_skill import main as install_skill_main

ALLOWED_DOWNLOAD_HOST_SUFFIXES = ("github.com", "githubusercontent.com")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="Immutable release tag, for example v0.3.0-beta")
    parser.add_argument("--destination-root", required=True, type=Path)
    parser.add_argument("--repository", required=True, help="GitHub owner/repository; never inferred or embedded")
    parser.add_argument("--install", action="store_true", help="Perform installation; default verifies and previews")
    parser.add_argument("--upgrade", action="store_true", help="Preserve the current Skill as a timestamped backup")
    parser.add_argument("--minisign-public-key", help="Verify the optional release .minisig with this trusted public key")
    parser.add_argument("--max-download-size", type=int, default=100_000_000)
    return parser.parse_args()


def validate_release(args: argparse.Namespace) -> None:
    if not re.fullmatch(r"v[0-9A-Za-z][0-9A-Za-z._-]{0,99}", args.version):
        raise ValueError("version must be an explicit immutable v-prefixed release tag")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        raise ValueError("repository must be GitHub owner/repository")
    if args.upgrade and not args.install:
        raise ValueError("--upgrade requires --install")
    if not 1_024 <= args.max_download_size <= 1_000_000_000:
        raise ValueError("max-download-size is outside the supported safety range")


def download(url: str, output: Path, max_size: int) -> None:
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream", "User-Agent": "app-store-preflight-audit"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            hostname = final.hostname or ""
            if final.scheme != "https" or not any(hostname == suffix or hostname.endswith("." + suffix) for suffix in ALLOWED_DOWNLOAD_HOST_SUFFIXES):
                raise ValueError("release download redirected outside the GitHub asset origin")
            payload = response.read(max_size + 1)
    except urllib.error.HTTPError as error:
        raise ValueError(f"release asset returned HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise ValueError(f"release asset download failed: {error.reason}") from error
    if len(payload) > max_size:
        raise ValueError("release asset exceeded max-download-size")
    output.write_bytes(payload)


def main() -> int:
    args = parse_args()
    try:
        validate_release(args)
        base = f"https://github.com/{args.repository}/releases/download/{args.version}"
        with tempfile.TemporaryDirectory(prefix="app-store-preflight-release-") as temporary:
            root = Path(temporary)
            package = root / "app-store-preflight-audit.zip"
            checksum = root / "app-store-preflight-audit.zip.sha256"
            provenance = root / "app-store-preflight-audit.provenance.json"
            download(f"{base}/{package.name}", package, args.max_download_size)
            download(f"{base}/{checksum.name}", checksum, 4_096)
            download(f"{base}/{provenance.name}", provenance, 10_000_000)
            expected = checksum.read_text(encoding="utf-8").strip().split()[0].lower()
            actual = sha256_bytes(package.read_bytes())
            if expected != actual:
                raise ValueError("release package checksum mismatch")
            external_provenance = json.loads(provenance.read_text(encoding="utf-8"))
            if external_provenance.get("version") != args.version:
                raise ValueError("release provenance version does not match the requested tag")
            with zipfile.ZipFile(package) as archive:
                embedded = json.loads(archive.read("app-store-preflight-audit/PROVENANCE.json"))
            if embedded != external_provenance:
                raise ValueError("embedded and detached provenance records differ")
            signature = None
            if args.minisign_public_key:
                signature = root / "app-store-preflight-audit.zip.minisig"
                download(f"{base}/{signature.name}", signature, 100_000)
            install_arguments = [
                "install_skill.py", "--source", str(package), "--checksum-file", str(checksum),
                "--destination-root", str(args.destination_root),
            ]
            if args.install:
                install_arguments.append("--install")
            if args.upgrade:
                install_arguments.append("--upgrade")
            if signature and args.minisign_public_key:
                install_arguments.extend(["--minisign-signature", str(signature), "--minisign-public-key", args.minisign_public_key])
            previous = sys.argv
            try:
                sys.argv = install_arguments
                return install_skill_main()
            finally:
                sys.argv = previous
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile, KeyError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    raise SystemExit(main())
