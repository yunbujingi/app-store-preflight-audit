#!/usr/bin/env python3
"""Run the documented source, Archive, and CI command paths against an installed CLI."""

from __future__ import annotations

import argparse
import json
import plistlib
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "evals" / "fixtures" / "minimal-app"
SUPPRESSIONS = ROOT / "examples" / "suppressions.example.json"


def run(cli: Path, *arguments: str) -> None:
    result = subprocess.run(
        [str(cli), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {cli.name} {' '.join(arguments)}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )


def assert_report(path: Path, expected_tool: str) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != "0.3.0":
        raise AssertionError(f"unexpected schema version in {path}")
    fragments = value.get("fragments", [])
    if not any(item.get("tool") == expected_tool for item in fragments):
        raise AssertionError(f"{expected_tool} fragment missing from {path}")
    if value.get("verdict") not in {"GO", "CONDITIONAL_GO", "NO_GO"}:
        raise AssertionError(f"unexpected verdict in {path}")
    return value


def make_synthetic_ipa(path: Path) -> None:
    info = plistlib.dumps({
        "CFBundleIdentifier": "org.example.DocumentationFixture",
        "CFBundleExecutable": "DocumentationFixture",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "CFBundleSupportedPlatforms": ["iPhoneOS"],
        "MinimumOSVersion": "17.0",
    })
    privacy = plistlib.dumps({
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyAccessedAPITypes": [],
    })
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("Payload/DocumentationFixture.app/Info.plist", info)
        archive.writestr("Payload/DocumentationFixture.app/PrivacyInfo.xcprivacy", privacy)
        archive.writestr("Payload/DocumentationFixture.app/DocumentationFixture", b"\xcf\xfa\xed\xfe")


def smoke(cli: Path) -> None:
    if not cli.is_file():
        raise SystemExit(f"installed CLI does not exist: {cli}")
    with tempfile.TemporaryDirectory(prefix="app-store-preflight-docs-") as temporary:
        output = Path(temporary)
        source = output / "source"
        source.mkdir()

        inventory = source / "inventory.json"
        privacy = source / "privacy.json"
        audit = source / "audit.json"
        run(cli, "inventory", "--root", str(FIXTURE), "--output", str(inventory))
        run(cli, "privacy", "--root", str(FIXTURE), "--output", str(privacy))
        run(
            cli, "assemble", "--input", str(inventory), "--input", str(privacy),
            "--json-output", str(audit), "--markdown-output", str(source / "audit.md"),
            "--sarif-output", str(source / "audit.sarif"),
            "--junit-output", str(source / "audit.xml"),
        )
        assert_report(audit, "project_inventory")
        json.loads((source / "audit.sarif").read_text(encoding="utf-8"))
        ET.parse(source / "audit.xml")

        ipa = output / "DocumentationFixture.ipa"
        archive_fragment = output / "archive.json"
        archive_report = output / "archive-audit.json"
        make_synthetic_ipa(ipa)
        run(cli, "archive", "--archive", str(ipa), "--output", str(archive_fragment))
        run(
            cli, "assemble", "--input", str(archive_fragment),
            "--json-output", str(archive_report),
            "--markdown-output", str(output / "archive-audit.md"),
            "--sarif-output", str(output / "archive-audit.sarif"),
            "--junit-output", str(output / "archive-audit.xml"),
        )
        assert_report(archive_report, "inspect_archive")

        compared = output / "compared-audit.json"
        run(
            cli, "assemble", "--input", str(inventory), "--input", str(privacy),
            "--baseline", str(audit), "--suppressions", str(SUPPRESSIONS),
            "--json-output", str(compared),
            "--markdown-output", str(output / "compared-audit.md"),
            "--sarif-output", str(output / "compared-audit.sarif"),
            "--junit-output", str(output / "compared-audit.xml"),
        )
        compared_value = assert_report(compared, "inspect_privacy_manifests")
        if not compared_value.get("triage", {}).get("baseline_used"):
            raise AssertionError("baseline comparison was not recorded")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path, help="Path to an installed app-store-preflight-audit executable")
    args = parser.parse_args()
    smoke(args.cli.resolve())
    print("Documented CLI paths passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
