#!/usr/bin/env python3
"""Inspect bundle structure and privacy evidence without executing archive code."""

from __future__ import annotations

import argparse
import plistlib
import shutil
import subprocess
from pathlib import Path

from _common import add_check, add_finding, new_fragment, read_plist, relpath, write_json

BUNDLE_SUFFIXES = {".app", ".appex", ".framework", ".xpc"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="Path to .xcarchive or exported .app")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--read-entitlements", action="store_true", help="Use codesign in read-only display mode")
    return parser.parse_args()


def bundle_info(bundle: Path, root: Path, read_entitlements: bool) -> tuple[dict, list[dict]]:
    findings: list[dict] = []
    info_path = bundle / "Info.plist"
    if bundle.suffix == ".framework" and not info_path.exists():
        info_path = bundle / "Resources" / "Info.plist"
    info: dict = {}
    error = None
    if info_path.exists():
        try:
            info = read_plist(info_path)
        except Exception as exc:
            error = str(exc)

    direct_manifests = []
    for candidate in bundle.rglob("PrivacyInfo.xcprivacy"):
        owning_bundle = next((parent for parent in candidate.parents if parent.suffix in BUNDLE_SUFFIXES), None)
        if owning_bundle == bundle:
            try:
                read_plist(candidate)
                direct_manifests.append({"path": relpath(candidate, root), "valid": True})
            except Exception as exc:
                direct_manifests.append({"path": relpath(candidate, root), "valid": False, "error": str(exc)})

    entitlements = None
    executable_name = info.get("CFBundleExecutable")
    executable = bundle / executable_name if isinstance(executable_name, str) else bundle
    if read_entitlements and shutil.which("codesign") and executable.exists():
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(executable)],
            check=False, capture_output=True, timeout=20,
        )
        raw = result.stdout or result.stderr
        start = raw.find(b"<?xml")
        if start >= 0:
            try:
                end = raw.find(b"</plist>", start)
                payload = raw[start:end + len(b"</plist>")] if end >= 0 else raw[start:]
                entitlements = plistlib.loads(payload)
            except Exception:
                entitlements = {"parse_error": True}

    return ({
        "path": relpath(bundle, root),
        "kind": bundle.suffix.lstrip("."),
        "bundle_identifier": info.get("CFBundleIdentifier"),
        "display_name": info.get("CFBundleDisplayName") or info.get("CFBundleName"),
        "short_version": info.get("CFBundleShortVersionString"),
        "build_version": info.get("CFBundleVersion"),
        "minimum_os": info.get("MinimumOSVersion") or info.get("LSMinimumSystemVersion"),
        "supported_platforms": info.get("CFBundleSupportedPlatforms", []),
        "device_family": info.get("UIDeviceFamily", []),
        "executable": executable_name,
        "info_plist_error": error,
        "privacy_manifests": direct_manifests,
        "embedded_provisioning_profile": (bundle / "embedded.mobileprovision").exists(),
        "entitlements": entitlements,
    }, findings)


def main() -> int:
    args = parse_args()
    archive = args.archive.resolve()
    if not archive.exists() or not archive.is_dir():
        raise SystemExit(f"archive/app is not a directory: {archive}")
    fragment = new_fragment("inspect_archive", "archive", archive)

    bundles = []
    if archive.suffix in BUNDLE_SUFFIXES:
        candidates = [archive]
    else:
        candidates = sorted((path for path in archive.rglob("*") if path.is_dir() and path.suffix in BUNDLE_SUFFIXES), key=str)

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        info, _ = bundle_info(candidate, archive, args.read_entitlements)
        bundles.append(info)
        if info["info_plist_error"]:
            add_finding(
                fragment, f"ARCHIVE-INFO-{len(bundles)}", "P0", "FAIL", "CONFIRMED", "Archive",
                "Packaged bundle has an unreadable Info.plist",
                "The final bundle metadata could not be parsed.",
                evidence=[{"path": info["path"], "detail": info["info_plist_error"]}],
                remediation="Rebuild the archive with a valid packaged Info.plist.",
            )
        for manifest in info["privacy_manifests"]:
            if not manifest["valid"]:
                add_finding(
                    fragment, f"ARCHIVE-PRIVACY-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Privacy",
                    "Packaged privacy manifest is malformed",
                    "A privacy manifest in the shipped bundle could not be parsed.",
                    authority_type="PRIVACY_REQUIREMENT",
                    authority_url="https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
                    evidence=[{"path": manifest["path"], "detail": manifest.get("error", "parse error")}],
                    remediation="Fix the source manifest and verify the rebuilt archive.",
                )

    apps = [item for item in bundles if item["kind"] == "app"]
    frameworks = [item for item in bundles if item["kind"] == "framework"]
    extensions = [item for item in bundles if item["kind"] == "appex"]
    fragment["data"] = {
        "artifact_type": archive.suffix.lstrip(".") or "directory",
        "bundles": bundles,
        "summary": {"apps": len(apps), "extensions": len(extensions), "frameworks": len(frameworks)},
        "frameworks_without_direct_privacy_manifest": [item["path"] for item in frameworks if not item["privacy_manifests"]],
        "entitlements_requested": args.read_entitlements,
        "entitlements_tool_available": bool(shutil.which("codesign")),
    }
    if apps:
        add_check(fragment, "ARCHIVE-001", "PASS", "At least one packaged app bundle was discovered.")
    else:
        add_check(fragment, "ARCHIVE-001", "FAIL", "No packaged app bundle was discovered.")
        add_finding(
            fragment, "ARCHIVE-NO-APP", "P0", "FAIL", "CONFIRMED", "Archive",
            "Artifact does not contain an app bundle",
            "The supplied artifact cannot be audited as an App Store app archive.",
            evidence=[{"path": archive.name, "detail": "No .app directory found"}],
            remediation="Provide the exact .xcarchive or exported .app intended for submission.",
        )
    invalid = any(not manifest["valid"] for item in bundles for manifest in item["privacy_manifests"])
    add_check(fragment, "ARCHIVE-002", "FAIL" if invalid else "PASS", "All discovered packaged privacy manifests were parsed.")
    if frameworks and any(not item["privacy_manifests"] for item in frameworks):
        add_check(
            fragment, "ARCHIVE-003", "NEEDS_VERIFY",
            "Some embedded frameworks do not contain a direct privacy manifest; applicability requires SDK/API evidence.",
            verification="UNRESOLVED",
            blocker="A missing framework manifest is not automatically noncompliant.",
        )
    else:
        add_check(fragment, "ARCHIVE-003", "PASS", "No unresolved embedded-framework manifest gap was discovered.")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
