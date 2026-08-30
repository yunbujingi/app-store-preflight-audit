#!/usr/bin/env python3
"""Inspect bundle, Mach-O, SDK, privacy, entitlement, and signature evidence without executing code."""

from __future__ import annotations

import argparse
import plistlib
import shutil
import subprocess
from pathlib import Path

from _common import add_check, add_finding, new_fragment, read_plist, relpath, write_json

BUNDLE_SUFFIXES = {".app", ".appex", ".framework", ".xpc"}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}
REQUIRED_REASON_BINARY_PATTERNS = {
    "NSPrivacyAccessedAPICategoryUserDefaults": (b"NSUserDefaults", b"UserDefaults"),
    "NSPrivacyAccessedAPICategoryFileTimestamp": (b"statfs", b"fstatat", b"getattrlist"),
    "NSPrivacyAccessedAPICategoryDiskSpace": (b"volumeAvailableCapacity", b"systemFreeSize"),
    "NSPrivacyAccessedAPICategorySystemBootTime": (b"systemUptime", b"kern.boottime", b"mach_absolute_time"),
    "NSPrivacyAccessedAPICategoryActiveKeyboards": (b"activeInputModes",),
}
PRIVACY_KEYS = {
    "NSPrivacyTracking", "NSPrivacyTrackingDomains", "NSPrivacyCollectedDataTypes",
    "NSPrivacyAccessedAPITypes",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="Path to .xcarchive or exported .app")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--read-entitlements", action="store_true", help="Use codesign in read-only display mode")
    parser.add_argument("--skip-binary-tools", action="store_true", help="Skip file/lipo/otool/nm; byte-level inspection still runs")
    parser.add_argument("--verify-signatures", action="store_true", help="Run codesign verification in read-only mode")
    return parser.parse_args()


def readonly_tool(command: list[str], timeout: int = 20) -> dict:
    if not shutil.which(command[0]):
        return {"available": False, "return_code": None, "output": ""}
    try:
        result = subprocess.run(command, check=False, capture_output=True, timeout=timeout)
        raw = (result.stdout or b"") + (result.stderr or b"")
        return {"available": True, "return_code": result.returncode, "output": raw.decode("utf-8", "replace")[:20000].strip()}
    except (OSError, subprocess.SubprocessError) as error:
        return {"available": True, "return_code": None, "output": str(error)}


def info_plist_path(bundle: Path) -> Path:
    candidates = [bundle / "Info.plist", bundle / "Contents" / "Info.plist", bundle / "Resources" / "Info.plist"]
    return next((path for path in candidates if path.exists()), candidates[0])


def executable_path(bundle: Path, executable_name: object) -> Path | None:
    if not isinstance(executable_name, str) or not executable_name:
        return None
    candidates = [bundle / executable_name, bundle / "Contents" / "MacOS" / executable_name]
    return next((path for path in candidates if path.is_file()), candidates[0])


def manifest_info(candidate: Path, root: Path) -> dict:
    result: dict = {"path": relpath(candidate, root), "valid": False, "required_reason_categories": {}}
    try:
        value = read_plist(candidate)
        unknown = sorted(set(value) - PRIVACY_KEYS)
        if unknown:
            raise ValueError(f"unexpected root keys: {', '.join(unknown)}")
        tracking = value.get("NSPrivacyTracking", False)
        domains = value.get("NSPrivacyTrackingDomains", [])
        collected = value.get("NSPrivacyCollectedDataTypes", [])
        if not isinstance(tracking, bool):
            raise ValueError("NSPrivacyTracking must be a Boolean")
        if not isinstance(domains, list) or not all(isinstance(domain, str) for domain in domains):
            raise ValueError("NSPrivacyTrackingDomains must be an array of strings")
        if domains and not tracking:
            raise ValueError("tracking domains require NSPrivacyTracking=true")
        if not isinstance(collected, list):
            raise ValueError("NSPrivacyCollectedDataTypes must be an array")
        accessed = value.get("NSPrivacyAccessedAPITypes", [])
        if not isinstance(accessed, list):
            raise ValueError("NSPrivacyAccessedAPITypes must be an array")
        categories: dict[str, list[str]] = {}
        for index, item in enumerate(accessed):
            if not isinstance(item, dict):
                raise ValueError(f"NSPrivacyAccessedAPITypes[{index}] must be a dictionary")
            category = item.get("NSPrivacyAccessedAPIType")
            reasons = item.get("NSPrivacyAccessedAPITypeReasons")
            if not isinstance(category, str) or not isinstance(reasons, list) or not reasons or not all(isinstance(reason, str) and reason for reason in reasons):
                raise ValueError(f"invalid required-reason declaration at index {index}")
            categories[category] = sorted(set(reasons))
        result.update({"valid": True, "required_reason_categories": categories})
    except Exception as error:
        result["error"] = str(error)
    return result


def binary_info(executable: Path | None, root: Path, skip_tools: bool, verify_signatures: bool) -> dict:
    result: dict = {
        "path": relpath(executable, root) if executable else None,
        "exists": bool(executable and executable.is_file()),
        "is_macho": False,
        "architectures": [],
        "dynamic_dependencies": [],
        "required_reason_api_signals": {},
        "signature": {"status": "NOT_RUN"},
    }
    if not executable or not executable.is_file():
        return result
    try:
        payload = executable.read_bytes()
    except OSError as error:
        result["read_error"] = str(error)
        return result
    result["is_macho"] = payload[:4] in MACHO_MAGICS
    if result["is_macho"]:
        for category, patterns in REQUIRED_REASON_BINARY_PATTERNS.items():
            matches = sorted({pattern.decode("ascii") for pattern in patterns if pattern in payload})
            if matches:
                result["required_reason_api_signals"][category] = matches
    if not skip_tools and result["is_macho"]:
        file_result = readonly_tool(["file", "-b", str(executable)])
        result["file_description"] = file_result
        lipo = readonly_tool(["lipo", "-archs", str(executable)])
        if lipo["return_code"] == 0:
            result["architectures"] = lipo["output"].split()
        otool = readonly_tool(["otool", "-L", str(executable)])
        if otool["return_code"] == 0:
            result["dynamic_dependencies"] = [
                line.strip().split(" (", 1)[0]
                for line in otool["output"].splitlines()[1:]
                if line.strip()
            ]
        nm = readonly_tool(["nm", "-u", str(executable)])
        if nm["return_code"] == 0:
            symbol_text = nm["output"].encode("utf-8", "replace")
            for category, patterns in REQUIRED_REASON_BINARY_PATTERNS.items():
                matches = sorted({pattern.decode("ascii") for pattern in patterns if pattern in symbol_text})
                if matches:
                    existing = result["required_reason_api_signals"].setdefault(category, [])
                    result["required_reason_api_signals"][category] = sorted(set(existing + matches))
    if verify_signatures:
        verification = readonly_tool(["codesign", "--verify", "--strict", "--verbose=2", str(executable)])
        result["signature"] = {
            "status": "VALID" if verification["return_code"] == 0 else ("TOOL_UNAVAILABLE" if not verification["available"] else "INVALID_OR_UNSIGNED"),
            "return_code": verification["return_code"],
        }
    return result


def bundle_info(bundle: Path, root: Path, read_entitlements: bool, skip_tools: bool,
                verify_signatures: bool) -> dict:
    info_path = info_plist_path(bundle)
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
                direct_manifests.append(manifest_info(candidate, root))
            except Exception as exc:
                direct_manifests.append({"path": relpath(candidate, root), "valid": False, "error": str(exc), "required_reason_categories": {}})

    entitlements = None
    executable_name = info.get("CFBundleExecutable")
    executable = executable_path(bundle, executable_name)
    if read_entitlements and shutil.which("codesign") and executable and executable.exists():
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

    return {
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
        "binary": binary_info(executable, root, skip_tools, verify_signatures),
    }


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
        info = bundle_info(candidate, archive, args.read_entitlements, args.skip_binary_tools, args.verify_signatures)
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

        declared_categories = {
            category
            for manifest in info["privacy_manifests"] if manifest["valid"]
            for category in manifest["required_reason_categories"]
        }
        binary_categories = set(info["binary"]["required_reason_api_signals"])
        missing_categories = sorted(binary_categories - declared_categories)
        if missing_categories:
            add_finding(
                fragment, f"ARCHIVE-REASON-{len(bundles)}", "P1", "NEEDS_VERIFY", "INFERRED", "Privacy",
                "Packaged binary required-reason API signals lack a direct declaration",
                "Byte and symbol evidence in a shipped executable indicates covered API categories that are not declared by a valid privacy manifest in the containing bundle.",
                authority_type="PRIVACY_REQUIREMENT",
                authority_url="https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api",
                evidence=[{"path": info["binary"]["path"] or info["path"], "detail": ", ".join(missing_categories)}],
                remediation="Confirm reachable shipped API use and add accurate approved reasons to the same app or SDK bundle; do not copy reasons without validating purpose.",
                assumptions=["Static binary strings and undefined symbols can over-approximate reachable API use."],
            )
        entitlement_identifier = info["entitlements"].get("application-identifier") if isinstance(info["entitlements"], dict) else None
        if isinstance(entitlement_identifier, str) and info["bundle_identifier"] and not entitlement_identifier.endswith(f".{info['bundle_identifier']}"):
            add_finding(
                fragment, f"ARCHIVE-ENTITLEMENT-{len(bundles)}", "P1", "FAIL", "CONFIRMED", "Signing",
                "Application identifier entitlement does not match the bundle identifier",
                "The signed executable entitlement is inconsistent with its packaged Info.plist bundle identifier.",
                evidence=[{"path": info["path"], "detail": "application-identifier suffix mismatch"}],
                remediation="Reconcile target bundle ID, provisioning profile, and signing entitlements, then create a new archive.",
            )

    apps = [item for item in bundles if item["kind"] == "app"]
    frameworks = [item for item in bundles if item["kind"] == "framework"]
    extensions = [item for item in bundles if item["kind"] == "appex"]
    bundle_by_path = {item["path"]: item for item in bundles}
    dynamic_libraries = []
    for index, library in enumerate(sorted(archive.rglob("*.dylib")), 1):
        binary = binary_info(library, archive, args.skip_binary_tools, args.verify_signatures)
        owner_path = next(
            (relpath(parent, archive) for parent in library.parents if parent.suffix in BUNDLE_SUFFIXES),
            None,
        )
        owner = bundle_by_path.get(owner_path or "")
        declared = {
            category
            for manifest in (owner or {}).get("privacy_manifests", []) if manifest["valid"]
            for category in manifest["required_reason_categories"]
        }
        missing = sorted(set(binary["required_reason_api_signals"]) - declared)
        item = {"path": relpath(library, archive), "containing_bundle": owner_path, "binary": binary, "missing_required_reason_categories": missing}
        dynamic_libraries.append(item)
        if missing:
            add_finding(
                fragment, f"ARCHIVE-DYLIB-REASON-{index}", "P1", "NEEDS_VERIFY", "INFERRED", "Privacy",
                "Packaged dynamic library API signals lack a containing-bundle declaration",
                "A standalone shipped dynamic library contains required-reason API leads not declared by the privacy manifest of its containing bundle.",
                authority_type="PRIVACY_REQUIREMENT",
                authority_url="https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api",
                evidence=[{"path": relpath(library, archive), "detail": ", ".join(missing)}],
                remediation="Confirm shipped use and add accurate approved reasons to the containing bundle or SDK package.",
                assumptions=["Static binary evidence can over-approximate reachable API use."],
            )
    fragment["data"] = {
        "artifact_type": archive.suffix.lstrip(".") or "directory",
        "bundles": bundles,
        "summary": {"apps": len(apps), "extensions": len(extensions), "frameworks": len(frameworks)},
        "macho_executables": [item["binary"]["path"] for item in bundles if item["binary"]["is_macho"]],
        "dynamic_dependencies": sorted({dependency for item in bundles for dependency in item["binary"]["dynamic_dependencies"]}),
        "required_reason_binary_signals": {
            item["path"]: item["binary"]["required_reason_api_signals"]
            for item in bundles if item["binary"]["required_reason_api_signals"]
        },
        "standalone_dynamic_libraries": dynamic_libraries,
        "frameworks_without_direct_privacy_manifest": [item["path"] for item in frameworks if not item["privacy_manifests"]],
        "entitlements_requested": args.read_entitlements,
        "entitlements_tool_available": bool(shutil.which("codesign")),
        "binary_tools_skipped": args.skip_binary_tools,
        "signature_verification_requested": args.verify_signatures,
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
    missing_reason_count = sum(
        1 for item in fragment["findings"]
        if item["id"].startswith(("ARCHIVE-REASON-", "ARCHIVE-DYLIB-REASON-"))
    )
    add_check(
        fragment, "ARCHIVE-004", "NEEDS_VERIFY" if missing_reason_count else "PASS",
        "Packaged executable required-reason API signals were cross-checked against direct bundle manifests.",
        verification="INFERRED" if missing_reason_count else "CONFIRMED",
        blocker="Static binary evidence requires reachability and approved-reason confirmation." if missing_reason_count else None,
    )
    if args.read_entitlements:
        parsed = sum(isinstance(item["entitlements"], dict) and not item["entitlements"].get("parse_error") for item in bundles)
        add_check(
            fragment, "ARCHIVE-005", "PASS" if parsed else "BLOCKED",
            f"Parsed entitlements for {parsed} packaged executable(s)." if parsed else "No packaged entitlements could be parsed.",
            blocker=None if parsed else "codesign may be unavailable, or the artifact may be unsigned.",
        )
    else:
        add_check(fragment, "ARCHIVE-005", "NOT_RUN", "Entitlement extraction was not requested.", blocker="Pass --read-entitlements for read-only extraction.")
    if args.verify_signatures:
        statuses = [item["binary"]["signature"]["status"] for item in bundles if item["binary"]["exists"]]
        disposition = "PASS" if statuses and all(status == "VALID" for status in statuses) else "FAIL"
        add_check(fragment, "ARCHIVE-006", disposition, "Packaged executable signatures were verified in read-only mode.")
    else:
        add_check(fragment, "ARCHIVE-006", "NOT_RUN", "Signature verification was not requested.", blocker="Pass --verify-signatures to run codesign --verify.")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
