#!/usr/bin/env python3
"""Inspect bundle, Mach-O, SDK, privacy, entitlement, and signature evidence without executing code."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import plistlib
import re
import stat
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from _common import add_check, add_finding, new_fragment, read_plist, relpath, sha256_bytes, write_json

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
    parser.add_argument("--privacy-report", type=Path, help="Optional Xcode-generated privacy report (JSON or plist)")
    parser.add_argument("--sanitized-signing-fixture", type=Path,
                        help="Offline JSON/plist fixture containing only bundle paths and sanitized entitlement dictionaries")
    parser.add_argument("--max-files", type=int, default=50_000)
    parser.add_argument("--max-total-size", type=int, default=2_000_000_000)
    parser.add_argument("--max-file-size", type=int, default=500_000_000)
    parser.add_argument("--max-binary-scan-size", type=int, default=64_000_000)
    return parser.parse_args()


def load_signing_fixtures(path: Path | None, max_file_size: int) -> dict[str, dict]:
    if not path:
        return {}
    resolved = path.resolve()
    if resolved.is_symlink() or not resolved.is_file() or resolved.stat().st_size > max_file_size:
        raise ValueError("sanitized signing fixture is unavailable or exceeds the file-size limit")
    payload = resolved.read_bytes()
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = plistlib.loads(payload)
    records = value.get("bundles") if isinstance(value, dict) else None
    if not isinstance(records, list):
        raise ValueError("sanitized signing fixture must contain a bundles array")
    result = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError("each sanitized signing fixture record needs a relative bundle path")
        bundle_path = Path(record["path"])
        if bundle_path.is_absolute() or ".." in bundle_path.parts:
            raise ValueError("sanitized signing fixture bundle path must be relative and traversal-free")
        allowed = {"path", "signed_entitlements", "profile_entitlements"}
        if set(record) - allowed:
            raise ValueError("sanitized signing fixture contains unsupported fields")
        for key in ("signed_entitlements", "profile_entitlements"):
            if key in record and not isinstance(record[key], dict):
                raise ValueError(f"{key} must be a dictionary")
        result[bundle_path.as_posix()] = record
    return result


def safe_zip_extract(source: Path, destination: Path, max_files: int,
                     max_total_size: int, max_file_size: int) -> dict:
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        files = [item for item in entries if not item.is_dir()]
        if len(files) > max_files:
            raise ValueError(f"IPA file count exceeds limit ({max_files})")
        total = sum(item.file_size for item in files)
        if total > max_total_size:
            raise ValueError(f"IPA uncompressed size exceeds limit ({max_total_size})")
        for item in entries:
            parts = Path(item.filename).parts
            mode = item.external_attr >> 16
            if item.filename.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe IPA member path: {item.filename}")
            if stat.S_ISLNK(mode):
                raise ValueError(f"symlink IPA member is not allowed: {item.filename}")
            if item.file_size > max_file_size:
                raise ValueError(f"IPA member exceeds size limit: {item.filename}")
            if item.compress_size and item.file_size / item.compress_size > 200:
                raise ValueError(f"IPA member compression ratio is unsafe: {item.filename}")
            target = destination.joinpath(*parts)
            try:
                target.resolve().relative_to(destination.resolve())
            except ValueError as error:
                raise ValueError(f"IPA member escapes extraction root: {item.filename}") from error
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(item) as incoming, target.open("wb") as outgoing:
                shutil.copyfileobj(incoming, outgoing, length=1024 * 1024)
        return {"file_count": len(files), "total_uncompressed_size": total}


def safe_artifact_inventory(root: Path, max_files: int, max_total_size: int,
                            max_file_size: int) -> tuple[list[Path], list[Path], int]:
    files: list[Path] = []
    directories: list[Path] = []
    total = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(dirs):
            candidate = current_path / name
            if candidate.is_symlink():
                raise ValueError(f"symlink directory is not allowed in artifact: {relpath(candidate, root)}")
            directories.append(candidate)
        for name in sorted(names):
            candidate = current_path / name
            if candidate.is_symlink():
                raise ValueError(f"symlink file is not allowed in artifact: {relpath(candidate, root)}")
            size = candidate.stat().st_size
            if size > max_file_size:
                raise ValueError(f"artifact member exceeds size limit: {relpath(candidate, root)}")
            total += size
            files.append(candidate)
            if len(files) > max_files:
                raise ValueError(f"artifact file count exceeds limit ({max_files})")
            if total > max_total_size:
                raise ValueError(f"artifact total size exceeds limit ({max_total_size})")
    return sorted(files), sorted(directories), total


def readonly_tool(command: list[str], timeout: int = 20, max_output: int = 20000) -> dict:
    if not shutil.which(command[0]):
        return {"available": False, "return_code": None, "output": ""}
    try:
        result = subprocess.run(command, check=False, capture_output=True, timeout=timeout)
        raw = (result.stdout or b"") + (result.stderr or b"")
        return {"available": True, "return_code": result.returncode, "output": raw.decode("utf-8", "replace")[:max_output].strip()}
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


def binary_info(executable: Path | None, root: Path, skip_tools: bool,
                verify_signatures: bool, max_scan_size: int) -> dict:
    result: dict = {
        "path": relpath(executable, root) if executable else None,
        "exists": bool(executable and executable.is_file()),
        "is_macho": False,
        "architectures": [],
        "dynamic_dependencies": [],
        "dynamic_dependency_records": [],
        "install_names": [],
        "required_reason_api_signals": {},
        "required_reason_signal_evidence": [],
        "build_versions": [],
        "signature": {"status": "NOT_RUN"},
    }
    if not executable or not executable.is_file():
        return result
    try:
        with executable.open("rb") as handle:
            payload = handle.read(max_scan_size + 1)
    except OSError as error:
        result["read_error"] = str(error)
        return result
    result["binary_scan_truncated"] = len(payload) > max_scan_size
    payload = payload[:max_scan_size]
    result["is_macho"] = payload[:4] in MACHO_MAGICS
    if result["is_macho"]:
        for category, patterns in REQUIRED_REASON_BINARY_PATTERNS.items():
            matches = sorted({pattern.decode("ascii") for pattern in patterns if pattern in payload})
            if matches:
                result["required_reason_api_signals"][category] = matches
                result["required_reason_signal_evidence"].append({
                    "category": category, "source": "binary-bytes",
                    "executable": result["path"], "matches": matches, "confidence": "LOW",
                })
    if not skip_tools and result["is_macho"]:
        file_result = readonly_tool(["file", "-b", str(executable)])
        result["file_description"] = file_result
        lipo = readonly_tool(["lipo", "-archs", str(executable)])
        if lipo["return_code"] == 0:
            result["architectures"] = lipo["output"].split()
        otool = readonly_tool(["otool", "-L", str(executable)])
        if otool["return_code"] == 0:
            for line in otool["output"].splitlines()[1:]:
                if not line.strip():
                    continue
                dependency, _, detail = line.strip().partition(" (")
                record = {"path": dependency}
                versions = re.search(r"compatibility version ([^,]+), current version ([^)]+)", detail)
                if versions:
                    record.update({"compatibility_version": versions.group(1), "current_version": versions.group(2)})
                result["dynamic_dependencies"].append(dependency)
                result["dynamic_dependency_records"].append(record)
        install_name = readonly_tool(["otool", "-D", str(executable)])
        if install_name["return_code"] == 0:
            result["install_names"] = [line.strip() for line in install_name["output"].splitlines()[1:] if line.strip()]
        load_commands = readonly_tool(["otool", "-l", str(executable)], max_output=2_000_000)
        if load_commands["return_code"] == 0:
            blocks = load_commands["output"].split("Load command ")[1:]
            for block in blocks:
                command_match = re.search(r"(?m)^\s*cmd\s+(LC_[A-Z0-9_]+)", block)
                command_name = command_match.group(1) if command_match else None
                legacy_platforms = {
                    "LC_VERSION_MIN_IPHONEOS": "ios", "LC_VERSION_MIN_MACOSX": "macos",
                    "LC_VERSION_MIN_TVOS": "tvos", "LC_VERSION_MIN_WATCHOS": "watchos",
                }
                if command_name != "LC_BUILD_VERSION" and command_name not in legacy_platforms:
                    continue
                record = {"source_command": command_name}
                key_names = ("platform", "minos", "sdk") if command_name == "LC_BUILD_VERSION" else ("version", "sdk")
                for key in key_names:
                    match = re.search(rf"(?m)^\s*{key}\s+([^\s]+)", block)
                    if match:
                        record[key] = match.group(1)
                if command_name in legacy_platforms:
                    record["platform"] = legacy_platforms[command_name]
                    record["minos"] = record.pop("version", None)
                record["normalized_platform"] = normalized_platform(record.get("platform"))
                record["minimum_os"] = normalize_version(record.get("minos"))
                record["sdk_version"] = normalize_version(record.get("sdk"))
                if record:
                    result["build_versions"].append(record)
        nm = readonly_tool(["nm", "-u", str(executable)])
        if nm["return_code"] == 0:
            symbol_text = nm["output"].encode("utf-8", "replace")
            for category, patterns in REQUIRED_REASON_BINARY_PATTERNS.items():
                matches = sorted({pattern.decode("ascii") for pattern in patterns if pattern in symbol_text})
                if matches:
                    existing = result["required_reason_api_signals"].setdefault(category, [])
                    result["required_reason_api_signals"][category] = sorted(set(existing + matches))
                    result["required_reason_signal_evidence"].append({
                        "category": category, "source": "undefined-symbols",
                        "executable": result["path"], "matches": matches, "confidence": "MEDIUM",
                    })
    if verify_signatures:
        verification = readonly_tool(["codesign", "--verify", "--strict", "--verbose=2", str(executable)])
        result["signature"] = {
            "status": "VALID" if verification["return_code"] == 0 else ("TOOL_UNAVAILABLE" if not verification["available"] else "INVALID_OR_UNSIGNED"),
            "return_code": verification["return_code"],
        }
    return result


def sanitize_entitlements(value: object) -> object:
    if not isinstance(value, dict):
        return value
    result = dict(value)
    for key in ("com.apple.developer.team-identifier", "com.apple.developer.ubiquity-kvstore-identifier"):
        if key in result:
            result[key] = "<TEAM_ID>"
    for key in ("application-identifier", "com.apple.application-identifier"):
        candidate = result.get(key)
        if isinstance(candidate, str) and "." in candidate:
            result[key] = "<TEAM_ID>." + candidate.split(".", 1)[1]
    groups = result.get("keychain-access-groups")
    if isinstance(groups, list):
        result["keychain-access-groups"] = [
            "<TEAM_ID>." + item.split(".", 1)[1] if isinstance(item, str) and "." in item else item
            for item in groups
        ]
    return result


def profile_entitlements(profile: Path) -> dict | None:
    if not profile.is_file() or not shutil.which("security"):
        return None
    decoded = readonly_tool(["security", "cms", "-D", "-i", str(profile)], max_output=5_000_000)
    if decoded["return_code"] != 0:
        return None
    try:
        payload = plistlib.loads(decoded["output"].encode("utf-8"))
        entitlements = payload.get("Entitlements") if isinstance(payload, dict) else None
        return entitlements if isinstance(entitlements, dict) else None
    except Exception:
        return None


def entitlement_matches(profile_value: object, signed_value: object) -> bool:
    if profile_value == signed_value:
        return True
    if isinstance(profile_value, str) and isinstance(signed_value, str) and "*" in profile_value:
        return fnmatch.fnmatchcase(signed_value, profile_value)
    if isinstance(profile_value, list) and isinstance(signed_value, list):
        return all(any(entitlement_matches(allowed, actual) for allowed in profile_value) for actual in signed_value)
    return False


def version_tuple(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    parts = tuple(int(item) for item in value.split("."))
    return parts + (0,) * (3 - len(parts))


def normalize_version(value: object) -> str | None:
    parsed = version_tuple(value)
    if not parsed:
        return None
    parts = list(parsed)
    while len(parts) > 2 and parts[-1] == 0:
        parts.pop()
    return ".".join(str(item) for item in parts)


def normalized_platform(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    aliases = {
        "1": "macos", "2": "ios", "3": "tvos", "4": "watchos",
        "6": "maccatalyst", "7": "ios", "8": "tvos", "9": "watchos",
        "11": "visionos", "12": "visionos",
        "iphoneos": "ios", "ios": "ios", "iphonesimulator": "ios",
        "macosx": "macos", "macos": "macos",
        "watchos": "watchos", "watchsimulator": "watchos",
        "appletvos": "tvos", "tvos": "tvos", "appletvsimulator": "tvos",
        "xros": "visionos", "visionos": "visionos", "xrsimulator": "visionos",
    }
    return aliases.get(value.lower())


def bundle_info(bundle: Path, root: Path, read_entitlements: bool, skip_tools: bool,
                verify_signatures: bool, max_scan_size: int,
                signing_fixture: dict | None = None) -> dict:
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
    entitlement_source = "NOT_RUN"
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
                entitlement_source = "CODESIGN"
            except Exception:
                entitlements = {"parse_error": True}
                entitlement_source = "CODESIGN_PARSE_ERROR"

    profile = profile_entitlements(bundle / "embedded.mobileprovision") if read_entitlements else None
    profile_source = "EMBEDDED_PROFILE" if profile is not None else "NOT_AVAILABLE"
    if signing_fixture:
        entitlements = signing_fixture.get("signed_entitlements", entitlements)
        profile = signing_fixture.get("profile_entitlements", profile)
        entitlement_source = "OFFLINE_SANITIZED_FIXTURE"
        profile_source = "OFFLINE_SANITIZED_FIXTURE"
    entitlement_mismatches = []
    if isinstance(entitlements, dict) and isinstance(profile, dict):
        ignored = {"get-task-allow", "beta-reports-active"}
        for key, value in entitlements.items():
            if key in ignored:
                continue
            if key not in profile or not entitlement_matches(profile.get(key), value):
                entitlement_mismatches.append(key)

    binary = binary_info(executable, root, skip_tools, verify_signatures, max_scan_size)
    extension = info.get("NSExtension") if isinstance(info.get("NSExtension"), dict) else {}
    relative_parts = Path(relpath(bundle, root)).parts
    special_kind = bundle.suffix.lstrip(".")
    if bundle.suffix == ".app" and "AppClips" in relative_parts:
        special_kind = "app_clip"
    elif bundle.suffix == ".app" and "Watch" in relative_parts:
        special_kind = "watch_app"
    elif bundle.suffix == ".appex" and any(part.endswith(".app") and "Watch" in relative_parts for part in relative_parts):
        special_kind = "watch_extension"
    return {
        "path": relpath(bundle, root),
        "kind": special_kind,
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
        "entitlements": sanitize_entitlements(entitlements),
        "entitlement_source": entitlement_source,
        "profile_source": profile_source,
        "provisioning_profile_entitlement_keys": sorted(profile) if isinstance(profile, dict) else [],
        "entitlement_profile_mismatches": sorted(entitlement_mismatches),
        "extension_point_identifier": extension.get("NSExtensionPointIdentifier"),
        "watch_companion_bundle_identifier": info.get("WKCompanionAppBundleIdentifier"),
        "app_clip_parent_identifiers": sanitize_entitlements(entitlements).get("com.apple.developer.parent-application-identifiers", []) if isinstance(sanitize_entitlements(entitlements), dict) else [],
        "sdk_identity": {
            "name": info.get("CFBundleName") or bundle.stem,
            "bundle_identifier": info.get("CFBundleIdentifier"),
            "short_version": info.get("CFBundleShortVersionString"),
            "build_version": info.get("CFBundleVersion"),
            "install_names": binary.get("install_names", []),
        } if bundle.suffix == ".framework" else None,
        "binary": binary,
    }


def privacy_report_info(path: Path | None, max_file_size: int) -> dict | None:
    if not path:
        return None
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("privacy report is not a file")
    payload = path.read_bytes()
    if len(payload) > max_file_size:
        raise ValueError("privacy report exceeds file size limit")
    try:
        value = json.loads(payload.decode("utf-8"))
        report_format = "json"
    except (UnicodeDecodeError, json.JSONDecodeError):
        value = plistlib.loads(payload)
        report_format = "plist"
    if not isinstance(value, (dict, list)):
        raise ValueError("privacy report root must be an object or array")
    identities: set[str] = set()
    sdk_names: set[str] = set()
    required_categories: set[str] = set()
    collected_types: set[str] = set()
    tracking_domains: set[str] = set()
    interesting = {"bundleIdentifier", "bundleID", "identifier", "bundle_identifier"}
    sdk_keys = {"sdkName", "sdk", "frameworkName", "libraryName"}
    required_keys = {"NSPrivacyAccessedAPIType", "apiType", "accessedAPIType", "requiredReasonAPIType"}
    collected_keys = {"NSPrivacyCollectedDataType", "dataType", "collectedDataType"}
    domain_keys = {"NSPrivacyTrackingDomains", "trackingDomains"}

    def visit(item: object) -> int:
        count = 1
        if isinstance(item, dict):
            for key, child in item.items():
                if key in interesting and isinstance(child, str) and len(child) <= 200:
                    identities.add(child)
                if key in sdk_keys and isinstance(child, str) and len(child) <= 200:
                    sdk_names.add(child)
                if key in required_keys and isinstance(child, str) and child.startswith("NSPrivacyAccessedAPICategory"):
                    required_categories.add(child)
                if key in collected_keys and isinstance(child, str) and child.startswith("NSPrivacyCollectedDataType"):
                    collected_types.add(child)
                if key in domain_keys and isinstance(child, list):
                    tracking_domains.update(value for value in child if isinstance(value, str) and len(value) <= 253)
                count += visit(child)
        elif isinstance(item, list):
            for child in item:
                count += visit(child)
        return count

    record_count = visit(value)
    top_level_keys = sorted(value) if isinstance(value, dict) else []
    if any(key.startswith("NSPrivacy") for key in top_level_keys):
        schema_family = "PRIVACY_MANIFEST_AGGREGATE"
    elif any(key.lower().startswith("privacyreport") for key in top_level_keys):
        schema_family = "XCODE_PRIVACY_REPORT_VERSIONED"
    else:
        schema_family = "XCODE_PRIVACY_REPORT_UNVERSIONED"
    return {
        "path": "<PRIVACY_REPORT>",
        "format": report_format,
        "sha256": sha256_bytes(payload),
        "schema_family": schema_family,
        "top_level_keys": top_level_keys,
        "record_count": record_count,
        "identities": sorted(identities),
        "sdk_names": sorted(sdk_names),
        "required_reason_categories": sorted(required_categories),
        "collected_data_types": sorted(collected_types),
        "tracking_domains": sorted(tracking_domains),
    }


def xcframework_info(container: Path, root: Path) -> dict:
    result = {"path": relpath(container, root), "valid": False, "slices": []}
    info = container / "Info.plist"
    try:
        value = read_plist(info)
        libraries = value.get("AvailableLibraries")
        if not isinstance(libraries, list):
            raise ValueError("AvailableLibraries must be an array")
        for record in libraries:
            if not isinstance(record, dict):
                raise ValueError("XCFramework slice must be a dictionary")
            identifier = record.get("LibraryIdentifier")
            library_path = record.get("LibraryPath")
            if not isinstance(identifier, str) or not isinstance(library_path, str):
                raise ValueError("XCFramework slice is missing LibraryIdentifier or LibraryPath")
            slice_root = container / identifier
            binary = slice_root / library_path
            result["slices"].append({
                "identifier": identifier,
                "library_path": library_path,
                "binary_exists": binary.exists(),
                "architectures": sorted(record.get("SupportedArchitectures", [])),
                "platform": normalized_platform(record.get("SupportedPlatform")) or record.get("SupportedPlatform"),
                "platform_variant": record.get("SupportedPlatformVariant"),
                "headers_path": record.get("HeadersPath"),
                "debug_symbols_path": record.get("DebugSymbolsPath"),
            })
        result["valid"] = True
        result["format_version"] = value.get("XCFrameworkFormatVersion")
    except Exception as error:
        result["error"] = str(error)
    result["slices"] = sorted(result["slices"], key=lambda item: item["identifier"])
    return result


def main() -> int:
    args = parse_args()
    supplied_artifact = args.archive.resolve()
    if not supplied_artifact.exists():
        raise SystemExit(f"archive/app/ipa does not exist: {supplied_artifact}")
    if min(args.max_files, args.max_total_size, args.max_file_size, args.max_binary_scan_size) <= 0:
        raise SystemExit("scan limits must be positive")
    temporary: tempfile.TemporaryDirectory[str] | None = None
    ipa_extraction = None
    artifact_type = supplied_artifact.suffix.lstrip(".") or "directory"
    try:
        if supplied_artifact.suffix.lower() == ".ipa":
            if not supplied_artifact.is_file():
                raise ValueError("IPA path is not a file")
            if supplied_artifact.stat().st_size > args.max_total_size:
                raise ValueError("IPA compressed size exceeds total-size limit")
            temporary = tempfile.TemporaryDirectory(prefix="app-store-preflight-ipa-")
            archive = Path(temporary.name)
            ipa_extraction = safe_zip_extract(
                supplied_artifact, archive, args.max_files,
                args.max_total_size, args.max_file_size,
            )
        elif supplied_artifact.is_dir():
            archive = supplied_artifact
        else:
            raise ValueError("artifact must be a .ipa, .xcarchive, or bundle directory")
        artifact_files, artifact_directories, artifact_total_size = safe_artifact_inventory(
            archive, args.max_files, args.max_total_size, args.max_file_size,
        )
        imported_privacy_report = privacy_report_info(args.privacy_report, args.max_file_size)
        signing_fixtures = load_signing_fixtures(args.sanitized_signing_fixture, args.max_file_size)
    except (OSError, ValueError, zipfile.BadZipFile, plistlib.InvalidFileException) as error:
        if temporary:
            temporary.cleanup()
        raise SystemExit(f"artifact safety validation failed: {error}") from error
    fragment = new_fragment("inspect_archive", "archive", supplied_artifact)

    bundles = []
    if archive.suffix in BUNDLE_SUFFIXES:
        candidates = [archive]
    else:
        candidates = sorted((path for path in artifact_directories if path.suffix in BUNDLE_SUFFIXES), key=str)

    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        info = bundle_info(
            candidate, archive, args.read_entitlements, args.skip_binary_tools,
            args.verify_signatures, args.max_binary_scan_size,
            signing_fixtures.get(relpath(candidate, archive)),
        )
        parent = next((parent for parent in candidate.parents if parent != candidate and parent.suffix in BUNDLE_SUFFIXES), None)
        info["parent_bundle"] = relpath(parent, archive) if parent and parent != archive else None
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
    app_clips = [item for item in bundles if item["kind"] == "app_clip"]
    watch_apps = [item for item in bundles if item["kind"] == "watch_app"]
    watch_extensions = [item for item in bundles if item["kind"] == "watch_extension"]
    frameworks = [item for item in bundles if item["kind"] == "framework"]
    extensions = [item for item in bundles if item["kind"] in {"appex", "watch_extension"}]
    bundle_by_path = {item["path"]: item for item in bundles}
    identifiers: dict[str, list[str]] = {}
    for item in bundles:
        identifier = item.get("bundle_identifier")
        if isinstance(identifier, str):
            identifiers.setdefault(identifier, []).append(item["path"])
        mismatches = item.get("entitlement_profile_mismatches", [])
        if mismatches:
            add_finding(
                fragment, f"ARCHIVE-PROFILE-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Signing",
                "Signed entitlements are not allowed by the embedded profile",
                "One or more signed entitlement values are absent from or incompatible with the embedded provisioning profile.",
                evidence=[{"path": item["path"], "detail": ", ".join(mismatches)}],
                remediation="Regenerate the profile or correct target entitlements, then sign and archive again.",
            )
        declared_minimum = version_tuple(item.get("minimum_os"))
        build_versions = item.get("binary", {}).get("build_versions", [])
        binary_minimums = {version_tuple(record.get("minimum_os")) for record in build_versions}
        binary_minimums.discard(None)
        if declared_minimum and binary_minimums and declared_minimum not in binary_minimums:
            add_finding(
                fragment, f"ARCHIVE-MIN-OS-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Info.plist and Mach-O minimum OS values differ",
                "The packaged bundle declaration is inconsistent with LC_BUILD_VERSION evidence in its executable.",
                evidence=[{"path": item["binary"]["path"] or item["path"], "detail": "minimum OS mismatch"}],
                remediation="Align deployment target and packaged Info.plist values, then rebuild the archive.",
            )
        declared_platforms = {normalized_platform(value) for value in item.get("supported_platforms", [])}
        declared_platforms.discard(None)
        binary_platforms = {normalized_platform(record.get("platform")) for record in build_versions}
        binary_platforms.discard(None)
        if declared_platforms and binary_platforms and not declared_platforms.intersection(binary_platforms):
            add_finding(
                fragment, f"ARCHIVE-MACHO-PLATFORM-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Info.plist and Mach-O platform values differ",
                "The bundle's supported platform is inconsistent with LC_BUILD_VERSION evidence.",
                evidence=[{"path": item["binary"]["path"] or item["path"], "detail": "platform mismatch"}],
                remediation="Select the correct platform slice and rebuild the submitted product.",
            )
        if item["kind"] == "framework":
            unsafe_install_names = [
                value for value in item.get("binary", {}).get("install_names", [])
                if not value.startswith(("@rpath/", "@loader_path/", "@executable_path/", "/System/Library/", "/usr/lib/"))
            ]
            if unsafe_install_names:
                add_finding(
                    fragment, f"ARCHIVE-FRAMEWORK-INSTALL-NAME-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                    "Embedded framework uses a non-portable install name",
                    "A shipped framework install name is not loader-relative or a system path.",
                    evidence=[{"path": item["path"], "detail": ", ".join(unsafe_install_names)}],
                    remediation="Set a portable dynamic-library install name, normally @rpath, and rebuild the framework.",
                )
            framework_parent = bundle_by_path.get(item.get("parent_bundle") or "")
            if framework_parent and framework_parent.get("kind") == "framework":
                add_finding(
                    fragment, f"ARCHIVE-NESTED-FRAMEWORK-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                    "Framework is nested inside another framework",
                    "The packaged framework hierarchy contains a nested framework bundle that may not be accepted or loaded as intended.",
                    evidence=[{"path": item["path"], "detail": "framework parent is another framework"}],
                    remediation="Flatten embedded framework ownership into the containing app or extension and rebuild.",
                )
        parent = bundle_by_path.get(item.get("parent_bundle") or "")
        allowed_parent_kinds = {"app"} if item["kind"] in {"appex", "app_clip", "watch_app"} else {"watch_app"}
        if not parent or parent.get("kind") not in allowed_parent_kinds or item["kind"] not in {"appex", "app_clip", "watch_app", "watch_extension"}:
            continue
        parent_id = parent.get("bundle_identifier")
        child_id = item.get("bundle_identifier")
        if isinstance(parent_id, str) and isinstance(child_id, str) and not child_id.startswith(parent_id + "."):
            add_finding(
                fragment, f"ARCHIVE-BUNDLE-ID-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Nested app or extension bundle identifier is not parent-prefixed",
                "The child product's bundle identifier does not extend the containing app's identifier.",
                evidence=[{"path": item["path"], "detail": "parent-child bundle ID prefix mismatch"}],
                remediation="Use a unique child bundle ID prefixed by the containing app bundle ID.",
            )
        if item["kind"] == "app_clip":
            allowed_parents = item.get("app_clip_parent_identifiers") or []
            if parent_id and not allowed_parents:
                add_finding(
                    fragment, f"ARCHIVE-APP-CLIP-PARENT-{len(fragment['findings'])+1}", "P1", "NEEDS_VERIFY", "UNRESOLVED", "Archive",
                    "App Clip parent entitlement was not available",
                    "The App Clip relationship cannot be verified without signed entitlement evidence.",
                    evidence=[{"path": item["path"], "detail": "parent-application-identifiers unavailable"}],
                    remediation="Import codesign entitlements or a sanitized signing fixture and rerun the audit.",
                )
            elif parent_id and not any(str(value).endswith(f".{parent_id}") for value in allowed_parents):
                add_finding(
                    fragment, f"ARCHIVE-APP-CLIP-PARENT-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                    "App Clip parent entitlement does not identify the containing app",
                    "The App Clip's parent-application-identifiers entitlement is inconsistent with the packaged parent app.",
                    evidence=[{"path": item["path"], "detail": "parent application identifier mismatch"}],
                    remediation="Align the App Clip entitlement, App ID, and containing app bundle identifier.",
                )
        if item["kind"] == "watch_app":
            companion = item.get("watch_companion_bundle_identifier")
            if parent_id and not companion:
                add_finding(
                    fragment, f"ARCHIVE-WATCH-COMPANION-{len(fragment['findings'])+1}", "P1", "NEEDS_VERIFY", "UNRESOLVED", "Archive",
                    "Watch companion identifier was not available",
                    "The packaged Watch app relationship cannot be verified from its Info.plist.",
                    evidence=[{"path": item["path"], "detail": "WKCompanionAppBundleIdentifier unavailable"}],
                    remediation="Set or verify WKCompanionAppBundleIdentifier for the containing iOS app.",
                )
            elif parent_id and companion != parent_id:
                add_finding(
                    fragment, f"ARCHIVE-WATCH-COMPANION-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                    "Watch companion identifier does not match the containing app",
                    "WKCompanionAppBundleIdentifier points to a different app bundle identifier.",
                    evidence=[{"path": item["path"], "detail": "watch companion bundle ID mismatch"}],
                    remediation="Set WKCompanionAppBundleIdentifier to the containing iOS app bundle identifier.",
                )
        for key, label in (("short_version", "marketing version"), ("build_version", "build version")):
            if parent.get(key) and item.get(key) and parent[key] != item[key]:
                add_finding(
                    fragment, f"ARCHIVE-VERSION-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                    f"App and extension {label} values differ",
                    "The containing app and child product do not carry a consistent release version.",
                    evidence=[{"path": item["path"], "detail": f"{label} mismatch with parent bundle"}],
                    remediation="Align app and extension version settings and rebuild the archive.",
                )
        parent_platforms = set(parent.get("supported_platforms") or [])
        child_platforms = set(item.get("supported_platforms") or [])
        if parent_platforms and child_platforms and not parent_platforms.intersection(child_platforms):
            add_finding(
                fragment, f"ARCHIVE-PLATFORM-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Parent and child bundles declare incompatible platforms",
                "The packaged child bundle has no supported platform in common with its containing app.",
                evidence=[{"path": item["path"], "detail": "CFBundleSupportedPlatforms mismatch"}],
                remediation="Correct platform/deployment target settings and rebuild all related targets.",
            )
        parent_arch = set(parent.get("binary", {}).get("architectures", []))
        child_arch = set(item.get("binary", {}).get("architectures", []))
        if parent_arch and child_arch and not parent_arch.intersection(child_arch):
            add_finding(
                fragment, f"ARCHIVE-ARCH-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Parent and child executables have incompatible architectures",
                "The packaged executables have no architecture slice in common.",
                evidence=[{"path": item["binary"]["path"] or item["path"], "detail": "architecture mismatch"}],
                remediation="Align ARCHS/VALID_ARCHS and rebuild the archive for the intended platform.",
            )
    for identifier, paths in identifiers.items():
        if len(paths) > 1:
            add_finding(
                fragment, f"ARCHIVE-DUPLICATE-ID-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Packaged bundle identifier is duplicated",
                "Multiple shipped bundles declare the same bundle identifier.",
                evidence=[{"path": path, "detail": "duplicate bundle identifier"} for path in paths],
                remediation="Assign a unique identifier to every shipped bundle target.",
            )
    dynamic_libraries = []
    for index, library in enumerate((path for path in artifact_files if path.suffix == ".dylib"), 1):
        binary = binary_info(library, archive, args.skip_binary_tools, args.verify_signatures, args.max_binary_scan_size)
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
    static_libraries = []
    for library in (path for path in artifact_files if path.suffix == ".a"):
        owner_path = next((relpath(parent, archive) for parent in library.parents if parent.suffix in BUNDLE_SUFFIXES), None)
        static_libraries.append({
            "path": relpath(library, archive),
            "containing_bundle": owner_path,
            "identity": library.stem,
            "attribution": "packaged-file",
        })

    xcframeworks = [
        xcframework_info(path, archive)
        for path in artifact_directories if path.suffix == ".xcframework"
    ]
    for item in xcframeworks:
        if not item["valid"]:
            add_finding(
                fragment, f"ARCHIVE-XCFRAMEWORK-{len(fragment['findings'])+1}", "P1", "FAIL", "CONFIRMED", "Archive",
                "Packaged XCFramework metadata is malformed",
                "A shipped XCFramework container could not be interpreted safely.",
                evidence=[{"path": item["path"], "detail": item.get("error", "invalid Info.plist")}],
                remediation="Fix the XCFramework package and embed only the intended platform slice.",
            )
        else:
            add_finding(
                fragment, f"ARCHIVE-XCFRAMEWORK-PACKAGED-{len(fragment['findings'])+1}", "P2", "NEEDS_VERIFY", "CONFIRMED", "Archive",
                "An XCFramework container is packaged in the final app artifact",
                "XCFrameworks are normally build-time containers; confirm that shipping all slices as resources is intentional.",
                evidence=[{"path": item["path"], "detail": f"{len(item['slices'])} slice(s)"}],
                remediation="Embed only the resolved framework/library slice unless the complete XCFramework is an intentional app resource.",
            )

    privacy_report_cross_check = None
    if imported_privacy_report:
        archive_identities = {
            str(item["bundle_identifier"]) for item in bundles if item.get("bundle_identifier")
        }
        archive_sdk_names = {
            str(item.get("sdk_identity", {}).get("name") or Path(item["path"]).stem).casefold()
            for item in frameworks
        }
        archive_sdk_names.update(Path(item["path"]).stem.casefold() for item in dynamic_libraries)
        unmatched_identities = sorted(
            identity for identity in imported_privacy_report["identities"]
            if "." in identity and identity not in archive_identities
        )
        unmatched_sdks = sorted(
            name for name in imported_privacy_report["sdk_names"] if name.casefold() not in archive_sdk_names
        )
        declared_categories = {
            category for item in bundles for manifest in item["privacy_manifests"] if manifest["valid"]
            for category in manifest["required_reason_categories"]
        }
        undeclared_report_categories = sorted(set(imported_privacy_report["required_reason_categories"]) - declared_categories)
        privacy_report_cross_check = {
            "archive_bundle_identifiers": sorted(archive_identities),
            "unmatched_report_identities": unmatched_identities,
            "unmatched_report_sdk_names": unmatched_sdks,
            "report_categories_without_packaged_declaration": undeclared_report_categories,
            "verification": "CONFIRMED" if not (unmatched_identities or unmatched_sdks or undeclared_report_categories) else "UNRESOLVED",
        }
        imported_privacy_report["cross_check"] = privacy_report_cross_check
        if unmatched_identities or unmatched_sdks or undeclared_report_categories:
            add_finding(
                fragment, "ARCHIVE-PRIVACY-REPORT-MISMATCH", "P1", "NEEDS_VERIFY", "INFERRED", "Privacy",
                "Xcode Privacy Report does not fully reconcile with packaged bundles",
                "Report identities, SDK names, or required-reason categories could not all be matched to the submitted artifact.",
                authority_type="PRIVACY_REQUIREMENT",
                authority_url="https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
                evidence=[{"detail": f"unmatched identities={len(unmatched_identities)}, SDKs={len(unmatched_sdks)}, categories={len(undeclared_report_categories)}"}],
                remediation="Confirm the report corresponds to this exact archive and reconcile each unmatched SDK, bundle, and required-reason category.",
                assumptions=["Privacy Report field names vary by Xcode version; unknown schemas remain inferred."],
            )

    suspicious_patterns = (".swift", ".m", ".mm", ".xctest", ".git", ".ds_store")
    debug_sample_resources = []
    for path in artifact_files:
        relative_lower = relpath(path, archive).lower()
        parts = set(Path(relative_lower).parts)
        if relative_lower.endswith(suspicious_patterns) or parts & {"tests", "test", "samples", "sample", "debug"}:
            debug_sample_resources.append(relpath(path, archive))
        if len(debug_sample_resources) >= 200:
            break

    fragment["data"] = {
        "artifact_type": artifact_type,
        "artifact_budget": {
            "max_files": args.max_files,
            "max_total_size": args.max_total_size,
            "max_file_size": args.max_file_size,
            "max_binary_scan_size": args.max_binary_scan_size,
            "observed_files": len(artifact_files),
            "observed_total_size": artifact_total_size,
        },
        "ipa_extraction": ipa_extraction,
        "bundles": bundles,
        "summary": {
            "apps": len(apps), "app_clips": len(app_clips), "watch_apps": len(watch_apps),
            "watch_extensions": len(watch_extensions), "extensions": len(extensions),
            "frameworks": len(frameworks), "xcframeworks": len(xcframeworks),
        },
        "macho_executables": [item["binary"]["path"] for item in bundles if item["binary"]["is_macho"]],
        "dynamic_dependencies": sorted({dependency for item in bundles for dependency in item["binary"]["dynamic_dependencies"]}),
        "required_reason_binary_signals": {
            item["path"]: item["binary"]["required_reason_api_signals"]
            for item in bundles if item["binary"]["required_reason_api_signals"]
        },
        "required_reason_signal_evidence": [
            evidence
            for item in bundles for evidence in item["binary"]["required_reason_signal_evidence"]
        ] + [
            evidence
            for item in dynamic_libraries for evidence in item["binary"]["required_reason_signal_evidence"]
        ],
        "standalone_dynamic_libraries": dynamic_libraries,
        "static_libraries": static_libraries,
        "xcframeworks": xcframeworks,
        "static_library_limitation": "Static libraries linked into a final Mach-O cannot be attributed without a Link Map or equivalent linker evidence.",
        "xcode_privacy_report": imported_privacy_report,
        "privacy_report_cross_check": privacy_report_cross_check,
        "debug_test_sample_resources": sorted(debug_sample_resources),
        "frameworks_without_direct_privacy_manifest": [item["path"] for item in frameworks if not item["privacy_manifests"]],
        "entitlements_requested": args.read_entitlements,
        "sanitized_signing_fixture_used": bool(signing_fixtures),
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
    if args.read_entitlements or signing_fixtures:
        parsed = sum(isinstance(item["entitlements"], dict) and not item["entitlements"].get("parse_error") for item in bundles)
        add_check(
            fragment, "ARCHIVE-005", "PASS" if parsed else "BLOCKED",
            f"Parsed entitlements for {parsed} packaged executable(s)." if parsed else "No packaged entitlements could be parsed.",
            blocker=None if parsed else "codesign may be unavailable, the artifact may be unsigned, or the sanitized fixture may not match a bundle.",
        )
    else:
        add_check(fragment, "ARCHIVE-005", "NOT_RUN", "Entitlement extraction was not requested.", blocker="Pass --read-entitlements for read-only extraction.")
    if args.verify_signatures:
        statuses = [item["binary"]["signature"]["status"] for item in bundles if item["binary"]["exists"]]
        disposition = "PASS" if statuses and all(status == "VALID" for status in statuses) else "FAIL"
        add_check(fragment, "ARCHIVE-006", disposition, "Packaged executable signatures were verified in read-only mode.")
    else:
        add_check(fragment, "ARCHIVE-006", "NOT_RUN", "Signature verification was not requested.", blocker="Pass --verify-signatures to run codesign --verify.")
    if imported_privacy_report:
        report_ok = privacy_report_cross_check and privacy_report_cross_check["verification"] == "CONFIRMED"
        add_check(fragment, "ARCHIVE-007", "PASS" if report_ok else "NEEDS_VERIFY",
                  "An Xcode-generated privacy report was imported, normalized, and cross-checked.",
                  verification="CONFIRMED" if report_ok else "INFERRED",
                  blocker=None if report_ok else "Resolve unmatched Privacy Report identities, SDKs, or categories.")
    else:
        add_check(fragment, "ARCHIVE-007", "NOT_RUN", "No Xcode-generated privacy report was supplied.",
                  blocker="Pass --privacy-report to cross-reference Xcode's generated report.")
    if debug_sample_resources:
        add_check(fragment, "ARCHIVE-008", "NEEDS_VERIFY", "Potential debug, test, sample, or source resources were packaged.",
                  verification="INFERRED", evidence=[{"path": path} for path in debug_sample_resources[:20]],
                  blocker="Confirm each packaged resource is intentional and production-safe.")
        add_finding(
            fragment, "ARCHIVE-DEBUG-RESOURCES", "P2", "NEEDS_VERIFY", "INFERRED", "Archive",
            "Potential debug, test, sample, or source resources are packaged",
            "Filename and directory evidence suggests non-production resources may be present in the submitted artifact.",
            evidence=[{"path": path} for path in debug_sample_resources[:20]],
            remediation="Review target membership and remove unneeded development resources from the release product.",
            assumptions=["Names are heuristic evidence and may describe intentional production content."],
        )
    else:
        add_check(fragment, "ARCHIVE-008", "PASS", "No obvious debug, test, sample, or source resources were detected.")
    write_json(args.output.resolve(), fragment)
    if temporary:
        temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
