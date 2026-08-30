#!/usr/bin/env python3
"""Validate privacy manifests and collect conservative required-reason API signals."""

from __future__ import annotations

import argparse
import re
from collections import defaultdict
from pathlib import Path

from _common import add_check, add_finding, iter_files, new_fragment, read_plist, read_text, relpath, strip_source_comments, write_json

PRIVACY_KEYS = {
    "NSPrivacyTracking", "NSPrivacyTrackingDomains", "NSPrivacyCollectedDataTypes",
    "NSPrivacyAccessedAPITypes",
}
API_PATTERNS = {
    "NSPrivacyAccessedAPICategoryUserDefaults": [r"\bUserDefaults\b", r"\bNSUserDefaults\b"],
    "NSPrivacyAccessedAPICategoryFileTimestamp": [r"contentModificationDateKey", r"creationDateKey", r"fileModificationDate", r"\bstatv?fs?\s*\("],
    "NSPrivacyAccessedAPICategoryDiskSpace": [r"volumeAvailableCapacity", r"systemFreeSize", r"systemSize"],
    "NSPrivacyAccessedAPICategorySystemBootTime": [r"systemUptime", r"kern\.boottime", r"ProcessInfo\.processInfo\.systemUptime"],
    "NSPrivacyAccessedAPICategoryActiveKeyboards": [r"activeInputModes"],
}
SOURCE_SUFFIXES = {".swift", ".m", ".mm", ".c", ".cc", ".cpp", ".h", ".hpp"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"root is not a directory: {root}")
    fragment = new_fragment("inspect_privacy_manifests", "source", root)
    manifests: list[dict] = []
    declarations: dict[str, list[str]] = defaultdict(list)
    signals: dict[str, list[dict[str, object]]] = defaultdict(list)

    files = list(iter_files(root))
    for path in files:
        if path.name == "PrivacyInfo.xcprivacy":
            relative = relpath(path, root)
            try:
                plist = read_plist(path)
                unknown = sorted(set(plist) - PRIVACY_KEYS)
                accessed = plist.get("NSPrivacyAccessedAPITypes", [])
                if not isinstance(accessed, list):
                    raise ValueError("NSPrivacyAccessedAPITypes must be an array")
                for index, item in enumerate(accessed):
                    if not isinstance(item, dict):
                        raise ValueError(f"NSPrivacyAccessedAPITypes[{index}] must be a dictionary")
                    category = item.get("NSPrivacyAccessedAPIType")
                    reasons = item.get("NSPrivacyAccessedAPITypeReasons")
                    if not isinstance(category, str) or not isinstance(reasons, list) or not reasons or not all(isinstance(r, str) and r for r in reasons):
                        raise ValueError(f"invalid required-reason declaration at index {index}")
                    declarations[category].extend(reasons)
                tracking = plist.get("NSPrivacyTracking", False)
                domains = plist.get("NSPrivacyTrackingDomains", [])
                if domains and tracking is not True:
                    add_finding(
                        fragment, "PRIVACY-TRACKING-DOMAINS", "P1", "FAIL", "CONFIRMED", "Privacy",
                        "Tracking domains are declared while tracking is not true",
                        "The manifest contains tracking domains without an affirmative NSPrivacyTracking value.",
                        authority_type="PRIVACY_REQUIREMENT",
                        authority_url="https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
                        evidence=[{"path": relative, "detail": "NSPrivacyTrackingDomains is non-empty"}],
                        remediation="Verify actual tracking behavior and make the manifest internally consistent.",
                    )
                if unknown:
                    add_finding(
                        fragment, f"PRIVACY-UNKNOWN-KEY-{len(manifests)+1}", "P1", "FAIL", "CONFIRMED", "Privacy",
                        "Privacy manifest contains unexpected root keys",
                        "Unexpected keys can make a packaged privacy manifest invalid.",
                        authority_type="PRIVACY_REQUIREMENT",
                        authority_url="https://developer.apple.com/documentation/bundleresources/adding-a-privacy-manifest-to-your-app-or-third-party-sdk",
                        evidence=[{"path": relative, "detail": ", ".join(unknown)}],
                        remediation="Remove unsupported keys or replace them with current documented keys.",
                    )
                manifests.append({"path": relative, "valid": True, "unknown_keys": unknown})
            except Exception as error:
                manifests.append({"path": relative, "valid": False, "error": str(error)})
                add_finding(
                    fragment, f"PRIVACY-INVALID-{len(manifests)}", "P1", "FAIL", "CONFIRMED", "Privacy",
                    "Privacy manifest is malformed",
                    "The file could not be parsed as a valid privacy manifest dictionary.",
                    authority_type="PRIVACY_REQUIREMENT",
                    authority_url="https://developer.apple.com/documentation/bundleresources/privacy-manifest-files",
                    evidence=[{"path": relative, "detail": str(error)}],
                    remediation="Correct the plist structure and validate the packaged manifest.",
                )
        elif path.suffix in SOURCE_SUFFIXES:
            text = strip_source_comments(read_text(path))
            for category, patterns in API_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, text)
                    if match:
                        prefix = text[:match.start()]
                        line = prefix.count("\n") + 1
                        signals[category].append({"path": relpath(path, root), "line": line, "pattern": pattern})
                        break

    for category, evidence in sorted(signals.items()):
        if category not in declarations:
            add_finding(
                fragment, f"PRIVACY-REASON-{category.rsplit('Category', 1)[-1].upper()}", "P1", "NEEDS_VERIFY", "INFERRED", "Privacy",
                "Required-reason API signal has no matching declaration",
                "Static source evidence suggests a covered API category, but target membership and packaged declarations still require confirmation.",
                authority_type="PRIVACY_REQUIREMENT",
                authority_url="https://developer.apple.com/documentation/bundleresources/describing-use-of-required-reason-api",
                evidence=evidence[:20],
                remediation="Confirm the API is shipped and used, then declare an accurate approved reason in the containing bundle or remove the covered use.",
                assumptions=["Static pattern matches can include non-shipping or unreachable source."],
            )

    fragment["data"] = {
        "manifests": manifests,
        "declared_required_reason_categories": {key: sorted(set(value)) for key, value in sorted(declarations.items())},
        "required_reason_api_signals": dict(sorted(signals.items())),
    }
    if manifests and all(item["valid"] for item in manifests):
        add_check(fragment, "PRIVACY-001", "PASS", "All discovered privacy manifests parsed successfully.")
    elif manifests:
        add_check(fragment, "PRIVACY-001", "FAIL", "One or more discovered privacy manifests were invalid.")
    else:
        add_check(fragment, "PRIVACY-001", "NEEDS_VERIFY", "No privacy manifest was discovered.",
                  verification="UNRESOLVED", blocker="A manifest may be unnecessary, generated, or only present in the final archive.")
    disposition = "PASS" if not any(category not in declarations for category in signals) else "NEEDS_VERIFY"
    add_check(fragment, "PRIVACY-002", disposition, "Required-reason API source signals were compared with discovered declarations.",
              verification="CONFIRMED" if disposition == "PASS" else "INFERRED")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
