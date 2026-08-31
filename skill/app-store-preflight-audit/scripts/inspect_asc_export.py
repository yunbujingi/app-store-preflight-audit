#!/usr/bin/env python3
"""Import local App Store Connect exports and compare safe metadata with archive evidence."""

from __future__ import annotations

import argparse
import json
import plistlib
from pathlib import Path
from typing import Any

from _common import ScanLimitExceeded, add_check, add_finding, iter_files, new_fragment, relpath, sha256_bytes, write_json
ALIASES = {
    "bundle_identifier": {"bundleid", "bundleidentifier", "bundle_id", "product_bundle_identifier"},
    "version": {"version", "versionstring", "cfbundleshortversionstring"},
    "build": {"build", "buildnumber", "cfbundleversion"},
    "age_rating": {"agerating", "age_rating", "ageratingdeclaration"},
    "app_privacy": {"appprivacy", "app_privacy", "privacyresponses", "privacy_details"},
    "review_notes": {"reviewnotes", "review_notes", "notes"},
    "iap": {"inapppurchases", "in_app_purchases", "iap"},
    "subscriptions": {"subscriptions", "subscriptiongroups", "subscription_groups"},
    "screenshots": {"screenshots", "screenshotsets", "appscreenshots"},
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", required=True, type=Path)
    parser.add_argument("--api-fragment", action="append", default=[], type=Path,
                        help="Optional output from fetch_asc_readonly.py")
    parser.add_argument("--expected", type=Path,
                        help="Optional canonical JSON expectations for privacy, age rating, commerce, screenshots, or build inventory")
    parser.add_argument("--archive-fragment", type=Path)
    parser.add_argument("--max-files", type=int, default=2_000)
    parser.add_argument("--max-total-size", type=int, default=100_000_000)
    parser.add_argument("--max-file-size", type=int, default=10_000_000)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def parse_document(path: Path) -> Any:
    payload = path.read_bytes()
    if path.suffix.lower() == ".json":
        return json.loads(payload.decode("utf-8"))
    if path.suffix.lower() in {".plist", ".xml"}:
        return plistlib.loads(payload)
    raise ValueError("unsupported export document")


def collect_aliases(value: Any, result: dict[str, list[Any]]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = str(key).lower()
            for canonical, aliases in ALIASES.items():
                if lowered in aliases:
                    result.setdefault(canonical, []).append(child)
            collect_aliases(child, result)
    elif isinstance(value, list):
        for child in value:
            collect_aliases(child, result)


def summarize_value(key: str, value: Any) -> dict[str, Any]:
    encoded = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    summary: dict[str, Any] = {"present": True, "sha256": sha256_bytes(encoded)}
    if isinstance(value, list):
        summary["count"] = len(value)
    elif isinstance(value, dict):
        summary["keys"] = sorted(str(item) for item in value)[:100]
    elif key not in {"review_notes"} and isinstance(value, (str, int, float, bool)):
        summary["value"] = value
    else:
        summary["type"] = type(value).__name__
    return summary


def canonical_hash(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False).encode("utf-8"))


def collect_api_fragment(path: Path, signals: dict[str, list[Any]]) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
        raise ValueError("ASC API fragment is unavailable or exceeds the size budget")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("api-fragment root must be an object")
    data = value.get("data")
    capabilities = data.get("capabilities") if isinstance(data, dict) else None
    if value.get("tool") != "fetch_asc_readonly" or not isinstance(capabilities, dict):
        raise ValueError("api-fragment was not produced by fetch_asc_readonly.py")
    if capabilities.get("upload") is not False or capabilities.get("modify") is not False or capabilities.get("submit") is not False:
        raise ValueError("api-fragment does not assert the permanent read-only capability boundary")
    records = data.get("records")
    if not isinstance(records, list):
        raise ValueError("api-fragment records must be an array")
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("attributes"), dict):
            continue
        grouped.setdefault(str(record.get("type")), []).append(record["attributes"])
    mappings = {
        "ageRatingDeclarations": "age_rating", "inAppPurchases": "iap",
        "subscriptions": "subscriptions", "appScreenshots": "screenshots",
        "builds": "build_inventory",
    }
    for resource_type, key in mappings.items():
        if resource_type in grouped:
            signals.setdefault(key, []).append(grouped[resource_type])
    for attributes in grouped.get("apps", []):
        if "bundleId" in attributes:
            signals.setdefault("bundle_identifier", []).append(attributes["bundleId"])
    for attributes in grouped.get("builds", []):
        if "version" in attributes:
            signals.setdefault("build", []).append(attributes["version"])
    for attributes in grouped.get("appStoreVersions", []):
        if "versionString" in attributes:
            signals.setdefault("version", []).append(attributes["versionString"])
    return {"path": path.name, "endpoint": data.get("endpoint"), "record_count": len(records)}


def main() -> int:
    args = parse_args()
    source = args.export.resolve()
    if not source.exists():
        raise SystemExit("App Store Connect export does not exist")
    if source.is_symlink():
        raise SystemExit("App Store Connect export must not be a symlink")
    try:
        if source.is_file():
            files = [source]
            root = source.parent
            if source.stat().st_size > args.max_file_size:
                raise ScanLimitExceeded("export file exceeds max-file-size")
        else:
            root = source
            files = list(iter_files(
                root, max_size=args.max_file_size,
                max_files=args.max_files, max_total_size=args.max_total_size,
            ))
    except ScanLimitExceeded as error:
        raise SystemExit(f"ASC export scan budget exceeded: {error}") from error
    documents = []
    signals: dict[str, list[Any]] = {}
    for path in files:
        if path.suffix.lower() not in {".json", ".plist", ".xml"}:
            continue
        try:
            value = parse_document(path)
        except (OSError, ValueError, json.JSONDecodeError, plistlib.InvalidFileException):
            continue
        collect_aliases(value, signals)
        documents.append({
            "path": relpath(path, root),
            "format": path.suffix.lower().lstrip("."),
            "sha256": sha256_bytes(path.read_bytes()),
        })
    api_fragments = []
    try:
        for path in args.api_fragment:
            api_fragments.append(collect_api_fragment(path.resolve(), signals))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    normalized = {
        key: [summarize_value(key, item) for item in values]
        for key, values in sorted(signals.items())
    }
    fragment = new_fragment("inspect_asc_export", "app_store_connect", source)
    fragment["data"] = {
        "mode": "READ_ONLY_IMPORT",
        "documents": sorted(documents, key=lambda item: item["path"]),
        "api_fragments": sorted(api_fragments, key=lambda item: (str(item["endpoint"]), item["path"])),
        "metadata": normalized,
        "capabilities": {"network": False, "upload": False, "modify": False, "submit": False},
    }
    add_check(fragment, "ASC-001", "PASS" if documents else "BLOCKED",
              f"Parsed {len(documents)} local App Store Connect export document(s).",
              blocker=None if documents else "Provide a supported JSON or plist export.")
    for key, check_id in (("app_privacy", "ASC-PRIVACY"), ("age_rating", "ASC-AGE-RATING"),
                          ("review_notes", "ASC-REVIEW-NOTES"), ("iap", "ASC-IAP"),
                          ("subscriptions", "ASC-SUBSCRIPTIONS"), ("screenshots", "ASC-SCREENSHOTS"),
                          ("build_inventory", "ASC-BUILD-INVENTORY")):
        add_check(fragment, check_id, "PASS" if key in normalized else "NEEDS_VERIFY",
                  f"{key.replace('_', ' ').title()} evidence is present in the export." if key in normalized else
                  f"{key.replace('_', ' ').title()} evidence was not found in the export.",
                  verification="CONFIRMED" if key in normalized else "UNRESOLVED",
                  blocker=None if key in normalized else "The export may be partial or use an unsupported shape.")

    if args.expected:
        try:
            expected = json.loads(args.expected.resolve().read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise SystemExit(f"invalid expected metadata: {error}") from error
        allowed_expected = {"app_privacy", "age_rating", "iap", "subscriptions", "screenshots", "build_inventory"}
        if not isinstance(expected, dict) or set(expected) - allowed_expected:
            raise SystemExit("expected metadata contains unsupported fields")
        comparisons = []
        for key, expected_value in sorted(expected.items()):
            actual_values = signals.get(key, [])
            expected_hash = canonical_hash(expected_value)
            match = any(canonical_hash(value) == expected_hash for value in actual_values)
            disposition = "PASS" if match else ("BLOCKED" if not actual_values else "FAIL")
            comparisons.append({"field": key, "disposition": disposition, "expected_sha256": expected_hash,
                                "observed_representations": len(actual_values)})
            add_check(
                fragment, f"ASC-EXPECTED-{key.upper().replace('_', '-')}", disposition,
                f"{key.replace('_', ' ').title()} {'matches' if match else 'does not match'} the canonical expectation.",
                verification="CONFIRMED" if match or actual_values else "UNRESOLVED",
                blocker=None if match else ("No comparable evidence was imported." if not actual_values else None),
            )
            if disposition == "FAIL":
                add_finding(
                    fragment, f"ASC-EXPECTED-{key.upper().replace('_', '-')}-MISMATCH", "P1", "FAIL", "CONFIRMED", "App Store Connect",
                    f"App Store Connect {key.replace('_', ' ')} differs from the expected inventory",
                    "A canonical, hash-based comparison found a mismatch without exposing the underlying metadata values.",
                    authority_type="APP_STORE_CONNECT_REQUIREMENT",
                    evidence=[{"detail": f"field={key}; observed representations={len(actual_values)}"}],
                    remediation="Review the read-only export/API inventory and reconcile the intended submission metadata.",
                )
        fragment["data"]["expected_comparisons"] = comparisons
    else:
        fragment["data"]["expected_comparisons"] = []

    if args.archive_fragment:
        archive = json.loads(args.archive_fragment.resolve().read_text(encoding="utf-8"))
        apps = archive.get("data", {}).get("bundles", [])
        app = next((item for item in apps if item.get("kind") == "app" and not item.get("parent_bundle")), None)
        mismatches = []
        if app:
            comparisons = (("bundle_identifier", app.get("bundle_identifier")),
                           ("version", app.get("short_version")), ("build", app.get("build_version")))
            for key, expected in comparisons:
                exported = [item.get("value") for item in normalized.get(key, []) if "value" in item]
                if expected and exported and str(expected) not in {str(item) for item in exported}:
                    mismatches.append(key)
        if mismatches:
            add_check(fragment, "ASC-BUILD-CROSSCHECK", "FAIL", "ASC metadata differs from the supplied archive.")
            add_finding(
                fragment, "ASC-BUILD-METADATA-MISMATCH", "P1", "FAIL", "CONFIRMED", "App Store Connect",
                "App Store Connect build metadata does not match the archive",
                "The read-only export and packaged app disagree on release identity fields.",
                authority_type="APP_STORE_CONNECT_REQUIREMENT",
                evidence=[{"detail": ", ".join(mismatches)}],
                remediation="Select/export the intended build and reconcile version metadata before submission.",
            )
        else:
            add_check(fragment, "ASC-BUILD-CROSSCHECK", "PASS" if app else "BLOCKED",
                      "ASC metadata was compared with the archive." if app else "No main app bundle was available for comparison.",
                      blocker=None if app else "Supply an archive fragment containing a main app bundle.")
    else:
        add_check(fragment, "ASC-BUILD-CROSSCHECK", "NOT_RUN", "Archive comparison was not requested.",
                  blocker="Pass --archive-fragment to compare bundle ID and versions.")
    write_json(args.output.resolve(), fragment)
    return 0 if documents else 2


if __name__ == "__main__":
    raise SystemExit(main())
