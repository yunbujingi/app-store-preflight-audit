#!/usr/bin/env python3
"""Collect a conservative, read-only Apple project inventory."""

from __future__ import annotations

import argparse
import re
import shutil
from collections import Counter
from pathlib import Path

from _common import ScanLimitExceeded, add_check, git_snapshot, iter_files, new_fragment, read_plist, read_text, relpath, strip_source_comments, write_json

DEPENDENCY_NAMES = {
    "Package.swift", "Package.resolved", "Podfile", "Podfile.lock",
    "Cartfile", "Cartfile.resolved", "Mintfile", "project.yml", "Project.swift",
}
PURPOSE_KEY = re.compile(r"^NS.*UsageDescription$")
IMPORT = re.compile(r"^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
CAPABILITY_MODULES = {
    "AppTrackingTransparency": "tracking",
    "AuthenticationServices": "login-services",
    "AVFoundation": "camera-or-microphone",
    "CloudKit": "cloudkit",
    "CoreBluetooth": "bluetooth",
    "CoreLocation": "location",
    "EventKit": "calendar-or-reminders",
    "HealthKit": "health",
    "Photos": "photos",
    "StoreKit": "commerce",
    "UserNotifications": "notifications",
    "WatchKit": "watch",
    "WidgetKit": "widget",
}
BEHAVIOR_PATTERNS = {
    "account-deletion": (r"\bdeleteAccount\b", r"\brequestAccountDeletion\b", r"\bdeleteUser\b"),
    "third-party-ai-data-flow": (r"\bAIProvider\b", r"\bThirdPartyAI\b", r"\bmodelProvider\b"),
    "external-purchase": (r"\bExternalPurchase", r"\bSKExternalPurchase"),
}
REGIONAL_COMMERCE_KEYS = {
    "SKExternalPurchase", "SKExternalPurchaseLink", "SKExternalPurchaseMultiLink",
    "SKExternalPurchaseCustomLinkRegions", "SKExternalPurchaseLinkStreamingRegions",
    "com.apple.developer.storekit.external-purchase",
    "com.apple.developer.storekit.external-purchase-link",
    "com.apple.developer.storekit.external-purchase-link-streaming",
    "com.apple.developer.storekit.custom-purchase-link.allowed-regions",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-files", type=int, default=50_000)
    parser.add_argument("--max-total-size", type=int, default=500_000_000)
    parser.add_argument("--max-file-size", type=int, default=2_000_000)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit(f"repository root is not a directory: {root}")

    fragment = new_fragment("project_inventory", "source", root)
    if min(args.max_files, args.max_total_size, args.max_file_size) <= 0:
        raise SystemExit("scan limits must be positive")
    try:
        files = list(iter_files(
            root, max_size=args.max_file_size,
            max_files=args.max_files, max_total_size=args.max_total_size,
        ))
    except ScanLimitExceeded as error:
        raise SystemExit(f"scan budget exceeded: {error}") from error
    projects: set[str] = set()
    workspaces: set[str] = set()
    dependencies: list[str] = []
    plists: list[str] = []
    entitlements: list[str] = []
    manifests: list[str] = []
    source_files: list[str] = []
    purpose_strings: dict[str, list[str]] = {}
    imports: Counter[str] = Counter()
    run_script_phases = 0
    execution_risks: list[dict[str, str]] = []
    target_names: set[str] = set()
    behavior_signals: dict[str, list[dict[str, object]]] = {}
    regional_commerce_signals: dict[str, list[str]] = {}

    for path in files:
        relative = relpath(path, root)
        for parent in path.parents:
            if parent == root.parent:
                break
            if parent.suffix == ".xcodeproj":
                projects.add(relpath(parent, root))
            elif parent.suffix == ".xcworkspace":
                workspaces.add(relpath(parent, root))
        if path.name in DEPENDENCY_NAMES:
            dependencies.append(relative)
        if path.name == "PrivacyInfo.xcprivacy":
            manifests.append(relative)
        if path.suffix == ".entitlements":
            entitlements.append(relative)
        if path.suffix in {".plist", ".entitlements"} or path.name.endswith(".xcprivacy"):
            plists.append(relative)
            try:
                plist = read_plist(path)
                keys = sorted(key for key in plist if PURPOSE_KEY.match(key))
                if keys:
                    purpose_strings[relative] = keys
                commerce_keys = sorted(set(plist) & REGIONAL_COMMERCE_KEYS)
                if commerce_keys:
                    regional_commerce_signals[relative] = commerce_keys
            except Exception:
                pass
        if path.suffix in {".swift", ".m", ".mm", ".h"}:
            source_files.append(relative)
            content = read_text(path)
            if path.suffix == ".swift":
                imports.update(IMPORT.findall(content))
            signal_content = strip_source_comments(content)
            for signal, patterns in BEHAVIOR_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, signal_content)
                    if match:
                        behavior_signals.setdefault(signal, []).append({
                            "path": relative,
                            "line": signal_content[:match.start()].count("\n") + 1,
                            "pattern": pattern,
                        })
                        break
        if path.name == "project.pbxproj":
            content = read_text(path)
            run_script_phases += content.count("PBXShellScriptBuildPhase")
            for marker, kind in (
                ("PBXShellScriptBuildPhase", "run-script-build-phase"),
                ("PBXBuildRule", "custom-build-rule"),
            ):
                if marker in content:
                    execution_risks.append({"path": relative, "kind": kind})
            for match in re.finditer(r"isa = PBXNativeTarget;[\s\S]{0,1200}?name = ([^;]+);", content):
                target_names.add(match.group(1).strip().strip('"'))
        if path.name == "Package.swift":
            content = strip_source_comments(read_text(path))
            markers = {
                ".plugin(": "swift-package-plugin",
                "BuildToolPlugin": "swift-build-tool-plugin",
                "CommandPlugin": "swift-command-plugin",
                "prebuildCommand": "swift-package-prebuild-command",
                "buildCommand": "swift-package-build-command",
            }
            for marker, kind in markers.items():
                if marker in content:
                    execution_risks.append({"path": relative, "kind": kind})
        if path.name in {"Podfile", "Podfile.lock"}:
            content = read_text(path)
            for marker, kind in (("post_install", "cocoapods-post-install-hook"), ("script_phase", "cocoapods-script-phase")):
                if marker in content:
                    execution_risks.append({"path": relative, "kind": kind})

    signals = sorted({CAPABILITY_MODULES[module] for module in imports if module in CAPABILITY_MODULES})
    fragment["data"] = {
        "git": git_snapshot(root),
        "projects": sorted(projects),
        "workspaces": sorted(workspaces),
        "targets": sorted(target_names),
        "dependency_files": sorted(dependencies),
        "privacy_manifests": sorted(manifests),
        "entitlements": sorted(entitlements),
        "plists": sorted(plists),
        "purpose_string_keys": purpose_strings,
        "source_file_count": len(source_files),
        "swift_imports": dict(sorted(imports.items())),
        "feature_signals": signals,
        "behavior_signals": dict(sorted(behavior_signals.items())),
        "regional_commerce_signals": dict(sorted(regional_commerce_signals.items())),
        "run_script_build_phase_count": run_script_phases,
        "execution_risks": sorted(execution_risks, key=lambda item: (item["path"], item["kind"])),
        "scan_budget": {
            "max_files": args.max_files,
            "max_total_size": args.max_total_size,
            "max_file_size": args.max_file_size,
            "files_readable": len(files),
        },
        "tools": {name: bool(shutil.which(name)) for name in ("git", "xcodebuild", "xcrun", "codesign")},
    }

    add_check(fragment, "SRC-001", "PASS", "Repository was readable and inventory collection completed.")
    if projects or workspaces:
        add_check(fragment, "SRC-002", "PASS", "At least one Xcode project or workspace was discovered.")
    else:
        add_check(fragment, "SRC-002", "NEEDS_VERIFY", "No Xcode project or workspace was discovered.",
                  verification="UNRESOLVED", blocker="The repository may use a generator or unsupported layout.")
    if fragment["data"]["git"]["available"]:
        add_check(fragment, "SRC-003", "PASS", "Git revision and worktree status were captured.")
    else:
        add_check(fragment, "SRC-003", "N/A", "The inspected directory is not a Git worktree.")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
