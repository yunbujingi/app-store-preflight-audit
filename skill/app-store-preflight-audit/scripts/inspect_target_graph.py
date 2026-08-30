#!/usr/bin/env python3
"""Build a stable source-to-product graph from Xcode project and build-setting evidence."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from _common import add_check, new_fragment, read_text, relpath, write_json

PHASE_TYPES = {
    "PBXSourcesBuildPhase": "sources",
    "PBXResourcesBuildPhase": "resources",
}
SETTING_KEYS = (
    "PRODUCT_BUNDLE_IDENTIFIER", "WRAPPER_EXTENSION", "MACH_O_TYPE",
    "SUPPORTED_PLATFORMS", "CONFIGURATION", "TARGET_BUILD_DIR",
    "EXECUTABLE_PATH", "FULL_PRODUCT_NAME", "PRODUCT_NAME",
    "INFOPLIST_PATH", "PRODUCT_TYPE",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    container = parser.add_mutually_exclusive_group()
    container.add_argument("--project", type=Path)
    container.add_argument("--workspace", type=Path)
    parser.add_argument("--configuration", action="append", default=[])
    parser.add_argument("--use-xcodebuild", action="store_true",
                        help="Run read-only xcodebuild metadata commands; off by default")
    parser.add_argument("--metadata-dir", type=Path,
                        help="Offline xcodebuild-list.json/build-settings-<configuration>.json evidence")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def clean(value: str) -> str:
    value = value.strip().rstrip(";").strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.replace('\\"', '"')


def section(text: str, name: str) -> str:
    match = re.search(
        rf"/\* Begin {re.escape(name)} section \*/([\s\S]*?)/\* End {re.escape(name)} section \*/",
        text,
    )
    return match.group(1) if match else ""


def objects(text: str, section_name: str) -> dict[str, str]:
    body = section(text, section_name)
    result: dict[str, str] = {}
    for match in re.finditer(r"(?m)^\s*([A-Za-z0-9]+)(?: /\*.*?\*/)? = \{([\s\S]*?)\};", body):
        result[match.group(1)] = match.group(2)
    return result


def assignment(body: str, key: str) -> str | None:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*([^;]+);", body)
    return clean(match.group(1)) if match else None


def id_array(body: str, key: str) -> list[str]:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*\(([\s\S]*?)\);", body)
    if not match:
        return []
    return re.findall(r"([A-Za-z0-9]{12,})(?: /\*.*?\*/)?\s*,", match.group(1))


def parse_pbxproj(project: Path, root: Path) -> dict[str, Any]:
    pbx = project / "project.pbxproj"
    text = read_text(pbx)
    file_refs = {
        object_id: clean(assignment(body, "path") or assignment(body, "name") or object_id)
        for object_id, body in objects(text, "PBXFileReference").items()
    }
    build_files = {
        object_id: (assignment(body, "fileRef") or "").split(" ", 1)[0]
        for object_id, body in objects(text, "PBXBuildFile").items()
    }
    phases: dict[str, dict[str, Any]] = {}
    for section_name, phase_kind in PHASE_TYPES.items():
        for object_id, body in objects(text, section_name).items():
            phase_files = []
            for build_id in id_array(body, "files"):
                file_ref = build_files.get(build_id)
                if file_ref and file_ref in file_refs:
                    phase_files.append(file_refs[file_ref])
            phases[object_id] = {"kind": phase_kind, "files": sorted(set(phase_files))}

    targets = []
    memberships = []
    for target_id, body in objects(text, "PBXNativeTarget").items():
        name = assignment(body, "name") or assignment(body, "productName") or target_id
        product_ref = (assignment(body, "productReference") or "").split(" ", 1)[0]
        target = {
            "id": target_id,
            "name": name,
            "product_reference": file_refs.get(product_ref),
            "phase_ids": id_array(body, "buildPhases"),
        }
        targets.append(target)
        for phase_id in target["phase_ids"]:
            phase = phases.get(phase_id)
            if not phase:
                continue
            for path in phase["files"]:
                memberships.append({"path": path, "target": name, "phase": phase["kind"]})
    return {
        "path": relpath(project, root),
        "targets": sorted(targets, key=lambda item: item["name"]),
        "memberships": sorted(memberships, key=lambda item: (item["path"], item["target"], item["phase"])),
    }


def run_json(command: list[str], timeout: int) -> Any:
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)
    if completed.returncode != 0:
        raise RuntimeError(f"xcodebuild metadata command exited {completed.returncode}")
    return json.loads(completed.stdout)


def load_xcode_metadata(args: argparse.Namespace, root: Path, container: Path,
                        configurations: list[str]) -> tuple[dict[str, Any] | None, list[dict[str, Any]], list[str]]:
    listed = None
    settings: list[dict[str, Any]] = []
    limitations: list[str] = []
    if args.metadata_dir:
        metadata = (args.metadata_dir if args.metadata_dir.is_absolute() else root / args.metadata_dir).resolve()
        list_path = metadata / "xcodebuild-list.json"
        if list_path.is_file():
            listed = json.loads(list_path.read_text(encoding="utf-8"))
        for configuration in configurations:
            candidate = metadata / f"build-settings-{configuration}.json"
            if candidate.is_file():
                settings.extend(json.loads(candidate.read_text(encoding="utf-8")))
            else:
                limitations.append(f"missing offline build settings for {configuration}")
        return listed, settings, limitations
    if not args.use_xcodebuild:
        return None, [], ["xcodebuild metadata collection was not requested"]
    if not shutil.which("xcodebuild"):
        return None, [], ["xcodebuild is unavailable"]
    selector = ["-project" if args.project else "-workspace", str(container)]
    base = ["xcodebuild", *selector, "-disableAutomaticPackageResolution"]
    try:
        listed = run_json([*base, "-list", "-json"], args.timeout)
        for configuration in configurations:
            value = run_json([*base, "-configuration", configuration, "-showBuildSettings", "-json"], args.timeout)
            if isinstance(value, list):
                settings.extend(value)
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        limitations.append(f"{type(error).__name__}: {error}")
    return listed, settings, limitations


def tokenized_setting(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if key == "TARGET_BUILD_DIR":
        return "<TARGET_BUILD_DIR>"
    if key in {"EXECUTABLE_PATH", "INFOPLIST_PATH", "FULL_PRODUCT_NAME"}:
        return value.replace("\\", "/")
    return value


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit("root is not a directory")
    configurations = sorted(set(args.configuration or ["Release"]))
    if args.project or args.workspace:
        selected = args.project or args.workspace
        assert selected is not None
        container = (selected if selected.is_absolute() else root / selected).resolve()
    else:
        candidates = sorted(root.glob("*.xcodeproj")) + sorted(root.glob("*.xcworkspace"))
        if len(candidates) != 1:
            raise SystemExit("select --project or --workspace when discovery is not unique")
        container = candidates[0].resolve()
        args.project = container if container.suffix == ".xcodeproj" else None
        args.workspace = container if container.suffix == ".xcworkspace" else None
    if not container.exists():
        raise SystemExit("selected Xcode container does not exist")

    projects = sorted(root.rglob("*.xcodeproj"))
    parsed = [parse_pbxproj(project, root) for project in projects if (project / "project.pbxproj").is_file()]
    listed, raw_settings, limitations = load_xcode_metadata(args, root, container, configurations)
    normalized_settings = []
    for item in raw_settings:
        if not isinstance(item, dict) or not isinstance(item.get("buildSettings"), dict):
            continue
        source = item["buildSettings"]
        target = item.get("target") or source.get("TARGET_NAME")
        values = {key.lower(): tokenized_setting(key, source.get(key)) for key in SETTING_KEYS if source.get(key) not in (None, "")}
        values["target"] = target
        values["configuration"] = source.get("CONFIGURATION") or next((c for c in configurations), "Release")
        normalized_settings.append(values)
    normalized_settings.sort(key=lambda item: (str(item.get("target")), str(item.get("configuration"))))

    by_target_config = {(item.get("target"), item.get("configuration")): item for item in normalized_settings}
    relations = []
    memberships = [membership for project in parsed for membership in project["memberships"]]
    for membership in memberships:
        for configuration in configurations:
            setting = by_target_config.get((membership["target"], configuration), {})
            wrapper = setting.get("wrapper_extension")
            product = setting.get("full_product_name") or setting.get("product_name")
            if product and wrapper and not str(product).endswith(f".{wrapper}"):
                product = f"{product}.{wrapper}"
            executable = setting.get("executable_path")
            manifest = membership["path"] if Path(membership["path"]).name == "PrivacyInfo.xcprivacy" else None
            relations.append({
                "source": membership["path"],
                "phase": membership["phase"],
                "target": membership["target"],
                "configuration": configuration,
                "product": product,
                "bundle_identifier": setting.get("product_bundle_identifier"),
                "executable": executable,
                "manifest": manifest,
            })
    relations.sort(key=lambda item: (item["source"], item["target"], item["configuration"], item["phase"]))

    fragment = new_fragment("inspect_target_graph", "source", root)
    fragment["data"] = {
        "container": relpath(container, root),
        "configurations": configurations,
        "projects": parsed,
        "xcodebuild_list": listed,
        "build_settings": normalized_settings,
        "relations": relations,
        "relation_contract": "source -> target -> configuration -> product -> bundle -> executable -> manifest",
        "limitations": limitations,
    }
    target_count = len({target["name"] for project in parsed for target in project["targets"]})
    add_check(fragment, "TARGET-GRAPH-001", "PASS" if target_count else "NEEDS_VERIFY",
              f"Parsed {target_count} native target(s) from PBX project evidence.",
              verification="CONFIRMED" if target_count else "UNRESOLVED",
              blocker=None if target_count else "No PBXNativeTarget objects were parsed.")
    if normalized_settings:
        add_check(fragment, "TARGET-GRAPH-002", "PASS", "Xcode build settings were normalized by target and configuration.")
    else:
        add_check(fragment, "TARGET-GRAPH-002", "NOT_RUN", "Xcode build-setting metadata was not available.",
                  blocker="Use --use-xcodebuild or provide --metadata-dir to resolve final product values.")
    add_check(fragment, "TARGET-GRAPH-003", "PASS" if memberships else "NEEDS_VERIFY",
              f"Mapped {len(memberships)} source/resource membership record(s) from build phases.",
              verification="CONFIRMED" if memberships else "UNRESOLVED",
              blocker=None if memberships else "Project format may be generated or unsupported.")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
