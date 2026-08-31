#!/usr/bin/env python3
"""Build a stable source-to-product graph from Xcode project and build-setting evidence."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from _common import add_check, iter_files, new_fragment, read_text, relpath, sha256_bytes, strip_source_comments, write_json

PHASE_TYPES = {
    "PBXSourcesBuildPhase": "sources",
    "PBXResourcesBuildPhase": "resources",
}
SETTING_KEYS = (
    "PRODUCT_BUNDLE_IDENTIFIER", "WRAPPER_EXTENSION", "MACH_O_TYPE",
    "SUPPORTED_PLATFORMS", "CONFIGURATION", "TARGET_BUILD_DIR",
    "EXECUTABLE_PATH", "FULL_PRODUCT_NAME", "PRODUCT_NAME",
    "INFOPLIST_PATH", "PRODUCT_TYPE",
    "EXCLUDED_SOURCE_FILE_NAMES", "INCLUDED_SOURCE_FILE_NAMES",
    "DERIVED_FILE_DIR", "DERIVED_SOURCES_DIR", "CONFIGURATION_BUILD_DIR",
    "SDKROOT", "PLATFORM_NAME", "ARCHS",
)
SOURCE_SUFFIXES = {".swift", ".m", ".mm", ".c", ".cc", ".cpp", ".h", ".hpp", ".metal", ".intentdefinition"}
XC_CONFIG_KEYS = {
    "PRODUCT_BUNDLE_IDENTIFIER", "WRAPPER_EXTENSION", "MACH_O_TYPE", "SUPPORTED_PLATFORMS",
    "EXCLUDED_SOURCE_FILE_NAMES", "INCLUDED_SOURCE_FILE_NAMES", "GENERATE_INFOPLIST_FILE",
    "INFOPLIST_FILE", "CODE_SIGN_ENTITLEMENTS", "SWIFT_ACTIVE_COMPILATION_CONDITIONS",
}


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
    parser.add_argument("--link-map", action="append", default=[], type=Path,
                        help="Read-only Link Map used for linked static-library attribution")
    parser.add_argument("--xcconfig", action="append", default=[], type=Path,
                        help="Limit XCConfig parsing to selected files; defaults to discovered files")
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


def string_array(body: str, key: str) -> list[str]:
    match = re.search(rf"\b{re.escape(key)}\s*=\s*\(([\s\S]*?)\);", body)
    if not match:
        return []
    values = []
    for raw in re.findall(r'"((?:\\.|[^"\\])*)"|([^,\s][^,]*?)\s*,', match.group(1)):
        value = raw[0] or raw[1]
        value = clean(value)
        if value:
            values.append(value)
    return values


def phase_kind_for_path(path: str) -> str:
    return "sources" if Path(path).suffix.lower() in SOURCE_SUFFIXES else "resources"


def workspace_projects(workspace: Path, root: Path) -> list[dict[str, str]]:
    contents = workspace / "contents.xcworkspacedata"
    if not contents.is_file() or contents.is_symlink():
        return []
    try:
        tree = ET.parse(contents)
    except (OSError, ET.ParseError):
        return []
    result = []
    for item in tree.findall(".//FileRef"):
        location = item.attrib.get("location", "")
        prefix, _, raw = location.partition(":")
        if prefix not in {"group", "container", "absolute"} or not raw.endswith(".xcodeproj"):
            continue
        candidate = Path(raw) if prefix == "absolute" else workspace.parent / raw
        resolved = candidate.resolve()
        try:
            resolved.relative_to(root)
            path = relpath(resolved, root)
        except ValueError:
            path = f"<EXTERNAL_PROJECT>/{resolved.name}"
        result.append({"location_type": prefix, "path": path})
    return sorted(result, key=lambda item: (item["path"], item["location_type"]))


def swift_calls(content: str, call_names: set[str]) -> list[tuple[str, str]]:
    """Extract selected Swift call bodies with balanced parentheses and string awareness."""
    calls = []
    pattern = re.compile(r"\.([A-Za-z][A-Za-z0-9]*)\s*\(")
    for match in pattern.finditer(content):
        name = match.group(1)
        if name not in call_names:
            continue
        depth = 1
        index = match.end()
        start = index
        quoted = False
        escaped = False
        while index < len(content) and depth:
            character = content[index]
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
            index += 1
        if depth == 0:
            calls.append((name, content[start:index - 1]))
    return calls


def swift_array_argument(content: str, name: str) -> str:
    candidates = []
    for match in re.finditer(rf"\b{re.escape(name)}\s*:\s*\[", content):
        depth = 1
        index = match.end()
        start = index
        quoted = False
        escaped = False
        while index < len(content) and depth:
            character = content[index]
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character == "[":
                depth += 1
            elif character == "]":
                depth -= 1
            index += 1
        if depth == 0:
            candidates.append(content[start:index - 1])
    return max(candidates, key=len, default="")


def parse_swift_packages(root: Path) -> list[dict[str, Any]]:
    packages = []
    for manifest in sorted(path for path in root.rglob("Package.swift") if not path.is_symlink()):
        content = strip_source_comments(read_text(manifest))
        target_section = swift_array_argument(content, "targets")
        product_section = swift_array_argument(content, "products")
        targets = []
        for kind, body in swift_calls(target_section, {"target", "testTarget", "executableTarget", "macro", "plugin"}):
            name_match = re.search(r'\bname\s*:\s*"([^"]+)"', body)
            if not name_match:
                continue
            name = name_match.group(1)
            dependencies_match = re.search(r"dependencies\s*:\s*\[([\s\S]*?)\]", body)
            dependencies = sorted(set(re.findall(r'\"([^\"]+)\"', dependencies_match.group(1)))) if dependencies_match else []
            plugins_match = re.search(r"plugins\s*:\s*\[([\s\S]*?)\]", body)
            plugins = sorted(set(re.findall(r'(?:name\s*:\s*)?\"([^\"]+)\"', plugins_match.group(1)))) if plugins_match else []
            capability = None
            if kind == "plugin":
                capability_match = re.search(r"capability\s*:\s*\.(buildTool|command)", body)
                if not capability_match:
                    continue
                capability = capability_match.group(1)
            targets.append({"name": name, "kind": kind, "dependencies": dependencies, "plugins": plugins, "capability": capability})
        products = []
        for kind, body in swift_calls(product_section, {"library", "executable", "plugin"}):
            name_match = re.search(r'\bname\s*:\s*"([^"]+)"', body)
            if not name_match or (kind == "plugin" and "capability" in body):
                continue
            name = name_match.group(1)
            target_match = re.search(r"targets\s*:\s*\[([\s\S]*?)\]", body)
            products.append({
                "name": name, "kind": kind,
                "targets": sorted(set(re.findall(r'\"([^\"]+)\"', target_match.group(1)))) if target_match else [],
            })
        packages.append({
            "manifest": relpath(manifest, root),
            "targets": sorted(targets, key=lambda item: (item["name"], item["kind"])),
            "products": sorted(products, key=lambda item: (item["name"], item["kind"])),
        })
    return packages


def parse_xcconfig(path: Path, root: Path, seen: set[Path] | None = None) -> list[dict[str, Any]]:
    resolved = path.resolve()
    seen = seen or set()
    if resolved in seen or resolved.is_symlink():
        return []
    try:
        resolved.relative_to(root)
    except ValueError:
        return [{"path": f"<EXTERNAL_XCCONFIG>/{resolved.name}", "status": "OUTSIDE_ROOT"}]
    seen.add(resolved)
    records = []
    logical_lines = []
    pending = ""
    for line in read_text(resolved).splitlines():
        stripped = line.strip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        logical_lines.append(pending + stripped)
        pending = ""
    for number, line in enumerate(logical_lines, 1):
        line = re.sub(r"//.*$", "", line).strip()
        if not line:
            continue
        include = re.match(r'#include\??\s+"([^"]+)"', line)
        if include:
            child = (resolved.parent / include.group(1)).resolve()
            records.append({"path": relpath(resolved, root), "line": number, "include": relpath(child, root), "optional": line.startswith("#include?")})
            if child.is_file():
                records.extend(parse_xcconfig(child, root, seen))
            continue
        match = re.match(r"([A-Za-z0-9_]+)((?:\[[^\]]+\])*)\s*(\?=|\+=|=)\s*(.*)$", line)
        if not match or match.group(1) not in XC_CONFIG_KEYS:
            continue
        conditions = dict(re.findall(r"\[([^=\]]+)=([^\]]+)\]", match.group(2)))
        records.append({
            "path": relpath(resolved, root), "line": number, "key": match.group(1),
            "operator": match.group(3), "value": match.group(4).strip(), "conditions": dict(sorted(conditions.items())),
        })
    return records


def tokenize_link_path(value: str) -> str:
    value = value.strip()
    if not value:
        return value
    name = Path(value).name
    return f"<LINK_INPUT>/{name}" if value.startswith("/") else value


def parse_link_map(path: Path, max_size: int = 50_000_000) -> dict[str, Any]:
    path = path.resolve()
    if path.is_symlink() or not path.is_file():
        raise ValueError("Link Map must be a regular file")
    payload = path.read_bytes()
    if len(payload) > max_size:
        raise ValueError("Link Map exceeds 50 MB")
    text = payload.decode("utf-8", "replace")
    executable_match = re.search(r"(?m)^# Path:\s*(.+)$", text)
    arch_match = re.search(r"(?m)^# Arch:\s*(.+)$", text)
    objects_by_index: dict[str, dict[str, str]] = {}
    static_libraries: dict[str, dict[str, Any]] = {}
    in_objects = False
    for line in text.splitlines():
        if line.startswith("# Object files:"):
            in_objects = True
            continue
        if in_objects and line.startswith("# Sections:"):
            in_objects = False
        if not in_objects:
            continue
        match = re.match(r"\[\s*(\d+)\]\s+(.+)$", line)
        if not match:
            continue
        index, raw = match.groups()
        library_match = re.search(r"([^/()]+\.a)\(([^)]+)\)$", raw)
        record = {"path": tokenize_link_path(raw)}
        if library_match:
            library, member = library_match.groups()
            record.update({"static_library": library, "member": member})
            entry = static_libraries.setdefault(library, {"identity": library, "members": set(), "object_indexes": [], "symbol_count": 0})
            entry["members"].add(member)
            entry["object_indexes"].append(int(index))
        objects_by_index[index] = record
    for match in re.finditer(r"(?m)^0x[0-9A-Fa-f]+\s+0x[0-9A-Fa-f]+\s+\[\s*(\d+)\]", text):
        record = objects_by_index.get(match.group(1))
        if record and record.get("static_library") in static_libraries:
            static_libraries[record["static_library"]]["symbol_count"] += 1
    normalized_libraries = []
    for item in static_libraries.values():
        normalized_libraries.append({
            **item, "members": sorted(item["members"]), "object_indexes": sorted(item["object_indexes"]),
            "attribution": "LINK_MAP_CONFIRMED",
        })
    return {
        "path": path.name, "sha256": sha256_bytes(payload),
        "executable": tokenize_link_path(executable_match.group(1)) if executable_match else None,
        "architecture": arch_match.group(1).strip() if arch_match else None,
        "object_count": len(objects_by_index),
        "static_libraries": sorted(normalized_libraries, key=lambda item: item["identity"]),
    }


def parse_pbxproj(project: Path, root: Path) -> dict[str, Any]:
    pbx = project / "project.pbxproj"
    text = read_text(pbx)
    file_refs = {
        object_id: clean(assignment(body, "path") or assignment(body, "name") or object_id)
        for object_id, body in objects(text, "PBXFileReference").items()
    }
    build_files = {}
    for object_id, body in objects(text, "PBXBuildFile").items():
        file_ref = (assignment(body, "fileRef") or assignment(body, "productRef") or "").split(" ", 1)[0]
        platform_filter = assignment(body, "platformFilter")
        platform_filters = string_array(body, "platformFilters")
        if platform_filter:
            platform_filters.append(platform_filter)
        build_files[object_id] = {"file_ref": file_ref, "platform_filters": sorted(set(platform_filters))}
    phases: dict[str, dict[str, Any]] = {}
    for section_name, phase_kind in PHASE_TYPES.items():
        for object_id, body in objects(text, section_name).items():
            phase_files = []
            for build_id in id_array(body, "files"):
                build_file = build_files.get(build_id, {})
                file_ref = build_file.get("file_ref")
                if file_ref and file_ref in file_refs:
                    phase_files.append({
                        "path": file_refs[file_ref],
                        "platform_filters": build_file.get("platform_filters", []),
                    })
            phases[object_id] = {
                "kind": phase_kind,
                "files": sorted(phase_files, key=lambda item: (item["path"], item["platform_filters"])),
            }

    synchronized_groups = {}
    for object_id, body in objects(text, "PBXFileSystemSynchronizedRootGroup").items():
        group_path = assignment(body, "path") or assignment(body, "name")
        exceptions = id_array(body, "exceptions")
        synchronized_groups[object_id] = {
            "path": group_path, "exceptions": exceptions,
            "explicit_file_types_present": "explicitFileTypes" in body,
            "explicit_folders_present": "explicitFolders" in body,
        }

    shell_phases = {}
    for object_id, body in objects(text, "PBXShellScriptBuildPhase").items():
        outputs = string_array(body, "outputPaths")
        file_lists = string_array(body, "outputFileListPaths")
        shell_phases[object_id] = {"outputs": outputs, "output_file_lists": file_lists}

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
            "synchronized_group_ids": id_array(body, "fileSystemSynchronizedGroups"),
        }
        targets.append(target)
        for phase_id in target["phase_ids"]:
            phase = phases.get(phase_id)
            if not phase:
                continue
            for item in phase["files"]:
                memberships.append({
                    "path": item["path"], "target": name, "phase": phase["kind"],
                    "platform_filters": item["platform_filters"],
                    "membership_source": "PBX_BUILD_PHASE", "verification": "CONFIRMED",
                })
        for group_id in target["synchronized_group_ids"]:
            group = synchronized_groups.get(group_id)
            if not group or not group.get("path"):
                continue
            group_root = (project.parent / group["path"]).resolve()
            if not group_root.is_dir():
                memberships.append({
                    "path": group["path"], "target": name, "phase": "UNRESOLVED",
                    "platform_filters": [], "membership_source": "PBX_FILE_SYSTEM_SYNCHRONIZED_ROOT_GROUP",
                    "verification": "UNRESOLVED", "exceptions_present": bool(group["exceptions"]),
                })
                continue
            for path in iter_files(group_root, max_files=20_000, max_total_size=500_000_000):
                relative = relpath(path, root)
                memberships.append({
                    "path": relative, "target": name, "phase": phase_kind_for_path(relative),
                    "platform_filters": [], "membership_source": "PBX_FILE_SYSTEM_SYNCHRONIZED_ROOT_GROUP",
                    "verification": "INFERRED" if group["exceptions"] else "CONFIRMED",
                    "exceptions_present": bool(group["exceptions"]),
                })
        for phase_id in target["phase_ids"]:
            shell = shell_phases.get(phase_id)
            if not shell:
                continue
            generated = list(shell["outputs"])
            for file_list in shell["output_file_lists"]:
                normalized_list = file_list.replace("$(SRCROOT)/", "")
                if "$" in normalized_list or Path(normalized_list).is_absolute():
                    continue
                resolved_list = (root / normalized_list).resolve()
                try:
                    resolved_list.relative_to(root)
                except ValueError:
                    continue
                if resolved_list.is_file() and not resolved_list.is_symlink():
                    generated.extend(line.strip() for line in read_text(resolved_list).splitlines() if line.strip() and not line.lstrip().startswith("#"))
            for output in sorted(set(generated)):
                memberships.append({
                    "path": output, "target": name, "phase": phase_kind_for_path(output),
                    "platform_filters": [], "membership_source": "GENERATED_BUILD_OUTPUT",
                    "verification": "INFERRED", "generated": True,
                })
    return {
        "path": relpath(project, root),
        "targets": sorted(targets, key=lambda item: item["name"]),
        "memberships": sorted(memberships, key=lambda item: (item["path"], item["target"], item["phase"], item["membership_source"])),
        "synchronized_groups": synchronized_groups,
        "generated_output_count": sum(bool(item.get("generated")) for item in memberships),
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
    if value.startswith("/"):
        return f"<BUILD_PATH>/{Path(value).name}"
    return value


def split_patterns(value: object) -> list[str]:
    if not isinstance(value, str):
        return []
    patterns = []
    for quoted, unquoted in re.findall(r'"([^"]+)"|([^\s]+)', value):
        item = quoted or unquoted
        if item and item != "$(inherited)":
            patterns.append(item)
    return patterns


def membership_state(membership: dict[str, Any], setting: dict[str, Any]) -> tuple[str, list[str]]:
    reasons = []
    platforms = set(str(setting.get("supported_platforms", "")).split())
    filters = set(membership.get("platform_filters", []))
    if filters and platforms and not any(any(fnmatch.fnmatchcase(platform, pattern) for platform in platforms) for pattern in filters):
        return "EXCLUDED", ["PBX platform filter does not match SUPPORTED_PLATFORMS"]
    path = str(membership["path"])
    name = Path(path).name
    excluded = split_patterns(setting.get("excluded_source_file_names"))
    included = split_patterns(setting.get("included_source_file_names"))
    if any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(name, pattern) for pattern in excluded):
        return "EXCLUDED", ["EXCLUDED_SOURCE_FILE_NAMES"]
    if included and membership.get("phase") == "sources":
        if not any(fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(name, pattern) for pattern in included):
            return "EXCLUDED", ["not selected by INCLUDED_SOURCE_FILE_NAMES"]
        reasons.append("INCLUDED_SOURCE_FILE_NAMES")
    if membership.get("verification") == "UNRESOLVED":
        return "UNRESOLVED", ["membership evidence unresolved"]
    if membership.get("exceptions_present"):
        reasons.append("synchronized-group exceptions require Xcode-resolved confirmation")
        return "UNRESOLVED", reasons
    return "INCLUDED", reasons


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

    projects = sorted(path for path in root.rglob("*.xcodeproj") if not path.is_symlink())
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

    workspaces = []
    for workspace in sorted(path for path in root.rglob("*.xcworkspace") if not path.is_symlink()):
        workspaces.append({"path": relpath(workspace, root), "projects": workspace_projects(workspace, root)})
    swift_packages = parse_swift_packages(root)
    if args.xcconfig:
        xcconfig_paths = [(path if path.is_absolute() else root / path).resolve() for path in args.xcconfig]
    else:
        xcconfig_paths = sorted(path for path in root.rglob("*.xcconfig") if not path.is_symlink())
    xcconfig_records = []
    for path in xcconfig_paths:
        if path.is_file():
            xcconfig_records.extend(parse_xcconfig(path, root))

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
            state, state_reasons = membership_state(membership, setting)
            relations.append({
                "source": membership["path"],
                "phase": membership["phase"],
                "target": membership["target"],
                "configuration": configuration,
                "membership_state": state,
                "membership_source": membership.get("membership_source", "PBX_BUILD_PHASE"),
                "membership_verification": membership.get("verification", "CONFIRMED"),
                "membership_reasons": state_reasons,
                "generated": bool(membership.get("generated")),
                "product": product,
                "bundle_identifier": setting.get("product_bundle_identifier"),
                "executable": executable,
                "manifest": manifest,
            })
    relations.sort(key=lambda item: (item["source"], item["target"], item["configuration"], item["phase"]))

    link_maps = []
    for raw_path in args.link_map:
        path = raw_path if raw_path.is_absolute() else root / raw_path
        parsed_map = parse_link_map(path)
        executable_name = Path(str(parsed_map.get("executable") or "")).name
        candidates = [
            item for item in normalized_settings
            if Path(str(item.get("executable_path") or "")).name == executable_name
        ]
        parsed_map["target_candidates"] = sorted({str(item.get("target")) for item in candidates if item.get("target")})
        parsed_map["configuration_candidates"] = sorted({str(item.get("configuration")) for item in candidates if item.get("configuration")})
        parsed_map["attribution_verification"] = "CONFIRMED" if len(parsed_map["target_candidates"]) == 1 else "UNRESOLVED"
        link_maps.append(parsed_map)

    xcconfig_applicability = []
    contexts = normalized_settings or [{"target": None, "configuration": configuration} for configuration in configurations]
    for record in xcconfig_records:
        if "key" not in record:
            continue
        conditions = record.get("conditions", {})
        for context in contexts:
            configuration = str(context.get("configuration") or "")
            config_pattern = conditions.get("config")
            matches_configuration = not config_pattern or fnmatch.fnmatchcase(configuration, config_pattern)
            sdk_pattern = conditions.get("sdk")
            sdk_value = str(context.get("sdkroot") or context.get("platform_name") or "")
            matches_sdk = not sdk_pattern or (bool(sdk_value) and fnmatch.fnmatchcase(sdk_value, sdk_pattern))
            unresolved_conditions = sorted(
                key for key in conditions
                if key not in {"config", "sdk"} or (key == "sdk" and not sdk_value)
            )
            applies: bool | None = matches_configuration and matches_sdk if not unresolved_conditions else None
            xcconfig_applicability.append({
                "path": record["path"], "line": record["line"], "key": record["key"],
                "target": context.get("target"), "configuration": configuration, "applies": applies,
                "unresolved_conditions": unresolved_conditions,
            })

    fragment = new_fragment("inspect_target_graph", "source", root)
    fragment["data"] = {
        "container": relpath(container, root),
        "configurations": configurations,
        "projects": parsed,
        "workspaces": workspaces,
        "swift_packages": swift_packages,
        "package_plugins": [
            {"package": package["manifest"], "target": target["name"], "capability": target["capability"]}
            for package in swift_packages for target in package["targets"] if target["kind"] == "plugin"
        ],
        "xcconfig_records": xcconfig_records,
        "xcconfig_applicability": xcconfig_applicability,
        "xcodebuild_list": listed,
        "build_settings": normalized_settings,
        "relations": relations,
        "link_maps": link_maps,
        "linked_static_libraries": [
            {**library, "target_candidates": link_map["target_candidates"], "architecture": link_map["architecture"]}
            for link_map in link_maps for library in link_map["static_libraries"]
        ],
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
    synchronized_count = sum(len(project["synchronized_groups"]) for project in parsed)
    unresolved_relations = sum(item["membership_state"] == "UNRESOLVED" for item in relations)
    add_check(
        fragment, "TARGET-GRAPH-004", "NEEDS_VERIFY" if unresolved_relations else "PASS",
        f"Resolved configuration membership with {synchronized_count} synchronized group(s); {unresolved_relations} relation(s) remain unresolved.",
        verification="INFERRED" if unresolved_relations else "CONFIRMED",
        blocker="Use Xcode-resolved build settings when synchronized-group exceptions or generated membership remain ambiguous." if unresolved_relations else None,
    )
    if args.link_map:
        resolved_maps = sum(item["attribution_verification"] == "CONFIRMED" for item in link_maps)
        add_check(fragment, "TARGET-GRAPH-LINK-MAP", "PASS" if resolved_maps == len(link_maps) else "NEEDS_VERIFY",
                  f"Imported {len(link_maps)} Link Map(s); {resolved_maps} mapped to one target.",
                  verification="CONFIRMED" if resolved_maps == len(link_maps) else "UNRESOLVED",
                  blocker=None if resolved_maps == len(link_maps) else "Match each Link Map executable to exactly one target/configuration.")
    else:
        add_check(fragment, "TARGET-GRAPH-LINK-MAP", "NOT_RUN", "No Link Map was supplied.",
                  blocker="Pass --link-map to attribute linked static-library members and symbols.")
    write_json(args.output.resolve(), fragment)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
