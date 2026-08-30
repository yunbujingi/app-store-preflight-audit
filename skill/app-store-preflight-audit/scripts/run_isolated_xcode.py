#!/usr/bin/env python3
"""Plan or run xcodebuild with isolated outputs and repository mutation checks."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from _common import add_check, add_finding, git_snapshot, new_fragment, read_text, relpath, strip_source_comments, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    container = parser.add_mutually_exclusive_group(required=True)
    container.add_argument("--project", type=Path)
    container.add_argument("--workspace", type=Path)
    parser.add_argument("--scheme", required=True)
    parser.add_argument("--action", choices=("build", "test", "archive"), required=True)
    parser.add_argument("--configuration", default="Release")
    parser.add_argument("--destination")
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--evidence-output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", help="Execute; default is a dry-run plan")
    parser.add_argument("--allow-run-scripts", action="store_true")
    parser.add_argument("--allow-build-hooks", action="store_true",
                        help="Acknowledge all detected package/build/dependency hooks")
    parser.add_argument("--allow-dependency-resolution", action="store_true")
    parser.add_argument("--allow-signing", action="store_true")
    parser.add_argument("--acknowledge-execution-risk", action="store_true",
                        help="Acknowledge the capability and side-effect preview")
    parser.add_argument("--timeout", type=int, default=3600)
    return parser.parse_args()


def inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def execution_risks(root: Path) -> list[dict[str, str]]:
    risks: list[dict[str, str]] = []
    for path in sorted(root.rglob("project.pbxproj")):
        content = read_text(path)
        for marker, kind in (("PBXShellScriptBuildPhase", "run-script-build-phase"),
                             ("PBXBuildRule", "custom-build-rule")):
            if marker in content:
                risks.append({"kind": kind, "path": relpath(path, root)})
    for path in sorted(root.rglob("Package.swift")):
        content = strip_source_comments(read_text(path))
        for marker, kind in ((".plugin(", "swift-package-plugin"),
                             ("BuildToolPlugin", "swift-build-tool-plugin"),
                             ("CommandPlugin", "swift-command-plugin"),
                             ("prebuildCommand", "swift-package-prebuild-command"),
                             ("buildCommand", "swift-package-build-command")):
            if marker in content:
                risks.append({"kind": kind, "path": relpath(path, root)})
    for path in sorted(root.rglob("Podfile")):
        content = read_text(path)
        for marker, kind in (("post_install", "cocoapods-post-install-hook"),
                             ("script_phase", "cocoapods-script-phase")):
            if marker in content:
                risks.append({"kind": kind, "path": relpath(path, root)})
    return sorted(risks, key=lambda item: (item["path"], item["kind"]))


def tokenized_command(command: list[str], root: Path, output_root: Path) -> list[str]:
    replacements = ((str(output_root), "<OUTPUT_ROOT>"), (str(root), "<REPO_ROOT>"))
    result = []
    for argument in command:
        value = argument
        for actual, token in replacements:
            value = value.replace(actual, token)
        result.append(value)
    return result


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    output_root = args.output_root.resolve()
    evidence_output = args.evidence_output.resolve()
    container = (args.project or args.workspace)
    assert container is not None
    container_path = container if container.is_absolute() else root / container
    container_path = container_path.resolve()

    if not root.is_dir() or not container_path.exists():
        raise SystemExit("root or Xcode container does not exist")
    if inside(output_root, root) or inside(evidence_output, root):
        raise SystemExit("output-root and evidence-output must be outside the audited repository")
    if args.action == "test" and not args.destination:
        raise SystemExit("test action requires an explicit --destination")

    risks = execution_risks(root)
    run_script_count = sum(item["kind"] == "run-script-build-phase" for item in risks)

    command = ["xcodebuild"]
    command += ["-project" if args.project else "-workspace", str(container_path)]
    command += ["-scheme", args.scheme, "-configuration", args.configuration]
    command += ["-derivedDataPath", str(output_root / "DerivedData")]
    command += ["-clonedSourcePackagesDirPath", str(output_root / "SourcePackages")]
    if not args.allow_dependency_resolution:
        command += ["-disableAutomaticPackageResolution"]
    if args.destination:
        command += ["-destination", args.destination]
    if args.action == "archive":
        command += ["-archivePath", str(output_root / f"{args.scheme}.xcarchive"), "archive"]
    else:
        result_name = "Tests.xcresult" if args.action == "test" else "Build.xcresult"
        command += ["-resultBundlePath", str(output_root / result_name), args.action]
    if not args.allow_signing:
        command += ["CODE_SIGNING_ALLOWED=NO", "CODE_SIGNING_REQUIRED=NO"]

    preview = {
        "will_execute": args.execute,
        "capabilities": {
            "filesystem_write": ["<OUTPUT_ROOT>"],
            "repository_write_expected": False,
            "network_may_be_used": args.allow_dependency_resolution,
            "signing_and_keychain_may_be_used": args.allow_signing,
            "simulator_or_device_may_be_used": bool(args.destination),
            "project_hooks_may_execute": bool(risks),
        },
        "detected_execution_risks": risks,
        "command": tokenized_command(command, root, output_root),
    }
    if args.execute:
        print(json.dumps({"execution_preview": preview}, indent=2))
    if args.execute and risks and not (args.allow_build_hooks or (args.allow_run_scripts and len(risks) == run_script_count)):
        kinds = ", ".join(sorted({item["kind"] for item in risks}))
        raise SystemExit(f"refusing to execute detected Run Script/build hooks ({kinds}); inspect them and pass --allow-build-hooks to acknowledge")
    if args.execute and not args.acknowledge_execution_risk:
        raise SystemExit("refusing execution until the capability preview is acknowledged with --acknowledge-execution-risk")

    layer = "unit_test" if args.action == "test" else ("archive" if args.action == "archive" else "build")
    fragment = new_fragment("run_isolated_xcode", layer, root)
    before = git_snapshot(root)
    fragment["data"] = {
        "executed": args.execute,
        "command": tokenized_command(command, root, output_root),
        "execution_preview": preview,
        "execution_risks": risks,
        "run_script_build_phase_count": run_script_count,
        "signing_allowed": args.allow_signing,
        "dependency_resolution_allowed": args.allow_dependency_resolution,
        "output_root_fingerprint": new_fragment("output", layer, output_root)["subject"]["path_fingerprint"],
        "git_before": before,
    }

    if not args.execute:
        add_check(fragment, "XCODE-001", "NOT_RUN", "Xcode command was planned but not executed.",
                  verification="CONFIRMED", blocker="Pass --execute after reviewing the command and build scripts.")
        write_json(evidence_output, fragment)
        print(json.dumps({"execution_preview": preview}, indent=2))
        return 0
    if not shutil.which("xcodebuild"):
        add_check(fragment, "XCODE-001", "BLOCKED", "xcodebuild is unavailable.",
                  verification="CONFIRMED", blocker="Run on macOS with a compatible Xcode installation.")
        write_json(evidence_output, fragment)
        return 2

    output_root.mkdir(parents=True, exist_ok=True)
    log_path = output_root / "xcodebuild.log"
    try:
        with log_path.open("wb") as log:
            completed = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=args.timeout, check=False)
        return_code = completed.returncode
    except subprocess.TimeoutExpired:
        return_code = 124
    after = git_snapshot(root)
    fragment["data"]["return_code"] = return_code
    fragment["data"]["log"] = log_path.name
    fragment["data"]["git_after"] = after
    mutated = before.get("status") != after.get("status") or before.get("revision") != after.get("revision")

    if mutated:
        add_check(fragment, "XCODE-REPO-STATE", "FAIL", "Repository state changed during Xcode execution.")
        add_finding(
            fragment, "SAFETY-REPOSITORY-MUTATED", "P0", "FAIL", "CONFIRMED", "Safety",
            "Executable audit changed the repository",
            "The build/test/archive command changed Git revision or worktree status. No automatic rollback was attempted.",
            authority_type="QUALITY_ONLY",
            evidence=[{"detail": "Compare data.git_before and data.git_after"}],
            remediation="Inspect and recover the repository changes manually, then isolate or disable the mutating phase before retrying.",
        )
    else:
        add_check(fragment, "XCODE-REPO-STATE", "PASS", "Repository Git state was unchanged by Xcode execution.")

    if return_code == 0:
        add_check(fragment, "XCODE-001", "PASS", f"xcodebuild {args.action} completed successfully.")
    else:
        add_check(fragment, "XCODE-001", "FAIL", f"xcodebuild {args.action} exited with code {return_code}.")
        add_finding(
            fragment, f"BUILD-{args.action.upper()}-FAILED", "P0" if args.action in {"build", "archive"} else "P1",
            "FAIL", "CONFIRMED", "Build",
            f"Xcode {args.action} did not complete successfully",
            "The exact isolated Xcode action failed or timed out.",
            authority_type="PLATFORM_TECHNICAL_REQUIREMENT",
            evidence=[{"path": log_path.name, "detail": f"exit code {return_code}"}],
            remediation="Inspect the preserved log and fix the root cause without weakening the audit.",
        )
    write_json(evidence_output, fragment)
    return 0 if return_code == 0 and not mutated else 1


if __name__ == "__main__":
    raise SystemExit(main())
