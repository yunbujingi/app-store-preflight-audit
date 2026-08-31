#!/usr/bin/env python3
"""Create a safe Simulator review plan or normalize manually observed scenario evidence."""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
import uuid
from pathlib import Path
from typing import Any

from _common import ScanLimitExceeded, add_check, add_finding, iter_files, new_fragment, redact, relpath, sha256_bytes, write_json

ALLOWED_RESULTS = {"PASS", "FAIL", "BLOCKED", "NOT_RUN"}
SENSITIVE_SCENARIOS = {"permission-denied", "offline-weak-network", "storekit"}
DEFAULT_SCENARIOS = [
    {"id": "first-launch", "state": "fresh install", "assertion": "Core value and reviewer path are understandable."},
    {"id": "permission-denied", "state": "all optional permissions denied", "assertion": "Denial is recoverable and core value is not misleadingly gated."},
    {"id": "dynamic-type-dark", "state": "dark appearance and largest supported Dynamic Type", "assertion": "Controls and long text remain usable without clipping."},
    {"id": "empty-loading-error", "state": "empty, loading, timeout, and server error", "assertion": "Each state is distinguishable and offers a natural next action."},
    {"id": "offline-weak-network", "state": "offline and weak network", "assertion": "The app fails safely without indefinite or deceptive UI."},
    {"id": "storekit", "state": "authorized StoreKit test configuration", "assertion": "Purchase and restore paths use a dedicated non-production test state."},
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--device", action="append", default=[])
    parser.add_argument("--os", action="append", default=[])
    parser.add_argument("--locale", action="append", default=[])
    parser.add_argument("--appearance", action="append", choices=("light", "dark"), default=[])
    parser.add_argument("--dynamic-type", action="append", default=[])
    parser.add_argument("--scenario-file", type=Path, help="Optional JSON array replacing default scenarios")
    parser.add_argument("--observations", type=Path, help="JSON object mapping scenario IDs to result/evidence")
    parser.add_argument("--screenshots", type=Path, help="Screenshot directory to inventory as imported evidence")
    parser.add_argument("--xcresult", type=Path, help="Existing .xcresult bundle or exported JSON to import")
    parser.add_argument("--use-xcresulttool", action="store_true", help="Read the supplied .xcresult with xcrun xcresulttool")
    parser.add_argument("--xctestplan-output", type=Path, help="Write a reviewable .xctestplan; does not run it")
    parser.add_argument("--test-target-id", help="PBX target identifier required for .xctestplan generation")
    parser.add_argument("--test-target-name", help="XCTest/XCUITest target name required for .xctestplan generation")
    parser.add_argument("--container-path", help="Repository-relative project/workspace path recorded in the plan")
    parser.add_argument("--list-devices", action="store_true", help="Read available simulator devices with simctl")
    parser.add_argument("--max-evidence-files", type=int, default=2_000)
    parser.add_argument("--max-evidence-size", type=int, default=250_000_000)
    return parser.parse_args()


def load_scenarios(path: Path | None) -> list[dict]:
    if not path:
        return DEFAULT_SCENARIOS
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ValueError("scenario-file must contain a non-empty JSON array")
    required = {"id", "state", "assertion"}
    if any(not isinstance(item, dict) or not required <= set(item) for item in value):
        raise ValueError("each scenario needs id, state, and assertion")
    if len({item["id"] for item in value}) != len(value):
        raise ValueError("scenario IDs must be unique")
    return value


def available_devices() -> dict:
    if not shutil.which("xcrun"):
        return {"status": "BLOCKED", "devices": [], "reason": "xcrun unavailable"}
    result = subprocess.run(["xcrun", "simctl", "list", "-j", "devices", "available"], check=False, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        return {"status": "BLOCKED", "devices": [], "reason": "simctl list failed"}
    value = json.loads(result.stdout)
    devices = [
        {
            "runtime": runtime,
            "name": item.get("name"),
            "state": item.get("state"),
            "udid_hash": sha256_bytes(str(item.get("udid", "")).encode("utf-8")),
        }
        for runtime, items in value.get("devices", {}).items() for item in items
    ]
    return {"status": "PASS", "devices": devices}


def image_dimensions(path: Path) -> tuple[int, int] | None:
    """Read PNG dimensions without loading or decoding untrusted image content."""
    try:
        with path.open("rb") as handle:
            payload = handle.read(24)
        if payload.startswith(b"\x89PNG\r\n\x1a\n") and len(payload) >= 24:
            return struct.unpack(">II", payload[16:24])
    except OSError:
        pass
    return None


def import_screenshots(path: Path | None, max_files: int, max_total_size: int) -> dict[str, Any]:
    if path is None:
        return {"status": "NOT_RUN", "items": []}
    root = path.resolve()
    if not root.is_dir() or root.is_symlink():
        raise ValueError("screenshots must be a real directory")
    try:
        files = list(iter_files(root, max_size=50_000_000, max_files=max_files, max_total_size=max_total_size))
    except ScanLimitExceeded as error:
        raise ValueError(f"screenshot evidence budget exceeded: {error}") from error
    items = []
    for item in files:
        if item.suffix.lower() not in {".png", ".jpg", ".jpeg", ".heic"}:
            continue
        dimensions = image_dimensions(item)
        items.append({
            "path": relpath(item, root),
            "sha256": sha256_bytes(item.read_bytes()),
            "size": item.stat().st_size,
            "dimensions": list(dimensions) if dimensions else None,
        })
    return {"status": "PASS" if items else "BLOCKED", "items": items}


def summarize_xcresult_json(value: Any) -> dict[str, Any]:
    encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    summary: dict[str, Any] = {
        "sha256": sha256_bytes(encoded),
        "top_level_type": type(value).__name__,
    }
    if isinstance(value, dict):
        summary["top_level_keys"] = sorted(str(key) for key in value)[:100]
        text = json.dumps(value, separators=(",", ":"), default=str)
        summary["failure_signal_count"] = text.count('"testStatus":"Failure"') + text.count('"status":"Failure"')
    return summary


def import_xcresult(path: Path | None, use_tool: bool, max_files: int, max_total_size: int) -> dict[str, Any]:
    if path is None:
        return {"status": "NOT_RUN"}
    source = path.resolve()
    if not source.exists() or source.is_symlink():
        raise ValueError("xcresult evidence does not exist or is a symlink")
    if source.is_file():
        if source.stat().st_size > max_total_size:
            raise ValueError("xcresult JSON exceeds evidence size budget")
        value = json.loads(source.read_text(encoding="utf-8"))
        return {"status": "PASS", "source": source.name, "summary": summarize_xcresult_json(value)}
    try:
        files = list(iter_files(source, max_size=100_000_000, max_files=max_files, max_total_size=max_total_size))
    except ScanLimitExceeded as error:
        raise ValueError(f"xcresult evidence budget exceeded: {error}") from error
    inventory = {"file_count": len(files), "total_size": sum(item.stat().st_size for item in files)}
    if not use_tool:
        return {
            "status": "BLOCKED", "source": source.name, "inventory": inventory,
            "reason": "Bundle inventoried only; pass --use-xcresulttool for semantic import.",
        }
    if not shutil.which("xcrun"):
        return {"status": "BLOCKED", "source": source.name, "inventory": inventory, "reason": "xcrun unavailable"}
    result = None
    variant = None
    commands = [
        ["xcrun", "xcresulttool", "get", "object", "--legacy", "--path", str(source), "--format", "json"],
        ["xcrun", "xcresulttool", "get", "--path", str(source), "--format", "json"],
    ]
    for index, command in enumerate(commands, 1):
        try:
            candidate = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        if candidate.returncode == 0:
            result = candidate
            variant = f"XCODE_SCHEMA_VARIANT_{index}"
            break
    if result is None or len(result.stdout.encode("utf-8")) > max_total_size:
        return {
            "status": "BLOCKED", "source": source.name, "inventory": inventory,
            "reason": "xcresulttool failed or exceeded output budget",
        }
    return {
        "status": "PASS", "source": source.name, "inventory": inventory,
        "schema_variant": variant,
        "summary": summarize_xcresult_json(json.loads(result.stdout)),
    }


def build_xctestplan(args: argparse.Namespace, matrix: dict[str, list[str]]) -> dict[str, Any] | None:
    if not args.xctestplan_output:
        return None
    if not all((args.test_target_id, args.test_target_name, args.container_path)):
        raise ValueError("--test-target-id, --test-target-name, and --container-path are required with --xctestplan-output")
    container = str(args.container_path).replace("\\", "/")
    if container.startswith("/") or ".." in Path(container).parts:
        raise ValueError("container-path must be repository-relative and must not traverse parents")
    configurations = []
    for locale in matrix["locales"]:
        for appearance in matrix["appearance"]:
            for size in matrix["dynamic_type"]:
                name = f"{locale} · {appearance} · {size}"
                configurations.append({
                    "id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"app-store-preflight:{name}")),
                    "name": name,
                    "options": {
                        "language": locale.split("-")[0],
                        "region": locale.split("-")[1] if "-" in locale else "",
                        "environmentVariableEntries": [
                            {"key": "APP_PREFLIGHT_APPEARANCE", "value": appearance, "enabled": True},
                            {"key": "APP_PREFLIGHT_DYNAMIC_TYPE", "value": size, "enabled": True},
                        ],
                    },
                })
    plan = {
        "configurations": configurations,
        "defaultOptions": {},
        "testTargets": [{"skippedTests": [], "target": {
            "containerPath": f"container:{container}",
            "identifier": args.test_target_id,
            "name": args.test_target_name,
        }}],
        "version": 1,
    }
    write_json(args.xctestplan_output.resolve(), plan)
    return {"path": args.xctestplan_output.name, "configuration_count": len(configurations), "executed": False}


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit("root is not a directory")
    try:
        scenarios = load_scenarios(args.scenario_file.resolve() if args.scenario_file else None)
        screenshot_evidence = import_screenshots(
            args.screenshots, args.max_evidence_files, args.max_evidence_size,
        )
        xcresult_evidence = import_xcresult(
            args.xcresult, args.use_xcresulttool, args.max_evidence_files, args.max_evidence_size,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error
    observations = {}
    if args.observations:
        value = json.loads(args.observations.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise SystemExit("observations must be a JSON object")
        observations = value

    matrix = {
        "devices": sorted(set(args.device)),
        "os_versions": sorted(set(args.os)),
        "locales": sorted(set(args.locale)),
        "appearance": sorted(set(args.appearance)),
        "dynamic_type": sorted(set(args.dynamic_type)),
    }
    matrix_complete = all(matrix.values())
    try:
        generated_plan = build_xctestplan(args, matrix) if matrix_complete else None
    except ValueError as error:
        raise SystemExit(str(error)) from error

    fragment = new_fragment("simulator_review", "runtime", root)
    add_check(
        fragment, "SIM-MATRIX", "PASS" if matrix_complete else "BLOCKED",
        "Simulator, OS, locale, appearance, and Dynamic Type were explicitly specified." if matrix_complete else
        "Runtime matrix is incomplete; no implicit device or presentation state was assumed.",
        verification="CONFIRMED" if matrix_complete else "UNRESOLVED",
        blocker=None if matrix_complete else
        "Pass at least one --device, --os, --locale, --appearance, and --dynamic-type.",
    )
    normalized = []
    for scenario in scenarios:
        observation = observations.get(scenario["id"])
        if observation is None:
            result, detail, authorized = "NOT_RUN", "No direct runtime observation was supplied.", False
        elif not isinstance(observation, dict) or observation.get("result") not in ALLOWED_RESULTS:
            raise SystemExit(f"invalid observation for {scenario['id']}")
        else:
            result = observation["result"]
            detail = str(observation.get("detail", "Observation recorded."))
            authorized = observation.get("authorized") is True and bool(observation.get("test_state"))
            if scenario["id"] in SENSITIVE_SCENARIOS and not authorized:
                result = "BLOCKED"
                detail = "Sensitive scenario lacks authorized=true and a named dedicated test_state."
        normalized.append({
            **scenario, "result": result, "detail": detail,
            "authorization_verified": authorized if scenario["id"] in SENSITIVE_SCENARIOS else None,
        })
        add_check(
            fragment, f"SIM-{scenario['id'].upper()}", result,
            f"{scenario['assertion']} {detail}",
            verification="CONFIRMED" if observation is not None and result not in {"NOT_RUN", "BLOCKED"} else "UNRESOLVED",
            evidence=[] if observation is None else [{"detail": detail}],
            blocker="Run on the designated Simulator and record direct evidence; sensitive scenarios require explicit authorization and a dedicated test state."
            if result in {"NOT_RUN", "BLOCKED"} else None,
        )
        if result == "FAIL":
            add_finding(
                fragment, f"RUNTIME-{scenario['id'].upper()}", "P2", "FAIL", "CONFIRMED", "Runtime",
                f"Simulator scenario failed: {scenario['id']}", detail,
                authority_type="QUALITY_ONLY",
                evidence=[{"detail": f"state={scenario['state']}"}],
                remediation="Fix the observed user path and rerun the same recorded scenario.",
            )
    device_inventory = available_devices() if args.list_devices else {"status": "NOT_RUN", "devices": []}
    fragment["data"] = {
        "bundle_id": args.bundle_id,
        "matrix": matrix,
        "scenarios": normalized,
        "generated_xctestplan": generated_plan,
        "screenshots": screenshot_evidence,
        "xcresult": xcresult_evidence,
        "available_devices": device_inventory,
        "safety": {
            "mutates_simulator": False,
            "resets_devices": False,
            "installs_or_launches_apps": False,
            "creates_accounts": False,
            "purchases_products": False,
            "generated_plan_requires_human_review": True,
        },
    }
    write_json(args.output.resolve(), redact(fragment))
    return 1 if any(item["result"] == "FAIL" for item in normalized) else 0


if __name__ == "__main__":
    raise SystemExit(main())
