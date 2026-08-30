#!/usr/bin/env python3
"""Create a safe Simulator review plan or normalize manually observed scenario evidence."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from _common import add_check, add_finding, new_fragment, redact, write_json

ALLOWED_RESULTS = {"PASS", "FAIL", "BLOCKED", "NOT_RUN"}
DEFAULT_SCENARIOS = [
    {"id": "first-launch", "state": "fresh install", "assertion": "Core value and reviewer path are understandable."},
    {"id": "permission-denied", "state": "all optional permissions denied", "assertion": "Denial is recoverable and core value is not misleadingly gated."},
    {"id": "dynamic-type-dark", "state": "dark appearance and largest supported Dynamic Type", "assertion": "Controls and long text remain usable without clipping."},
    {"id": "empty-loading-error", "state": "empty, loading, timeout, and server error", "assertion": "Each state is distinguishable and offers a natural next action."},
    {"id": "offline-weak-network", "state": "offline and weak network", "assertion": "The app fails safely without indefinite or deceptive UI."},
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--device", action="append", default=[])
    parser.add_argument("--os", action="append", default=[])
    parser.add_argument("--locale", action="append", default=[])
    parser.add_argument("--scenario-file", type=Path, help="Optional JSON array replacing default scenarios")
    parser.add_argument("--observations", type=Path, help="JSON object mapping scenario IDs to result/evidence")
    parser.add_argument("--list-devices", action="store_true", help="Read available simulator devices with simctl")
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
        {"runtime": runtime, "name": item.get("name"), "state": item.get("state")}
        for runtime, items in value.get("devices", {}).items() for item in items
    ]
    return {"status": "PASS", "devices": devices}


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        raise SystemExit("root is not a directory")
    scenarios = load_scenarios(args.scenario_file.resolve() if args.scenario_file else None)
    observations = {}
    if args.observations:
        value = json.loads(args.observations.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise SystemExit("observations must be a JSON object")
        observations = value

    fragment = new_fragment("simulator_review", "runtime", root)
    normalized = []
    for scenario in scenarios:
        observation = observations.get(scenario["id"])
        if observation is None:
            result, detail = "NOT_RUN", "No direct runtime observation was supplied."
        elif not isinstance(observation, dict) or observation.get("result") not in ALLOWED_RESULTS:
            raise SystemExit(f"invalid observation for {scenario['id']}")
        else:
            result = observation["result"]
            detail = str(observation.get("detail", "Observation recorded."))
        normalized.append({**scenario, "result": result, "detail": detail})
        add_check(
            fragment, f"SIM-{scenario['id'].upper()}", result,
            f"{scenario['assertion']} {detail}",
            verification="CONFIRMED" if observation is not None else "UNRESOLVED",
            evidence=[] if observation is None else [{"detail": detail}],
            blocker="Run this scenario on an explicitly designated Simulator and record direct evidence." if result in {"NOT_RUN", "BLOCKED"} else None,
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
        "matrix": {
            "devices": sorted(set(args.device)),
            "os_versions": sorted(set(args.os)),
            "locales": sorted(set(args.locale)),
            "appearance": ["light", "dark"],
            "dynamic_type": ["default", "largest-supported"],
            "network": ["online", "offline", "weak", "timeout"],
        },
        "scenarios": normalized,
        "available_devices": device_inventory,
        "safety": {
            "mutates_simulator": False,
            "resets_devices": False,
            "installs_or_launches_apps": False,
        },
    }
    write_json(args.output.resolve(), redact(fragment))
    return 1 if any(item["result"] == "FAIL" for item in normalized) else 0


if __name__ == "__main__":
    raise SystemExit(main())
