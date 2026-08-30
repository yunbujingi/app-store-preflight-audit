#!/usr/bin/env python3
"""Run reproducible synthetic evals and report false-positive/false-negative metrics."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from _common import SCHEMA_VERSION, utc_now, write_json

COLLECTORS = {"project_inventory.py", "inspect_privacy_manifests.py"}
OUTCOMES = {"tp", "tn", "fp", "fn", "unknown", "blocked"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-false-positives", type=int, default=0)
    parser.add_argument("--max-false-negatives", type=int, default=0)
    return parser.parse_args()


def dotted(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            raise KeyError(path)
        current = current[part]
    return current


def classify(expectation: dict, fragment: dict) -> tuple[str, str]:
    kind = expectation["kind"]
    rule_id = expectation["rule_id"]
    findings = {item["id"]: item for item in fragment.get("findings", [])}
    checks = {item["id"]: item for item in fragment.get("checks", [])}
    if kind == "finding_present":
        actual = findings.get(rule_id)
        if actual is None:
            return "fn", "expected finding was absent"
        if actual.get("disposition") in {"BLOCKED", "NOT_RUN"}:
            return "blocked", actual.get("disposition", "BLOCKED")
        expected_state = expectation.get("disposition")
        if expected_state and actual.get("disposition") != expected_state:
            return "fn", f"expected {expected_state}, got {actual.get('disposition')}"
        return "tp", "expected finding observed"
    if kind == "finding_absent":
        return ("tn", "finding correctly absent") if rule_id not in findings else ("fp", "unexpected finding observed")
    if kind == "check_state":
        actual = checks.get(rule_id)
        if actual is None:
            return "unknown", "check was not emitted"
        if actual.get("disposition") in {"BLOCKED", "NOT_RUN"}:
            return "blocked", actual.get("disposition", "BLOCKED")
        return ("tp", "expected check state observed") if actual.get("disposition") == expectation["disposition"] else ("fn", f"got {actual.get('disposition')}")
    if kind in {"data_contains", "data_not_contains"}:
        try:
            actual = dotted(fragment, expectation["path"])
        except KeyError:
            return "unknown", "data path was unavailable"
        contained = expectation["value"] in actual
        success = contained if kind == "data_contains" else not contained
        return ("tp" if kind == "data_contains" else "tn", "data invariant satisfied") if success else (("fn" if kind == "data_contains" else "fp"), "data invariant failed")
    raise ValueError(f"unsupported expectation kind: {kind}")


def ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def main() -> int:
    args = parse_args()
    case_path = args.cases.resolve()
    root = case_path.parent
    scripts = Path(__file__).resolve().parent
    config = json.loads(case_path.read_text(encoding="utf-8"))
    if config.get("schema_version") not in {"0.1.0", SCHEMA_VERSION}:
        raise SystemExit("unsupported eval case schema")
    results = []
    counts = {outcome: 0 for outcome in sorted(OUTCOMES)}
    per_rule: dict[str, dict[str, int]] = defaultdict(lambda: {outcome: 0 for outcome in sorted(OUTCOMES)})
    with tempfile.TemporaryDirectory(prefix="app-store-preflight-evals-") as temporary:
        for case in config.get("cases", []):
            collector = case.get("collector")
            if collector not in COLLECTORS:
                raise SystemExit(f"unsupported collector in {case.get('id')}: {collector}")
            fixture = (root / case["fixture"]).resolve()
            if root not in fixture.parents:
                raise SystemExit(f"fixture escapes eval root: {case['fixture']}")
            output = Path(temporary) / f"{case['id']}.json"
            collector_error = None
            try:
                completed = subprocess.run(
                    [sys.executable, str(scripts / collector), "--root", str(fixture), "--output", str(output)],
                    check=False, capture_output=True, text=True, timeout=60,
                )
                if completed.returncode != 0:
                    collector_error = f"collector exited {completed.returncode}"
            except (OSError, subprocess.SubprocessError) as error:
                collector_error = type(error).__name__
            if collector_error or not output.exists():
                case_result = {"id": case["id"], "collector": collector, "status": "BLOCKED", "reason": collector_error or "collector produced no output", "expectations": []}
                for expectation in case.get("expectations", []):
                    counts["blocked"] += 1
                    per_rule[expectation["rule_id"]]["blocked"] += 1
                results.append(case_result)
                continue
            fragment = json.loads(output.read_text(encoding="utf-8"))
            evaluated = []
            for expectation in case.get("expectations", []):
                outcome, detail = classify(expectation, fragment)
                counts[outcome] += 1
                per_rule[expectation["rule_id"]][outcome] += 1
                evaluated.append({"rule_id": expectation["rule_id"], "outcome": outcome, "detail": detail})
            results.append({
                "id": case["id"], "collector": collector,
                "status": "PASS" if all(item["outcome"] in {"tp", "tn"} for item in evaluated) else "FAIL",
                "expectations": evaluated,
            })
    metrics = {
        **counts,
        "precision": ratio(counts["tp"], counts["tp"] + counts["fp"]),
        "recall": ratio(counts["tp"], counts["tp"] + counts["fn"]),
        "false_positive_rate": ratio(counts["fp"], counts["fp"] + counts["tn"]),
        "per_rule": dict(sorted(per_rule.items())),
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "case_file": case_path.name,
        "metrics": metrics,
        "cases": results,
        "gate": {
            "max_false_positives": args.max_false_positives,
            "max_false_negatives": args.max_false_negatives,
            "passed": counts["fp"] <= args.max_false_positives and counts["fn"] <= args.max_false_negatives and counts["blocked"] == 0,
        },
    }
    write_json(args.output.resolve(), report)
    return 0 if report["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
