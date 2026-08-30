#!/usr/bin/env python3
"""Merge audit fragments, redact secrets, calculate coverage, and render Markdown."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from _common import DISPOSITIONS, LAYERS, SCHEMA_VERSION, redact, utc_now, write_json

SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
RESOLVED = {"PASS", "FAIL", "N/A"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    parser.add_argument("--title", default="App Store Preflight Audit")
    parser.add_argument("--policy-source", action="append", nargs=2, metavar=("URL", "RETRIEVED_AT"), default=[])
    parser.add_argument("--storefront", action="append", default=[])
    return parser.parse_args()


def validate_fragment(value: Any, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{path}: unsupported fragment schema")
    if value.get("layer") not in LAYERS:
        raise ValueError(f"{path}: invalid layer")
    for check in value.get("checks", []):
        if check.get("disposition") not in DISPOSITIONS:
            raise ValueError(f"{path}: invalid disposition")
    return value


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for finding in findings:
        existing = by_id.get(finding["id"])
        if not existing:
            by_id[finding["id"]] = finding
            continue
        existing["evidence"] = existing.get("evidence", []) + finding.get("evidence", [])
        existing["assumptions"] = sorted(set(existing.get("assumptions", []) + finding.get("assumptions", [])))
        if SEVERITY_ORDER[finding["severity"]] < SEVERITY_ORDER[existing["severity"]]:
            existing["severity"] = finding["severity"]
    return sorted(by_id.values(), key=lambda item: (SEVERITY_ORDER[item["severity"]], item["id"]))


def verdict(findings: list[dict[str, Any]], checks: list[dict[str, Any]]) -> str:
    if any(item["severity"] == "P0" and item["disposition"] == "FAIL" for item in findings):
        return "NO_GO"
    if any(item["severity"] == "P1" and item["disposition"] == "FAIL" and item["verification"] == "CONFIRMED" for item in findings):
        return "NO_GO"
    if any(item["severity"] in {"P1", "P2"} for item in findings):
        return "CONDITIONAL_GO"
    if any(item["disposition"] not in RESOLVED for item in checks):
        return "CONDITIONAL_GO"
    return "GO"


def markdown(report: dict[str, Any]) -> str:
    lines = [f"# {report['title']}", "", f"Verdict: **{report['verdict']}**", ""]
    lines += ["## Scope", "", f"Generated: {report['generated_at']}",
              f"Storefront assumptions: {', '.join(report['scope']['storefronts']) or 'UNRESOLVED'}", ""]
    if report["scope"]["policy_sources"]:
        lines += ["Policy sources:", ""]
        for source in report["scope"]["policy_sources"]:
            lines.append(f"- {source['url']} (retrieved {source['retrieved_at']})")
        lines.append("")
    lines += ["## Coverage", "", "| Layer | Resolved | Applicable | Coverage |", "| --- | ---: | ---: | ---: |"]
    for layer, value in report["coverage"].items():
        coverage = f"{value['coverage_percent']}%" if value["applicable"] else "N/A"
        lines.append(f"| {layer} | {value['resolved']} | {value['applicable']} | {coverage} |")
    lines += ["", "## Findings", ""]
    if not report["findings"]:
        lines += ["No findings were generated within the collected evidence scope.", ""]
    else:
        lines += ["| ID | Severity | Disposition | Verification | Category | Title |", "| --- | --- | --- | --- | --- | --- |"]
        for item in report["findings"]:
            title = str(item["title"]).replace("|", "\\|")
            lines.append(f"| {item['id']} | {item['severity']} | {item['disposition']} | {item['verification']} | {item['category']} | {title} |")
        lines.append("")
        for item in report["findings"]:
            lines += [f"### {item['id']} — {item['title']}", "", item["explanation"], "",
                      f"Remediation direction: {item['remediation']}", ""]
            if item.get("evidence"):
                lines.append("Evidence:")
                lines.append("")
                for evidence in item["evidence"]:
                    where = evidence.get("path") or evidence.get("detail") or "evidence"
                    detail = evidence.get("detail", "")
                    lines.append(f"- {where}: {detail}".rstrip())
                lines.append("")
    lines += ["## Limitations", ""]
    unresolved = [check for check in report["checks"] if check["disposition"] not in RESOLVED]
    if unresolved:
        for check in unresolved:
            lines.append(f"- {check['id']} ({check['disposition']}): {check['summary']}")
    else:
        lines.append("- No unresolved checks were reported for the collected layers.")
    lines += ["", "> This unofficial preflight report is not an Apple review decision or legal advice.", ""]
    return "\n".join(lines)


def main() -> int:
    args = parse_args()
    fragments = []
    for path in args.input:
        with path.open(encoding="utf-8") as handle:
            fragments.append(validate_fragment(json.load(handle), path))
    checks = [check for fragment in fragments for check in fragment.get("checks", [])]
    findings = deduplicate([finding for fragment in fragments for finding in fragment.get("findings", [])])
    layer_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"resolved": 0, "applicable": 0})
    for check in checks:
        layer = check["layer"]
        if check["disposition"] != "N/A":
            layer_counts[layer]["applicable"] += 1
            if check["disposition"] in RESOLVED:
                layer_counts[layer]["resolved"] += 1
    coverage = {}
    for layer in sorted(layer_counts):
        counts = layer_counts[layer]
        percent = round(counts["resolved"] * 100 / counts["applicable"]) if counts["applicable"] else 0
        coverage[layer] = {**counts, "coverage_percent": percent}
    report = redact({
        "schema_version": SCHEMA_VERSION,
        "title": args.title,
        "generated_at": utc_now(),
        "verdict": verdict(findings, checks),
        "scope": {
            "storefronts": sorted(set(args.storefront)),
            "policy_sources": [
                {"url": url, "retrieved_at": retrieved_at}
                for url, retrieved_at in sorted({tuple(item) for item in args.policy_source})
            ],
        },
        "coverage": coverage,
        "checks": checks,
        "findings": findings,
        "fragments": [{"tool": fragment["tool"], "layer": fragment["layer"], "generated_at": fragment["generated_at"]} for fragment in fragments],
    })
    write_json(args.json_output.resolve(), report)
    args.markdown_output.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.markdown_output.resolve().write_text(markdown(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
