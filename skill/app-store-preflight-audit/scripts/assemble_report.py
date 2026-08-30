#!/usr/bin/env python3
"""Merge audit fragments and emit stable JSON, Markdown, SARIF, and JUnit."""

from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any

from _common import (
    DISPOSITIONS, LAYERS, SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS,
    redact, utc_now, write_json,
)

SEVERITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
RESOLVED = {"PASS", "FAIL", "N/A"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    parser.add_argument("--markdown-output", required=True, type=Path)
    parser.add_argument("--sarif-output", type=Path)
    parser.add_argument("--junit-output", type=Path)
    parser.add_argument("--title", default="App Store Preflight Audit")
    parser.add_argument("--policy-source", action="append", nargs=2, metavar=("URL", "RETRIEVED_AT"), default=[])
    parser.add_argument("--storefront", action="append", default=[])
    return parser.parse_args()


def validate_fragment(value: Any, path: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(f"{path}: unsupported fragment schema")
    if value.get("layer") not in LAYERS:
        raise ValueError(f"{path}: invalid layer")
    for check in value.get("checks", []):
        if check.get("disposition") not in DISPOSITIONS:
            raise ValueError(f"{path}: invalid disposition")
    return value


def policy_sources(fragments: list[dict[str, Any]], cli_sources: list[list[str]]) -> list[dict[str, Any]]:
    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for url, retrieved_at in cli_sources:
        sources[(url, retrieved_at)] = {"url": url, "retrieved_at": retrieved_at}
    for fragment in fragments:
        for source in fragment.get("data", {}).get("policy_sources", []):
            if not isinstance(source, dict) or not source.get("url") or not source.get("retrieved_at"):
                continue
            item = {
                key: source[key]
                for key in ("url", "retrieved_at", "status", "content_sha256", "change", "storefronts", "platforms")
                if key in source
            }
            sources[(item["url"], item["retrieved_at"])] = item
    return [sources[key] for key in sorted(sources)]


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


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules = []
    results = []
    for finding in report["findings"]:
        rule_id = finding["id"]
        rule = {
            "id": rule_id,
            "name": finding["title"],
            "shortDescription": {"text": finding["title"]},
            "properties": {
                "category": finding["category"],
                "severity": finding["severity"],
            },
        }
        help_uri = finding.get("authority", {}).get("url")
        if help_uri:
            rule["helpUri"] = help_uri
        rules.append(rule)
        level = "error" if finding["severity"] in {"P0", "P1"} else ("warning" if finding["severity"] == "P2" else "note")
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": finding["explanation"]},
            "properties": {
                "disposition": finding["disposition"],
                "verification": finding["verification"],
            },
        }
        locations = []
        for evidence in finding.get("evidence", []):
            if not evidence.get("path"):
                continue
            physical: dict[str, Any] = {"artifactLocation": {"uri": evidence["path"]}}
            if isinstance(evidence.get("line"), int):
                physical["region"] = {"startLine": evidence["line"]}
            locations.append({"physicalLocation": physical})
        if locations:
            result["locations"] = locations
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "App Store Preflight Audit", "version": SCHEMA_VERSION, "rules": rules}},
            "results": results,
        }],
    }


def junit(report: dict[str, Any]) -> str:
    items = [("check", item) for item in report["checks"]] + [("finding", item) for item in report["findings"]]
    failures = sum(1 for _, item in items if item["disposition"] == "FAIL")
    skipped = sum(1 for _, item in items if item["disposition"] in {"N/A", "NOT_RUN", "NEEDS_VERIFY", "BLOCKED"})
    suite = ET.Element("testsuite", {
        "name": "app-store-preflight-audit",
        "tests": str(len(items)),
        "failures": str(failures),
        "errors": "0",
        "skipped": str(skipped),
        "timestamp": report["generated_at"],
    })
    for kind, item in items:
        case = ET.SubElement(suite, "testcase", {
            "classname": f"app_store_preflight.{item.get('layer', item.get('category', 'finding')).lower().replace(' ', '_')}",
            "name": item["id"],
        })
        disposition = item["disposition"]
        message = item.get("summary") or item.get("title") or item["id"]
        detail = item.get("explanation") or message
        if disposition == "FAIL":
            failure = ET.SubElement(case, "failure", {"message": message, "type": item.get("severity", "audit")})
            failure.text = detail
        elif disposition in {"N/A", "NOT_RUN", "NEEDS_VERIFY", "BLOCKED"}:
            skipped_node = ET.SubElement(case, "skipped", {"message": f"{disposition}: {message}"})
            skipped_node.text = detail
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def write_text(path: Path, value: str) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


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
        "schema_compatibility": {
            "accepts_fragment_versions": sorted(SUPPORTED_SCHEMA_VERSIONS),
            "breaking_changes_require_major_version": True,
        },
        "title": args.title,
        "generated_at": utc_now(),
        "verdict": verdict(findings, checks),
        "scope": {
            "storefronts": sorted(set(args.storefront)),
            "policy_sources": policy_sources(fragments, args.policy_source),
        },
        "coverage": coverage,
        "checks": checks,
        "findings": findings,
        "fragments": [{"tool": fragment["tool"], "layer": fragment["layer"], "generated_at": fragment["generated_at"]} for fragment in fragments],
    })
    write_json(args.json_output.resolve(), report)
    write_text(args.markdown_output, markdown(report))
    if args.sarif_output:
        write_json(args.sarif_output.resolve(), redact(sarif(report)))
    if args.junit_output:
        write_text(args.junit_output, junit(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
