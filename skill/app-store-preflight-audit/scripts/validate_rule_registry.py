#!/usr/bin/env python3
"""Validate and diff the rule-level Apple policy registry without fetching or copying policy text."""

from __future__ import annotations

import argparse
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from _common import SCHEMA_VERSION, SUPPORTED_SCHEMA_VERSIONS, sha256_bytes, utc_now, write_json

RULE_ID = re.compile(r"^ASPA-[A-Z0-9]+(?:-[A-Z0-9]+)*-\d{3}$")
FINGERPRINT_FIELDS = (
    "apple_url", "guideline_section", "effective_date", "platforms", "storefronts",
    "app_categories", "business_models", "applicable_checks", "related_eval_cases",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", required=True, type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def fingerprint(rule: dict[str, Any]) -> str:
    normalized = {key: rule.get(key) for key in FINGERPRINT_FIELDS}
    return sha256_bytes(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def load_registry(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") not in SUPPORTED_SCHEMA_VERSIONS or not isinstance(value.get("rules"), list):
        raise ValueError("unsupported rule registry schema")
    seen = set()
    for rule in value["rules"]:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not RULE_ID.match(rule_id) or rule_id in seen:
            raise ValueError(f"invalid or duplicate stable rule ID: {rule_id}")
        seen.add(rule_id)
        parsed = urllib.parse.urlparse(str(rule.get("apple_url", "")))
        if parsed.scheme != "https" or parsed.hostname != "developer.apple.com":
            raise ValueError(f"rule {rule_id} must use an official developer.apple.com URL")
        for key in ("guideline_section", "retrieved_at", "platforms", "storefronts",
                    "app_categories", "business_models", "applicable_checks",
                    "last_reviewed_version", "related_eval_cases"):
            if key not in rule:
                raise ValueError(f"rule {rule_id} is missing {key}")
        expected = fingerprint(rule)
        if rule.get("content_fingerprint") != expected:
            raise ValueError(f"rule {rule_id} content_fingerprint is stale; expected {expected}")
    return value


def main() -> int:
    args = parse_args()
    current = load_registry(args.registry.resolve())
    previous = load_registry(args.previous.resolve()) if args.previous else {"rules": []}
    current_by_id = {item["id"]: item for item in current["rules"]}
    previous_by_id = {item["id"]: item for item in previous["rules"]}
    added = sorted(set(current_by_id) - set(previous_by_id))
    removed = sorted(set(previous_by_id) - set(current_by_id))
    changed = sorted(
        rule_id for rule_id in set(current_by_id).intersection(previous_by_id)
        if current_by_id[rule_id]["content_fingerprint"] != previous_by_id[rule_id]["content_fingerprint"]
    )
    unchanged = sorted(set(current_by_id).intersection(previous_by_id) - set(changed))
    write_json(args.output.resolve(), {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_now(),
        "registry": args.registry.name,
        "rule_count": len(current_by_id),
        "affected_rule_ids": {"added": added, "changed": changed, "removed": removed},
        "unchanged_rule_ids": unchanged,
        "valid": True,
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
