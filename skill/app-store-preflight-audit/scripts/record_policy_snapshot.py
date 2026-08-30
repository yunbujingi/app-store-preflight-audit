#!/usr/bin/env python3
"""Record hash-only Apple policy freshness evidence and compare it with a prior snapshot."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from _common import add_check, new_fragment, sha256_bytes, utc_now, write_json


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", action="append", default=[], help="Official https://developer.apple.com URL")
    parser.add_argument("--source-file", action="append", nargs=2, metavar=("URL", "FILE"), default=[], help="Offline fixture for a URL")
    parser.add_argument("--previous", type=Path, help="Prior policy fragment to compare")
    parser.add_argument("--storefront", action="append", default=[])
    parser.add_argument("--platform", action="append", default=[])
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def validate_url(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "developer.apple.com":
        raise ValueError(f"only official https://developer.apple.com sources are accepted: {value}")
    return value


def previous_hashes(path: Path | None) -> dict[str, str]:
    if not path:
        return {}
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    return {
        item["url"]: item["content_sha256"]
        for item in value.get("data", {}).get("policy_sources", [])
        if isinstance(item, dict) and item.get("url") and item.get("content_sha256")
    }


def fetch(url: str, timeout: int) -> tuple[bytes, dict[str, str]]:
    request = urllib.request.Request(url, headers={"User-Agent": "app-store-preflight-audit/0.2"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        validate_url(response.geturl())
        payload = response.read(10_000_001)
        if len(payload) > 10_000_000:
            raise ValueError("policy response exceeded 10 MB")
        return payload, {
            "etag": response.headers.get("ETag", ""),
            "last_modified": response.headers.get("Last-Modified", ""),
        }


def main() -> int:
    args = parse_args()
    sources: list[tuple[str, Path | None]] = [(validate_url(url), None) for url in args.source]
    sources += [(validate_url(url), Path(path).resolve()) for url, path in args.source_file]
    if not sources:
        raise SystemExit("provide at least one --source or --source-file")
    if len({url for url, _ in sources}) != len(sources):
        raise SystemExit("duplicate policy source URL")

    fragment = new_fragment("record_policy_snapshot", "policy", Path.cwd())
    before = previous_hashes(args.previous.resolve() if args.previous else None)
    retrieved_at = utc_now()
    records = []
    for index, (url, fixture) in enumerate(sorted(sources), 1):
        record = {
            "url": url,
            "retrieved_at": retrieved_at,
            "status": "UNAVAILABLE",
            "content_sha256": None,
            "change": "UNAVAILABLE",
            "storefronts": sorted(set(args.storefront)),
            "platforms": sorted(set(args.platform)),
        }
        try:
            if fixture:
                payload = fixture.read_bytes()
                headers: dict[str, str] = {}
                record["status"] = "OFFLINE_FIXTURE"
            else:
                payload, headers = fetch(url, args.timeout)
                record["status"] = "FETCHED"
            digest = sha256_bytes(payload)
            record["content_sha256"] = digest
            old = before.get(url)
            record["change"] = "NEW" if old is None else ("UNCHANGED" if old == digest else "CHANGED")
            record.update({key: value for key, value in headers.items() if value})
            disposition = "NEEDS_VERIFY" if record["change"] == "CHANGED" else "PASS"
            add_check(
                fragment, f"POLICY-{index:03d}", disposition,
                f"Official policy source recorded; content state is {record['change']}.",
                verification="CONFIRMED",
                evidence=[{"detail": f"{url} sha256={digest}"}],
                blocker="Review the official page change before carrying forward policy-dependent conclusions." if disposition == "NEEDS_VERIFY" else None,
            )
        except (OSError, ValueError, urllib.error.URLError) as error:
            record["error_type"] = type(error).__name__
            add_check(
                fragment, f"POLICY-{index:03d}", "BLOCKED",
                "Official policy source could not be recorded.",
                evidence=[{"detail": url}],
                blocker=f"{type(error).__name__}; retry from a trusted network without storing page content in the report.",
            )
        records.append(record)
    fragment["data"] = {
        "policy_sources": records,
        "comparison_snapshot": bool(args.previous),
    }
    write_json(args.output.resolve(), fragment)
    return 0 if all(item["status"] != "UNAVAILABLE" for item in records) else 2


if __name__ == "__main__":
    raise SystemExit(main())
