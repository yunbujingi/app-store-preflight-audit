#!/usr/bin/env python3
"""Fetch one allowlisted App Store Connect API inventory endpoint using GET only."""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from _common import add_check, new_fragment, redact, write_json

API_HOST = "api.appstoreconnect.apple.com"
TOKEN_ENV = "ASC_API_TOKEN"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--resource-id")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fixture", type=Path, help="Offline API response fixture; no credential or network is used")
    parser.add_argument("--token-env", default=TOKEN_ENV, help="Environment variable containing a pre-generated JWT")
    parser.add_argument("--max-pages", type=int, default=5)
    parser.add_argument("--max-response-size", type=int, default=10_000_000)
    return parser.parse_args()


def load_allowlist() -> dict[str, Any]:
    path = Path(__file__).resolve().parents[1] / "references" / "asc-read-allowlist.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("endpoints"), dict):
        raise ValueError("invalid ASC read allowlist")
    return value


def validate_identifier(value: str | None) -> str:
    if not value or len(value) > 200 or not all(character.isalnum() or character in "-_" for character in value):
        raise ValueError("resource-id is required and must be an opaque alphanumeric, hyphen, or underscore identifier")
    return value


def endpoint_url(allowlist: dict[str, Any], endpoint_name: str, resource_id: str | None) -> str:
    endpoint = allowlist["endpoints"].get(endpoint_name)
    if not isinstance(endpoint, dict):
        raise ValueError(f"endpoint is not allowlisted: {endpoint_name}")
    path = endpoint["path"]
    if endpoint.get("resource_id_required"):
        path = path.replace("{id}", urllib.parse.quote(validate_identifier(resource_id), safe=""))
    elif resource_id:
        raise ValueError("resource-id is not accepted for this endpoint")
    query_values = {f"fields[{endpoint['resource_type']}]": ",".join(endpoint["attributes"])}
    if endpoint_name != "age_rating":
        query_values["limit"] = "200"
    query = urllib.parse.urlencode(query_values)
    return f"https://{API_HOST}{path}?{query}"


def safe_next_url(value: Any) -> str | None:
    if value in (None, ""):
        return None
    parsed = urllib.parse.urlparse(str(value))
    if parsed.scheme != "https" or parsed.hostname != API_HOST or not parsed.path.startswith("/v1/"):
        raise ValueError("API pagination link escaped the fixed App Store Connect origin")
    return parsed.geturl()


def read_live(url: str, token: str, max_pages: int, max_response_size: int) -> list[dict[str, Any]]:
    opener = urllib.request.build_opener(NoRedirect)
    pages = []
    next_url: str | None = url
    while next_url and len(pages) < max_pages:
        request = urllib.request.Request(
            next_url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, method="GET",
        )
        try:
            with opener.open(request, timeout=30) as response:
                payload = response.read(max_response_size + 1)
        except urllib.error.HTTPError as error:
            raise ValueError(f"App Store Connect returned HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise ValueError(f"App Store Connect request failed: {error.reason}") from error
        if len(payload) > max_response_size:
            raise ValueError("App Store Connect response exceeded size budget")
        page = json.loads(payload.decode("utf-8"))
        if not isinstance(page, dict):
            raise ValueError("App Store Connect response root must be an object")
        pages.append(page)
        next_url = safe_next_url(page.get("links", {}).get("next")) if isinstance(page.get("links"), dict) else None
    if next_url:
        raise ValueError("App Store Connect pagination exceeded max-pages")
    return pages


def filter_resource(value: Any, endpoint: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("type") != endpoint["resource_type"]:
        return None
    attributes = value.get("attributes") if isinstance(value.get("attributes"), dict) else {}
    return {
        "type": value["type"],
        "id": str(value.get("id", "")),
        "attributes": {key: attributes[key] for key in endpoint["attributes"] if key in attributes},
    }


def normalize_pages(pages: list[dict[str, Any]], endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    records = []
    for page in pages:
        values = page.get("data", [])
        if isinstance(values, dict):
            values = [values]
        if not isinstance(values, list):
            raise ValueError("App Store Connect data must be an object or array")
        records.extend(item for value in values if (item := filter_resource(value, endpoint)) is not None)
    return sorted(records, key=lambda item: (item["type"], item["id"]))


def main() -> int:
    args = parse_args()
    if not 1 <= args.max_pages <= 50 or not 1_024 <= args.max_response_size <= 100_000_000:
        raise SystemExit("invalid read budget")
    try:
        allowlist = load_allowlist()
        if args.endpoint not in allowlist["endpoints"]:
            raise ValueError(f"endpoint is not allowlisted: {args.endpoint}")
        url = endpoint_url(allowlist, args.endpoint, args.resource_id)
        if args.fixture:
            fixture = args.fixture.resolve()
            if not fixture.is_file() or fixture.is_symlink() or fixture.stat().st_size > args.max_response_size:
                raise ValueError("fixture is missing, unsafe, or exceeds the response budget")
            pages = [json.loads(fixture.read_text(encoding="utf-8"))]
            mode = "OFFLINE_FIXTURE"
        else:
            token = os.environ.get(args.token_env)
            if not token:
                raise ValueError(f"missing JWT in environment variable {args.token_env}")
            pages = read_live(url, token, args.max_pages, args.max_response_size)
            mode = "LIVE_READ_ONLY"
        records = normalize_pages(pages, allowlist["endpoints"][args.endpoint])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(str(error)) from error

    fragment = new_fragment("fetch_asc_readonly", "app_store_connect", Path(args.endpoint))
    fragment["data"] = {
        "mode": mode,
        "endpoint": args.endpoint,
        "method": "GET",
        "origin": f"https://{API_HOST}",
        "record_count": len(records),
        "records": records,
        "allowlist_reviewed_at": allowlist["reviewed_at"],
        "official_sources": allowlist.get("sources", []),
        "capabilities": {"read": True, "upload": False, "modify": False, "submit": False},
        "coverage_gaps": {
            "app_privacy_answers": "No documented read endpoint is enabled in this allowlist; import a user export instead."
        },
    }
    add_check(
        fragment, "ASC-API-READ", "PASS" if records else "NEEDS_VERIFY",
        f"Read and allowlist-filtered {len(records)} {args.endpoint} record(s).",
        verification="CONFIRMED" if records else "UNRESOLVED",
        blocker=None if records else "The endpoint returned no allowlisted records; confirm IDs, permissions, and inventory state.",
    )
    write_json(args.output.resolve(), redact(fragment))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
