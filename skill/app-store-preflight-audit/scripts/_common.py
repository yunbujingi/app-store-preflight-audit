#!/usr/bin/env python3
"""Shared, dependency-free helpers for preflight evidence collectors."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Any, Iterable, Iterator

SCHEMA_VERSION = "0.1.0"
DISPOSITIONS = {"PASS", "FAIL", "N/A", "NOT_RUN", "NEEDS_VERIFY", "BLOCKED"}
VERIFICATIONS = {"CONFIRMED", "INFERRED", "UNRESOLVED"}
SEVERITIES = {"P0", "P1", "P2", "P3", "P4"}
LAYERS = {"source", "policy", "build", "unit_test", "ui_test", "archive", "runtime", "app_store_connect"}
EXCLUDED_DIRS = {
    ".git", ".build", ".swiftpm", "DerivedData", "build", "Pods",
    "Carthage", "node_modules", ".idea", ".vscode", "xcuserdata",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def path_fingerprint(path: Path) -> str:
    return sha256_bytes(str(path.resolve()).encode("utf-8"))


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def iter_files(root: Path, *, max_size: int = 2_000_000) -> Iterator[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED_DIRS)
        for name in sorted(files):
            path = Path(current) / name
            try:
                if path.is_symlink() or path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_plist(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        value = plistlib.load(handle)
    if not isinstance(value, dict):
        raise ValueError("plist root must be a dictionary")
    return value


def git_snapshot(root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"available": False, "revision": None, "status": []}
    try:
        inside = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return result
        revision = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"],
            check=False, capture_output=True, text=True, timeout=15,
        )
        result["available"] = True
        result["revision"] = revision.stdout.strip() if revision.returncode == 0 else None
        result["status"] = [line for line in status.stdout.splitlines() if line]
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def new_fragment(tool: str, layer: str, subject: Path) -> dict[str, Any]:
    if layer not in LAYERS:
        raise ValueError(f"unsupported layer: {layer}")
    git = git_snapshot(subject) if subject.is_dir() else {"available": False, "revision": None, "status": []}
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": tool,
        "generated_at": utc_now(),
        "layer": layer,
        "subject": {
            "name": subject.name,
            "path_fingerprint": path_fingerprint(subject),
            "revision": git.get("revision"),
        },
        "checks": [],
        "findings": [],
        "data": {},
    }


def add_check(fragment: dict[str, Any], check_id: str, disposition: str,
              summary: str, *, verification: str = "CONFIRMED",
              evidence: Iterable[dict[str, Any]] = (), blocker: str | None = None) -> None:
    if disposition not in DISPOSITIONS or verification not in VERIFICATIONS:
        raise ValueError("invalid check state")
    item: dict[str, Any] = {
        "id": check_id,
        "layer": fragment["layer"],
        "disposition": disposition,
        "verification": verification,
        "summary": summary,
        "evidence": list(evidence),
    }
    if blocker:
        item["blocker"] = blocker
    fragment["checks"].append(item)


def add_finding(fragment: dict[str, Any], finding_id: str, severity: str,
                disposition: str, verification: str, category: str, title: str,
                explanation: str, *, authority_type: str = "PLATFORM_TECHNICAL_REQUIREMENT",
                authority_url: str | None = None,
                evidence: Iterable[dict[str, Any]] = (), remediation: str = "Review and resolve before submission.",
                assumptions: Iterable[str] = ()) -> None:
    if severity not in SEVERITIES or disposition not in DISPOSITIONS or verification not in VERIFICATIONS:
        raise ValueError("invalid finding state")
    fragment["findings"].append({
        "id": finding_id,
        "severity": severity,
        "disposition": disposition,
        "verification": verification,
        "category": category,
        "title": title,
        "explanation": explanation,
        "authority": {"type": authority_type, "url": authority_url},
        "evidence": list(evidence),
        "remediation": remediation,
        "assumptions": list(assumptions),
    })


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    return value
