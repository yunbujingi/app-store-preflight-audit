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

SCHEMA_VERSION = "0.2.0"
SUPPORTED_SCHEMA_VERSIONS = {"0.1.0", SCHEMA_VERSION}
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


class ScanLimitExceeded(RuntimeError):
    """Raised when a collector exceeds its explicit, user-visible scan budget."""


def ensure_within(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"path escapes scan root: {path}") from error
    return resolved


def iter_files(root: Path, *, max_size: int = 2_000_000,
               max_files: int = 50_000, max_total_size: int = 500_000_000) -> Iterator[Path]:
    """Yield regular, non-symlink files under root within a deterministic budget."""
    root = root.resolve()
    count = 0
    total_size = 0
    for current, dirs, files in os.walk(root):
        safe_dirs = []
        for name in sorted(d for d in dirs if d not in EXCLUDED_DIRS):
            candidate = Path(current) / name
            try:
                if candidate.is_symlink():
                    continue
                ensure_within(candidate, root)
            except (OSError, ValueError):
                continue
            safe_dirs.append(name)
        dirs[:] = safe_dirs
        for name in sorted(files):
            path = Path(current) / name
            try:
                if path.is_symlink():
                    continue
                ensure_within(path, root)
                size = path.stat().st_size
            except OSError:
                continue
            if size > max_size:
                continue
            count += 1
            total_size += size
            if count > max_files:
                raise ScanLimitExceeded(f"file count exceeded limit ({max_files})")
            if total_size > max_total_size:
                raise ScanLimitExceeded(f"total readable bytes exceeded limit ({max_total_size})")
            yield path


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def strip_source_comments(text: str) -> str:
    """Remove common C/Swift comments before conservative static signal matching."""
    def preserve_lines(match: re.Match[str]) -> str:
        return "".join("\n" if character == "\n" else " " for character in match.group(0))

    text = re.sub(r"/\*[\s\S]*?\*/", preserve_lines, text)
    return re.sub(r"//.*", preserve_lines, text)


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
    temporary.write_text(json.dumps(redact(value), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


SECRET_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
]

ABSOLUTE_PATH_PATTERNS = [
    re.compile(r"(?<![A-Za-z0-9_.-])/(?:Users|home)/[^\s\"'<>]+"),
    re.compile(r"(?<![A-Za-z0-9_.-])/(?:private/)?(?:tmp|var/folders)/[^\s\"'<>]+"),
]


def redact_text(value: str) -> str:
    redacted = value
    for pattern in SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(lambda match: match.group(1) + "[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    for pattern in ABSOLUTE_PATH_PATTERNS:
        redacted = pattern.sub("<PATH>", redacted)
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {key: redact(item) for key, item in value.items()}
    return value
