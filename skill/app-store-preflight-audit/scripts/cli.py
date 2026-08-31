"""Single command entry point for the App Store preflight scanner package."""

from __future__ import annotations

import argparse
import importlib
import sys
from collections.abc import Callable

from . import __version__

COMMANDS = {
    "inventory": "project_inventory",
    "target-graph": "inspect_target_graph",
    "privacy": "inspect_privacy_manifests",
    "archive": "inspect_archive",
    "asc-export": "inspect_asc_export",
    "asc-read": "fetch_asc_readonly",
    "runtime-plan": "simulator_review",
    "assemble": "assemble_report",
    "eval": "run_evals",
    "policy-snapshot": "record_policy_snapshot",
    "policy-registry": "validate_rule_registry",
    "xcode": "run_isolated_xcode",
    "package-skill": "package_skill",
    "install-skill": "install_skill",
    "install-release": "install_release",
}


def dispatch(module_name: str, arguments: list[str]) -> int:
    module = importlib.import_module(f".{module_name}", __package__)
    entry: Callable[[], int] = module.main
    previous = sys.argv
    try:
        sys.argv = [f"app-store-preflight-audit {module_name}", *arguments]
        return int(entry())
    finally:
        sys.argv = previous


def main() -> int:
    parser = argparse.ArgumentParser(prog="app-store-preflight-audit")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    return dispatch(COMMANDS[args.command], args.arguments)


if __name__ == "__main__":
    raise SystemExit(main())
