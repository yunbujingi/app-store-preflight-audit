"""Dependency-free scanner package shared by the CLI and Codex Skill."""

from __future__ import annotations

import importlib
import sys

__version__ = "0.3.0b1"

# Existing scripts remain directly executable from the Skill directory. Registering
# the shared helper under its historical module name keeps those entry points and
# package imports backed by the same source files.
sys.modules.setdefault("_common", importlib.import_module("._common", __name__))
