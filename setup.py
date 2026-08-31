"""Compatibility build shim for older setuptools bundled with macOS Python 3.9."""

from pathlib import Path

from setuptools import setup

ROOT = Path(__file__).parent

setup(
    name="app-store-preflight-audit",
    version="0.3.0b1",
    description="Evidence-driven, read-only App Store submission preflight scanner and Codex Skill",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    license="Apache-2.0",
    python_requires=">=3.9",
    package_dir={"app_store_preflight_audit": "skill/app-store-preflight-audit"},
    packages=["app_store_preflight_audit", "app_store_preflight_audit.scripts"],
    package_data={"app_store_preflight_audit": [
        "SKILL.md", "agents/*.yaml", "references/*.md", "references/*.json", "references/schemas/*.json",
    ]},
    entry_points={"console_scripts": [
        "app-store-preflight-audit=app_store_preflight_audit.scripts.cli:main",
    ]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
)
