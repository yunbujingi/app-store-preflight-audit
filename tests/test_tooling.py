from __future__ import annotations

import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skill" / "app-store-preflight-audit" / "scripts"
FIXTURES = ROOT / "evals" / "fixtures"


def run_script(name: str, *args: str, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / name), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != expect:
        raise AssertionError(f"{name} exited {result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}")
    return result


class ToolingTests(unittest.TestCase):
    def test_project_inventory_uses_relative_paths_and_detects_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "inventory.json"
            fixture = FIXTURES / "minimal-app"
            run_script("project_inventory.py", "--root", str(fixture), "--output", str(output))
            data = json.loads(output.read_text())
            self.assertEqual(data["data"]["swift_imports"]["Foundation"], 1)
            self.assertIn("App/PrivacyInfo.xcprivacy", data["data"]["privacy_manifests"])
            self.assertNotIn(str(fixture), output.read_text())

    def test_privacy_signal_is_covered(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "privacy.json"
            run_script("inspect_privacy_manifests.py", "--root", str(FIXTURES / "minimal-app"), "--output", str(output))
            data = json.loads(output.read_text())
            ids = {item["id"] for item in data["findings"]}
            self.assertNotIn("PRIVACY-REASON-USERDEFAULTS", ids)
            self.assertEqual(data["checks"][0]["disposition"], "PASS")

    def test_privacy_gap_is_inferred_not_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "privacy.json"
            run_script("inspect_privacy_manifests.py", "--root", str(FIXTURES / "privacy-gap"), "--output", str(output))
            data = json.loads(output.read_text())
            finding = next(item for item in data["findings"] if item["id"] == "PRIVACY-REASON-USERDEFAULTS")
            self.assertEqual(finding["disposition"], "NEEDS_VERIFY")
            self.assertEqual(finding["verification"], "INFERRED")
            self.assertEqual(len(finding["evidence"]), 1)

    def test_archive_inventory_associates_nested_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "Sample.xcarchive"
            app = archive / "Products" / "Applications" / "Sample.app"
            framework = app / "Frameworks" / "SampleKit.framework"
            framework.mkdir(parents=True)
            for bundle, identifier in ((app, "org.example.Sample"), (framework, "org.example.SampleKit")):
                (bundle / "Info.plist").write_bytes(plistlib.dumps({
                    "CFBundleIdentifier": identifier,
                    "CFBundleExecutable": bundle.stem,
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "1",
                }))
                (bundle / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({
                    "NSPrivacyTracking": False,
                    "NSPrivacyTrackingDomains": [],
                    "NSPrivacyCollectedDataTypes": [],
                    "NSPrivacyAccessedAPITypes": [],
                }))
            output = root / "archive.json"
            run_script("inspect_archive.py", "--archive", str(archive), "--output", str(output))
            data = json.loads(output.read_text())
            bundles = {item["kind"]: item for item in data["data"]["bundles"]}
            self.assertEqual(len(bundles["app"]["privacy_manifests"]), 1)
            self.assertEqual(len(bundles["framework"]["privacy_manifests"]), 1)
            self.assertEqual(data["checks"][0]["disposition"], "PASS")

    def test_runner_is_dry_run_and_rejects_repo_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            project = root / "Sample.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text("// empty synthetic project\n")
            evidence = Path(temp) / "evidence.json"
            output = Path(temp) / "out"
            run_script(
                "run_isolated_xcode.py", "--root", str(root), "--project", str(project),
                "--scheme", "Sample", "--action", "build", "--output-root", str(output),
                "--evidence-output", str(evidence),
            )
            data = json.loads(evidence.read_text())
            self.assertFalse(data["data"]["executed"])
            self.assertEqual(data["checks"][0]["disposition"], "NOT_RUN")

            result = run_script(
                "run_isolated_xcode.py", "--root", str(root), "--project", str(project),
                "--scheme", "Sample", "--action", "build", "--output-root", str(root / "out"),
                "--evidence-output", str(evidence), expect=1,
            )
            self.assertIn("outside the audited repository", result.stderr)

    def test_runner_requires_acknowledgement_for_run_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            project = root / "Sample.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text("isa = PBXShellScriptBuildPhase;\n")
            result = run_script(
                "run_isolated_xcode.py", "--root", str(root), "--project", str(project),
                "--scheme", "Sample", "--action", "build", "--output-root", str(Path(temp) / "out"),
                "--evidence-output", str(Path(temp) / "evidence.json"), "--execute", expect=1,
            )
            self.assertIn("detected Run Script", result.stderr)

    def test_report_assembly_redacts_secrets_and_calculates_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fragment = {
                "schema_version": "0.1.0", "tool": "fixture", "generated_at": "2026-08-30T00:00:00+00:00",
                "layer": "source", "subject": {"name": "fixture", "path_fingerprint": "a" * 64, "revision": None},
                "checks": [
                    {"id": "A", "layer": "source", "disposition": "PASS", "verification": "CONFIRMED", "summary": "done", "evidence": []},
                    {"id": "B", "layer": "source", "disposition": "NEEDS_VERIFY", "verification": "UNRESOLVED", "summary": "token=super-secret-value", "evidence": []}
                ],
                "findings": [], "data": {}
            }
            input_path = directory / "fragment.json"
            input_path.write_text(json.dumps(fragment))
            json_output = directory / "report.json"
            md_output = directory / "report.md"
            run_script("assemble_report.py", "--input", str(input_path), "--json-output", str(json_output), "--markdown-output", str(md_output))
            report = json.loads(json_output.read_text())
            self.assertEqual(report["verdict"], "CONDITIONAL_GO")
            self.assertEqual(report["coverage"]["source"]["coverage_percent"], 50)
            self.assertNotIn("super-secret-value", json_output.read_text())
            self.assertIn("[REDACTED]", md_output.read_text())

    def test_report_records_policy_retrieval_date(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fragment = {
                "schema_version": "0.1.0", "tool": "fixture", "generated_at": "2026-08-30T00:00:00+00:00",
                "layer": "policy", "subject": {"name": "policy", "path_fingerprint": "b" * 64, "revision": None},
                "checks": [{"id": "POLICY", "layer": "policy", "disposition": "PASS", "verification": "CONFIRMED", "summary": "current", "evidence": []}],
                "findings": [], "data": {}
            }
            input_path = directory / "fragment.json"
            input_path.write_text(json.dumps(fragment))
            json_output = directory / "report.json"
            md_output = directory / "report.md"
            run_script(
                "assemble_report.py", "--input", str(input_path), "--json-output", str(json_output),
                "--markdown-output", str(md_output), "--policy-source",
                "https://developer.apple.com/app-store/review/guidelines/", "2026-08-30",
            )
            report = json.loads(json_output.read_text())
            self.assertEqual(report["scope"]["policy_sources"][0]["retrieved_at"], "2026-08-30")
            self.assertIn("retrieved 2026-08-30", md_output.read_text())

    def test_schemas_are_valid_json(self) -> None:
        schema_dir = ROOT / "skill" / "app-store-preflight-audit" / "references" / "schemas"
        for path in schema_dir.glob("*.json"):
            with self.subTest(path=path.name):
                json.loads(path.read_text())


if __name__ == "__main__":
    unittest.main()
