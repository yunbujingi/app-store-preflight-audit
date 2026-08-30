from __future__ import annotations

import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile
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

    def test_archive_binary_signal_is_inferred_and_bundle_local(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "Sample.xcarchive"
            app = archive / "Products" / "Applications" / "Sample.app"
            app.mkdir(parents=True)
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "org.example.Sample",
                "CFBundleExecutable": "Sample",
            }))
            (app / "Sample").write_bytes(b"\xcf\xfa\xed\xfe\x00NSUserDefaults\x00")
            frameworks = app / "Frameworks"
            frameworks.mkdir()
            (frameworks / "libFixture.dylib").write_bytes(b"\xcf\xfa\xed\xfe\x00systemUptime\x00")
            output = root / "archive.json"
            run_script("inspect_archive.py", "--archive", str(archive), "--output", str(output), "--skip-binary-tools")
            data = json.loads(output.read_text())
            finding = next(item for item in data["findings"] if item["id"].startswith("ARCHIVE-REASON-"))
            self.assertEqual(finding["verification"], "INFERRED")
            self.assertEqual(finding["disposition"], "NEEDS_VERIFY")
            self.assertIn("NSPrivacyAccessedAPICategoryUserDefaults", data["data"]["required_reason_binary_signals"]["Products/Applications/Sample.app"])
            dylib = data["data"]["standalone_dynamic_libraries"][0]
            self.assertEqual(dylib["containing_bundle"], "Products/Applications/Sample.app")
            self.assertIn("NSPrivacyAccessedAPICategorySystemBootTime", dylib["missing_required_reason_categories"])

    def test_ipa_support_and_path_traversal_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ipa = root / "Sample.ipa"
            info = plistlib.dumps({
                "CFBundleIdentifier": "org.example.Sample",
                "CFBundleExecutable": "Sample",
                "CFBundleShortVersionString": "1.0",
                "CFBundleVersion": "1",
                "CFBundleSupportedPlatforms": ["iPhoneOS"],
            })
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Sample.app/Info.plist", info)
                archive.writestr("Payload/Sample.app/Sample", b"\xcf\xfa\xed\xfe")
            output = root / "ipa.json"
            run_script("inspect_archive.py", "--archive", str(ipa), "--output", str(output), "--skip-binary-tools")
            data = json.loads(output.read_text())
            self.assertEqual(data["data"]["artifact_type"], "ipa")
            self.assertEqual(data["data"]["summary"]["apps"], 1)
            self.assertNotIn(str(root), output.read_text())

            unsafe = root / "Unsafe.ipa"
            with zipfile.ZipFile(unsafe, "w") as archive:
                archive.writestr("../escaped", b"no")
            result = run_script("inspect_archive.py", "--archive", str(unsafe), "--output", str(output), expect=1)
            self.assertIn("safety validation failed", result.stderr)

    def test_target_graph_uses_phase_membership_and_offline_build_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "graph.json"
            fixture = FIXTURES / "multi-target"
            run_script(
                "inspect_target_graph.py", "--root", str(fixture), "--project", "Sample.xcodeproj",
                "--metadata-dir", str(fixture / "metadata"), "--configuration", "Release",
                "--output", str(output),
            )
            data = json.loads(output.read_text())
            relations = data["data"]["relations"]
            self.assertEqual(len(relations), 5)
            manifest = next(item for item in relations if item["manifest"])
            self.assertEqual(manifest["target"], "SampleApp")
            self.assertEqual(manifest["bundle_identifier"], "org.example.Sample")
            self.assertNotIn("/tmp/build", output.read_text())

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

    def test_runner_execute_requires_capability_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "repo"
            project = root / "Sample.xcodeproj"
            project.mkdir(parents=True)
            (project / "project.pbxproj").write_text("// empty synthetic project\n")
            result = run_script(
                "run_isolated_xcode.py", "--root", str(root), "--project", str(project),
                "--scheme", "Sample", "--action", "build", "--output-root", str(Path(temp) / "out"),
                "--evidence-output", str(Path(temp) / "evidence.json"), "--execute", expect=1,
            )
            self.assertIn("capability preview", result.stderr)
            self.assertIn("execution_preview", result.stdout)

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
            sarif_output = directory / "report.sarif"
            junit_output = directory / "report.xml"
            run_script(
                "assemble_report.py", "--input", str(input_path), "--json-output", str(json_output),
                "--markdown-output", str(md_output), "--sarif-output", str(sarif_output),
                "--junit-output", str(junit_output),
            )
            report = json.loads(json_output.read_text())
            self.assertEqual(report["schema_version"], "0.2.0")
            self.assertEqual(report["verdict"], "CONDITIONAL_GO")
            self.assertEqual(report["coverage"]["source"]["coverage_percent"], 50)
            self.assertNotIn("super-secret-value", json_output.read_text())
            self.assertIn("[REDACTED]", md_output.read_text())
            self.assertEqual(json.loads(sarif_output.read_text())["version"], "2.1.0")
            self.assertEqual(ET.parse(junit_output).getroot().tag, "testsuite")

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

    def test_baseline_and_suppression_remove_ci_noise_but_preserve_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fragment = {
                "schema_version": "0.2.0", "tool": "fixture", "generated_at": "2026-08-30T00:00:00+00:00",
                "layer": "source", "subject": {"name": "fixture", "path_fingerprint": "c" * 64, "revision": None},
                "checks": [],
                "findings": [{
                    "id": "KNOWN-FP", "severity": "P1", "disposition": "FAIL", "verification": "CONFIRMED",
                    "category": "Fixture", "title": "Known false positive", "explanation": "synthetic",
                    "authority": {"type": "QUALITY_ONLY", "url": None}, "evidence": [{"path": "App/File.swift"}],
                    "remediation": "review", "assumptions": []
                }], "data": {}
            }
            input_path = directory / "fragment.json"
            input_path.write_text(json.dumps(fragment))
            suppressions = directory / "suppressions.json"
            suppressions.write_text(json.dumps({"suppressions": [{
                "finding_id": "KNOWN-FP", "justification": "Confirmed generated-code false positive.",
                "owner": "mobile-team", "expires_at": "2099-12-31", "rule_version": "fixture@1"
            }]}))
            report_path = directory / "report.json"
            sarif_path = directory / "report.sarif"
            run_script(
                "assemble_report.py", "--input", str(input_path), "--json-output", str(report_path),
                "--markdown-output", str(directory / "report.md"), "--sarif-output", str(sarif_path),
                "--suppressions", str(suppressions),
            )
            report = json.loads(report_path.read_text())
            self.assertEqual(report["verdict"], "GO")
            self.assertEqual(report["findings"][0]["id"], "KNOWN-FP")
            self.assertEqual(report["triage"]["suppressed"][0]["id"], "KNOWN-FP")
            self.assertEqual(json.loads(sarif_path.read_text())["runs"][0]["results"], [])

    def test_schemas_are_valid_json(self) -> None:
        schema_dir = ROOT / "skill" / "app-store-preflight-audit" / "references" / "schemas"
        for path in schema_dir.glob("*.json"):
            with self.subTest(path=path.name):
                json.loads(path.read_text())

    def test_policy_snapshot_records_hash_and_change_without_copying_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            page = directory / "policy.html"
            page.write_text("official policy fixture v1")
            first = directory / "first.json"
            url = "https://developer.apple.com/app-store/review/guidelines/"
            run_script(
                "record_policy_snapshot.py", "--source-file", url, str(page),
                "--storefront", "US", "--platform", "iOS", "--output", str(first),
            )
            initial = json.loads(first.read_text())
            record = initial["data"]["policy_sources"][0]
            self.assertEqual(record["change"], "NEW")
            self.assertNotIn("official policy fixture", first.read_text())
            second = directory / "second.json"
            run_script(
                "record_policy_snapshot.py", "--source-file", url, str(page),
                "--previous", str(first), "--output", str(second),
            )
            self.assertEqual(json.loads(second.read_text())["data"]["policy_sources"][0]["change"], "UNCHANGED")

    def test_rule_registry_is_valid_and_reports_affected_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "registry.json"
            run_script(
                "validate_rule_registry.py", "--registry",
                str(ROOT / "skill" / "app-store-preflight-audit" / "references" / "policy-registry.json"),
                "--output", str(output),
            )
            data = json.loads(output.read_text())
            self.assertTrue(data["valid"])
            self.assertEqual(data["rule_count"], 4)
            self.assertEqual(len(data["affected_rule_ids"]["added"]), 4)

    def test_app_store_connect_import_is_read_only_and_redacts_review_notes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            export = directory / "asc.json"
            export.write_text(json.dumps({
                "bundleId": "org.example.Sample", "versionString": "1.0", "buildNumber": "1",
                "ageRating": {"rating": "4+"}, "appPrivacy": {"tracking": False},
                "reviewNotes": "username=test password=private-value", "screenshots": ["one.png"],
            }))
            output = directory / "asc-fragment.json"
            run_script("inspect_asc_export.py", "--export", str(export), "--output", str(output))
            text = output.read_text()
            data = json.loads(text)
            self.assertEqual(data["data"]["mode"], "READ_ONLY_IMPORT")
            self.assertNotIn("private-value", text)
            self.assertFalse(data["data"]["capabilities"]["modify"])

    def test_simulator_plan_marks_unobserved_states_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "runtime.json"
            run_script(
                "simulator_review.py", "--root", str(FIXTURES / "minimal-app"),
                "--bundle-id", "org.example.Sample", "--device", "iPhone", "--output", str(output),
            )
            data = json.loads(output.read_text())
            self.assertTrue(all(item["disposition"] == "NOT_RUN" for item in data["checks"]))
            self.assertFalse(data["data"]["safety"]["mutates_simulator"])

    def test_eval_runner_reports_zero_false_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "eval.json"
            run_script("run_evals.py", "--cases", str(ROOT / "evals" / "cases.json"), "--output", str(output))
            data = json.loads(output.read_text())
            self.assertTrue(data["gate"]["passed"])
            self.assertEqual(data["metrics"]["fp"], 0)
            self.assertEqual(data["metrics"]["fn"], 0)
            self.assertGreater(data["metrics"]["tp"] + data["metrics"]["tn"], 0)

    def test_packaging_is_deterministic_and_install_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            skill = ROOT / "skill" / "app-store-preflight-audit"
            first = directory / "first.zip"
            second = directory / "second.zip"
            run_script("package_skill.py", "--skill", str(skill), "--output", str(first))
            run_script("package_skill.py", "--skill", str(skill), "--output", str(second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertIn("app-store-preflight-audit/SKILL.md", archive.namelist())
            destination = directory / "skills"
            run_script("install_skill.py", "--source", str(first), "--destination-root", str(destination), "--install")
            self.assertTrue((destination / "app-store-preflight-audit" / "SKILL.md").is_file())
            result = run_script(
                "install_skill.py", "--source", str(first), "--destination-root", str(destination),
                "--install", expect=1,
            )
            self.assertIn("refusing to overwrite", result.stderr)


if __name__ == "__main__":
    unittest.main()
