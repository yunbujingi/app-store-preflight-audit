from __future__ import annotations

import json
import hashlib
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
    def test_advanced_target_graph_resolves_sync_groups_xcconfig_packages_and_link_map(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sources = root / "Sources"
            sources.mkdir()
            (sources / "Included.swift").write_text("struct Included {}")
            (sources / "Excluded.swift").write_text("struct Excluded {}")
            project = root / "Sample.xcodeproj"
            project.mkdir()
            (project / "project.pbxproj").write_text("""// !$*UTF8*$!
/* Begin PBXFileSystemSynchronizedRootGroup section */
G10000000000000000000001 = {isa = PBXFileSystemSynchronizedRootGroup; path = Sources; sourceTree = \"<group>\"; };
/* End PBXFileSystemSynchronizedRootGroup section */
/* Begin PBXShellScriptBuildPhase section */
S10000000000000000000001 = {isa = PBXShellScriptBuildPhase; outputPaths = ( \"$(SRCROOT)/Generated/Generated.swift\", ); };
/* End PBXShellScriptBuildPhase section */
/* Begin PBXNativeTarget section */
T10000000000000000000001 = {isa = PBXNativeTarget; name = Sample; buildPhases = ( S10000000000000000000001, ); fileSystemSynchronizedGroups = ( G10000000000000000000001, ); };
/* End PBXNativeTarget section */
""")
            workspace = root / "Sample.xcworkspace"
            workspace.mkdir()
            (workspace / "contents.xcworkspacedata").write_text(
                "<Workspace version=\"1.0\"><FileRef location=\"group:Sample.xcodeproj\"/></Workspace>"
            )
            (root / "Package.swift").write_text("""// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: \"Fixture\", products: [.library(name: \"Core\", targets: [\"Core\"])], targets: [
  .target(name: \"Core\", plugins: [.plugin(name: \"AuditPlugin\")]),
  .plugin(name: \"AuditPlugin\", capability: .buildTool())
])
""")
            (root / "Release.xcconfig").write_text(
                "EXCLUDED_SOURCE_FILE_NAMES[config=Release][sdk=iphoneos*] = Excluded.swift\n"
                "PRODUCT_BUNDLE_IDENTIFIER = org.example.Sample\n"
            )
            metadata = root / "metadata"
            metadata.mkdir()
            (metadata / "build-settings-Release.json").write_text(json.dumps([{
                "target": "Sample", "buildSettings": {
                    "CONFIGURATION": "Release", "SDKROOT": "iphoneos17.0", "PLATFORM_NAME": "iphoneos",
                    "EXCLUDED_SOURCE_FILE_NAMES": "Excluded.swift", "PRODUCT_BUNDLE_IDENTIFIER": "org.example.Sample",
                    "WRAPPER_EXTENSION": "app", "FULL_PRODUCT_NAME": "Sample.app", "EXECUTABLE_PATH": "Sample.app/Sample",
                },
            }]))
            link_map = root / "Sample-LinkMap-normal-arm64.txt"
            link_map.write_text("""# Path: /tmp/Sample.app/Sample
# Arch: arm64
# Object files:
[  1] /tmp/libCore.a(Core.o)
# Sections:
0x1000 0x10 [  1] __TEXT
""")
            output = root / "graph.json"
            run_script(
                "inspect_target_graph.py", "--root", str(root), "--workspace", "Sample.xcworkspace",
                "--metadata-dir", str(metadata), "--configuration", "Release", "--link-map", str(link_map),
                "--output", str(output),
            )
            data = json.loads(output.read_text())["data"]
            relations = {item["source"]: item for item in data["relations"]}
            self.assertEqual(relations["Sources/Included.swift"]["membership_state"], "INCLUDED")
            self.assertEqual(relations["Sources/Excluded.swift"]["membership_state"], "EXCLUDED")
            self.assertTrue(relations["$(SRCROOT)/Generated/Generated.swift"]["generated"])
            self.assertEqual(data["linked_static_libraries"][0]["identity"], "libCore.a")
            self.assertEqual(data["link_maps"][0]["attribution_verification"], "CONFIRMED")
            self.assertEqual(data["workspaces"][0]["projects"][0]["path"], "Sample.xcodeproj")
            self.assertEqual(data["package_plugins"][0]["target"], "AuditPlugin")
            conditional = next(item for item in data["xcconfig_applicability"] if item["key"] == "EXCLUDED_SOURCE_FILE_NAMES")
            self.assertTrue(conditional["applies"])

    def test_archive_special_bundles_privacy_report_xcframework_and_signing_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "Sample.xcarchive"
            app = archive / "Products" / "Applications" / "Sample.app"
            clip = app / "AppClips" / "Clip.app"
            watch = app / "Watch" / "Watch.app"
            outer = app / "Frameworks" / "Outer.framework"
            inner = outer / "Frameworks" / "Inner.framework"

            def make_bundle(path: Path, identifier: str, **extra: object) -> None:
                path.mkdir(parents=True)
                executable = path.stem
                info = {
                    "CFBundleIdentifier": identifier, "CFBundleExecutable": executable,
                    "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
                    "CFBundleSupportedPlatforms": ["iPhoneOS"], **extra,
                }
                (path / "Info.plist").write_bytes(plistlib.dumps(info))
                (path / executable).write_bytes(b"\xcf\xfa\xed\xfe")
                (path / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({
                    "NSPrivacyTracking": False, "NSPrivacyTrackingDomains": [],
                    "NSPrivacyCollectedDataTypes": [], "NSPrivacyAccessedAPITypes": [],
                }))

            make_bundle(app, "org.example.Sample")
            make_bundle(clip, "org.example.Sample.Clip")
            make_bundle(watch, "org.example.Sample.Watch", WKCompanionAppBundleIdentifier="org.example.Sample")
            make_bundle(outer, "org.example.Outer", CFBundleName="Outer")
            make_bundle(inner, "org.example.Inner", CFBundleName="Inner")
            xcframework = app / "Resources" / "Kit.xcframework"
            slice_dir = xcframework / "ios-arm64"
            slice_dir.mkdir(parents=True)
            (slice_dir / "Kit.framework").mkdir()
            (xcframework / "Info.plist").write_bytes(plistlib.dumps({
                "XCFrameworkFormatVersion": "1.0", "AvailableLibraries": [{
                    "LibraryIdentifier": "ios-arm64", "LibraryPath": "Kit.framework",
                    "SupportedArchitectures": ["arm64"], "SupportedPlatform": "ios",
                }],
            }))
            fixture = FIXTURES / "archive-evidence" / "sanitized-signing.json"
            privacy = root / "privacy-report.json"
            privacy.write_text(json.dumps({"privacyReportVersion": "2", "bundles": [
                {"bundleIdentifier": "org.example.Sample"}, {"bundleIdentifier": "org.example.Sample.Clip"},
                {"bundleIdentifier": "org.example.Sample.Watch"}, {"bundleIdentifier": "org.example.Outer"},
                {"bundleIdentifier": "org.example.Inner"},
            ], "SDKs": [{"sdkName": "Outer"}, {"sdkName": "Inner"}]}))
            output = root / "archive.json"
            run_script(
                "inspect_archive.py", "--archive", str(archive), "--privacy-report", str(privacy),
                "--sanitized-signing-fixture", str(fixture), "--skip-binary-tools", "--output", str(output),
            )
            data = json.loads(output.read_text())
            self.assertEqual(data["data"]["summary"]["app_clips"], 1)
            self.assertEqual(data["data"]["summary"]["watch_apps"], 1)
            self.assertTrue(data["data"]["xcframeworks"][0]["valid"])
            self.assertEqual(data["data"]["xcframeworks"][0]["slices"][0]["platform"], "ios")
            self.assertEqual(data["data"]["privacy_report_cross_check"]["verification"], "CONFIRMED")
            self.assertTrue(any(item["id"].startswith("ARCHIVE-NESTED-FRAMEWORK-") for item in data["findings"]))
            self.assertEqual(next(item for item in data["checks"] if item["id"] == "ARCHIVE-005")["disposition"], "PASS")
            aggregate_output = root / "archive-aggregate.json"
            run_script(
                "inspect_archive.py", "--archive", str(archive), "--privacy-report",
                str(FIXTURES / "archive-evidence" / "privacy-report-manifest-aggregate.plist"),
                "--skip-binary-tools", "--output", str(aggregate_output),
            )
            aggregate = json.loads(aggregate_output.read_text())
            self.assertEqual(aggregate["data"]["xcode_privacy_report"]["schema_family"], "PRIVACY_MANIFEST_AGGREGATE")

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
            self.assertEqual(report["schema_version"], "0.3.0")
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

    def test_app_store_connect_api_adapter_is_get_only_and_allowlist_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            fixture = directory / "apps.json"
            fixture.write_text(json.dumps({"data": [{
                "type": "apps", "id": "123", "attributes": {
                    "name": "Sample", "bundleId": "org.example.Sample", "privateField": "must-not-pass",
                },
            }]}))
            output = directory / "asc.json"
            run_script(
                "fetch_asc_readonly.py", "--endpoint", "apps", "--fixture", str(fixture), "--output", str(output),
            )
            text = output.read_text()
            data = json.loads(text)
            self.assertEqual(data["data"]["method"], "GET")
            self.assertFalse(data["data"]["capabilities"]["modify"])
            self.assertNotIn("privateField", text)
            self.assertNotIn("must-not-pass", text)
            export = directory / "export.json"
            export.write_text(json.dumps({"appPrivacy": {"tracking": False}, "ageRating": {"rating": "4+"}}))
            expected = directory / "expected.json"
            expected.write_text(json.dumps({"app_privacy": {"tracking": False}, "age_rating": {"rating": "4+"}}))
            comparison = directory / "comparison.json"
            run_script(
                "inspect_asc_export.py", "--export", str(export), "--api-fragment", str(output),
                "--expected", str(expected), "--output", str(comparison),
            )
            compared = json.loads(comparison.read_text())
            self.assertTrue(all(item["disposition"] == "PASS" for item in compared["data"]["expected_comparisons"]))
            rejected = run_script(
                "fetch_asc_readonly.py", "--endpoint", "users", "--fixture", str(fixture),
                "--output", str(output), expect=1,
            )
            self.assertIn("not allowlisted", rejected.stderr)

    def test_simulator_plan_marks_unobserved_states_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "runtime.json"
            run_script(
                "simulator_review.py", "--root", str(FIXTURES / "minimal-app"),
                "--bundle-id", "org.example.Sample", "--device", "iPhone", "--output", str(output),
            )
            data = json.loads(output.read_text())
            scenario_checks = [item for item in data["checks"] if item["id"] != "SIM-MATRIX"]
            self.assertTrue(all(item["disposition"] == "NOT_RUN" for item in scenario_checks))
            self.assertEqual(next(item for item in data["checks"] if item["id"] == "SIM-MATRIX")["disposition"], "BLOCKED")
            self.assertFalse(data["data"]["safety"]["mutates_simulator"])

    def test_runtime_plan_imports_evidence_and_blocks_unauthorized_sensitive_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            screenshots = directory / "screenshots"
            screenshots.mkdir()
            (screenshots / "home.png").write_bytes(
                b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\x0dIHDR" + (1170).to_bytes(4, "big") + (2532).to_bytes(4, "big")
            )
            xcresult = directory / "xcresult.json"
            xcresult.write_text(json.dumps({"tests": [{"testStatus": "Success"}]}))
            observations = directory / "observations.json"
            observations.write_text(json.dumps({
                "storekit": {"result": "PASS", "detail": "ran against a test session"},
                "first-launch": {"result": "PASS", "detail": "reviewer path visible"},
            }))
            output = directory / "runtime.json"
            plan = directory / "AppStorePreflight.xctestplan"
            run_script(
                "simulator_review.py", "--root", str(FIXTURES / "minimal-app"),
                "--bundle-id", "org.example.Sample", "--device", "iPhone 17 Pro", "--os", "iOS 20.0",
                "--locale", "zh-CN", "--appearance", "dark", "--dynamic-type", "accessibility5",
                "--observations", str(observations), "--screenshots", str(screenshots), "--xcresult", str(xcresult),
                "--xctestplan-output", str(plan), "--test-target-id", "UITESTTARGETID",
                "--test-target-name", "SampleUITests", "--container-path", "Sample.xcodeproj",
                "--output", str(output),
            )
            data = json.loads(output.read_text())
            self.assertTrue(plan.is_file())
            self.assertEqual(json.loads(plan.read_text())["version"], 1)
            self.assertEqual(data["data"]["screenshots"]["items"][0]["dimensions"], [1170, 2532])
            self.assertEqual(data["data"]["xcresult"]["status"], "PASS")
            storekit = next(item for item in data["data"]["scenarios"] if item["id"] == "storekit")
            self.assertEqual(storekit["result"], "BLOCKED")
            self.assertFalse(data["data"]["safety"]["purchases_products"])

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
            checksum = directory / "first.zip.sha256"
            provenance = directory / "provenance.json"
            run_script(
                "package_skill.py", "--skill", str(skill), "--output", str(first),
                "--checksum-output", str(checksum), "--provenance-output", str(provenance),
            )
            run_script("package_skill.py", "--skill", str(skill), "--output", str(second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(checksum.read_text().split()[0], hashlib.sha256(first.read_bytes()).hexdigest())
            self.assertEqual(json.loads(provenance.read_text())["format"], "app-store-preflight-skill-provenance-v1")
            with zipfile.ZipFile(first) as archive:
                self.assertIn("app-store-preflight-audit/SKILL.md", archive.namelist())
                self.assertIn("app-store-preflight-audit/PROVENANCE.json", archive.namelist())
            destination = directory / "skills"
            run_script(
                "install_skill.py", "--source", str(first), "--checksum-file", str(checksum),
                "--destination-root", str(destination), "--install",
            )
            self.assertTrue((destination / "app-store-preflight-audit" / "SKILL.md").is_file())
            result = run_script(
                "install_skill.py", "--source", str(first), "--destination-root", str(destination),
                "--install", expect=1,
            )
            self.assertIn("refusing to overwrite", result.stderr)
            run_script(
                "install_skill.py", "--source", str(first), "--checksum-file", str(checksum),
                "--destination-root", str(destination), "--install", "--upgrade",
            )
            self.assertEqual(len(list(destination.glob("app-store-preflight-audit.backup-*"))), 1)


if __name__ == "__main__":
    unittest.main()
