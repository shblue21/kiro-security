"""Scan lifecycle, phase transition, finalization, and export coverage."""

import json
import re
import subprocess
import threading
import unittest
from copy import deepcopy
from pathlib import Path

from workflow_test_support import WorkflowTestCase
from kiro_security.artifacts import (
    ArtifactContractError,
    finding_authoring_schema,
    validate_finding_authoring,
)
from kiro_security.errors import WorkbenchError
from kiro_security.models import DiffTarget, WorkspaceSetup
from kiro_security.semantic_materialization import validate_derived_writeups


class WorkflowLifecycleTests(WorkflowTestCase):
    def test_canonical_authoring_schema_matches_runtime_constraints(self):
        schema = finding_authoring_schema(
            required_sections=("rootCause", "validation", "attackPath"),
            required_extension_fields=("candidateId", "candidateInstanceId"),
        )
        properties = schema["properties"]

        self.assertIs(properties["findingId"], False)
        self.assertIs(properties["occurrenceId"], False)
        self.assertIs(properties["fingerprints"], False)
        self.assertEqual(
            properties["ruleId"]["pattern"],
            r"^[a-z0-9][a-z0-9._/-]*$",
        )
        self.assertEqual(
            properties["identity"]["properties"]["anchor"]["pattern"],
            properties["ruleId"]["pattern"],
        )
        self.assertEqual(
            properties["severity"]["dependentRequired"],
            {"score": ["scoringSystem"]},
        )
        self.assertNotIn(
            "minItems",
            properties["taxonomy"]["properties"]["cwe"],
        )
        self.assertEqual(
            set(properties["codeEvidence"]["items"]["required"]),
            {"id", "label", "path", "startLine", "code", "explanation"},
        )
        self.assertTrue(
            re.fullmatch(
                properties["locations"]["items"]["properties"]["path"]["pattern"],
                "src/app.py",
            )
        )
        self.assertFalse(
            re.fullmatch(
                properties["locations"]["items"]["properties"]["path"]["pattern"],
                "../app.py",
            )
        )
        self.assertTrue(
            {"rootCause", "validation", "attackPath", "extensions"}.issubset(
                schema["required"]
            )
        )
        self.assertEqual(
            properties["extensions"]["required"],
            ["candidateId", "candidateInstanceId"],
        )

    def test_canonical_authoring_runtime_accepts_advertised_shape(self):
        finding = self._finding()
        finding["identity"].pop("instance")
        finding["taxonomy"]["cwe"] = []
        finding["codeEvidence"] = [
            {
                "id": "untrusted-input",
                "label": "Untrusted input",
                "path": "app.py",
                "startLine": 1,
                "endLine": 2,
                "code": "def execute(value):\n    return value",
                "explanation": "The caller controls value.",
            }
        ]
        finding["rootCause"]["evidenceRefs"] = ["untrusted-input"]
        validate_finding_authoring(finding, "finding")

        invalid = deepcopy(finding)
        invalid["identity"]["instance"] = ""
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["identity"]["anchor"] = "Class#method"
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["locations"][0]["path"] = "../app.py"
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["severity"].pop("scoringSystem")
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["locations"][0]["startLine"] = 2
        invalid["locations"][0]["endLine"] = 1
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["rootCause"]["evidenceRefs"] = ["missing-evidence"]
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

        invalid = deepcopy(finding)
        invalid["findingId"] = "csf_000000000000000000000000"
        with self.assertRaises(ArtifactContractError):
            validate_finding_authoring(invalid, "finding")

    def test_invalid_canonical_replacement_is_side_effect_free(self):
        def reject_invalid_replacement(scan_id):
            contract = self.workbench.get_scan_artifact_contract(
                scan_id,
                self.owner_a,
            )
            canonical_schema = contract["descriptorSchemas"]["canonical-result"]
            self.assertEqual(
                canonical_schema["properties"]["findings"]["properties"]
                ["findings"]["type"],
                "array",
            )
            coverage_schema = contract["descriptorSchemas"]["coverage"]
            self.assertIn("explicitExclusions", coverage_schema["required"])
            self.assertEqual(
                coverage_schema["properties"]["mode"],
                {"const": "repository"},
            )
            self.assertEqual(
                coverage_schema["properties"]["surfaces"]["items"]
                ["properties"]["receipt"]["properties"]["closed"],
                {"const": True},
            )
            writeup_example = contract["descriptorSchemas"]["derived-writeup"][
                "examples"
            ][0]
            self.assertEqual(
                set(writeup_example["outputs"][0]),
                {"path", "markdown"},
            )
            self.assertEqual(
                writeup_example["outputs"][0]["path"],
                "findings/example-finding/example-finding.md",
            )
            persisted = {
                item["descriptor"]: item
                for item in contract["persisted"]
            }
            coverage_path = Path(persisted["coverage"]["path"])
            original_coverage = coverage_path.read_bytes()
            invalid_coverage = json.loads(original_coverage)
            invalid_coverage["deferred"] = ["none"]
            with self.assertRaises(WorkbenchError) as raised:
                self.workbench.write_scan_artifact(
                    scan_id,
                    "coverage",
                    invalid_coverage,
                    expected_digest=persisted["coverage"]["digest"],
                    owner_session_hash=self.owner_a,
                )
            self.assertEqual(raised.exception.code, "invalid_artifact")
            self.assertEqual(coverage_path.read_bytes(), original_coverage)
            coverage_path.write_text(
                json.dumps(invalid_coverage),
                encoding="utf-8",
            )
            legacy_contract = self.workbench.get_scan_artifact_contract(
                scan_id,
                self.owner_a,
            )
            self.assertFalse(legacy_contract["closure"]["complete"])
            self.assertIn(
                "coverage.invalid",
                legacy_contract["closure"]["missing"],
            )
            coverage_path.write_bytes(original_coverage)

            canonical_path = Path(persisted["canonical-result"]["path"])
            original = canonical_path.read_bytes()
            with self.assertRaises(WorkbenchError) as raised:
                self.workbench.write_scan_artifact(
                    scan_id,
                    "canonical-result",
                    {
                        "scanId": scan_id,
                        "manifest": {"scan": {}},
                        "findings": {"count": 1},
                    },
                    expected_digest=persisted["canonical-result"]["digest"],
                    owner_session_hash=self.owner_a,
                )
            self.assertEqual(raised.exception.code, "invalid_canonical_result")
            self.assertEqual(canonical_path.read_bytes(), original)

            unrelated = json.loads(original)
            extra_finding = json.loads(
                json.dumps(unrelated["findings"]["findings"][0])
            )
            extra_finding["ruleId"] = "python.unvalidated-execution"
            extra_finding["identity"]["instance"] = "other-value"
            extra_finding["title"] = "Unvalidated execution path"
            extra_finding["writeup"]["reportPath"] = (
                "findings/unvalidated-execution/unvalidated-execution.md"
            )
            extra_finding["extensions"]["candidateInstanceId"] = "instance-2"
            unrelated["findings"]["findings"].append(extra_finding)
            with self.assertRaises(WorkbenchError) as raised:
                self.workbench.write_scan_artifact(
                    scan_id,
                    "canonical-result",
                    unrelated,
                    expected_digest=persisted["canonical-result"]["digest"],
                    owner_session_hash=self.owner_a,
                )
            self.assertEqual(
                raised.exception.code,
                "canonical_attack_path_mismatch",
            )
            self.assertEqual(canonical_path.read_bytes(), original)

            writeup_path = Path(persisted["derived-writeup"]["path"])
            original_writeup = writeup_path.read_bytes()
            invalid_writeup = json.loads(original_writeup)
            invalid_writeup["outputs"][0]["path"] = "findings/wrong/name.md"
            with self.assertRaises(WorkbenchError) as raised:
                self.workbench.write_scan_artifact(
                    scan_id,
                    "derived-writeup",
                    invalid_writeup,
                    expected_digest=persisted["derived-writeup"]["digest"],
                    owner_session_hash=self.owner_a,
                )
            self.assertIn(
                raised.exception.code,
                ("derived_writeup_mismatch", "invalid_derived_path"),
            )
            self.assertEqual(writeup_path.read_bytes(), original_writeup)

        self._complete(before_complete=reject_invalid_replacement)

    def test_semantic_artifacts_finalize_index_export_and_retry(self):
        scan_id, completed = self._complete()
        self.assertEqual(completed["scan"]["status"], "complete")
        self.assertTrue(completed["manifestDigest"].startswith("sha256:"))
        self.assertTrue(Path(completed["reportPath"]).is_file())
        report = Path(completed["reportPath"]).read_text(encoding="utf-8")
        self.assertIn(
            "source integrity (high): Generated code must match reviewed source.",
            report,
        )
        scan_dir = Path(completed["scan"]["scanDir"])
        self.assertTrue(
            (
                scan_dir
                / "findings"
                / "untrusted-execution"
                / "untrusted-execution.md"
            ).is_file()
        )
        self.assertTrue((scan_dir / "hardening" / "hardening.md").is_file())
        dashboard = self.workbench.dashboard_projection()
        self.assertEqual(len(dashboard["findings"]), 1)
        finding = dashboard["findings"][0]
        self.assertRegex(finding["findingId"], r"^csf_[a-f0-9]{24}$")
        self.assertRegex(finding["occurrenceId"], r"^occ_[a-f0-9]{24}$")
        self.assertEqual(finding["locations"][0]["path"], "app.py")
        csv_result = self.workbench.export_scan(scan_id, "csv", self.owner_a)
        self.assertTrue(Path(csv_result["path"]).is_file())
        manifest_path = scan_dir / "scan-manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        report_path = Path(completed["reportPath"])
        sarif_path = Path(completed["sarifPath"])
        report_path.unlink()
        sarif_path.unlink()
        retry = self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertTrue(retry["reusedSeal"])
        self.assertTrue(report_path.is_file())
        self.assertTrue(sarif_path.is_file())
        self.assertEqual(manifest_path.read_bytes(), manifest_bytes)
        self.assertEqual(retry["manifestDigest"], completed["manifestDigest"])

    def test_filesystem_seal_blocks_semantic_writes_before_db_publish(self):
        scan_id, completed = self._complete()
        scan_dir = Path(completed["scan"]["scanDir"])
        canonical_path = scan_dir / "artifacts" / "semantic" / "canonical-result.json"
        original = canonical_path.read_bytes()

        with self.workbench.database.connect() as connection:
            connection.execute(
                """
                UPDATE scans
                SET status = 'running', completed_at = NULL,
                    seal_manifest_digest = NULL
                WHERE id = ?
                """,
                (scan_id,),
            )

        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(contract["descriptorSchemas"], {})
        canonical = json.loads(original)
        canonical["findings"]["findings"][0]["severity"]["level"] = "low"
        persisted = {
            item["descriptor"]: item
            for item in contract["persisted"]
        }
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "canonical-result",
                canonical,
                expected_digest=persisted["canonical-result"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "scan_sealed")
        self.assertEqual(canonical_path.read_bytes(), original)

        report_path = Path(completed["reportPath"])
        sarif_path = Path(completed["sarifPath"])
        report_path.unlink()
        sarif_path.unlink()
        retry = self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertTrue(retry["reusedSeal"])
        self.assertEqual(retry["scan"]["status"], "complete")
        self.assertTrue(report_path.is_file())
        self.assertTrue(sarif_path.is_file())

    def test_filesystem_seal_blocks_failure_and_cancel_before_db_publish(self):
        for action in ("fail", "cancel"):
            with self.subTest(action=action):
                scan_id, _completed = self._complete()
                with self.workbench.database.connect() as connection:
                    connection.execute(
                        """
                        UPDATE scans
                        SET status = 'running', completed_at = NULL,
                            seal_manifest_digest = NULL
                        WHERE id = ?
                        """,
                        (scan_id,),
                    )
                (self.target / ("after-seal-%s.txt" % action)).write_text(
                    "changed after seal\n",
                    encoding="utf-8",
                )

                with self.assertRaises(WorkbenchError) as raised:
                    if action == "fail":
                        self.workbench.fail_scan(
                            scan_id,
                            "late failure",
                            self.owner_a,
                        )
                    else:
                        self.workbench.cancel_scan(scan_id, self.owner_a)
                self.assertEqual(raised.exception.code, "scan_sealed")

                retried = self.workbench.complete_scan(scan_id, self.owner_a)
                self.assertEqual(retried["scan"]["status"], "complete")
                self.assertTrue(retried["reusedSeal"])

    def test_completion_replaces_stale_progress_finding_count(self):
        def publish_stale_telemetry(scan_id):
            state = self.workbench.update_scan_progress(
                scan_id,
                reportable_findings_count=10,
                owner_session_hash=self.owner_a,
            )
            self.assertEqual(
                state["progress"]["reportableFindingsCount"],
                10,
            )

        _scan_id, completed = self._complete(
            before_complete=publish_stale_telemetry,
        )
        self.assertEqual(
            completed["scan"]["progress"]["reportableFindingsCount"],
            1,
        )

    def test_informational_finding_is_canonical_but_not_reportable(self):
        _scan_id, completed = self._complete(finding_severity="informational")
        self.assertEqual(completed["scan"]["status"], "complete")
        self.assertEqual(
            completed["scan"]["progress"]["reportableFindingsCount"],
            0,
        )
        findings = json.loads(Path(completed["findingsPath"]).read_text("utf-8"))
        self.assertEqual(findings["findings"][0]["severity"]["level"], "informational")
        manifest = json.loads(Path(completed["manifestPath"]).read_text("utf-8"))
        self.assertEqual(manifest["totalFindings"], 1)
        self.assertEqual(manifest["severityCounts"], {"informational": 1})
        report = Path(completed["reportPath"]).read_text("utf-8")
        self.assertIn("| Reportable findings | 0 |", report)
        self.assertFalse(
            (Path(completed["scan"]["scanDir"]) / "hardening").exists()
        )

    def test_informational_finding_supports_an_optional_writeup(self):
        _scan_id, completed = self._complete(
            finding_severity="informational",
            informational_writeup=True,
        )
        scan_dir = Path(completed["scan"]["scanDir"])
        self.assertTrue(
            (
                scan_dir
                / "findings"
                / "untrusted-execution"
                / "untrusted-execution.md"
            ).is_file()
        )
        self.assertFalse((scan_dir / "hardening").exists())
        self.assertEqual(
            completed["scan"]["progress"]["reportableFindingsCount"],
            0,
        )

    def test_informational_writeup_reference_requires_derived_output(self):
        with self.assertRaises(WorkbenchError) as raised:
            self._complete(
                finding_severity="informational",
                informational_writeup=True,
                omit_derived_writeup=True,
            )
        self.assertEqual(raised.exception.code, "artifact_closure_incomplete")
        self.assertIn("derived-writeup", str(raised.exception))

    def test_derived_writeup_requires_only_declared_references(self):
        report_path = "findings/reportable/reportable.md"
        supplied = validate_derived_writeups(
            {
                "findings": [
                    {"writeup": {"reportPath": report_path}},
                    {"severity": {"level": "informational"}},
                ]
            },
            {"outputs": [{"path": report_path, "markdown": "# Reportable\n"}]},
        )
        self.assertEqual(supplied, {report_path: "# Reportable\n"})

    def test_reportable_count_resets_after_discovery_and_can_decrease(self):
        _workspace_id, scan_id = self._start()
        self._write(scan_id, "brief", self._ready_brief())
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "threat-model", {"summary": "Count model."})
        discovery = self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=1,
            review_items_completed=1,
            reportable_findings_count=10,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(
            discovery["progress"]["reportableFindingsCount"],
            10,
        )
        self._write(
            scan_id,
            "discovery",
            {"candidates": [{"id": "candidate-1"}]},
        )
        validation = self.workbench.update_scan_progress(
            scan_id,
            phase="validation",
            review_items_total=6,
            review_items_completed=0,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(validation["progress"]["reviewItemsCompleted"], 0)
        self.assertEqual(validation["progress"]["reviewItemsTotal"], 6)
        self.assertEqual(
            validation["progress"]["reportableFindingsCount"],
            0,
        )
        self.workbench.update_scan_progress(
            scan_id,
            reportable_findings_count=10,
            owner_session_hash=self.owner_a,
        )
        refined = self.workbench.update_scan_progress(
            scan_id,
            reportable_findings_count=6,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(
            refined["progress"]["reportableFindingsCount"],
            6,
        )

    def test_threat_model_rejects_an_unnamed_object_before_phase_close(self):
        _workspace_id, scan_id = self._start()
        self._write(scan_id, "brief", self._ready_brief())
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        items = contract["descriptorSchemas"]["threat-model"]["properties"][
            "assets"
        ]["items"]
        self.assertEqual(len(items["oneOf"]), 2)
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "threat-model",
                {
                    "summary": "Invalid model.",
                    "assets": [{"description": "Missing stable name."}],
                },
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")

    def test_attack_path_rejects_inconsistent_decision_before_phase_close(self):
        with self.assertRaises(WorkbenchError) as raised:
            self._complete(
                attack_path_instance={
                    "instanceId": "instance-1",
                    "disposition": "reportable",
                    "finalSeverity": "ignore",
                }
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")

    def test_canonical_severity_must_match_attack_path_final_severity(self):
        with self.assertRaises(WorkbenchError) as raised:
            self._complete(
                finding_severity="critical",
                attack_path_instance={
                    "instanceId": "instance-1",
                    "disposition": "reportable",
                    "finalSeverity": "low",
                    "priority": "P3",
                },
            )
        self.assertEqual(raised.exception.code, "canonical_attack_path_mismatch")

        _scan_id, completed = self._complete(
            finding_severity="low",
            attack_path_instance={
                "instanceId": "instance-1",
                "disposition": "reportable",
                "finalSeverity": "low",
                "priority": "P3",
            },
        )
        self.assertEqual(completed["scan"]["status"], "complete")

    def test_semantic_artifacts_reject_symlinked_output_parent(self):
        outside = self.root / "outside"
        outside.mkdir()

        def install_symlink(scan_id):
            context = self.workbench.get_scan_context(
                scan_id,
                owner_session_hash=self.owner_a,
            )
            artifacts = Path(context["scan"]["scanDir"]) / "artifacts"
            artifacts.mkdir(exist_ok=True)
            (artifacts / "03_coverage").symlink_to(
                outside,
                target_is_directory=True,
            )

        with self.assertRaisesRegex(WorkbenchError, "scan directory"):
            self._complete(before_complete=install_symlink)
        self.assertEqual(list(outside.iterdir()), [])

    def test_no_candidate_canonical_finding_is_rejected_on_write(self):
        scan_id = self._advance_empty_standard_to_reporting()
        for descriptor, invalid_content in (
            ("derived-writeup", {"writeups": []}),
            ("derived-hardening", {"content": "# Hardening"}),
        ):
            with self.subTest(descriptor=descriptor):
                with self.assertRaises(WorkbenchError) as raised:
                    self._write(scan_id, descriptor, invalid_content)
                self.assertEqual(raised.exception.code, "artifact_phase_not_active")
                self.assertIn("canonical-result is persisted", str(raised.exception))
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "canonical-result",
                {
                    "manifest": {"scan": {}},
                    "findings": {"findings": [self._finding()]},
                },
            )
        self.assertEqual(raised.exception.code, "canonical_discovery_mismatch")
        self._write_empty_reporting_contract(scan_id)
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertNotIn("derived-writeup", contract["descriptorSchemas"])
        with self.assertRaises(WorkbenchError) as raised:
            self._write(scan_id, "derived-writeup", {"outputs": []})
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")

    def test_completion_rechecks_no_candidate_canonical_binding(self):
        scan_id = self._advance_empty_standard_to_reporting()
        self._write_empty_reporting_contract(scan_id)
        context = self.workbench.get_scan_context(
            scan_id,
            owner_session_hash=self.owner_a,
        )
        canonical_path = (
            Path(context["scan"]["scanDir"])
            / "artifacts"
            / "semantic"
            / "canonical-result.json"
        )
        (canonical_path.parent / "derived-writeup.json").write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "outputs": [
                        {
                            "path": "findings/untrusted-execution/untrusted-execution.md",
                            "markdown": "# Untrusted execution\n",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (canonical_path.parent / "derived-hardening.json").write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "outputs": [
                        {
                            "path": "hardening/hardening.md",
                            "markdown": "# Structural hardening\n",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        canonical_path.write_text(
            json.dumps(
                {
                    "scanId": scan_id,
                    "manifest": {"scan": {}},
                    "findings": {"findings": [self._finding()]},
                }
            ),
            encoding="utf-8",
        )
        self.workbench.update_scan_progress(
            scan_id,
            reportable_findings_count=1,
            owner_session_hash=self.owner_a,
        )
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertEqual(raised.exception.code, "canonical_discovery_mismatch")

    def test_closed_phase_artifact_is_not_writable(self):
        _workspace_id, scan_id = self._start()
        written = self._write(
            scan_id,
            "brief",
            self._ready_brief(),
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "brief",
                {
                    "scanId": scan_id,
                    **self._ready_brief(),
                },
                expected_digest=written["artifact"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")

    def test_artifact_write_and_phase_transition_share_scan_lock(self):
        _workspace_id, scan_id = self._start()
        self._write(
            scan_id,
            "brief",
            self._ready_brief(),
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "threat-model", {"summary": "Race model."})
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=1,
            review_items_completed=1,
            owner_session_hash=self.owner_a,
        )
        discovery = self._write(scan_id, "discovery", {"candidates": []})

        entered_write = threading.Event()
        release_write = threading.Event()
        transition_finished = threading.Event()
        errors = []
        original_write = self.workbench.semantic_artifacts.write

        def delayed_write(*args, **kwargs):
            entered_write.set()
            if not release_write.wait(5):
                raise AssertionError("Timed out waiting to release artifact write.")
            return original_write(*args, **kwargs)

        self.workbench.semantic_artifacts.write = delayed_write

        def replace_discovery():
            try:
                self.workbench.write_scan_artifact(
                    scan_id,
                    "discovery",
                    {"scanId": scan_id, "candidates": [], "revision": 2},
                    expected_digest=discovery["artifact"]["digest"],
                    owner_session_hash=self.owner_a,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def enter_validation():
            try:
                self.workbench.update_scan_progress(
                    scan_id,
                    phase="validation",
                    owner_session_hash=self.owner_a,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                transition_finished.set()

        writer = threading.Thread(target=replace_discovery)
        transition = threading.Thread(target=enter_validation)
        writer.start()
        self.assertTrue(entered_write.wait(5))
        transition.start()
        self.assertFalse(transition_finished.wait(0.2))
        release_write.set()
        writer.join(5)
        transition.join(5)
        self.assertFalse(writer.is_alive())
        self.assertFalse(transition.is_alive())
        self.assertEqual(errors, [])
        context = self.workbench.get_scan_context(
            scan_id,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(context["scan"]["phase"], "validation")

    def test_diff_no_findings_skips_candidate_tail_and_completes(self):
        subprocess.run(
            ["git", "init", str(self.target)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(self.target), "config", "user.name", "Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.target),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.target), "add", "app.py"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.target), "commit", "-m", "base"],
            check=True,
            capture_output=True,
        )
        (self.target / "app.py").write_text(
            "def execute(value):\n    return value.strip()\n",
            encoding="utf-8",
        )
        workspace = self.workbench.create_workspace(
            owner_session_hash=self.owner_a,
        )
        setup = self.workbench.inspect_setup(
            WorkspaceSetup(
                target_path=str(self.target),
                mode="diff",
                scope=".",
                diff_target=DiffTarget("working_tree"),
            )
        )
        saved = self.workbench.update_workspace_setup(
            workspace["id"],
            setup,
            owner_session_hash=self.owner_a,
        )
        started = self.workbench.start_scan(
            workspace["id"],
            saved["setupRevision"],
            saved["setupDigest"],
            setup,
            self.owner_a,
        )
        scan_id = started["scanId"]
        self._write(
            scan_id,
            "brief",
            self._ready_brief("diff"),
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "threat-model",
            {"summary": "Diff threat model."},
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=1,
            review_items_completed=1,
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "discovery", {"candidates": []})
        discovery_contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(
            discovery_contract["phaseContract"]["allowedNextPhases"],
            ["reporting"],
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="reporting",
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "coverage",
            {
                "documentType": "codex-security.coverage",
                "schemaVersion": "1.0",
                "mode": "working_tree",
                "completeness": "complete",
                "inventoryStrategy": "diff",
                "includePaths": ["."],
                "excludePaths": [],
                "surfaces": [
                    {
                        "id": "changed-python",
                        "label": "Changed Python source",
                        "disposition": "no_issue_found",
                        "receipt": {
                            "closed": True,
                            "reviewedPaths": ["app.py"],
                        },
                    }
                ],
                "explicitExclusions": [],
                "deferred": [],
            },
        )
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "canonical-result",
                {
                    "manifest": {"scan": {}},
                    "findings": {"findings": [self._finding()]},
                },
            )
        self.assertEqual(raised.exception.code, "canonical_discovery_mismatch")
        self._write(
            scan_id,
            "canonical-result",
            {
                "manifest": {"scan": {}},
                "findings": {"findings": []},
            },
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertTrue(contract["closure"]["complete"])
        self.assertNotIn("validation", contract["requiredDescriptors"])
        self.assertNotIn("attack-path", contract["requiredDescriptors"])
        self.assertNotIn("derived-writeup", contract["requiredDescriptors"])
        completed = self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertEqual(completed["scan"]["status"], "complete")
        self.assertFalse(
            (Path(completed["scan"]["scanDir"]) / "hardening").exists()
        )

    def test_scan_artifact_read_rejects_invalid_and_unsafe_files(self):
        _workspace_id, scan_id = self._start()
        written = self._write(
            scan_id,
            "brief",
            self._ready_brief(),
        )
        digest = written["artifact"]["digest"]
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.read_scan_artifact(
                scan_id,
                "../../outside",
                digest,
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "invalid_artifact_descriptor")

        artifact_path = Path(written["artifact"]["path"])
        outside = self.root / "outside-brief.json"
        artifact_path.replace(outside)
        artifact_path.symlink_to(outside)
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.read_scan_artifact(
                scan_id,
                "brief",
                digest,
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "unsafe_artifact_path")

    def test_complete_coverage_requires_explicit_surface_evidence(self):
        scan_id = self._advance_empty_standard_to_reporting()
        coverage = {
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            "mode": "repository",
            "completeness": "complete",
            "inventoryStrategy": "repository",
            "includePaths": ["."],
            "excludePaths": [],
            "surfaces": [],
            "explicitExclusions": [],
            "deferred": [],
        }

        contract = self.workbench.get_scan_artifact_contract(scan_id, self.owner_a)
        coverage_schema = contract["descriptorSchemas"]["coverage"]
        self.assertEqual(
            coverage_schema["allOf"][0]["then"]["properties"]["surfaces"],
            {"minItems": 1},
        )
        with self.assertRaises(WorkbenchError) as raised:
            self._write(scan_id, "coverage", coverage)
        self.assertEqual(raised.exception.code, "invalid_artifact")

        reviewed_surface = {
            "id": "python-source",
            "label": "Python source",
            "disposition": "no_issue_found",
            "receipt": {"closed": True, "reviewedPaths": []},
        }
        coverage["surfaces"] = [reviewed_surface]
        with self.assertRaises(WorkbenchError) as raised:
            self._write(scan_id, "coverage", coverage)
        self.assertEqual(raised.exception.code, "invalid_artifact")

        not_applicable = {
            "id": "source-inventory",
            "label": "Source inventory",
            "disposition": "not_applicable",
            "receipt": {"closed": True, "reviewedPaths": []},
        }
        coverage["surfaces"] = [not_applicable]
        with self.assertRaises(WorkbenchError) as raised:
            self._write(scan_id, "coverage", coverage)
        self.assertEqual(raised.exception.code, "invalid_artifact")

        not_applicable["notes"] = "No applicable source paths exist."
        self._write(scan_id, "coverage", coverage)
        self._write(
            scan_id,
            "canonical-result",
            {"manifest": {"scan": {}}, "findings": {"findings": []}},
        )
        completed = self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertEqual(completed["scan"]["status"], "complete")

    def test_phase_skip_and_unclosed_coverage_are_rejected(self):
        _workspace_id, scan_id = self._start()
        self._write(
            scan_id,
            "brief",
            self._ready_brief(),
        )
        with self.assertRaisesRegex(WorkbenchError, "can advance only"):
            self.workbench.update_scan_progress(
                scan_id,
                phase="discovery",
                owner_session_hash=self.owner_a,
            )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        with self.assertRaisesRegex(WorkbenchError, "closed"):
            self._write(
                scan_id,
                "coverage",
                {
                    "documentType": "codex-security.coverage",
                    "schemaVersion": "1.0",
                    "mode": "repository",
                    "completeness": "complete",
                    "inventoryStrategy": "repository",
                    "includePaths": ["."],
                    "excludePaths": [],
                    "surfaces": [
                        {
                            "id": "source",
                            "label": "Source",
                            "disposition": "no_issue_found",
                            "receipt": {"reviewedPaths": ["app.py"]},
                        }
                    ],
                    "explicitExclusions": [],
                    "deferred": [],
                },
            )

    def test_preflight_requires_ready_source_inspection(self):
        _workspace_id, scan_id = self._start()
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        schema = contract["descriptorSchemas"]["brief"]
        self.assertIn("status", schema["required"])
        self.assertIn("capabilities", schema["required"])
        self.assertEqual(
            schema["properties"]["capabilities"]["required"],
            ["sourceInspection"],
        )
        self.assertEqual(schema["properties"]["mode"], {"const": "standard"})
        self.assertEqual(
            schema["properties"]["target"],
            {"const": str(self.target.resolve())},
        )
        self.assertEqual(schema["properties"]["scope"], {"const": "."})

        for field, value in (
            ("mode", "deep"),
            ("target", str(self.root / "other-target")),
            ("scope", "src"),
        ):
            with self.subTest(mismatched_field=field):
                with self.assertRaises(WorkbenchError) as raised:
                    self._write(
                        scan_id,
                        "brief",
                        {**self._ready_brief(), field: value},
                    )
                self.assertEqual(raised.exception.code, "brief_scan_mismatch")

        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "brief",
                {
                    "mode": "standard",
                    "target": str(self.target.resolve()),
                    "scope": ".",
                },
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")

        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "brief",
                {
                    **self._ready_brief(),
                    "capabilities": {"sourceInspection": False},
                },
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")

        for status in ("blocked", "incomplete"):
            with self.subTest(status=status):
                _workspace_id, non_ready_scan = self._start()
                self._write(
                    non_ready_scan,
                    "brief",
                    {
                        **self._ready_brief(),
                        "status": status,
                        "capabilities": {"sourceInspection": False},
                    },
                )
                with self.assertRaises(WorkbenchError) as raised:
                    self.workbench.update_scan_progress(
                        non_ready_scan,
                        phase="threat_model",
                        owner_session_hash=self.owner_a,
                    )
                self.assertEqual(raised.exception.code, "preflight_not_ready")

        _workspace_id, ready_scan = self._start()
        self._write(ready_scan, "brief", self._ready_brief())
        self.workbench.update_scan_progress(
            ready_scan,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        context = self.workbench.get_scan_context(
            ready_scan,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(context["scan"]["phase"], "threat_model")

        _workspace_id, deep_scan = self._start("deep")
        deep_schema = self.workbench.get_scan_artifact_contract(
            deep_scan,
            self.owner_a,
        )["descriptorSchemas"]["brief"]
        self.assertIn(
            "pattern",
            deep_schema["properties"]["worklist"]["items"]["properties"]["path"],
        )
        for unsafe_path in (
            "../outside.py",
            "./..",
            "./../outside.py",
            "././app.py",
            "/tmp/outside.py",
            "C:/Windows/System32/config/SAM",
            "dir//app.py",
            "dir/./app.py",
            "dir/",
            "dir/\tapp.py",
            "a" * 4097,
        ):
            with self.subTest(unsafe_deep_worklist_path=unsafe_path):
                with self.assertRaises(WorkbenchError) as raised:
                    self._write(
                        deep_scan,
                        "brief",
                        self._ready_brief(
                            "deep",
                            worklist=[{"id": "unsafe", "path": unsafe_path}],
                        ),
                    )
                self.assertEqual(raised.exception.code, "invalid_artifact")

    def test_artifact_contract_discloses_only_the_current_phase(self):
        _workspace_id, scan_id = self._start()
        first = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        repeated = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(set(first["descriptorSchemas"]), {"brief"})
        self.assertEqual(first["phaseContract"]["phase"], "preflight")
        self.assertEqual(
            first["phaseContract"]["contractDigest"],
            repeated["phaseContract"]["contractDigest"],
        )
        serialized = str(first["phaseContract"])
        self.assertNotIn("deterministic source-like inventory", serialized)
        self.assertNotIn("attacker position, entry point", serialized)
        self.assertNotIn("canonical manifest and findings", serialized)

        self._write(
            scan_id,
            "brief",
            self._ready_brief(),
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        threat_model = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(
            set(threat_model["descriptorSchemas"]),
            {"threat-model"},
        )
        self.assertEqual(
            threat_model["phaseContract"]["phase"],
            "threat_model",
        )
        self.assertNotIn(
            "deterministic source-like inventory",
            str(threat_model["phaseContract"]),
        )

        self.workbench.fail_scan(
            scan_id,
            "test terminal contract",
            self.owner_a,
        )
        terminal = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(terminal["descriptorSchemas"], {})
        self.assertEqual(terminal["phaseContract"]["title"], "Terminal scan")
        self.assertEqual(terminal["phaseContract"]["allowedNextPhases"], [])


if __name__ == "__main__":
    unittest.main()
