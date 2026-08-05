"""Scan lifecycle, phase transition, finalization, and export coverage."""

import json
import subprocess
import threading
import unittest
from pathlib import Path

from workflow_test_support import WorkflowTestCase
from kiro_security.errors import WorkbenchError
from kiro_security.models import DiffTarget, WorkspaceSetup


class WorkflowLifecycleTests(WorkflowTestCase):
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
        retry = self.workbench.complete_scan(scan_id, self.owner_a)
        self.assertTrue(retry["reusedSeal"])

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
            {
                "mode": "standard",
                "target": str(self.target),
                "scope": ".",
            },
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
                    "mode": "standard",
                    "target": str(self.target),
                    "scope": ".",
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
            {
                "mode": "standard",
                "target": str(self.target),
                "scope": ".",
            },
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
            {"mode": "diff", "target": str(self.target), "scope": "."},
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
            {
                "mode": "standard",
                "target": str(self.target),
                "scope": ".",
            },
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

    def test_phase_skip_and_unclosed_coverage_are_rejected(self):
        _workspace_id, scan_id = self._start()
        self._write(
            scan_id,
            "brief",
            {"mode": "standard", "target": str(self.target), "scope": "."},
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
            {"mode": "standard", "target": str(self.target), "scope": "."},
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
