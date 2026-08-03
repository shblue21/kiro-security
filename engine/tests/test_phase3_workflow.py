"""End-to-end semantic completion and follow-up lifecycle coverage."""

import hashlib
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from kiro_security.errors import WorkbenchError
from kiro_security.models import DiffTarget, WorkspaceSetup
from kiro_security.phase_contracts import build_phase_contract
from kiro_security.workbench import Workbench


class PhaseThreeWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "app.py").write_text(
            "def execute(value):\n    return value\n",
            encoding="utf-8",
        )
        self.workbench = Workbench(
            str(self.root / "state"),
            str(self.root / "scans"),
        )
        self.owner_a = "a" * 64
        self.owner_b = "b" * 64

    def tearDown(self):
        self.temporary.cleanup()

    def _start(self, mode="standard"):
        workspace = self.workbench.create_workspace(
            owner_session_hash=self.owner_a,
        )
        setup = self.workbench.inspect_setup(
            WorkspaceSetup(
                target_path=str(self.target),
                mode=mode,
                scope=".",
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
        return workspace["id"], started["scanId"]

    def _write(self, scan_id, descriptor, content):
        payload = {"scanId": scan_id}
        payload.update(content)
        return self.workbench.write_scan_artifact(
            scan_id,
            descriptor,
            payload,
            owner_session_hash=self.owner_a,
        )

    def _write_deep_brief(self, scan_id):
        self._write(
            scan_id,
            "brief",
            {
                "mode": "deep",
                "target": str(self.target),
                "scope": ".",
                "worklist": [{"id": "app-source", "path": "app.py"}],
            },
        )
        return self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )["deep"]

    @staticmethod
    def _deep_worker(deep, round_number, worker_number, candidates):
        return {
            "round": round_number,
            "worker": worker_number,
            "inputDigest": deep["inputDigest"],
            "threatModel": {
                "summary": "Independent worker model.",
                "assets": ["source integrity"],
                "trustBoundaries": ["repository input"],
                "attackerCapabilities": ["control repository content"],
                "securityInvariants": ["untrusted input cannot reach a privileged sink"],
                "evidence": ["app.py"],
            },
            "candidates": candidates,
            "coverage": {
                "closed": True,
                "worklistDigest": deep["worklistDigest"],
                "receipts": [
                    {
                        "worklistId": "app-source",
                        "disposition": "reviewed",
                        "evidence": ["app.py"],
                    }
                ],
            },
        }

    @staticmethod
    def _deep_checkpoint(
        deep,
        round_number,
        worker_number,
        attempt=1,
        status="in_progress",
    ):
        checkpoint = {
            "round": round_number,
            "worker": worker_number,
            "attempt": attempt,
            "inputDigest": deep["inputDigest"],
            "worklistDigest": deep["worklistDigest"],
            "status": status,
            "partial": {
                "threatModel": {"summary": "Partial independent model."},
                "candidates": [],
                "coverage": {"closed": False, "receipts": []},
            },
        }
        if status == "failed":
            checkpoint["failure"] = "worker terminated"
        return checkpoint

    @staticmethod
    def _deep_lineage(candidate_id):
        if candidate_id is None:
            return []
        return [
            {
                "worker": worker_number,
                "candidateId": candidate_id,
                "canonicalCandidateId": candidate_id,
            }
            for worker_number in range(1, 5)
        ]

    def _complete(self, with_finding=True, before_complete=None):
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
        self._write(
            scan_id,
            "threat-model",
            {
                "summary": "Untrusted input crosses an execution boundary.",
                "assets": ["source integrity"],
                "trustBoundaries": ["call boundary"],
            },
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=1,
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "discovery",
            {"candidates": [{"id": "candidate-1"}]},
        )
        self.workbench.update_scan_progress(
            scan_id,
            review_items_completed=1,
            owner_session_hash=self.owner_a,
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="validation",
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "validation",
            {"results": [{"candidateId": "candidate-1"}]},
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="attack_path",
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "attack-path",
            {"results": [{"candidateId": "candidate-1"}]},
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="reporting",
            reportable_findings_count=1 if with_finding else 0,
            owner_session_hash=self.owner_a,
        )
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
                        "id": "python-source",
                        "label": "Python source",
                        "disposition": "reported" if with_finding else "no_issue_found",
                        "riskArea": "execution",
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
        findings = [self._finding()] if with_finding else []
        self._write(
            scan_id,
            "canonical-result",
            {
                "manifest": {"scan": {}},
                "findings": {"findings": findings},
            },
        )
        if with_finding:
            self._write(
                scan_id,
                "derived-writeup",
                {
                    "outputs": [
                        {
                            "path": "findings/untrusted-execution/untrusted-execution.md",
                            "markdown": "# Untrusted execution\n",
                        }
                    ],
                },
            )
            self._write(
                scan_id,
                "derived-hardening",
                {
                    "outputs": [
                        {
                            "path": "hardening/hardening.md",
                            "markdown": "# Structural hardening\n",
                        }
                    ]
                },
            )
        if before_complete is not None:
            before_complete(scan_id)
        return scan_id, self.workbench.complete_scan(scan_id, self.owner_a)

    def _advance_empty_standard_to_reporting(self):
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
        self._write(scan_id, "threat-model", {"summary": "No candidate model."})
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=1,
            review_items_completed=1,
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "discovery", {"candidates": []})
        self.workbench.update_scan_progress(
            scan_id,
            phase="validation",
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "validation", {"results": []})
        self.workbench.update_scan_progress(
            scan_id,
            phase="attack_path",
            owner_session_hash=self.owner_a,
        )
        self._write(scan_id, "attack-path", {"results": []})
        self.workbench.update_scan_progress(
            scan_id,
            phase="reporting",
            owner_session_hash=self.owner_a,
        )
        return scan_id

    def _write_empty_reporting_contract(self, scan_id):
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
                        "id": "python-source",
                        "label": "Python source",
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
        self._write(
            scan_id,
            "canonical-result",
            {
                "manifest": {"scan": {}},
                "findings": {"findings": []},
            },
        )

    @staticmethod
    def _finding():
        return {
            "ruleId": "python.untrusted-execution",
            "identity": {
                "anchor": "app.execute",
                "instance": "value",
            },
            "title": "Untrusted value reaches execution boundary",
            "summary": "The input reaches an execution-sensitive operation.",
            "severity": {
                "level": "medium",
                "score": 6.5,
                "scoringSystem": "CVSS:3.1",
                "rationale": "Exploitation requires a reachable caller.",
            },
            "confidence": {
                "level": "high",
                "rationale": "The static path is direct.",
            },
            "taxonomy": {
                "category": "injection",
                "cwe": ["CWE-94"],
            },
            "locations": [
                {
                    "path": "app.py",
                    "startLine": 1,
                    "endLine": 2,
                    "role": "root_control",
                }
            ],
            "remediation": "Validate input before the execution boundary.",
            "validation": {"summary": "Static validation confirmed the path."},
            "attackPath": {"summary": "Caller input reaches execute."},
            "provenance": {"source": "standard-scan"},
            "writeup": {
                "reportPath": "findings/untrusted-execution/untrusted-execution.md",
            },
        }

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

    def test_explicit_recovery_transfers_only_scan_ownership(self):
        workspace_id, scan_id = self._start()
        recovery = self.workbench.create_scan_recovery_request(scan_id)
        claimed = self.workbench.claim_scan_recovery(
            recovery["id"],
            recovery["version"],
            self.owner_b,
        )
        _other_workspace, other_scan = self._start()
        with self.assertRaisesRegex(WorkbenchError, "another scan"):
            self.workbench.get_scan_context(
                other_scan,
                recovery_request_id=recovery["id"],
                recovery_token=claimed["recoveryToken"],
                expected_version=claimed["version"],
                owner_session_hash=self.owner_b,
            )
        self.workbench.get_scan_context(
            scan_id,
            owner_session_hash=self.owner_a,
        )
        with self.assertRaisesRegex(WorkbenchError, "does not belong"):
            self.workbench.get_scan_context(scan_id, owner_session_hash=self.owner_b)
        delivered = self.workbench.get_scan_context(
            scan_id,
            recovery_request_id=recovery["id"],
            recovery_token=claimed["recoveryToken"],
            expected_version=claimed["version"],
            owner_session_hash=self.owner_b,
        )
        self.assertEqual(delivered["scanId"], scan_id)
        self.workbench.write_scan_artifact(
            scan_id,
            "brief",
            {
                "scanId": scan_id,
                "mode": "standard",
                "target": str(self.target),
                "scope": ".",
            },
            owner_session_hash=self.owner_b,
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_b,
        )
        with self.assertRaisesRegex(WorkbenchError, "does not belong"):
            self.workbench.update_scan_progress(
                scan_id,
                owner_session_hash=self.owner_a,
            )
        workspace = self.workbench.get_workspace(
            workspace_id,
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(workspace["activeScanId"], scan_id)

    def test_recovery_delivery_waits_for_scan_write_lock(self):
        _workspace_id, scan_id = self._start()
        recovery = self.workbench.create_scan_recovery_request(scan_id)
        claimed = self.workbench.claim_scan_recovery(
            recovery["id"],
            recovery["version"],
            self.owner_b,
        )
        entered_write = threading.Event()
        release_write = threading.Event()
        recovery_finished = threading.Event()
        errors = []
        original_write = self.workbench.semantic_artifacts.write

        def delayed_write(*args, **kwargs):
            entered_write.set()
            if not release_write.wait(5):
                raise AssertionError("Timed out waiting to release artifact write.")
            return original_write(*args, **kwargs)

        self.workbench.semantic_artifacts.write = delayed_write

        def write_brief():
            try:
                self._write(
                    scan_id,
                    "brief",
                    {
                        "mode": "standard",
                        "target": str(self.target),
                        "scope": ".",
                    },
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def deliver_recovery():
            try:
                self.workbench.get_scan_context(
                    scan_id,
                    recovery_request_id=recovery["id"],
                    recovery_token=claimed["recoveryToken"],
                    expected_version=claimed["version"],
                    owner_session_hash=self.owner_b,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                recovery_finished.set()

        writer = threading.Thread(target=write_brief)
        recovery_delivery = threading.Thread(target=deliver_recovery)
        writer.start()
        self.assertTrue(entered_write.wait(5))
        recovery_delivery.start()
        self.assertFalse(recovery_finished.wait(0.2))
        release_write.set()
        writer.join(5)
        recovery_delivery.join(5)
        self.assertFalse(writer.is_alive())
        self.assertFalse(recovery_delivery.is_alive())
        self.assertEqual(errors, [])
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.get_scan_context(
                scan_id,
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "scan_not_owned")
        self.workbench.get_scan_context(
            scan_id,
            owner_session_hash=self.owner_b,
        )

    def test_triage_and_remediation_use_exact_request_token_and_cas(self):
        _scan_id, _completed = self._complete()
        finding = self.workbench.dashboard_projection()["findings"][0]
        occurrence_id = finding["occurrenceId"]
        closed = self.workbench.set_finding_triage(
            occurrence_id,
            "closed",
            "false_positive",
        )
        self.assertEqual(closed["status"], "closed")
        with self.assertRaisesRegex(WorkbenchError, "Reopen"):
            self.workbench.request_finding_remediation(
                occurrence_id,
                "generate",
            )
        self.workbench.set_finding_triage(occurrence_id, "open")
        requested = self.workbench.request_finding_remediation(
            occurrence_id,
            "generate",
        )
        claimed = self.workbench.claim_remediation_action(
            requested["requestId"],
            requested["version"],
            self.owner_b,
        )
        context = self.workbench.get_remediation_context(
            requested["requestId"],
            claimed["actionToken"],
            claimed["version"],
            self.owner_b,
        )
        patch = (
            Path(context["scan"]["scan_dir"])
            / "remediation"
            / "generated.patch"
        )
        patch.parent.mkdir()
        patch.write_text(
            "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
            "-def execute(value):\n+def execute(validated_value):\n"
            "     return value\n",
            encoding="utf-8",
        )
        patch_digest = hashlib.sha256(patch.read_bytes()).hexdigest()
        generated = self.workbench.set_finding_remediation(
            occurrence_id,
            requested["requestId"],
            context["request"]["version"],
            claimed["actionToken"],
            "generated",
            str(patch),
            patch_digest,
            summary="Generated in a scan-local artifact.",
            owner_session_hash=self.owner_b,
        )
        self.assertEqual(generated["state"], "generated")
        apply_request = self.workbench.request_finding_remediation(
            occurrence_id,
            "apply",
            requested["requestId"],
        )
        apply_claim = self.workbench.claim_remediation_action(
            requested["requestId"],
            apply_request["version"],
            self.owner_b,
        )
        apply_context = self.workbench.get_remediation_context(
            requested["requestId"],
            apply_claim["actionToken"],
            apply_claim["version"],
            self.owner_b,
        )
        subprocess.run(
            ["git", "-C", str(self.target), "apply", str(patch)],
            check=True,
            capture_output=True,
        )
        unrelated = self.target / "unrelated.txt"
        unrelated.write_text("unexpected\n", encoding="utf-8")
        changed = self.workbench._portable_tree_digest(self.target)
        with self.assertRaisesRegex(WorkbenchError, "exact digest-bound patch"):
            self.workbench.set_finding_remediation(
                occurrence_id,
                requested["requestId"],
                apply_context["request"]["version"],
                apply_claim["actionToken"],
                "applied",
                applied_content_digest=changed,
                owner_session_hash=self.owner_b,
            )
        unrelated.unlink()
        applied_digest = self.workbench._portable_tree_digest(self.target)
        applied = self.workbench.set_finding_remediation(
            occurrence_id,
            requested["requestId"],
            apply_context["request"]["version"],
            apply_claim["actionToken"],
            "applied",
            applied_content_digest=applied_digest,
            owner_session_hash=self.owner_b,
        )
        self.assertEqual(applied["state"], "applied")
        with self.assertRaisesRegex(WorkbenchError, "pending remediation"):
            self.workbench.set_finding_triage(
                occurrence_id,
                "closed",
                "already_fixed",
            )

    def test_tracking_handoff_delivers_exact_sealed_finding(self):
        scan_id, _completed = self._complete()
        finding = self.workbench.dashboard_projection()["findings"][0]
        requested = self.workbench.create_finding_tracking_request(
            finding["occurrenceId"],
        )
        claimed = self.workbench.claim_tracking_request(
            requested["requestId"],
            requested["version"],
            self.owner_b,
        )
        context = self.workbench.get_tracking_context(
            requested["requestId"],
            claimed["trackingToken"],
            claimed["version"],
            self.owner_b,
        )
        self.assertEqual(context["occurrence"]["occurrenceId"], finding["occurrenceId"])
        self.assertEqual(context["scan"]["id"], scan_id)
        self.assertEqual(context["request"]["status"], "delivered")
        refreshed = self.workbench.get_tracking_context(
            requested["requestId"],
            claimed["trackingToken"],
            context["request"]["version"],
            self.owner_b,
        )
        self.assertEqual(refreshed["request"]["status"], "delivered")

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

    def test_deep_closure_requires_exact_four_worker_round(self):
        _workspace_id, scan_id = self._start("deep")
        deep = self._write_deep_brief(scan_id)
        self.assertEqual(deep["workersPerRound"], 4)
        self.assertEqual(
            deep["workerDescriptor"],
            "discovery-round-<1..10>-worker-<1..4>",
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=4,
            deep_review_pass=1,
            owner_session_hash=self.owner_a,
        )
        placeholder = self._deep_worker(deep, 1, 1, [])
        placeholder["threatModel"] = {}
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-1",
                placeholder,
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")
        wrong_input = self._deep_worker(deep, 1, 1, [])
        wrong_input["inputDigest"] = "0" * 64
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-1",
                wrong_input,
            )
        self.assertEqual(raised.exception.code, "deep_worker_input_mismatch")
        missing_receipt = self._deep_worker(deep, 1, 1, [])
        missing_receipt["coverage"]["receipts"] = []
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-1",
                missing_receipt,
            )
        self.assertEqual(raised.exception.code, "deep_worker_incomplete")
        for worker in range(1, 4):
            self._write(
                scan_id,
                "discovery-round-1-worker-%d" % worker,
                self._deep_worker(deep, 1, worker, []),
            )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertNotIn(
            "discovery-round-<1..10>-merge",
            contract["descriptorSchemas"],
        )
        self.assertNotIn("discovery", contract["descriptorSchemas"])
        self.assertNotIn("threat-model", contract["descriptorSchemas"])
        self.assertEqual(contract["phaseContract"]["allowedNextPhases"], [])
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-merge",
                {
                    "round": 1,
                    "mergedCandidateIds": [],
                    "newCanonicalCandidateCount": 0,
                    "lineage": [],
                },
            )
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery",
                {
                    "candidates": [],
                    "roundsCompleted": 1,
                    "termination": "saturated",
                },
            )
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "threat-model",
                {"summary": "Canonical post-discovery threat model."},
            )
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")
        mismatched_worker = self._deep_worker(deep, 1, 4, [])
        mismatched_worker["worker"] = 3
        with self.assertRaisesRegex(WorkbenchError, "must match"):
            self._write(
                scan_id,
                "discovery-round-1-worker-4",
                mismatched_worker,
            )
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-5",
                self._deep_worker(deep, 1, 5, []),
            )
        self.assertEqual(raised.exception.code, "invalid_artifact_descriptor")
        self._write(
            scan_id,
            "discovery-round-1-worker-4",
            self._deep_worker(deep, 1, 4, []),
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertIn(
            "discovery-round-<1..10>-merge",
            contract["descriptorSchemas"],
        )
        self.assertNotIn("discovery", contract["descriptorSchemas"])
        self._write(
            scan_id,
            "discovery-round-1-merge",
            {
                "round": 1,
                "mergedCandidateIds": [],
                "newCanonicalCandidateCount": 0,
                "lineage": [],
            },
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(set(contract["descriptorSchemas"]), {"discovery"})
        self.assertEqual(contract["phaseContract"]["allowedNextPhases"], [])
        self._write(
            scan_id,
            "discovery",
            {
                "candidates": [],
                "roundsCompleted": 1,
                "termination": "saturated",
            },
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(set(contract["descriptorSchemas"]), {"threat-model"})
        self.assertEqual(contract["phaseContract"]["allowedNextPhases"], [])
        threat_model = self._write(
            scan_id,
            "threat-model",
            {"summary": "Canonical post-discovery threat model."},
        )
        corrected = self.workbench.write_scan_artifact(
            scan_id,
            "threat-model",
            {
                "scanId": scan_id,
                "summary": "Corrected canonical post-discovery threat model.",
            },
            expected_digest=threat_model["artifact"]["digest"],
            owner_session_hash=self.owner_a,
        )
        for descriptor, content in (
            (
                "discovery-round-1-worker-1",
                dict(
                    {"scanId": scan_id},
                    **self._deep_worker(deep, 1, 1, []),
                ),
            ),
            (
                "discovery-round-1-merge",
                {
                    "scanId": scan_id,
                    "round": 1,
                    "mergedCandidateIds": [],
                    "newCanonicalCandidateCount": 0,
                    "lineage": [],
                },
            ),
            (
                "discovery",
                {
                    "scanId": scan_id,
                    "candidates": [],
                    "roundsCompleted": 1,
                    "termination": "saturated",
                },
            ),
        ):
            with self.assertRaises(WorkbenchError) as raised:
                self.workbench.write_scan_artifact(
                    scan_id,
                    descriptor,
                    content,
                    owner_session_hash=self.owner_a,
                )
            self.assertEqual(raised.exception.code, "artifact_phase_not_active")
        self.workbench.update_scan_progress(
            scan_id,
            review_items_completed=4,
            owner_session_hash=self.owner_a,
        )
        reporting = self.workbench.update_scan_progress(
            scan_id,
            phase="reporting",
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(reporting["phase"], "reporting")
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "threat-model",
                {
                    "scanId": scan_id,
                    "summary": "Late threat model rewrite.",
                },
                expected_digest=corrected["artifact"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "artifact_phase_not_active")
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertNotIn("validation", contract["requiredDescriptors"])
        self.assertNotIn("attack-path", contract["requiredDescriptors"])
        self.assertEqual(contract["phaseContract"]["phase"], "reporting")
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

    def test_deep_candidates_enter_validation_after_terminal_discovery(self):
        _workspace_id, scan_id = self._start("deep")
        deep = self._write_deep_brief(scan_id)
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=4,
            review_items_completed=4,
            deep_review_pass=1,
            owner_session_hash=self.owner_a,
        )
        for round_number in (1, 2):
            if round_number == 2:
                self.workbench.update_scan_progress(
                    scan_id,
                    review_items_total=4,
                    review_items_completed=4,
                    deep_review_pass=2,
                    owner_session_hash=self.owner_a,
                )
            for worker in range(1, 5):
                self._write(
                    scan_id,
                    "discovery-round-%d-worker-%d"
                    % (round_number, worker),
                    self._deep_worker(
                        deep,
                        round_number,
                        worker,
                        [{"id": "candidate-1"}],
                    ),
                )
            if round_number == 1:
                with self.assertRaises(WorkbenchError) as raised:
                    self._write(
                        scan_id,
                        "discovery-round-1-merge",
                        {
                            "round": 1,
                            "mergedCandidateIds": ["candidate-2"],
                            "newCanonicalCandidateCount": 1,
                            "lineage": self._deep_lineage("candidate-1"),
                        },
                    )
                self.assertEqual(raised.exception.code, "deep_merge_mismatch")
                with self.assertRaises(WorkbenchError) as raised:
                    self._write(
                        scan_id,
                        "discovery-round-1-merge",
                        {
                            "round": 1,
                            "mergedCandidateIds": [],
                            "newCanonicalCandidateCount": 0,
                            "lineage": [],
                        },
                    )
                self.assertEqual(raised.exception.code, "deep_merge_mismatch")
            self._write(
                scan_id,
                "discovery-round-%d-merge" % round_number,
                {
                    "round": round_number,
                    "mergedCandidateIds": ["candidate-1"],
                    "newCanonicalCandidateCount": (
                        1 if round_number == 1 else 0
                    ),
                    "lineage": self._deep_lineage("candidate-1"),
                },
            )
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery",
                {
                    "candidates": [],
                    "roundsCompleted": 2,
                    "termination": "saturated",
                },
            )
        self.assertEqual(raised.exception.code, "deep_terminal_mismatch")
        self._write(
            scan_id,
            "discovery",
            {
                "candidates": [{"id": "candidate-1"}],
                "roundsCompleted": 2,
                "termination": "saturated",
            },
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(contract["phaseContract"]["allowedNextPhases"], [])
        self._write(
            scan_id,
            "threat-model",
            {"summary": "Canonical post-discovery threat model."},
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(
            contract["phaseContract"]["allowedNextPhases"],
            ["validation"],
        )
        validation = self.workbench.update_scan_progress(
            scan_id,
            phase="validation",
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(validation["phase"], "validation")

    def test_deep_checkpoint_is_durable_but_never_a_merge_input(self):
        _workspace_id, scan_id = self._start("deep")
        deep = self._write_deep_brief(scan_id)
        self.assertEqual(
            deep["checkpointDescriptor"],
            "discovery-round-<1..10>-worker-<1..4>-checkpoint",
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=4,
            deep_review_pass=1,
            owner_session_hash=self.owner_a,
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertIn(
            deep["checkpointDescriptor"],
            contract["descriptorSchemas"],
        )

        empty_partial = self._deep_checkpoint(deep, 1, 1)
        empty_partial["partial"] = {}
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                empty_partial,
            )
        self.assertEqual(raised.exception.code, "invalid_artifact")

        foreign_receipt = self._deep_checkpoint(deep, 1, 1)
        foreign_receipt["partial"]["coverage"]["receipts"] = [
            {
                "worklistId": "not-in-worklist",
                "disposition": "reviewed",
                "evidence": ["outside.py"],
            }
        ]
        with self.assertRaises(WorkbenchError) as raised:
            self._write(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                foreign_receipt,
            )
        self.assertEqual(raised.exception.code, "deep_worker_input_mismatch")

        checkpoint = self._deep_checkpoint(deep, 1, 1)
        checkpoint["partial"]["candidates"] = [
            {"id": "checkpoint-only-candidate"}
        ]
        written = self._write(
            scan_id,
            "discovery-round-1-worker-1-checkpoint",
            checkpoint,
        )
        checkpoint_path = Path(written["artifact"]["path"])
        self.assertEqual(
            json.loads(checkpoint_path.read_text(encoding="utf-8"))["attempt"],
            1,
        )

        failed = self._deep_checkpoint(deep, 1, 1, status="failed")
        failed["partial"]["candidates"] = [
            {"id": "checkpoint-only-candidate"}
        ]
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                {"scanId": scan_id, **failed},
                expected_digest="0" * 64,
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "artifact_changed")
        failed_write = self.workbench.write_scan_artifact(
            scan_id,
            "discovery-round-1-worker-1-checkpoint",
            {"scanId": scan_id, **failed},
            expected_digest=written["artifact"]["digest"],
            owner_session_hash=self.owner_a,
        )

        skipped_attempt = self._deep_checkpoint(deep, 1, 1, attempt=3)
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                {"scanId": scan_id, **skipped_attempt},
                expected_digest=failed_write["artifact"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(
            raised.exception.code,
            "deep_checkpoint_attempt_invalid",
        )

        retry = self._deep_checkpoint(deep, 1, 1, attempt=2)
        retry["partial"]["candidates"] = [
            {"id": "checkpoint-only-candidate"}
        ]
        retry_write = self.workbench.write_scan_artifact(
            scan_id,
            "discovery-round-1-worker-1-checkpoint",
            {"scanId": scan_id, **retry},
            expected_digest=failed_write["artifact"]["digest"],
            owner_session_hash=self.owner_a,
        )
        complete = self._write(
            scan_id,
            "discovery-round-1-worker-1",
            self._deep_worker(deep, 1, 1, []),
        )
        repeated = self._write(
            scan_id,
            "discovery-round-1-worker-1",
            self._deep_worker(deep, 1, 1, []),
        )
        self.assertEqual(
            repeated["artifact"]["digest"],
            complete["artifact"]["digest"],
        )

        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                {"scanId": scan_id, **retry},
                expected_digest=retry_write["artifact"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "deep_worker_closed")

        changed_worker = self._deep_worker(
            deep,
            1,
            1,
            [{"id": "checkpoint-only-candidate"}],
        )
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.write_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1",
                {"scanId": scan_id, **changed_worker},
                expected_digest=complete["artifact"]["digest"],
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "deep_worker_closed")

        for worker in range(2, 5):
            self._write(
                scan_id,
                "discovery-round-1-worker-%d" % worker,
                self._deep_worker(deep, 1, worker, []),
            )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertNotIn(
            deep["checkpointDescriptor"],
            contract["descriptorSchemas"],
        )
        self.assertIn(
            "discovery-round-<1..10>-merge",
            contract["descriptorSchemas"],
        )
        self._write(
            scan_id,
            "discovery-round-1-merge",
            {
                "round": 1,
                "mergedCandidateIds": [],
                "newCanonicalCandidateCount": 0,
                "lineage": [],
            },
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(set(contract["descriptorSchemas"]), {"discovery"})
        self.assertIn(
            "discovery-round-1-worker-1-checkpoint",
            {item["descriptor"] for item in contract["persisted"]},
        )
        self._write(
            scan_id,
            "discovery",
            {
                "candidates": [],
                "roundsCompleted": 1,
                "termination": "saturated",
            },
        )
        self._write(
            scan_id,
            "threat-model",
            {"summary": "Canonical post-discovery threat model."},
        )
        contract = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )
        self.assertEqual(contract["closure"]["deep"]["missing"], [])
        self.assertFalse(
            any(
                "checkpoint" in descriptor
                for descriptor in contract["requiredDescriptors"]
            )
        )

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

    def test_phase_contracts_preserve_complete_current_phase_rules(self):
        def contract(phase, mode="standard"):
            return build_phase_contract(
                {
                    "id": "scan-contract-test",
                    "status": "running",
                    "mode": mode,
                    "phase": phase,
                },
                (),
            )

        preflight = str(contract("preflight"))
        self.assertIn("blocked when a blocking requirement is absent", preflight)
        self.assertIn("incomplete when a required fact", preflight)
        self.assertIn("ready only when", preflight)
        self.assertNotIn("impact=high", preflight)

        threat_model = str(contract("threat_model"))
        self.assertIn("repository or authoritative target as a whole", threat_model)
        self.assertIn("sole source of truth", threat_model)
        self.assertNotIn("full-file receipt", threat_model)

        standard = str(contract("discovery"))
        self.assertIn("tightly coupled shard of at most five files", standard)
        self.assertIn("immutable pool plan of at most six slots", standard)
        self.assertIn("Never describe that path as exhaustive coverage", standard)
        self.assertNotIn("impact=high", standard)

        diff = str(contract("discovery", mode="diff"))
        self.assertIn("Anchor every candidate to changed behavior", diff)
        self.assertIn("Do not broaden into a repository-wide audit", diff)
        self.assertNotIn("four usable outputs", diff)

        deep = str(contract("discovery", mode="deep"))
        self.assertIn("exactly four usable workers", deep)
        self.assertIn("Retry or replace only the failed or missing worker slot", deep)
        self.assertIn("latest checkpoint with expectedDigest CAS", deep)
        self.assertIn("checkpoints never contribute to lineage", deep)
        self.assertIn("cannot produce four usable outputs", deep)
        self.assertIn("Never shrink the round", deep)
        self.assertNotIn("impact=high", deep)

        validation = str(contract("validation"))
        self.assertIn(
            "crashing PoC; Valgrind or ASan; non-interactive debugger trace; "
            "focused unit or integration test; realistic-interface reproduction; "
            "source-based static trace",
            validation,
        )
        self.assertIn("strongest counterevidence", validation)
        self.assertIn("every expanded child instance exactly once inside", validation)
        self.assertNotIn("critical -> P0", validation)

        attack_path = str(contract("attack_path"))
        self.assertIn("Apply hard suppression before the matrix", attack_path)
        self.assertIn(
            "impact=high with likelihood high -> critical only when", attack_path
        )
        self.assertIn(
            "Matrix row impact=unknown: likelihood high -> medium; medium -> low; "
            "low -> ignore; ignore -> ignore; unknown -> low",
            attack_path,
        )
        self.assertIn("critical -> P0, high -> P1, medium -> P2", attack_path)
        self.assertIn("Never assign priority to ignore", attack_path)
        self.assertNotIn("new dedicated worker", attack_path)

        reporting = str(contract("reporting"))
        self.assertIn("exactly one dedicated writeup worker", reporting)
        self.assertIn("new dedicated worker", reporting)
        self.assertIn("retry once", reporting)
        self.assertIn("leave reporting unclosed", reporting)
        self.assertIn("exactly one collection-wide", reporting)
        self.assertIn("report.md exists", reporting)
        self.assertNotIn("Matrix row impact=unknown", reporting)


if __name__ == "__main__":
    unittest.main()
