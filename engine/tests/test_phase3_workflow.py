"""End-to-end semantic completion and follow-up lifecycle coverage."""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path

from kiro_security.errors import WorkbenchError
from kiro_security.models import WorkspaceSetup
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

    def _complete(self, with_finding=True):
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
        self._write(
            scan_id,
            "derived-writeup",
            {
                "outputs": (
                    [
                        {
                            "path": "findings/untrusted-execution/untrusted-execution.md",
                            "markdown": "# Untrusted execution\n",
                        }
                    ]
                    if with_finding
                    else []
                )
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
        return scan_id, self.workbench.complete_scan(scan_id, self.owner_a)

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

    def test_deep_closure_requires_exact_six_worker_round(self):
        _workspace_id, scan_id = self._start("deep")
        self._write(
            scan_id,
            "brief",
            {"mode": "deep", "target": str(self.target), "scope": "."},
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="threat_model",
            owner_session_hash=self.owner_a,
        )
        self._write(
            scan_id,
            "threat-model",
            {"summary": "Deep threat model."},
        )
        self.workbench.update_scan_progress(
            scan_id,
            phase="discovery",
            review_items_total=6,
            deep_review_pass=1,
            owner_session_hash=self.owner_a,
        )
        for worker in range(1, 6):
            self._write(
                scan_id,
                "discovery-round-1-worker-%d" % worker,
                {
                    "round": 1,
                    "worker": worker,
                    "candidates": [],
                    "coverage": {"closed": True},
                },
            )
        self._write(
            scan_id,
            "discovery-round-1-merge",
            {
                "round": 1,
                "mergedCandidateIds": [],
                "newCanonicalCandidateCount": 0,
            },
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
        closure = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )["closure"]
        self.assertIn("discovery-round-1-worker-6", closure["missing"])
        with self.assertRaisesRegex(WorkbenchError, "must match"):
            self._write(
                scan_id,
                "discovery-round-1-worker-6",
                {
                    "round": 1,
                    "worker": 5,
                    "candidates": [],
                    "coverage": {"closed": True},
                },
            )
        self._write(
            scan_id,
            "discovery-round-1-worker-6",
            {
                "round": 1,
                "worker": 6,
                "candidates": [],
                "coverage": {"closed": True},
            },
        )
        closure = self.workbench.get_scan_artifact_contract(
            scan_id,
            self.owner_a,
        )["closure"]
        self.assertNotIn("discovery-round-1-worker-6", closure["missing"])

    def test_phase_skip_and_unclosed_coverage_are_rejected(self):
        _workspace_id, scan_id = self._start()
        self._write(
            scan_id,
            "brief",
            {"mode": "standard", "target": str(self.target), "scope": "."},
        )
        with self.assertRaisesRegex(WorkbenchError, "one semantic phase"):
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


if __name__ == "__main__":
    unittest.main()
