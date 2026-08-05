"""Shared fixtures and artifact builders for workflow integration tests."""

import tempfile
import sys
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "engine"))

from kiro_security.models import WorkspaceSetup
from kiro_security.workbench import Workbench


class WorkflowTestCase(unittest.TestCase):
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
            "rootCause": {
                "summary": "Untrusted input reaches an execution boundary."
            },
            "remediation": "Validate input before the execution boundary.",
            "validation": {"summary": "Static validation confirmed the path."},
            "attackPath": {"summary": "Caller input reaches execute."},
            "provenance": {"source": "standard-scan"},
            "writeup": {
                "reportPath": "findings/untrusted-execution/untrusted-execution.md",
            },
        }
