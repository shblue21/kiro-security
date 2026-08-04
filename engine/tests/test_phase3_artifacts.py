"""Canonical artifact and deterministic finalizer coverage."""

from __future__ import annotations

import copy
import csv
import hashlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from kiro_security.artifacts import (
    ArtifactContractError,
    canonical_json_bytes,
    derive_finding_identity,
    finalize_scan,
    verify_seal,
    write_csv_projection,
    write_sarif_projection,
)
from kiro_security.artifact_projections import build_findings_csv


class ArtifactFinalizerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        (self.root / "artifacts" / "03_coverage").mkdir(parents=True)
        (self.root / "artifacts" / "03_coverage" / "receipt.json").write_text(
            '{"closed":true}\n', encoding="utf-8"
        )
        self.scan_id = "scan_test_001"
        self.completed_at = "2026-07-30T10:00:00Z"
        self.manifest = {
            "documentType": "codex-security.scan-manifest",
            "schemaVersion": "1.0",
            "scan": {
                "id": self.scan_id,
                "producer": {"name": "Kiro Security", "version": "0.1.0"},
                "status": "completed",
                "startedAt": "2026-07-30T09:00:00Z",
                "completedAt": self.completed_at,
                "target": {
                    "kind": "git_worktree",
                    "targetId": "target_sha256_test",
                    "displayName": "Example <repo>",
                    "snapshotDigest": (
                        "codex-security-snapshot/v1:sha256:" + "a" * 64
                    ),
                },
                "scope": {
                    "includePaths": ["."],
                    "excludePaths": ["vendor"],
                    "summary": "Repository security review.",
                },
                "threatModel": {
                    "summary": "Untrusted input crosses an API boundary.",
                    "assets": ["credentials"],
                    "trustBoundaries": ["HTTP API"],
                },
                "coverageRef": "coverage.json",
                "findingsRef": "findings.json",
            },
        }
        self.finding = {
            "ruleId": "python.command-injection",
            "identity": {
                "anchor": "src.handler.run_command",
                "instance": "shell-path",
            },
            "title": "=Untrusted command reaches shell",
            "summary": "A request value can reach a shell invocation.",
            "severity": {
                "level": "high",
                "score": 8.1,
                "scoringSystem": "CVSS:3.1",
                "rationale": "Remote code execution is plausible.",
            },
            "confidence": {
                "level": "high",
                "rationale": "The source-to-sink path is direct.",
            },
            "taxonomy": {"category": "injection", "cwe": ["CWE-78"]},
            "locations": [
                {
                    "path": "src/handler.py",
                    "startLine": 12,
                    "endLine": 14,
                    "role": "root_control",
                },
                {"path": "src/shell.py", "startLine": 8, "role": "sink"},
            ],
            "remediation": "Use an argv-based subprocess API.",
            "validation": {"summary": "Static validation confirmed the flow."},
            "attackPath": {"summary": "HTTP input reaches the subprocess sink."},
            "provenance": {"source": "standard-scan"},
            "extensions": {"candidateId": "candidate-1"},
        }
        self.findings = {
            "documentType": "codex-security.findings",
            "schemaVersion": "1.0",
            "scanId": self.scan_id,
            "findings": [self.finding],
        }
        self.coverage = {
            "documentType": "codex-security.coverage",
            "schemaVersion": "1.0",
            "scanId": self.scan_id,
            "mode": "repository",
            "completeness": "complete",
            "inventoryStrategy": "repository",
            "includePaths": ["."],
            "excludePaths": ["vendor"],
            "surfaces": [
                {
                    "id": "api",
                    "label": "HTTP API",
                    "disposition": "reported",
                    "receiptRefs": ["artifacts/03_coverage/receipt.json"],
                    "riskArea": "command execution",
                }
            ],
            "explicitExclusions": [
                {"pattern": "vendor", "reason": "third-party code"}
            ],
            "deferred": [],
        }
        self._write_inputs()

    def tearDown(self):
        self.temporary.cleanup()

    def _write_inputs(self):
        (self.root / "scan-manifest.json").write_bytes(
            canonical_json_bytes(self.manifest)
        )
        (self.root / "findings.json").write_bytes(
            canonical_json_bytes(self.findings)
        )
        (self.root / "coverage.json").write_bytes(
            canonical_json_bytes(self.coverage)
        )

    def test_finalizes_seals_projects_and_retries_idempotently(self):
        result = finalize_scan(self.root, expected_coverage_mode="repository")
        self.assertFalse(result.reused_seal)
        self.assertEqual(result.manifest["scan"]["sealedAt"], self.completed_at)
        self.assertRegex(
            result.findings["findings"][0]["findingId"], r"^csf_[a-f0-9]{24}$"
        )
        self.assertRegex(
            result.findings["findings"][0]["occurrenceId"], r"^occ_[a-f0-9]{24}$"
        )
        self.assertEqual(
            result.manifest_digest,
            "sha256:"
            + hashlib.sha256(
                (self.root / "scan-manifest.json").read_bytes()
            ).hexdigest(),
        )
        artifact_paths = {
            item["path"] for item in result.manifest["scan"]["artifacts"]
        }
        self.assertEqual(
            artifact_paths,
            {
                "findings.json",
                "coverage.json",
                "artifacts/03_coverage/receipt.json",
            },
        )
        report = (self.root / "report.md").read_text(encoding="utf-8")
        self.assertIn("# Security Review: Example \\<repo\\>", report)
        self.assertIn("python.command-injection", json.dumps(result.findings))
        self.assertTrue((self.root / "exports" / "results.sarif").is_file())

        sealed_manifest = (self.root / "scan-manifest.json").read_bytes()
        sealed_findings = (self.root / "findings.json").read_bytes()
        sealed_coverage = (self.root / "coverage.json").read_bytes()
        (self.root / "report.md").write_text("corrupt projection", encoding="utf-8")
        (self.root / "exports" / "results.sarif").unlink()
        retry = finalize_scan(self.root)
        self.assertTrue(retry.reused_seal)
        self.assertEqual(
            (self.root / "scan-manifest.json").read_bytes(), sealed_manifest
        )
        self.assertEqual((self.root / "findings.json").read_bytes(), sealed_findings)
        self.assertEqual((self.root / "coverage.json").read_bytes(), sealed_coverage)
        self.assertNotEqual(
            (self.root / "report.md").read_text(encoding="utf-8"),
            "corrupt projection",
        )
        self.assertTrue((self.root / "exports" / "results.sarif").is_file())
        self.assertFalse(list(self.root.rglob("*.tmp")))

    def test_stable_finding_identity_and_scan_local_occurrence_identity(self):
        first = derive_finding_identity(
            "target-a", "scan-a", copy.deepcopy(self.finding)
        )
        second = derive_finding_identity(
            "target-a", "scan-b", copy.deepcopy(self.finding)
        )
        other_target = derive_finding_identity(
            "target-b", "scan-a", copy.deepcopy(self.finding)
        )
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertNotEqual(first.occurrence_id, second.occurrence_id)
        self.assertNotEqual(first.finding_id, other_target.finding_id)

    def test_rejects_duplicate_semantic_finding_without_instance(self):
        duplicate = copy.deepcopy(self.finding)
        self.findings["findings"].append(duplicate)
        self._write_inputs()
        with self.assertRaisesRegex(
            ArtifactContractError, "duplicate occurrence identity"
        ):
            finalize_scan(self.root)

    def test_rejects_complete_coverage_with_deferred_work(self):
        self.coverage["deferred"] = [
            {"id": "deferred-1", "reason": "runtime unavailable"}
        ]
        self._write_inputs()
        with self.assertRaisesRegex(
            ArtifactContractError, "complete coverage cannot have deferred"
        ):
            finalize_scan(self.root)

    def test_rejects_receipt_escape_and_symlink(self):
        self.coverage["surfaces"][0]["receiptRefs"] = ["artifacts/../outside.json"]
        self._write_inputs()
        with self.assertRaisesRegex(ArtifactContractError, "safe relative POSIX path"):
            finalize_scan(self.root)

        self.coverage["surfaces"][0]["receiptRefs"] = [
            "artifacts/03_coverage/receipt-link.json"
        ]
        os.symlink(
            self.root / "artifacts" / "03_coverage" / "receipt.json",
            self.root / "artifacts" / "03_coverage" / "receipt-link.json",
        )
        self._write_inputs()
        with self.assertRaisesRegex(ArtifactContractError, "missing or unsafe"):
            finalize_scan(self.root)

    def test_rejects_writeup_reference_that_is_missing(self):
        self.finding["writeup"] = {
            "reportPath": "findings/command-injection/command-injection.md"
        }
        self._write_inputs()
        with self.assertRaisesRegex(ArtifactContractError, "missing or unsafe"):
            finalize_scan(self.root)

    def test_seal_detects_canonical_or_receipt_tampering(self):
        finalize_scan(self.root)
        (self.root / "artifacts" / "03_coverage" / "receipt.json").write_text(
            '{"closed":false}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(ArtifactContractError, "sealed artifact changed"):
            verify_seal(self.root)

    def test_explicit_sarif_and_csv_exports_are_deterministic(self):
        result = finalize_scan(self.root)
        sarif_path = write_sarif_projection(self.root)
        sarif_first = sarif_path.read_bytes()
        self.assertEqual(write_sarif_projection(self.root).read_bytes(), sarif_first)
        sarif = json.loads(sarif_first)
        sarif_result = sarif["runs"][0]["results"][0]
        self.assertEqual(sarif_result["level"], "error")
        self.assertEqual(
            sarif_result["partialFingerprints"]["codexSecurity/v1"],
            result.findings["findings"][0]["fingerprints"]["primary"],
        )

        occurrence_id = result.findings["findings"][0]["occurrenceId"]
        triage = {
            occurrence_id: {
                "status": "closed",
                "closeReason": "wont_fix",
                "note": "=Accepted risk",
            }
        }
        csv_path = write_csv_projection(self.root, triage)
        first = csv_path.read_bytes()
        self.assertEqual(write_csv_projection(self.root, triage).read_bytes(), first)
        rows = list(csv.DictReader(io.StringIO(first.decode("utf-8"))))
        self.assertEqual(rows[0]["status"], "closed")
        self.assertEqual(rows[0]["close_reason"], "wont_fix")
        self.assertEqual(rows[0]["note"], "'=Accepted risk")
        self.assertEqual(rows[0]["title"], "'=Untrusted command reaches shell")

    def test_csv_rejects_unknown_or_invalid_triage(self):
        result = finalize_scan(self.root)
        occurrence_id = result.findings["findings"][0]["occurrenceId"]
        with self.assertRaisesRegex(
            ArtifactContractError, "unknown occurrences"
        ):
            build_findings_csv(result.findings, {"occ_unknown": {"status": "open"}})
        with self.assertRaisesRegex(ArtifactContractError, "requires a note"):
            build_findings_csv(
                result.findings,
                {
                    occurrence_id: {
                        "status": "closed",
                        "closeReason": "wont_fix",
                    }
                },
            )

    def test_rejects_non_finite_json(self):
        raw = (self.root / "findings.json").read_text(encoding="utf-8")
        payload = json.loads(raw)
        payload["findings"][0]["severity"]["score"] = float("nan")
        (self.root / "findings.json").write_text(
            json.dumps(payload, allow_nan=True), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            ArtifactContractError, "non-finite JSON number"
        ):
            finalize_scan(self.root)


if __name__ == "__main__":
    unittest.main()
