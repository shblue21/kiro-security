"""Deep discovery round, worker, merge, and terminal-state coverage."""

import unittest

from workflow_test_support import WorkflowTestCase
from kiro_security.errors import WorkbenchError


class DeepWorkflowTests(WorkflowTestCase):
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


if __name__ == "__main__":
    unittest.main()
