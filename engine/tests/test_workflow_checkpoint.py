"""Deep worker checkpoint durability and merge-isolation coverage."""

import json
import unittest
from pathlib import Path

from workflow_test_support import WorkflowTestCase
from kiro_security.errors import WorkbenchError


class DeepCheckpointTests(WorkflowTestCase):
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
        readback = self.workbench.read_scan_artifact(
            scan_id,
            "discovery-round-1-worker-1-checkpoint",
            written["artifact"]["digest"],
            owner_session_hash=self.owner_a,
        )
        self.assertEqual(readback["content"], {"scanId": scan_id, **checkpoint})
        self.assertEqual(
            readback["artifact"]["digest"],
            written["artifact"]["digest"],
        )
        self.assertNotIn("path", readback["artifact"])
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.read_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                written["artifact"]["digest"],
                owner_session_hash=self.owner_b,
            )
        self.assertEqual(raised.exception.code, "scan_not_owned")
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.read_scan_artifact(
                scan_id,
                "discovery-round-1-worker-1-checkpoint",
                "0" * 64,
                owner_session_hash=self.owner_a,
            )
        self.assertEqual(raised.exception.code, "artifact_changed")
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


if __name__ == "__main__":
    unittest.main()
