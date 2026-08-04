"""Recovery ownership, remediation, triage, and tracking coverage."""

import hashlib
import subprocess
import threading
import unittest
from pathlib import Path

from workflow_test_support import WorkflowTestCase
from kiro_security.errors import WorkbenchError


class RecoveryFollowupWorkflowTests(WorkflowTestCase):
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
        changed = self.workbench.remediation_integrity.portable_tree_digest(
            self.target
        )
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
        applied_digest = self.workbench.remediation_integrity.portable_tree_digest(
            self.target
        )
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
        verify_request = self.workbench.request_finding_remediation(
            occurrence_id,
            "verify",
            requested["requestId"],
        )
        verify_claim = self.workbench.claim_remediation_action(
            requested["requestId"],
            verify_request["version"],
            self.owner_b,
        )
        verify_context = self.workbench.get_remediation_context(
            requested["requestId"],
            verify_claim["actionToken"],
            verify_claim["version"],
            self.owner_b,
        )
        verified = self.workbench.set_finding_remediation(
            occurrence_id,
            requested["requestId"],
            verify_context["request"]["version"],
            verify_claim["actionToken"],
            "verified",
            verification_summary="Focused verification passed.",
            owner_session_hash=self.owner_b,
        )
        self.assertEqual(verified["state"], "verified")
        fixed = self.workbench.set_finding_triage(
            occurrence_id,
            "closed",
            "already_fixed",
        )
        self.assertEqual(fixed["closeReason"], "already_fixed")

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


if __name__ == "__main__":
    unittest.main()
