"""Stdlib adversarial smoke tests for the Skill-owned model-scan contract.

These tests deliberately author only coordinator artifacts.  They never call a
repository scanner or semantic validator: the direct Codex-contract finalizer
is the only Python component that derives identities, projections, and seals.
Run directly when pytest is unavailable:

    PYTHONPATH=engine python3 engine/tests/test_integration.py
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any

import kiro_security.model as model
import kiro_security.service as service_module
from kiro_security.codex_contract import completion_lock
from kiro_security.errors import EngineError
from kiro_security.service import SecurityService


def _run_git(workspace: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", *args], cwd=workspace, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")


def _workspace(root: Path) -> Path:
    workspace = root / "workspace"
    (workspace / "src").mkdir(parents=True)
    (workspace / "src/app.py").write_text("def app(value):\n    return value\n", encoding="utf-8")
    _run_git(workspace, "init")
    _run_git(workspace, "config", "user.email", "security-test@example.invalid")
    _run_git(workspace, "config", "user.name", "Kiro Security Test")
    _run_git(workspace, "add", ".")
    _run_git(workspace, "commit", "-m", "fixture baseline")
    return workspace


def _service(workspace: Path) -> SecurityService:
    return SecurityService(str(workspace), "contract-smoke", lambda *_: None)


def _lease_params(scan: dict[str, Any]) -> dict[str, Any]:
    lease = scan.get("coordinatorLease")
    assert isinstance(lease, dict) and lease.get("state") == "acquired"
    assert isinstance(lease.get("token"), str) and len(lease["token"]) == 64
    assert isinstance(lease.get("generation"), int)
    return {
        "scanId": scan["id"],
        "coordinatorToken": lease["token"],
        "coordinatorGeneration": lease["generation"],
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _candidate_ledger(root: Path, candidate_id: str, rows: list[dict[str, Any]]) -> Path:
    path = root / "artifacts/05_findings" / candidate_id / "candidate_ledger.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    return path


def _write_bundle(
    service: SecurityService,
    scan: dict[str, Any],
    *,
    surfaces: list[dict[str, Any]],
    deferred: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
) -> Path:
    """Author the minimal semantic outputs a Power coordinator is allowed to author."""
    root = Path(scan["artifact_dir"])
    receipt = root / "artifacts/03_coverage/coverage.md"
    receipt.parent.mkdir(parents=True, exist_ok=True)
    receipt.write_text("# Coordinator coverage receipt\n", encoding="utf-8")
    context = service.get_scan_context({"scanId": scan["id"]})
    target = dict(context["target"])
    target.pop("root")
    deferred = deferred or []
    findings = findings or []
    completeness = "partial" if deferred or any(
        row["disposition"] == "needs_follow_up" for row in surfaces
    ) else "complete"
    coverage = {
        "documentType": "kiro-security-power.coverage",
        "schemaVersion": "1.0",
        "scanId": scan["id"],
        "mode": {"standard": "repository", "deep": "deep_repository", "diff": "working_tree"}[scan["mode"]],
        "completeness": completeness,
        "inventoryStrategy": "repository" if scan["mode"] != "diff" else "diff",
        "includePaths": [scan["scope"]],
        "excludePaths": [],
        "surfaces": surfaces,
        "explicitExclusions": [],
        "deferred": deferred,
    }
    manifest = {
        "documentType": "kiro-security-power.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": scan["id"],
            "producer": {"name": "kiro-security-power", "version": "0.3.0"},
            "status": "completed",
            "startedAt": scan["started_at"],
            "completedAt": scan["started_at"],
            "target": target,
            "scope": {"includePaths": [scan["scope"]], "excludePaths": [], "summary": "Skill-owned smoke scan."},
            "threatModel": {"summary": "Authored by the threat-model Skill."},
            "coverageRef": "coverage.json",
            "findingsRef": "findings.json",
        },
    }
    _write_json(root / "coverage.json", coverage)
    _write_json(root / "findings.json", {
        "documentType": "kiro-security-power.findings", "schemaVersion": "1.0",
        "scanId": scan["id"], "findings": findings,
    })
    _write_json(root / "scan-manifest.json", manifest)
    return root


def _surface(identifier: str, label: str, disposition: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "label": label,
        "disposition": disposition,
        "receiptRefs": ["artifacts/03_coverage/coverage.md"],
    }


def _reportable_finding() -> dict[str, Any]:
    return {
        "ruleId": "test.untrusted-input",
        "identity": {"anchor": "app-input", "instance": "direct"},
        "title": "Test finding",
        "summary": "A Skill-authored reportable finding used to exercise deterministic projection.",
        "severity": {"level": "high", "rationale": "Controlled test impact."},
        "confidence": {"level": "high", "rationale": "Controlled test evidence."},
        "taxonomy": {"category": "test", "cwe": ["CWE-20"]},
        "locations": [{"path": "src/app.py", "startLine": 1, "role": "root_control"}],
        "codeEvidence": [{
            "id": "ev.input", "label": "Test source", "path": "src/app.py", "startLine": 1,
            "role": "root_control", "code": "def app(value):", "explanation": "Controlled smoke evidence.",
        }],
        "rootCause": {"summary": "Controlled smoke root cause.", "evidenceRefs": ["ev.input"]},
        "remediation": "Use the safe test control.",
        "writeup": {"reportPath": "findings/test-finding/test-finding.md"},
        "provenance": {"source": "kiro-native-subagent"},
        "extensions": {"candidateId": "cand-reportable", "ledgerRowId": "file:src/app.py"},
    }


def test_standard_rank_input_is_not_premature_deep_input() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        service = _service(_workspace(Path(temporary)))
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            context = service.get_scan_context({"scanId": scan["id"]})
            row = json.loads(Path(context["inputs"]["rankInput"]).read_text(encoding="utf-8").splitlines()[0])
            assert set(row) == {"path", "area", "preview"}
            assert context["inputs"]["deepReviewInputReady"] is False
        finally:
            service.shutdown({})


def test_rejected_and_ignored_candidates_are_auditable_but_not_canonical() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        service = _service(_workspace(Path(temporary)))
        try:
            suppressed = service.start_scan({"mode": "standard", "scope": "."})
            root = _write_bundle(service, suppressed, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            ledger = _candidate_ledger(root, "cand-suppressed", [
                {"phase": "discovery", "disposition": "reportable", "candidateId": "cand-suppressed"},
                {"phase": "validation", "disposition": "suppressed", "candidateId": "cand-suppressed"},
            ])
            completed = service.complete_scan(_lease_params(suppressed))
            assert completed["status"] == "completed"
            assert json.loads((root / "findings.json").read_text(encoding="utf-8"))["findings"] == []
            assert '"suppressed"' in ledger.read_text(encoding="utf-8")

            ignored = service.start_scan({"mode": "standard", "scope": "."})
            root = _write_bundle(service, ignored, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            ledger = _candidate_ledger(root, "cand-ignored", [
                {"phase": "discovery", "disposition": "reportable", "candidateId": "cand-ignored"},
                {"phase": "validation", "disposition": "reportable", "candidateId": "cand-ignored"},
                {"phase": "attack_path", "disposition": "ignore", "candidateId": "cand-ignored"},
            ])
            assert service.complete_scan(_lease_params(ignored))["status"] == "completed"
            assert json.loads((root / "findings.json").read_text(encoding="utf-8"))["findings"] == []
            assert '"ignore"' in ledger.read_text(encoding="utf-8")
        finally:
            service.shutdown({})


def test_deferred_and_extra_security_coverage_complete_without_inventory_equality() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        service = _service(_workspace(Path(temporary)))
        try:
            scan = service.start_scan({"mode": "deep", "scope": "."})
            root = _write_bundle(
                service,
                scan,
                surfaces=[
                    _surface("file:src/app.py", "src/app.py", "rejected"),
                    _surface("seed:GHSA-demo", "Advisory seed GHSA-demo", "rejected"),
                    _surface("root-control:src/app.py:1", "Root control", "needs_follow_up"),
                ],
                deferred=[{"id": "root-control:src/app.py:1", "reason": "Need deployment evidence.", "paths": ["src/app.py"]}],
            )
            ledger = _candidate_ledger(root, "cand-deferred", [
                {"phase": "discovery", "disposition": "deferred", "candidateId": "cand-deferred"},
            ])
            completed = service.complete_scan(_lease_params(scan))
            assert completed["status"] == "completed"
            assert "Need deployment evidence." in (root / "report.md").read_text(encoding="utf-8")
            assert '"deferred"' in ledger.read_text(encoding="utf-8")
            assert json.loads((root / "exports/results.sarif").read_text(encoding="utf-8"))["version"] == "2.1.0"
        finally:
            service.shutdown({})


def test_canonical_finding_identity_report_sarif_and_seal_are_projected() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        service = _service(_workspace(Path(temporary)))
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            finding = _reportable_finding()
            root = _write_bundle(
                service, scan, surfaces=[_surface("file:src/app.py", "src/app.py", "reported")], findings=[finding],
            )
            writeup = root / "findings/test-finding/test-finding.md"
            writeup.parent.mkdir(parents=True, exist_ok=True)
            writeup.write_text("# Test finding\n", encoding="utf-8")
            portfolio = root / "hardening/hardening.md"
            portfolio.parent.mkdir(parents=True, exist_ok=True)
            portfolio.write_text("# Test hardening\n", encoding="utf-8")
            manifest_path = root / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["scan"]["hardening"] = {"portfolioPath": "hardening/hardening.md"}
            _write_json(manifest_path, manifest)

            completed = service.complete_scan(_lease_params(scan))
            canonical = json.loads((root / "findings.json").read_text(encoding="utf-8"))["findings"][0]
            assert canonical["findingId"].startswith("kspf_")
            assert canonical["occurrenceId"].startswith("occ_")
            assert canonical["fingerprints"]["algorithm"] == "kiro-security/v1"
            assert service.list_findings({"scanId": scan["id"]})[0]["findingId"] == canonical["findingId"]
            sarif = json.loads((root / "exports/results.sarif").read_text(encoding="utf-8"))
            assert sarif["runs"][0]["results"][0]["partialFingerprints"]["kiroSecurity/v1"] == canonical["fingerprints"]["primary"]
            assert completed["sealed_manifest_digest"] == hashlib.sha256(
                (root / "scan-manifest.json").read_bytes()
            ).hexdigest()
        finally:
            service.shutdown({})


def test_manifest_completed_at_cannot_control_db_lifecycle_timestamps() -> None:
    future = "2099-12-31T23:59:59Z"
    with tempfile.TemporaryDirectory() as temporary:
        service = _service(_workspace(Path(temporary)))
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            root = _write_bundle(
                service,
                scan,
                surfaces=[_surface("file:src/app.py", "src/app.py", "reported")],
                findings=[_reportable_finding()],
            )
            writeup = root / "findings/test-finding/test-finding.md"
            writeup.parent.mkdir(parents=True, exist_ok=True)
            writeup.write_text("# Test finding\n", encoding="utf-8")
            manifest_path = root / "scan-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["scan"]["completedAt"] = future
            _write_json(manifest_path, manifest)

            completed = service.complete_scan(_lease_params(scan))
            assert completed["status"] == "completed"
            assert completed["completed_at"] != future
            assert json.loads(manifest_path.read_text(encoding="utf-8"))["scan"]["completedAt"] == future

            with sqlite3.connect(service.workbench.db_path) as connection:
                scan_row = connection.execute(
                    "SELECT workspace_id, completed_at, updated_at FROM scans WHERE id=?", (scan["id"],)
                ).fetchone()
                assert scan_row is not None
                workspace_id, timestamp, scan_updated_at = scan_row
                assert timestamp != future
                assert scan_updated_at == timestamp
                assert connection.execute(
                    "SELECT updated_at FROM scan_progress WHERE scan_id=?", (scan["id"],)
                ).fetchone() == (timestamp,)
                assert connection.execute(
                    "SELECT DISTINCT created_at FROM scan_artifacts WHERE scan_id=?", (scan["id"],)
                ).fetchall() == [(timestamp,)]
                assert connection.execute(
                    "SELECT created_at, updated_at FROM findings"
                ).fetchall() == [(timestamp, timestamp)]
                assert connection.execute(
                    "SELECT created_at, updated_at FROM finding_occurrences WHERE scan_id=?", (scan["id"],)
                ).fetchall() == [(timestamp, timestamp)]
                assert connection.execute(
                    "SELECT created_at FROM finding_evidence"
                ).fetchall() == [(timestamp,)]
                assert connection.execute(
                    "SELECT updated_at FROM workspaces WHERE id=?", (workspace_id,)
                ).fetchone() == (timestamp,)
        finally:
            service.shutdown({})


def test_commit_diff_requires_checked_out_clean_evidence_target() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        (workspace / "src/app.py").write_text("def app(value):\n    return value + 'commit'\n", encoding="utf-8")
        _run_git(workspace, "add", "src/app.py")
        _run_git(workspace, "commit", "-m", "target commit")
        service = _service(workspace)
        try:
            scan = service.start_scan({"mode": "diff", "scope": ".", "diffTargetKind": "commit"})
            context = service.get_scan_context({"scanId": scan["id"]})
            assert context["target"]["headRevision"] == scan["diff_head_revision"]
            assert service.cancel_scan(_lease_params(scan))["status"] == "cancelled"
            (workspace / "src/app.py").write_text("def app(value):\n    return value + 'drift'\n", encoding="utf-8")
            try:
                service.start_scan({"mode": "diff", "scope": ".", "diffTargetKind": "commit"})
            except EngineError as error:
                assert error.code == "diff_target_dirty"
            else:
                raise AssertionError("dirty commit target was accepted")
        finally:
            service.shutdown({})


def test_target_drift_fails_before_finalization_and_leaves_running_scan() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        service = _service(workspace)
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            _write_bundle(service, scan, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            source = workspace / "src/app.py"
            source.write_text(source.read_text(encoding="utf-8") + "# target drift\n", encoding="utf-8")
            try:
                service.complete_scan(_lease_params(scan))
            except EngineError as error:
                assert error.code == "target_changed"
            else:
                raise AssertionError("target drift was accepted")
            assert service.get_scan({"scanId": scan["id"]})["status"] == "running"
        finally:
            service.shutdown({})


def test_failed_scan_is_terminal_and_engine_shutdown_preserves_running_scan() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        service = _service(workspace)
        second = _service(workspace)
        service_closed = False
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            failed = service.fail_scan({**_lease_params(scan), "reason": "Unrecoverable test failure"})
            completed_at = failed["completed_at"]
            (workspace / "src/app.py").write_text("def app(value):\n    return 'drift'\n", encoding="utf-8")
            try:
                second.acquire_scan_coordinator({"scanId": scan["id"]})
            except EngineError as error:
                assert error.code == "scan_not_running"
            else:
                raise AssertionError("terminal failed scan acquired a coordinator lease")
            unchanged = service.get_scan({"scanId": scan["id"]})
            assert unchanged["status"] == "failed"
            assert unchanged["failure_code"] == "scan_failed"
            assert unchanged["failure_message"] == "Unrecoverable test failure"
            assert unchanged["completed_at"] == completed_at
            running = service.start_scan({"mode": "standard", "scope": "."})
            repeated = second.start_scan({"mode": "standard", "scope": "."})
            assert repeated["id"] == running["id"]
            assert repeated["coordinatorLease"]["state"] == "busy"
            try:
                second.update_scan_progress({
                    "scanId": running["id"], "coordinatorToken": "0" * 64,
                    "coordinatorGeneration": 1, "phasePercent": 10,
                })
            except EngineError as error:
                assert error.code == "coordinator_lease_invalid"
            else:
                raise AssertionError("a non-owner coordinator mutated scan progress")
            released = service.shutdown({})
            service_closed = True
            assert released == {"releasedCoordinatorLeaseScanIds": [running["id"]]}
            assert second.get_scan({"scanId": running["id"]})["status"] == "running"
            acquired = second.acquire_scan_coordinator({"scanId": running["id"]})
            progress = second.update_scan_progress({**_lease_params(acquired), "phasePercent": 25})
            assert progress["phase_percent"] == 25
        finally:
            if not service_closed:
                service.shutdown({})
            second.shutdown({})


def test_workspace_has_exactly_one_running_scan_across_starts() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second = _service(workspace)
        try:
            standard = first.start_scan({"mode": "standard", "scope": "."})
            running_id = standard["id"]
            repeated = second.start_scan({"mode": "standard", "scope": "."})
            assert repeated["id"] == running_id
            for incompatible in (
                {"mode": "deep", "scope": "."},
                {"mode": "standard", "scope": ".", "maxFiles": 1},
                {"mode": "standard", "scope": ".", "userContext": "different"},
            ):
                try:
                    second.start_scan(incompatible)
                except EngineError as error:
                    assert error.code == "scan_already_running"
                    assert error.data == {
                        "scanId": running_id,
                        "mode": "standard",
                        "scope": ".",
                        "diffTargetKind": None,
                    }
                else:
                    raise AssertionError(f"an incompatible start request reused the running scan: {incompatible}")
            with sqlite3.connect(first.workbench.db_path) as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM scans WHERE workspace_id=? AND status='running'",
                    (standard["workspace_id"],),
                ).fetchone() == (1,)
                assert connection.execute(
                    "SELECT active_scan_id FROM workspaces WHERE id=?", (standard["workspace_id"],)
                ).fetchone() == (running_id,)
                index_sql = connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND name='scans_one_running_per_workspace'"
                ).fetchone()
                assert index_sql is not None
                assert "WHERE status = 'running'" in index_sql[0]

            with first.workbench.transaction() as connection:
                connection.execute(
                    "UPDATE workspaces SET active_scan_id=NULL WHERE id=?", (standard["workspace_id"],)
                )
            try:
                second.start_scan({"mode": "standard", "scope": "."})
            except EngineError as error:
                assert error.code == "workspace_scan_invariant"
                assert error.data == {
                    "workspaceId": standard["workspace_id"],
                    "activeScanId": None,
                    "runningScanId": running_id,
                    "runningCount": 1,
                }
            else:
                raise AssertionError("an orphan running scan pointer was silently repaired or reused")
            for mutation in (
                lambda: second.acquire_scan_coordinator({"scanId": running_id}),
                lambda: first.update_scan_progress({**_lease_params(standard), "phasePercent": 33}),
                lambda: first.cancel_scan(_lease_params(standard)),
            ):
                try:
                    mutation()
                except EngineError as error:
                    assert error.code == "workspace_scan_invariant"
                else:
                    raise AssertionError("an orphan running scan remained mutable through its coordinator lease")
            with first.workbench.transaction() as connection:
                connection.execute(
                    "UPDATE workspaces SET active_scan_id=? WHERE id=?", (running_id, standard["workspace_id"])
                )

            assert first.cancel_scan(_lease_params(standard))["status"] == "cancelled"
            with sqlite3.connect(first.workbench.db_path) as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM scan_coordinator_leases WHERE scan_id=?", (running_id,)
                ).fetchone() == (0,)
            active = first.start_scan({"mode": "deep", "scope": "."})
            assert active["id"] != running_id

            try:
                with first.workbench.transaction() as connection:
                    connection.execute(
                        "UPDATE scans SET status='running' WHERE id=?", (running_id,)
                    )
            except sqlite3.IntegrityError:
                pass
            else:
                raise AssertionError("the partial unique index accepted a second running scan")
            assert first.cancel_scan(_lease_params(active))["status"] == "cancelled"
            with sqlite3.connect(first.workbench.db_path) as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM scans WHERE workspace_id=? AND status='running'",
                    (active["workspace_id"],),
                ).fetchone() == (0,)
                assert connection.execute(
                    "SELECT active_scan_id FROM workspaces WHERE id=?", (active["workspace_id"],)
                ).fetchone() == (None,)
        finally:
            second.shutdown({})
            first.shutdown({})


def test_running_scan_without_start_contract_fails_closed() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second = _service(workspace)
        first_closed = False
        try:
            scan = first.start_scan({"mode": "standard", "scope": "."})
            with first.workbench.transaction() as connection:
                capabilities = json.loads(connection.execute(
                    "SELECT capability_json FROM scans WHERE id=?", (scan["id"],)
                ).fetchone()[0])
                capabilities.pop("startContract")
                connection.execute(
                    "UPDATE scans SET capability_json=? WHERE id=?",
                    (json.dumps(capabilities, separators=(",", ":")), scan["id"]),
                )
            try:
                second.start_scan({"mode": "standard", "scope": "."})
            except EngineError as error:
                assert error.code == "legacy_scan_incompatible"
                assert error.data == {"scanId": scan["id"]}
            else:
                raise AssertionError("a running scan without startContract was reused")
            for mutation in (
                lambda: first.update_scan_progress({**_lease_params(scan), "phasePercent": 33}),
                lambda: first.fail_scan({**_lease_params(scan), "reason": "must fail closed"}),
            ):
                try:
                    mutation()
                except EngineError as error:
                    assert error.code == "legacy_scan_incompatible"
                else:
                    raise AssertionError("a running scan without startContract remained mutable")
            first.shutdown({})
            first_closed = True
            try:
                second.acquire_scan_coordinator({"scanId": scan["id"]})
            except EngineError as error:
                assert error.code == "legacy_scan_incompatible"
            else:
                raise AssertionError("a running scan without startContract issued a coordinator lease")
            assert second.get_scan({"scanId": scan["id"]})["status"] == "running"
            assert second.get_scan({"scanId": scan["id"]})["id"] == scan["id"]
        finally:
            second.shutdown({})
            if not first_closed:
                first.shutdown({})


def test_start_scan_never_combines_a_terminal_scan_with_available_lease_state() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second = _service(workspace)
        original_projection = second.workbench._scan_with_lease_state
        active_observed = threading.Event()
        release_projection = threading.Event()

        def controlled_projection(
            scan: dict[str, Any], *, connection: sqlite3.Connection | None = None
        ) -> dict[str, Any]:
            if connection is not None:
                active_observed.set()
                assert release_projection.wait(20)
            return original_projection(scan, connection=connection)

        second.workbench._scan_with_lease_state = controlled_projection
        try:
            scan = first.start_scan({"mode": "standard", "scope": "."})
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                repeated_start = executor.submit(
                    second.start_scan, {"mode": "standard", "scope": "."}
                )
                assert active_observed.wait(20)
                assert first.cancel_scan(_lease_params(scan))["status"] == "cancelled"
                release_projection.set()
                repeated = repeated_start.result(timeout=20)

            assert repeated["id"] == scan["id"]
            assert repeated["status"] == "running"
            assert repeated["coordinatorLease"]["state"] == "busy"
            assert second.get_scan({"scanId": scan["id"]})["status"] == "cancelled"
        finally:
            release_projection.set()
            second.workbench._scan_with_lease_state = original_projection
            second.shutdown({})
            first.shutdown({})


def test_coordinator_lease_generation_expiry_and_secret_projection() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second = _service(workspace)
        try:
            scan = first.start_scan({"mode": "standard", "scope": "."})
            original = _lease_params(scan)
            renewed = first.renew_scan_coordinator(original)
            next_generation = renewed["coordinatorLease"]["generation"]
            assert next_generation == original["coordinatorGeneration"] + 1
            current = {**original, "coordinatorGeneration": next_generation}
            try:
                first.update_scan_progress({**original, "phasePercent": 10})
            except EngineError as error:
                assert error.code == "coordinator_lease_invalid"
            else:
                raise AssertionError("a stale lease generation mutated progress")
            assert first.update_scan_progress({**current, "phasePercent": 20})["phase_percent"] == 20
            with first.workbench.transaction() as connection:
                stored = connection.execute(
                    "SELECT token_hash FROM scan_coordinator_leases WHERE scan_id=?", (scan["id"],)
                ).fetchone()[0]
                assert stored != original["coordinatorToken"]
                connection.execute(
                    "UPDATE scan_coordinator_leases SET expires_at='2000-01-01T00:00:00.000Z' WHERE scan_id=?",
                    (scan["id"],),
                )
            token_bytes = original["coordinatorToken"].encode("utf-8")
            for suffix in ("", "-wal", "-shm"):
                database_file = Path(f"{first.workbench.db_path}{suffix}")
                if database_file.is_file():
                    assert token_bytes not in database_file.read_bytes()
            assert original["coordinatorToken"] not in json.dumps(first.workbench.events_since(0))
            for artifact in Path(scan["artifact_dir"]).rglob("*"):
                if artifact.is_file() and not artifact.is_symlink():
                    assert token_bytes not in artifact.read_bytes()
            acquired = second.acquire_scan_coordinator({"scanId": scan["id"]})
            replacement = _lease_params(acquired)
            assert replacement["coordinatorGeneration"] > next_generation
            try:
                first.fail_scan({**current, "reason": "stale holder"})
            except EngineError as error:
                assert error.code == "coordinator_lease_invalid"
            else:
                raise AssertionError("an expired coordinator failed the scan")
            failed = second.fail_scan({**replacement, "reason": "terminal test"})
            assert failed["status"] == "failed"
            with sqlite3.connect(first.workbench.db_path) as connection:
                assert connection.execute(
                    "SELECT COUNT(*) FROM scan_coordinator_leases WHERE scan_id=?", (scan["id"],)
                ).fetchone() == (0,)
            projected = second.get_scan({"scanId": scan["id"]})
            assert "coordinatorLease" not in projected
            assert original["coordinatorToken"] not in json.dumps(projected)
        finally:
            second.shutdown({})
            first.shutdown({})


def test_expired_lease_takeover_is_single_winner() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        contenders = [_service(workspace), _service(workspace)]
        try:
            scan = first.start_scan({"mode": "standard", "scope": "."})
            with first.workbench.transaction() as connection:
                connection.execute(
                    "UPDATE scan_coordinator_leases SET expires_at='2000-01-01T00:00:00.000Z' WHERE scan_id=?",
                    (scan["id"],),
                )
            results: list[tuple[SecurityService, dict[str, Any]]] = []
            errors: list[EngineError] = []

            def acquire(candidate: SecurityService) -> tuple[SecurityService, dict[str, Any]]:
                return candidate, candidate.acquire_scan_coordinator({"scanId": scan["id"]})

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(acquire, candidate) for candidate in contenders
                ]
                for future in futures:
                    try:
                        results.append(future.result(timeout=20))
                    except EngineError as error:
                        errors.append(error)
            assert len(results) == 1
            winner_service, winner_scan = results[0]
            assert winner_scan["coordinatorLease"]["state"] == "acquired"
            assert [error.code for error in errors] == ["coordinator_busy"]
            winner = _lease_params(winner_scan)
            assert contenders[0].get_scan({"scanId": scan["id"]})["status"] == "running"
            assert winner_service.release_scan_coordinator(winner)["coordinatorLease"]["state"] == "released"
        finally:
            for contender in contenders:
                contender.shutdown({})
            first.shutdown({})


def test_integrity_reconciliation_never_rewrites_terminal_lifecycle() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        service = _service(workspace)
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            _write_bundle(service, scan, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            completed = service.complete_scan(_lease_params(scan))
            assert completed["status"] == "completed"
            with service.workbench.transaction() as connection:
                connection.execute(
                    "UPDATE scans SET sealed_manifest_digest=NULL WHERE id=?", (scan["id"],)
                )
            issues = service.workbench.reconcile_finalization_integrity()
            assert any(issue["code"] == "completed_scan_unsealed" for issue in issues)
            preserved = service.get_scan({"scanId": scan["id"]})
            assert preserved["status"] == "completed"
            assert preserved["failure_code"] is None
            assert preserved["completed_at"] == completed["completed_at"]
        finally:
            service.shutdown({})


def test_scan_setup_is_complete_before_running_publication() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second = _service(workspace)
        original_setup = service_module.setup_model_scan
        first_setup_entered = threading.Event()
        release_first_setup = threading.Event()
        call_lock = threading.Lock()
        calls = 0

        def controlled_setup(workbench: Any, draft: dict[str, Any]) -> dict[str, Any]:
            nonlocal calls
            with call_lock:
                calls += 1
                call_number = calls
            if call_number == 1:
                first_setup_entered.set()
                assert release_first_setup.wait(20)
            return original_setup(workbench, draft)

        service_module.setup_model_scan = controlled_setup
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                first_start = executor.submit(first.start_scan, {"mode": "standard", "scope": "."})
                assert first_setup_entered.wait(20)
                with sqlite3.connect(first.workbench.db_path) as connection:
                    assert connection.execute("SELECT COUNT(*) FROM scans WHERE status='running'").fetchone() == (0,)

                second_start = second.start_scan({"mode": "standard", "scope": "."})
                assert second_start["target_identity"]
                assert second_start["snapshot_digest"]
                assert {item["kind"] for item in second_start["artifacts"]} >= {"securityGuidance", "rankInput"}
                assert second.get_scan_context({"scanId": second_start["id"]})["target"]["targetId"]

                release_first_setup.set()
                first_result = first_start.result(timeout=20)
                assert first_result["id"] == second_start["id"]
                assert first_result["target_identity"] == second_start["target_identity"]
        finally:
            release_first_setup.set()
            service_module.setup_model_scan = original_setup
            second.shutdown({})
            first.shutdown({})


def test_failed_setup_never_publishes_a_scan() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        service = _service(workspace)
        original_setup = service_module.setup_model_scan

        def fail_setup(_workbench: Any, draft: dict[str, Any]) -> dict[str, Any]:
            Path(draft["artifact_dir"]).mkdir(parents=True, exist_ok=True)
            raise EngineError("controlled_setup_failure", "Controlled prepublication failure.")

        service_module.setup_model_scan = fail_setup
        try:
            try:
                service.start_scan({"mode": "standard", "scope": "."})
            except EngineError as error:
                assert error.code == "controlled_setup_failure"
            else:
                raise AssertionError("a controlled setup failure was accepted")
            with sqlite3.connect(service.workbench.db_path) as connection:
                assert connection.execute("SELECT COUNT(*) FROM scans").fetchone() == (0,)
                assert connection.execute("SELECT active_scan_id FROM workspaces").fetchone() == (None,)
            assert list(service.workbench.artifacts_dir.iterdir()) == []
        finally:
            service_module.setup_model_scan = original_setup
            service.shutdown({})


def test_post_finalize_target_mutation_cannot_commit_completion() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        service = _service(workspace)
        original_finalize = model._finalize
        source = workspace / "src/app.py"
        original_source = source.read_text(encoding="utf-8")
        try:
            scan = service.start_scan({"mode": "standard", "scope": "."})
            _write_bundle(service, scan, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            before_artifacts = service.get_scan({"scanId": scan["id"]})["artifacts"]

            def mutate_after_finalize(
                root: Path, current_scan: dict[str, Any], source_root: Path
            ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
                result = original_finalize(root, current_scan, source_root)
                source.write_text(original_source + "# post-finalize target mutation\n", encoding="utf-8")
                return result

            model._finalize = mutate_after_finalize
            try:
                service.complete_scan(_lease_params(scan))
            except EngineError as error:
                assert error.code == "target_changed"
            else:
                raise AssertionError("post-finalize target mutation committed completion")

            unchanged = service.get_scan({"scanId": scan["id"]})
            assert unchanged["status"] == "running"
            assert unchanged["completed_at"] is None
            assert unchanged["sealed_manifest_digest"] is None
            assert unchanged["coverage"] is None
            assert unchanged["artifacts"] == before_artifacts
            assert service.list_findings({"scanId": scan["id"]}) == []

            model._finalize = original_finalize
            source.write_text(original_source, encoding="utf-8")
            completed = service.complete_scan(_lease_params(scan))
            assert completed["status"] == "completed"
            assert completed["phase"] == "reporting"
            assert completed["sealed_manifest_digest"]
        finally:
            model._finalize = original_finalize
            service.shutdown({})


def test_concurrent_completion_requires_the_valid_coordinator_lease() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = _workspace(Path(temporary))
        first = _service(workspace)
        second: SecurityService | None = None
        try:
            scan = first.start_scan({"mode": "standard", "scope": "."})
            _write_bundle(first, scan, surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")])
            second = _service(workspace)

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                futures = [
                    executor.submit(first.complete_scan, _lease_params(scan)),
                    executor.submit(
                        second.complete_scan,
                        {"scanId": scan["id"], "coordinatorToken": "0" * 64, "coordinatorGeneration": 1},
                    ),
                ]
                results: list[dict[str, Any]] = []
                errors: list[EngineError] = []
                for future in futures:
                    try:
                        results.append(future.result(timeout=20))
                    except EngineError as error:
                        errors.append(error)

            assert [item["status"] for item in results] == ["completed"]
            assert len(errors) == 1
            assert errors[0].code in {"coordinator_lease_invalid", "scan_not_running"}
            canonical = first.get_scan({"scanId": scan["id"]})
            assert canonical["phase"] == "reporting"
            kinds = [artifact["kind"] for artifact in canonical["artifacts"]]
            assert len(kinds) == len(set(kinds))
            assert "manifest" in kinds
            assert "securityGuidance" not in kinds
            assert "rankInput" not in kinds
        finally:
            if second is not None:
                second.shutdown({})
            first.shutdown({})


def test_post_finalize_manifest_or_artifact_mutation_cannot_commit() -> None:
    for relative in ("coverage.json", "scan-manifest.json"):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = _workspace(Path(temporary))
            service = _service(workspace)
            original_finalize = model._finalize
            try:
                scan = service.start_scan({"mode": "standard", "scope": "."})
                root = _write_bundle(
                    service,
                    scan,
                    surfaces=[_surface("file:src/app.py", "src/app.py", "rejected")],
                )

                def mutate_publication_after_finalize(
                    artifact_root: Path, current_scan: dict[str, Any], source_root: Path
                ) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
                    result = original_finalize(artifact_root, current_scan, source_root)
                    path = root / relative
                    path.write_bytes(path.read_bytes() + b"\n")
                    return result

                model._finalize = mutate_publication_after_finalize
                try:
                    service.complete_scan(_lease_params(scan))
                except EngineError as error:
                    assert error.code == "canonical_publication_changed"
                else:
                    raise AssertionError(f"post-finalize mutation committed: {relative}")
                unchanged = service.get_scan({"scanId": scan["id"]})
                assert unchanged["status"] == "running"
                assert unchanged["sealed_manifest_digest"] is None
                assert service.list_findings({"scanId": scan["id"]}) == []
            finally:
                model._finalize = original_finalize
                service.shutdown({})


def test_windows_completion_lock_branch_uses_one_byte_exclusive_lock() -> None:
    class FakeWindowsFileLock:
        LK_NBLCK = 1
        LK_UNLCK = 2

        def __init__(self) -> None:
            self.calls: list[tuple[int, int]] = []

        def locking(self, _descriptor: int, mode: int, length: int) -> None:
            self.calls.append((mode, length))

    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "completion.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        original_posix = completion_lock.posix_file_lock
        original_windows = completion_lock.windows_file_lock
        fake_windows = FakeWindowsFileLock()
        try:
            completion_lock.posix_file_lock = None
            completion_lock.windows_file_lock = fake_windows
            completion_lock.acquire_completion_file_lock(descriptor)
            assert os.fstat(descriptor).st_size == 1
            completion_lock.release_completion_file_lock(descriptor)
        finally:
            completion_lock.posix_file_lock = original_posix
            completion_lock.windows_file_lock = original_windows
            os.close(descriptor)

        assert fake_windows.calls == [
            (fake_windows.LK_NBLCK, 1),
            (fake_windows.LK_UNLCK, 1),
        ]


def main() -> None:
    for test in (
        test_standard_rank_input_is_not_premature_deep_input,
        test_rejected_and_ignored_candidates_are_auditable_but_not_canonical,
        test_deferred_and_extra_security_coverage_complete_without_inventory_equality,
        test_canonical_finding_identity_report_sarif_and_seal_are_projected,
        test_manifest_completed_at_cannot_control_db_lifecycle_timestamps,
        test_commit_diff_requires_checked_out_clean_evidence_target,
        test_target_drift_fails_before_finalization_and_leaves_running_scan,
        test_failed_scan_is_terminal_and_engine_shutdown_preserves_running_scan,
        test_workspace_has_exactly_one_running_scan_across_starts,
        test_running_scan_without_start_contract_fails_closed,
        test_start_scan_never_combines_a_terminal_scan_with_available_lease_state,
        test_coordinator_lease_generation_expiry_and_secret_projection,
        test_expired_lease_takeover_is_single_winner,
        test_integrity_reconciliation_never_rewrites_terminal_lifecycle,
        test_scan_setup_is_complete_before_running_publication,
        test_failed_setup_never_publishes_a_scan,
        test_post_finalize_target_mutation_cannot_commit_completion,
        test_concurrent_completion_requires_the_valid_coordinator_lease,
        test_post_finalize_manifest_or_artifact_mutation_cannot_commit,
        test_windows_completion_lock_branch_uses_one_byte_exclusive_lock,
    ):
        test()
        print(f"PASS {test.__name__}")


if __name__ == "__main__":
    main()
