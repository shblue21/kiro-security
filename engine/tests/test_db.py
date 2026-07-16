from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kiro_security.constants import PROTOCOL_VERSION
from kiro_security.db import Workbench
from kiro_security.errors import EngineError


def create_scan(workbench: Workbench, session: str = "session-a") -> dict:
    workbench.register_session(session, 12345, "test", PROTOCOL_VERSION)
    workspace = workbench.register_workspace(workbench.workspace)
    return workbench.create_scan(
        workspace_id=workspace["id"],
        mode="standard",
        scope=".",
        artifact_dir=None,
        session_id=session,
    )


def candidate(path: str = "src/app.py") -> dict:
    return {
        "ruleId": "test.rule",
        "fingerprint": f"test:{path}:1",
        "identity": {"anchor": "test-anchor", "instance": path},
        "title": "Test finding",
        "summary": "Test summary",
        "severity": {"level": "high", "score": 8.0, "rationale": "test"},
        "confidence": {"level": "high", "rationale": "test"},
        "taxonomy": {"category": "test", "cwe": ["CWE-1"]},
        "locations": [{"path": path, "startLine": 1, "endLine": 1, "role": "sink"}],
        "codeEvidence": [{"kind": "code", "label": "sink", "path": path, "startLine": 1, "endLine": 1, "role": "sink", "code": "danger()", "explanation": "test"}],
        "remediation": "Fix it.",
        "details": {"sourceToSink": True},
    }


def test_migrations_integrity_snapshot_and_active_lock(workspace: Path, tmp_path: Path) -> None:
    workbench = Workbench(workspace)
    info = workbench.database_info()
    assert info["schemaVersion"] == 8
    assert info["journalMode"].lower() == "wal"
    assert info["integrity"] == "ok"
    scan = create_scan(workbench)
    with pytest.raises(EngineError) as error:
        create_scan(workbench, "session-b")
    assert error.value.code == "scan_already_active"
    snapshot = workbench.snapshot(tmp_path / "snapshot.sqlite")
    connection = sqlite3.connect(snapshot)
    try:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan["id"],)).fetchone()[0] == 1
    finally:
        connection.close()


def test_stale_session_recovery_and_resume(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    stale = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with workbench.transaction() as connection:
        connection.execute("UPDATE engine_sessions SET heartbeat_at=? WHERE id='session-a'", (stale,))
        connection.execute("UPDATE scans SET heartbeat_at=? WHERE id=?", (stale, scan["id"]))
    assert workbench.recover_stale_sessions(stale_after_seconds=20) == [scan["id"]]
    interrupted = workbench.get_scan(scan["id"])
    assert interrupted["status"] == "interrupted"
    assert interrupted["handoff_state"] == "available"
    workbench.register_session("session-b", 67890, "test", PROTOCOL_VERSION)
    resumed = workbench.resume_scan(scan["id"], "session-b")
    assert resumed["status"] == "running"
    assert resumed["handoff_state"] == "claimed"
    assert resumed["resume_count"] == 1


def test_findings_validation_triage_remediation_and_parameterized_search(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    finding = workbench.upsert_finding(scan["id"], candidate())
    duplicate = workbench.upsert_finding(scan["id"], candidate())
    assert duplicate["findingId"] == finding["findingId"]
    assert len(workbench.list_findings(scan["id"])) == 1
    assert workbench.list_findings(scan["id"], search="' OR 1=1 --") == []
    validated = workbench.save_validation(finding["occurrenceId"], {"status": "validated", "method": "test", "rationale": "trace", "evidence": []})
    assert validated["validationStatus"] == "validated"
    triaged = workbench.triage_finding(finding["occurrenceId"], "accepted_risk", "approved")
    assert triaged["triageStatus"] == "accepted_risk"
    remediated = workbench.save_remediation(finding["occurrenceId"], "guidance", None)
    assert remediated["remediationRecords"][0]["state"] == "generated"


def test_migration_backups_are_created_before_and_after_pending_migration(workspace: Path) -> None:
    workbench = Workbench(workspace)
    with workbench.transaction() as connection:
        connection.execute("DROP TABLE deep_worker_coverage_receipts")
        connection.execute("DROP TABLE coverage_ledger")
        connection.execute("DELETE FROM schema_migrations WHERE version=8")
    migrated = Workbench(workspace)
    pre_backups = list(workbench.state_dir.glob("workbench.pre-migration-v7.*.sqlite"))
    post_backups = list(workbench.state_dir.glob("workbench.post-migration-v8.*.sqlite"))
    assert pre_backups
    assert post_backups
    assert migrated.database_info()["schemaVersion"] == 8
    connection = sqlite3.connect(post_backups[-1])
    try:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()[0] == 8
    finally:
        connection.close()


def test_corrupt_database_reports_structured_error(workspace: Path) -> None:
    state = workspace / ".kiro" / "security-power"
    state.mkdir(parents=True)
    (state / "workbench.sqlite").write_bytes(b"not-a-sqlite-database")
    with pytest.raises(EngineError) as error:
        Workbench(workspace)
    assert error.value.code == "database_error"


def test_state_directory_symlink_escape_is_rejected(workspace: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside-state"
    outside.mkdir()
    kiro = workspace / ".kiro"
    kiro.mkdir()
    try:
        (kiro / "security-power").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this platform")
    with pytest.raises(EngineError) as error:
        Workbench(workspace)
    assert error.value.code == "state_path_escape"
