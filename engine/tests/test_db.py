from __future__ import annotations

import concurrent.futures
import json
import sqlite3
from pathlib import Path

import pytest

from kiro_security.constants import PROTOCOL_VERSION
from kiro_security.db import Workbench
from kiro_security.errors import EngineError
from kiro_security.model import setup_model_scan
from kiro_security.security import utc_now


def create_scan(workbench: Workbench, session: str = "session-a") -> dict:
    workbench.register_session(session, 12345, "test", PROTOCOL_VERSION)
    workspace = workbench.register_workspace(workbench.workspace)
    if not workspace["submitted"]:
        workspace = workbench.save_workspace(
            workspace["id"], mode="standard", scope=".", user_context=None,
            diff_target_kind=None, diff_base_revision=None, diff_head_revision=None,
        )
    scan, _ = workbench.create_scan(
        workspace_id=workspace["id"],
        artifact_dir=None,
        session_id=session,
        setup_scan=lambda draft: setup_model_scan(workbench, draft),
    )
    return scan


def test_fresh_migrations_have_lifecycle_only_schema_and_allow_gate_observation(workspace: Path, tmp_path: Path) -> None:
    workbench = Workbench(workspace)
    info = workbench.database_info()
    assert info["schemaVersion"] == 13
    assert info["journalMode"].lower() == "wal"
    assert info["integrity"] == "ok"
    scan = create_scan(workbench)
    second = create_scan(workbench, "session-b")
    assert second["id"] == scan["id"]
    connection = workbench._connect()
    try:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        versions = [row[0] for row in connection.execute("SELECT version FROM schema_migrations ORDER BY version")]
        forbidden_columns = {
            "worker_id", "assignment_id", "model_profile", "runtime_attestation",
            "completion_attestation", "tail_assignment_id", "round_id", "merge_id",
            "owner_session_id", "handoff_state", "resumed_at", "resume_count",
        }
        bad_columns = {
            f"{table}.{row[1]}"
            for table in tables
            for row in connection.execute(f'PRAGMA table_info("{table}")')
            if row[1].lower() in forbidden_columns
        }
        scan_table_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()[0]
        scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        workspace_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
    finally:
        connection.close()
    assert versions == [1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13]
    assert not {
        "deep_scan_state", "deep_workers", "deep_merge_records",
        "deep_worker_coverage_receipts", "deep_tail_assignments",
    }.intersection(tables)
    assert not bad_columns
    assert "'queued'" not in scan_table_sql
    assert "'interrupted'" not in scan_table_sql
    assert "capability_json" not in scan_columns
    assert "user_context" in scan_columns
    assert {
        "thread_id", "user_context", "diff_target_kind", "diff_base_revision",
        "diff_head_revision", "diff_content_digest", "submitted",
    } <= workspace_columns
    snapshot = workbench.snapshot(tmp_path / "snapshot.sqlite")
    connection = sqlite3.connect(snapshot)
    try:
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM scans WHERE id=?", (scan["id"],)).fetchone()[0] == 1
    finally:
        connection.close()


def test_migration_11_adds_one_running_scan_guard_to_existing_schema(workspace: Path) -> None:
    workbench = Workbench(workspace)
    with workbench.transaction() as connection:
        connection.execute("DROP INDEX scans_one_running_per_workspace")
        connection.execute("DELETE FROM schema_migrations WHERE version=11")

    migrated = Workbench(workspace)
    assert migrated.database_info()["schemaVersion"] == 13
    connection = migrated._connect()
    try:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='scans_one_running_per_workspace'"
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    assert "WHERE status = 'running'" in row[0]


def test_migration_rejects_orphan_running_scan_pointer(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    with workbench.transaction() as connection:
        connection.execute("DROP INDEX scans_one_running_per_workspace")
        connection.execute("DELETE FROM schema_migrations WHERE version=11")
        connection.execute(
            "UPDATE workspaces SET active_scan_id=NULL WHERE id=?", (scan["workspace_id"],)
        )

    try:
        Workbench(workspace)
    except EngineError as error:
        assert error.code == "workspace_scan_invariant"
        assert error.data == {
            "workspaceId": scan["workspace_id"],
            "activeScanId": None,
            "runningScanId": scan["id"],
            "runningCount": 1,
        }
    else:
        raise AssertionError("migration silently accepted or repaired an orphan running scan pointer")


def test_concurrent_fresh_database_initialization_is_serialized(tmp_path: Path) -> None:
    workspace = tmp_path / "concurrent-workspace"
    workspace.mkdir()

    def initialize() -> dict:
        return Workbench(workspace).database_info()

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = [future.result(timeout=20) for future in [executor.submit(initialize) for _ in range(4)]]
    assert {result["schemaVersion"] for result in results} == {13}
    assert {result["integrity"] for result in results} == {"ok"}


def test_engine_session_release_does_not_change_scan_lifecycle(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    assert workbench.release_session_leases("session-a") == [scan["id"]]
    assert workbench.get_scan(scan["id"])["status"] == "running"
    workbench.register_session("session-b", 67890, "test", PROTOCOL_VERSION)
    acquired = workbench.acquire_coordinator_lease(scan["id"], "session-b")
    assert acquired["status"] == "running"
    assert acquired["coordinatorLease"]["state"] == "acquired"


def test_failed_scan_is_terminal_and_preserves_failure_metadata(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    lease = scan["coordinatorLease"]
    failed = workbench.fail_scan(
        scan["id"], "unrecoverable", "Terminal failure", lease["token"], lease["generation"]
    )
    completed_at = failed["completed_at"]
    assert failed["status"] == "failed"
    assert failed["failure_code"] == "unrecoverable"
    assert failed["failure_message"] == "Terminal failure"
    assert completed_at is not None
    with pytest.raises(EngineError) as error:
        workbench.acquire_coordinator_lease(scan["id"], "session-b")
    assert error.value.code == "scan_not_running"

    unchanged = workbench.get_scan(scan["id"])
    assert unchanged["status"] == "failed"
    assert unchanged["failure_code"] == "unrecoverable"
    assert unchanged["failure_message"] == "Terminal failure"
    assert unchanged["completed_at"] == completed_at
    assert workbench.get_workspace(scan["workspace_id"])["active_scan_id"] == scan["id"]


def test_migration_13_rebuilds_v12_scan_table_without_losing_children(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    with workbench.transaction() as connection:
        before = {
            "scans": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "progress": connection.execute("SELECT COUNT(*) FROM scan_progress").fetchone()[0],
            "artifacts": connection.execute("SELECT COUNT(*) FROM scan_artifacts").fetchone()[0],
            "occurrences": connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone()[0],
        }
        connection.execute("ALTER TABLE scans ADD COLUMN capability_json TEXT")
        connection.execute(
            "UPDATE scans SET capability_json=? WHERE id=?",
            (json.dumps({"userContext": "migrated context"}), scan["id"]),
        )
        connection.execute("DELETE FROM schema_migrations WHERE version=13")

    migrated = Workbench(workspace)
    connection = migrated._connect()
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        after = {
            "scans": connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "progress": connection.execute("SELECT COUNT(*) FROM scan_progress").fetchone()[0],
            "artifacts": connection.execute("SELECT COUNT(*) FROM scan_artifacts").fetchone()[0],
            "occurrences": connection.execute("SELECT COUNT(*) FROM finding_occurrences").fetchone()[0],
        }
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
    finally:
        connection.close()
    assert before == after
    assert "capability_json" not in columns
    migrated_scan = migrated.get_scan(scan["id"])
    assert migrated_scan["status"] == "running"
    assert migrated_scan["mode"] == scan["mode"]
    assert migrated_scan["scope"] == scan["scope"]
    assert migrated_scan["user_context"] == "migrated context"
    assert migrated.get_workspace()["user_context"] == "migrated context"


def test_migration_13_failure_rolls_back_parent_rebuild(
    workspace: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workbench = Workbench(workspace)
    scan = create_scan(workbench)
    with workbench.transaction() as connection:
        connection.execute("ALTER TABLE scans ADD COLUMN capability_json TEXT")
        connection.execute(
            "UPDATE scans SET capability_json=? WHERE id=?",
            (json.dumps({"userContext": "rollback context"}), scan["id"]),
        )
        connection.execute("DELETE FROM schema_migrations WHERE version=13")
        before = Workbench._scan_child_row_counts(connection)

    original = Workbench._apply_lifecycle_authority_migration

    def fail_after_rebuild(cls: type[Workbench], connection: sqlite3.Connection) -> None:
        original(connection)
        raise sqlite3.OperationalError("controlled migration failure")

    monkeypatch.setattr(
        Workbench, "_apply_lifecycle_authority_migration", classmethod(fail_after_rebuild)
    )
    with pytest.raises(EngineError) as error:
        Workbench(workspace)
    assert error.value.code == "migration_failed"

    connection = sqlite3.connect(workbench.db_path)
    try:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        assert "capability_json" in columns
        assert connection.execute(
            "SELECT COUNT(*) FROM schema_migrations WHERE version=13"
        ).fetchone() == (0,)
        assert Workbench._scan_child_row_counts(connection) == before
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT status FROM scans WHERE id=?", (scan["id"],)).fetchone() == ("running",)
    finally:
        connection.close()


def test_migration_12_rejects_queued_legacy_lifecycle(workspace: Path) -> None:
    state = workspace / ".kiro" / "security-power"
    state.mkdir(parents=True)
    database = state / "workbench.sqlite"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
        )
        migrations = Path(__file__).resolve().parents[1] / "migrations"
        for path in sorted(migrations.glob("[0-9][0-9][0-9]_*.sql")):
            version = int(path.name[:3])
            if version >= 12:
                continue
            script = path.read_text(encoding="utf-8")
            if version == 1:
                script = script.replace(
                    "status IN ('running','completed','cancelled','failed')",
                    "status IN ('queued','running','completed','cancelled','failed')",
                )
            connection.executescript(script)
            connection.execute(
                "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                (version, path.stem, utc_now()),
            )
        for statement in (
            "ALTER TABLE scans ADD COLUMN owner_session_id TEXT",
            "ALTER TABLE scans ADD COLUMN heartbeat_at TEXT",
            "ALTER TABLE scans ADD COLUMN handoff_state TEXT NOT NULL DEFAULT 'none'",
            "ALTER TABLE scans ADD COLUMN resumed_at TEXT",
            "ALTER TABLE scans ADD COLUMN resume_count INTEGER NOT NULL DEFAULT 0",
        ):
            connection.execute(statement)
        timestamp = utc_now()
        connection.execute(
            """
            INSERT INTO workspaces(
                id, root_path, display_name, default_scope, default_mode,
                active_scan_id, created_at, updated_at
            ) VALUES ('workspace', ?, 'workspace', '.', 'standard', 'queued-scan', ?, ?)
            """,
            (str(workspace), timestamp, timestamp),
        )
        connection.execute(
            """
            INSERT INTO scans(
                id, workspace_id, mode, scope, status, phase, phase_index,
                artifact_dir, created_at, updated_at
            ) VALUES ('queued-scan', 'workspace', 'standard', '.', 'queued',
                'preflight', 0, ?, ?, ?)
            """,
            (str(state / "artifacts" / "queued-scan"), timestamp, timestamp),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(EngineError) as error:
        Workbench(workspace)
    assert error.value.code == "legacy_scan_incompatible"
    assert error.value.data == {"incompatibleStatusCounts": {"queued": 1}}


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
