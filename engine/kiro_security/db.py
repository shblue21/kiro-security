from __future__ import annotations

import json
import os
import shutil
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .constants import ARTIFACT_KINDS, PHASES
from .coverage import COVERAGE_DISPOSITIONS
from .errors import EngineError
from .security import random_id, sha256_file, stable_id, utc_now
from .state_machine import require_phase_transition, require_status_transition


class Workbench:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve(strict=True)
        state_candidate = self.workspace / ".kiro" / "security-power"
        state_candidate.mkdir(parents=True, exist_ok=True)
        try:
            state_resolved = state_candidate.resolve(strict=True)
        except OSError as exc:
            raise EngineError("state_path_error", f"Unable to resolve workbench state directory: {exc}") from exc
        if state_resolved != self.workspace and self.workspace not in state_resolved.parents:
            raise EngineError("state_path_escape", "The .kiro/security-power state directory resolves outside the workspace boundary.")
        self.state_dir = state_resolved
        self.artifacts_dir = self.state_dir / "artifacts"
        self.exports_dir = self.state_dir / "exports"
        self.logs_dir = self.state_dir / "logs"
        self.db_path = self.state_dir / "workbench.sqlite"
        self.migrations_dir = Path(__file__).resolve().parent.parent / "migrations"
        self._lock = threading.RLock()
        for directory in (self.artifacts_dir, self.exports_dir, self.logs_dir):
            directory.mkdir(parents=True, exist_ok=True)
            resolved = directory.resolve(strict=True)
            if resolved != self.state_dir and self.state_dir not in resolved.parents:
                raise EngineError("state_path_escape", f"Workbench directory escapes state root: {directory.name}")
        self.apply_migrations()

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            connection.execute("PRAGMA busy_timeout = 15000")
            return connection
        except sqlite3.DatabaseError as exc:
            raise EngineError("database_error", f"Unable to open workbench database: {exc}") from exc

    @contextmanager
    def transaction(self, *, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
                yield connection
                connection.execute("COMMIT")
            except Exception:
                try:
                    connection.execute("ROLLBACK")
                except sqlite3.DatabaseError:
                    pass
                raise
            finally:
                connection.close()

    def apply_migrations(self) -> None:
        migration_files = sorted(self.migrations_dir.glob("[0-9][0-9][0-9]_*.sql"))
        if not migration_files:
            raise EngineError("migration_missing", f"No migrations found in {self.migrations_dir}")
        existed = self.db_path.exists() and self.db_path.stat().st_size > 0
        connection = self._connect()
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
            )
            current = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
            pending = [path for path in migration_files if int(path.name[:3]) > current]
            migration_stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            if pending and existed:
                backup = self.state_dir / f"workbench.pre-migration-v{current}.{migration_stamp}.sqlite"
                destination = sqlite3.connect(backup)
                try:
                    connection.backup(destination)
                finally:
                    destination.close()
            for path in pending:
                version = int(path.name[:3])
                sql = path.read_text(encoding="utf-8")
                try:
                    migration_name = path.stem.replace("'", "''")
                    applied_at = utc_now().replace("'", "''")
                    connection.executescript(
                        "BEGIN IMMEDIATE;\n"
                        + sql
                        + f"\nINSERT INTO schema_migrations(version, name, applied_at) VALUES ({version}, '{migration_name}', '{applied_at}');\n"
                        + "COMMIT;\n"
                    )
                except sqlite3.DatabaseError as exc:
                    try:
                        connection.execute("ROLLBACK")
                    except sqlite3.DatabaseError:
                        pass
                    raise EngineError(
                        "migration_failed",
                        f"Migration {path.name} failed: {exc}",
                        {"migration": path.name},
                    ) from exc
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise EngineError("database_corrupt", f"SQLite quick_check failed: {integrity}")
            if pending and existed:
                final_version = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
                post_backup = self.state_dir / f"workbench.post-migration-v{final_version}.{migration_stamp}.sqlite"
                destination = sqlite3.connect(post_backup)
                try:
                    connection.backup(destination)
                finally:
                    destination.close()
        finally:
            connection.close()

    def database_info(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            version = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
            journal = connection.execute("PRAGMA journal_mode").fetchone()[0]
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            return {
                "path": str(self.db_path),
                "schemaVersion": version,
                "journalMode": journal,
                "integrity": integrity,
            }
        finally:
            connection.close()

    def snapshot(self, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = self._connect()
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
        return destination

    def register_session(self, session_id: str, pid: int, client_kind: str, protocol_version: str) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO engine_sessions(id, pid, client_kind, protocol_version, started_at, heartbeat_at, closed_at)
                VALUES (?, ?, ?, ?, ?, ?, NULL)
                ON CONFLICT(id) DO UPDATE SET pid=excluded.pid, client_kind=excluded.client_kind,
                    protocol_version=excluded.protocol_version, heartbeat_at=excluded.heartbeat_at, closed_at=NULL
                """,
                (session_id, pid, client_kind, protocol_version, timestamp, timestamp),
            )

    def heartbeat_session(self, session_id: str) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "UPDATE engine_sessions SET heartbeat_at=? WHERE id=? AND closed_at IS NULL",
                (timestamp, session_id),
            )
            connection.execute(
                "UPDATE scans SET heartbeat_at=?, updated_at=? WHERE owner_session_id=? AND status='running'",
                (timestamp, timestamp, session_id),
            )

    def close_session(self, session_id: str) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute("UPDATE engine_sessions SET closed_at=?, heartbeat_at=? WHERE id=?", (timestamp, timestamp, session_id))

    def recover_stale_sessions(self, stale_after_seconds: int = 20) -> list[str]:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        recovered: list[str] = []
        with self.transaction() as connection:
            rows = connection.execute(
                """
                SELECT s.id
                FROM scans s
                LEFT JOIN engine_sessions e ON e.id = s.owner_session_id
                WHERE s.status='running'
                  AND (s.heartbeat_at IS NULL OR s.heartbeat_at < ? OR e.closed_at IS NOT NULL OR e.id IS NULL)
                """,
                (cutoff,),
            ).fetchall()
            timestamp = utc_now()
            for row in rows:
                connection.execute(
                    """
                    UPDATE scans
                    SET status='interrupted', handoff_state='available', owner_session_id=NULL,
                        heartbeat_at=NULL, updated_at=?
                    WHERE id=? AND status='running'
                    """,
                    (timestamp, row["id"]),
                )
                recovered.append(row["id"])
        return recovered

    def _quarantine_publication(self, artifact_dir: Path, stamp: str) -> list[str]:
        """Move an unsanctioned manifest and its projections out of the official paths."""

        quarantine_dir = artifact_dir / "quarantine" / stamp
        moved: list[str] = []
        for relative in (ARTIFACT_KINDS["manifest"], ARTIFACT_KINDS["markdownReport"], ARTIFACT_KINDS["hardening"]):
            source = artifact_dir / relative
            # os.replace moves a symlink itself without following it, so an
            # unsafe symlinked publication is also removed from the official path.
            if not source.is_file() and not source.is_symlink():
                continue
            destination = quarantine_dir / relative
            try:
                destination.parent.mkdir(parents=True, exist_ok=True)
                os.replace(source, destination)
                moved.append(str(destination))
            except OSError:
                pass
        return moved

    @staticmethod
    def _cleanup_stale_temp_files(artifact_dir: Path) -> None:
        for relative in ARTIFACT_KINDS.values():
            target = artifact_dir / relative
            if not target.parent.is_dir():
                continue
            for stale in target.parent.glob(f".{target.name}.*"):
                if stale.is_file() and not stale.is_symlink():
                    try:
                        stale.unlink()
                    except OSError:
                        pass

    def reconcile_finalization_integrity(self) -> list[dict[str, Any]]:
        """Detect and repair filesystem/SQLite contradictions after a hard crash.

        Official file publication happens inside the completion transaction
        but before COMMIT, so a crash in that window can leave a completed
        manifest on disk while the durable scan state rolled back.  This
        startup pass restores the invariant that an official manifest exists
        only for a completed scan whose sealed digest matches the file:

        - non-active scans with an official manifest but no committed seal
          have the manifest and its projections quarantined, and stale
          atomic-write temp files removed;
        - completed scans whose manifest is missing or does not match the
          durable sealed digest are surfaced as explicit integrity failures;
        - a completed scan that somehow lacks a sealed digest is revoked via
          the unsealed-completion failure path.
        """

        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT id, status, sealed_manifest_digest, artifact_dir FROM scans"
            ).fetchall()
        finally:
            connection.close()
        issues: list[dict[str, Any]] = []
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for row in rows:
            artifact_dir = Path(row["artifact_dir"])
            if not artifact_dir.is_dir():
                continue
            manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
            manifest_present = manifest_path.is_file() and not manifest_path.is_symlink()
            if row["status"] == "completed":
                digest = row["sealed_manifest_digest"]
                if not digest:
                    try:
                        self.fail_unsealed_completion(
                            row["id"],
                            "finalization_integrity_failure",
                            "The scan was completed without a committed sealed manifest digest.",
                        )
                    except EngineError:
                        pass
                    quarantined = self._quarantine_publication(artifact_dir, stamp) if manifest_present else []
                    issues.append({
                        "scanId": row["id"],
                        "code": "completed_scan_unsealed",
                        "message": "A completed scan had no sealed manifest digest; the completion was revoked.",
                        "quarantinedPaths": quarantined,
                    })
                elif not manifest_path.exists() and not manifest_path.is_symlink():
                    # The completion witness is gone; leftover projections must
                    # not keep impersonating a valid sealed publication.
                    quarantined = self._quarantine_publication(artifact_dir, stamp)
                    issues.append({
                        "scanId": row["id"],
                        "code": "sealed_manifest_missing",
                        "message": "The durable seal digest exists but the official manifest file is missing.",
                        "expected": digest,
                        "actual": None,
                        "quarantinedPaths": quarantined,
                    })
                else:
                    # A symlinked manifest is never trusted; otherwise compare
                    # the official bytes against the durable seal digest.
                    actual = None
                    if manifest_present:
                        try:
                            actual = sha256_file(manifest_path)
                        except OSError:
                            actual = None
                    if actual != digest:
                        quarantined = self._quarantine_publication(artifact_dir, stamp)
                        issues.append({
                            "scanId": row["id"],
                            "code": "sealed_manifest_digest_mismatch",
                            "message": (
                                "The official manifest does not match the durable sealed digest; "
                                "the publication was quarantined and the sealed bundle must not be trusted."
                            ),
                            "expected": digest,
                            "actual": actual,
                            "quarantinedPaths": quarantined,
                        })
            elif row["status"] in ("interrupted", "failed", "cancelled"):
                if manifest_present:
                    quarantined = self._quarantine_publication(artifact_dir, stamp)
                    issues.append({
                        "scanId": row["id"],
                        "code": "orphan_manifest_quarantined",
                        "message": "An official manifest existed for a scan without a committed completion; it was quarantined.",
                        "quarantinedPaths": quarantined,
                    })
                self._cleanup_stale_temp_files(artifact_dir)
        for issue in issues:
            try:
                self.add_event("scan.integrityIssue", issue, issue.get("scanId"))
            except Exception:
                pass
        return issues

    def register_workspace(self, root: Path, *, default_scope: str = ".", default_mode: str = "standard") -> dict[str, Any]:
        workspace_id = stable_id("ws", str(root))
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO workspaces(id, root_path, display_name, default_scope, default_mode, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(root_path) DO UPDATE SET display_name=excluded.display_name,
                    default_scope=excluded.default_scope, default_mode=excluded.default_mode, updated_at=excluded.updated_at
                """,
                (workspace_id, str(root), root.name or str(root), default_scope, default_mode, timestamp, timestamp),
            )
            row = connection.execute("SELECT * FROM workspaces WHERE root_path=?", (str(root),)).fetchone()
        return dict(row)

    def get_workspace(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM workspaces WHERE root_path=?", (str(self.workspace),)).fetchone()
            if row is None:
                return self.register_workspace(self.workspace)
            return dict(row)
        finally:
            connection.close()

    def create_scan(
        self,
        *,
        workspace_id: str,
        mode: str,
        scope: str,
        artifact_dir: Path | None,
        session_id: str,
        diff_target_kind: str | None = None,
        diff_base_revision: str | None = None,
        diff_head_revision: str | None = None,
    ) -> dict[str, Any]:
        scan_id = random_id("scan")
        artifact_dir = artifact_dir or (self.artifacts_dir / scan_id)
        timestamp = utc_now()
        try:
            stat = self.workspace.stat()
            device, inode = int(stat.st_dev), int(stat.st_ino)
        except OSError:
            device = inode = None
        with self.transaction() as connection:
            active = connection.execute(
                "SELECT id FROM scans WHERE workspace_id=? AND status IN ('queued','running')",
                (workspace_id,),
            ).fetchone()
            if active:
                raise EngineError("scan_already_active", "A scan is already active for this workspace.", {"scanId": active["id"]})
            connection.execute(
                """
                INSERT INTO scans(
                    id, workspace_id, mode, scope, diff_target_kind, diff_base_revision, diff_head_revision,
                    status, phase, phase_index, artifact_dir, owner_session_id, heartbeat_at,
                    started_at, created_at, updated_at, target_device, target_inode
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'running', 'preflight', 0, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id, workspace_id, mode, scope, diff_target_kind, diff_base_revision, diff_head_revision,
                    str(artifact_dir), session_id, timestamp, timestamp, timestamp, timestamp, device, inode,
                ),
            )
            connection.execute(
                """
                INSERT INTO scan_progress(scan_id, phase_percent, overall_percent, message, updated_at)
                VALUES (?, 0, 0, 'Starting preflight', ?)
                """,
                (scan_id, timestamp),
            )
            connection.execute("UPDATE workspaces SET active_scan_id=?, updated_at=? WHERE id=?", (scan_id, timestamp, workspace_id))
        return self.get_scan(scan_id)

    def resume_scan(self, scan_id: str, session_id: str) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] not in ("interrupted", "failed"):
                raise EngineError("scan_not_resumable", f"Scan {scan_id} is {row['status']}, not resumable.")
            active = connection.execute(
                "SELECT id FROM scans WHERE workspace_id=? AND status IN ('queued','running') AND id<>?",
                (row["workspace_id"], scan_id),
            ).fetchone()
            if active:
                raise EngineError("scan_already_active", "Another scan is active for this workspace.", {"scanId": active["id"]})
            require_status_transition(row["status"], "running")
            timestamp = utc_now()
            connection.execute(
                """
                UPDATE scans SET status='running', owner_session_id=?, heartbeat_at=?, cancellation_requested=0,
                    handoff_state='claimed', failure_code=NULL, failure_message=NULL, resumed_at=?, resume_count=resume_count+1,
                    completed_at=NULL, updated_at=? WHERE id=?
                """,
                (session_id, timestamp, timestamp, timestamp, scan_id),
            )
            connection.execute("UPDATE workspaces SET active_scan_id=?, updated_at=? WHERE id=?", (scan_id, timestamp, row["workspace_id"]))
        return self.get_scan(scan_id)

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            progress = connection.execute("SELECT * FROM scan_progress WHERE scan_id=?", (scan_id,)).fetchone()
            artifacts = connection.execute(
                "SELECT kind, path, sha256, media_type, created_at FROM scan_artifacts WHERE scan_id=? ORDER BY kind",
                (scan_id,),
            ).fetchall()
            result = dict(row)
            result["progress"] = dict(progress) if progress else None
            result["artifacts"] = [dict(item) for item in artifacts]
            result["cancellation_requested"] = bool(result["cancellation_requested"])
            if result.get("coverage_json"):
                result["coverage"] = json.loads(result["coverage_json"])
            else:
                result["coverage"] = None
            if result.get("capability_json"):
                result["capabilities"] = json.loads(result["capability_json"])
            else:
                result["capabilities"] = None
            return result
        finally:
            connection.close()

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT id FROM scans WHERE workspace_id=(SELECT id FROM workspaces WHERE root_path=?) ORDER BY created_at DESC LIMIT ?",
                (str(self.workspace), max(1, min(limit, 200))),
            ).fetchall()
        finally:
            connection.close()
        return [self.get_scan(row["id"]) for row in rows]

    def latest_resumable_scan(self) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT id FROM scans
                WHERE workspace_id=(SELECT id FROM workspaces WHERE root_path=?) AND status IN ('interrupted','failed')
                ORDER BY updated_at DESC LIMIT 1
                """,
                (str(self.workspace),),
            ).fetchone()
        finally:
            connection.close()
        return self.get_scan(row["id"]) if row else None

    def active_scan(self) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT id FROM scans
                WHERE workspace_id=(SELECT id FROM workspaces WHERE root_path=?) AND status IN ('queued','running')
                ORDER BY created_at DESC LIMIT 1
                """,
                (str(self.workspace),),
            ).fetchone()
        finally:
            connection.close()
        return self.get_scan(row["id"]) if row else None

    def set_scan_target(self, scan_id: str, *, revision: str | None, snapshot_digest: str | None) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE scans SET target_revision=?, snapshot_digest=?, updated_at=? WHERE id=?",
                (revision, snapshot_digest, utc_now(), scan_id),
            )

    def set_capabilities(self, scan_id: str, capabilities: dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE scans SET capability_json=?, updated_at=? WHERE id=?",
                (json.dumps(capabilities, separators=(",", ":"), allow_nan=False), utc_now(), scan_id),
            )

    def set_coverage(self, scan_id: str, coverage: dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE scans SET coverage_json=?, updated_at=? WHERE id=?",
                (json.dumps(coverage, separators=(",", ":"), allow_nan=False), utc_now(), scan_id),
            )

    @staticmethod
    def _coverage_row_values(scan_id: str, row: dict[str, Any], timestamp: str) -> tuple[Any, ...]:
        disposition = row.get("disposition")
        if disposition not in COVERAGE_DISPOSITIONS:
            raise EngineError("invalid_coverage_disposition", f"Unsupported coverage disposition: {disposition}")
        reason = row.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise EngineError("invalid_coverage_reason", "Coverage receipt reason is required.")
        receipt_id = stable_id("coverage-receipt", scan_id, row["rowId"], row["receiptDigest"])
        return (
            receipt_id, scan_id, row["rowId"], row["path"], row["surface"],
            row.get("entrypoint"), row.get("rootControl"), row.get("sink"),
            disposition, reason.strip(),
            json.dumps(row.get("evidenceRefs") or [], separators=(",", ":"), allow_nan=False),
            json.dumps(row.get("candidateIds") or [], separators=(",", ":"), allow_nan=False),
            row.get("workerId"), row["receiptDigest"], timestamp, timestamp,
        )

    @staticmethod
    def _insert_coverage_row(connection: sqlite3.Connection, values: tuple[Any, ...]) -> None:
        connection.execute(
            """
            INSERT INTO coverage_ledger(
                id, scan_id, row_id, path, surface, entrypoint, root_control, sink, disposition, reason,
                evidence_refs_json, candidate_ids_json, worker_id, receipt_digest, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, row_id) DO UPDATE SET
                id=excluded.id, path=excluded.path, surface=excluded.surface, entrypoint=excluded.entrypoint,
                root_control=excluded.root_control, sink=excluded.sink, disposition=excluded.disposition,
                reason=excluded.reason, evidence_refs_json=excluded.evidence_refs_json,
                candidate_ids_json=excluded.candidate_ids_json, worker_id=excluded.worker_id,
                receipt_digest=excluded.receipt_digest, updated_at=excluded.updated_at
            """,
            values,
        )

    def upsert_coverage_rows(
        self,
        scan_id: str,
        rows: list[dict[str, Any]],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        timestamp = utc_now()
        values = [self._coverage_row_values(scan_id, row, timestamp) for row in rows]

        def apply(target: sqlite3.Connection) -> None:
            exists = target.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
            if exists is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            for value in values:
                self._insert_coverage_row(target, value)

        if connection is not None:
            apply(connection)
            return
        with self.transaction() as tx:
            apply(tx)

    def upsert_coverage_row(self, scan_id: str, row: dict[str, Any]) -> dict[str, Any]:
        self.upsert_coverage_rows(scan_id, [row])
        return next(item for item in self.list_coverage_rows(scan_id) if item["rowId"] == row["rowId"])

    def replace_coverage_rows(self, scan_id: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        timestamp = utc_now()
        seen: set[str] = set()
        values: list[tuple[Any, ...]] = []
        for row in rows:
            row_id = str(row.get("rowId") or "")
            if not row_id or row_id in seen:
                raise EngineError("duplicate_coverage_row", f"Coverage rowId must be unique: {row_id or '<missing>'}")
            seen.add(row_id)
            values.append(self._coverage_row_values(scan_id, row, timestamp))
        with self.transaction() as connection:
            exists = connection.execute("SELECT id FROM scans WHERE id=?", (scan_id,)).fetchone()
            if exists is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            connection.execute("DELETE FROM coverage_ledger WHERE scan_id=?", (scan_id,))
            for value in values:
                self._insert_coverage_row(connection, value)
        return self.list_coverage_rows(scan_id)

    def list_coverage_rows(self, scan_id: str) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM coverage_ledger WHERE scan_id=? ORDER BY path, row_id",
                (scan_id,),
            ).fetchall()
            return [
                {
                    "id": row["id"],
                    "scanId": row["scan_id"],
                    "rowId": row["row_id"],
                    "path": row["path"],
                    "surface": row["surface"],
                    "entrypoint": row["entrypoint"],
                    "rootControl": row["root_control"],
                    "sink": row["sink"],
                    "disposition": row["disposition"],
                    "reason": row["reason"],
                    "evidenceRefs": json.loads(row["evidence_refs_json"]),
                    "candidateIds": json.loads(row["candidate_ids_json"]),
                    "workerId": row["worker_id"],
                    "receiptDigest": row["receipt_digest"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def replace_deep_worker_coverage_receipts(
        self,
        *,
        scan_id: str,
        worker_id: str,
        round_number: int,
        rows: list[dict[str, Any]],
        connection: sqlite3.Connection | None = None,
    ) -> None:
        def apply(target: sqlite3.Connection) -> None:
            now = utc_now()
            target.execute("DELETE FROM deep_worker_coverage_receipts WHERE worker_id=?", (worker_id,))
            for row in rows:
                target.execute(
                    """
                    INSERT INTO deep_worker_coverage_receipts(
                        id, scan_id, worker_id, round_number, row_id, path, surface, entrypoint, root_control, sink,
                        disposition, reason, evidence_refs_json, candidate_ids_json, receipt_digest, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        stable_id("deep-coverage-receipt", worker_id, row["rowId"], row["receiptDigest"]),
                        scan_id, worker_id, round_number, row["rowId"], row["path"], row["surface"],
                        row.get("entrypoint"), row.get("rootControl"), row.get("sink"), row["disposition"],
                        row["reason"], json.dumps(row.get("evidenceRefs") or [], separators=(",", ":"), allow_nan=False),
                        json.dumps(row.get("candidateIds") or [], separators=(",", ":"), allow_nan=False),
                        row["receiptDigest"], now, now,
                    ),
                )
        if connection is not None:
            apply(connection)
            return
        with self.transaction() as tx:
            apply(tx)

    def list_deep_worker_coverage_receipts(self, scan_id: str, round_number: int) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT r.*, w.worker_index
                FROM deep_worker_coverage_receipts r
                JOIN deep_workers w ON w.id=r.worker_id
                WHERE r.scan_id=? AND r.round_number=?
                ORDER BY r.row_id, w.worker_index
                """,
                (scan_id, round_number),
            ).fetchall()
            return [
                {
                    "id": row["id"], "scanId": row["scan_id"], "workerId": row["worker_id"],
                    "workerIndex": int(row["worker_index"]), "round": int(row["round_number"]),
                    "rowId": row["row_id"], "path": row["path"], "surface": row["surface"],
                    "entrypoint": row["entrypoint"], "rootControl": row["root_control"], "sink": row["sink"],
                    "disposition": row["disposition"], "reason": row["reason"],
                    "evidenceRefs": json.loads(row["evidence_refs_json"]),
                    "candidateIds": json.loads(row["candidate_ids_json"]),
                    "receiptDigest": row["receipt_digest"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def get_deep_scan_state(self, scan_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM deep_scan_state WHERE scan_id=?", (scan_id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["worklist"] = json.loads(result.pop("worklist_json"))
            result["canonicalCandidates"] = json.loads(result.pop("canonical_candidates_json"))
            return result
        finally:
            connection.close()

    def set_phase(self, scan_id: str, phase: str, *, resuming: bool = False) -> dict[str, Any]:
        if phase not in PHASES:
            raise EngineError("invalid_phase", f"Unknown phase: {phase}")
        with self.transaction() as connection:
            row = connection.execute("SELECT status, phase FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] != "running":
                raise EngineError("scan_not_running", f"Scan {scan_id} is {row['status']}.")
            require_phase_transition(row["phase"], phase, resuming=resuming)
            timestamp = utc_now()
            index = PHASES.index(phase)
            connection.execute(
                "UPDATE scans SET phase=?, phase_index=?, updated_at=? WHERE id=?",
                (phase, index, timestamp, scan_id),
            )
            connection.execute(
                "UPDATE scan_progress SET phase_percent=0, overall_percent=?, message=?, updated_at=? WHERE scan_id=?",
                ((index / len(PHASES)) * 100, f"Starting {phase.replace('_', ' ')}", timestamp, scan_id),
            )
        return self.get_scan(scan_id)

    def update_progress(
        self,
        scan_id: str,
        *,
        phase_percent: float | None = None,
        review_items_total: int | None = None,
        review_items_completed: int | None = None,
        reportable_findings_count: int | None = None,
        deep_review_pass: int | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        scan = self.get_scan(scan_id)
        current = scan["progress"] or {}
        phase_percent_value = float(current.get("phase_percent", 0) if phase_percent is None else phase_percent)
        phase_percent_value = max(0.0, min(100.0, phase_percent_value))
        phase_index = int(scan["phase_index"])
        overall = ((phase_index + phase_percent_value / 100.0) / len(PHASES)) * 100.0
        values = {
            "review_items_total": int(current.get("review_items_total", 0) if review_items_total is None else review_items_total),
            "review_items_completed": int(current.get("review_items_completed", 0) if review_items_completed is None else review_items_completed),
            "reportable_findings_count": int(current.get("reportable_findings_count", 0) if reportable_findings_count is None else reportable_findings_count),
            "deep_review_pass": current.get("deep_review_pass") if deep_review_pass is None else deep_review_pass,
            "message": current.get("message") if message is None else message,
        }
        if values["review_items_completed"] > values["review_items_total"]:
            values["review_items_total"] = values["review_items_completed"]
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE scan_progress SET phase_percent=?, overall_percent=?, review_items_total=?, review_items_completed=?,
                    reportable_findings_count=?, deep_review_pass=?, message=?, updated_at=? WHERE scan_id=?
                """,
                (
                    phase_percent_value, min(99.9, overall), values["review_items_total"], values["review_items_completed"],
                    values["reportable_findings_count"], values["deep_review_pass"], values["message"], utc_now(), scan_id,
                ),
            )
        return self.get_scan(scan_id)["progress"]

    def set_file_counts(self, scan_id: str, total: int, completed: int) -> None:
        total_value = max(0, int(total))
        completed_value = max(0, min(int(completed), total_value))
        with self.transaction() as connection:
            connection.execute(
                "UPDATE scans SET files_total=?, files_completed=?, updated_at=? WHERE id=?",
                (total_value, completed_value, utc_now(), scan_id),
            )

    def request_cancel(self, scan_id: str) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] in ("completed", "cancelled", "failed"):
                return self.get_scan(scan_id)
            connection.execute(
                "UPDATE scans SET cancellation_requested=1, updated_at=? WHERE id=?",
                (utc_now(), scan_id),
            )
        return self.get_scan(scan_id)

    def cancellation_requested(self, scan_id: str) -> bool:
        connection = self._connect()
        try:
            row = connection.execute("SELECT cancellation_requested, status FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            return bool(row["cancellation_requested"]) or row["status"] == "cancelled"
        finally:
            connection.close()

    def _finish_scan(self, scan_id: str, status: str, *, failure_code: str | None = None, failure_message: str | None = None) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute("SELECT status, workspace_id FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] == status:
                return self.get_scan(scan_id)
            require_status_transition(row["status"], status)
            timestamp = utc_now()
            completed_at = timestamp if status in ("completed", "cancelled", "failed") else None
            connection.execute(
                """
                UPDATE scans SET status=?, failure_code=?, failure_message=?, completed_at=?, owner_session_id=NULL,
                    heartbeat_at=NULL, handoff_state=?, updated_at=? WHERE id=?
                """,
                (status, failure_code, failure_message, completed_at, "available" if status == "interrupted" else "none", timestamp, scan_id),
            )
            if status == "completed":
                connection.execute(
                    "UPDATE scan_progress SET phase_percent=100, overall_percent=100, message='Completed', updated_at=? WHERE scan_id=?",
                    (timestamp, scan_id),
                )
            connection.execute(
                "UPDATE workspaces SET active_scan_id=NULL, updated_at=? WHERE id=? AND active_scan_id=?",
                (timestamp, row["workspace_id"], scan_id),
            )
        return self.get_scan(scan_id)

    def complete_scan(self, scan_id: str) -> dict[str, Any]:
        return self._finish_scan(scan_id, "completed")

    def fail_unsealed_completion(self, scan_id: str, code: str, message: str) -> dict[str, Any]:
        """Revoke a just-completed scan when final sealing fails.

        This narrow transition is allowed only before a manifest digest has been
        committed. It prevents a scan from remaining completed without a valid
        canonical bundle.
        """

        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT status, sealed_manifest_digest, workspace_id FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] != "completed" or row["sealed_manifest_digest"]:
                raise EngineError(
                    "completion_already_sealed",
                    "Only an unsealed completed scan may be revoked after finalization failure.",
                )
            connection.execute(
                """
                UPDATE scans SET status='failed', failure_code=?, failure_message=?, completed_at=?,
                    updated_at=? WHERE id=?
                """,
                (code, message[:4000], timestamp, timestamp, scan_id),
            )
            connection.execute(
                """
                UPDATE scan_progress SET message='Finalization failed', updated_at=? WHERE scan_id=?
                """,
                (timestamp, scan_id),
            )
        return self.get_scan(scan_id)

    def cancel_scan(self, scan_id: str) -> dict[str, Any]:
        return self._finish_scan(scan_id, "cancelled")

    def fail_scan(self, scan_id: str, code: str, message: str) -> dict[str, Any]:
        return self._finish_scan(scan_id, "failed", failure_code=code, failure_message=message[:4000])

    def interrupt_scan(self, scan_id: str) -> dict[str, Any]:
        return self._finish_scan(scan_id, "interrupted")

    def interrupt_owned_scans(self, session_id: str) -> list[str]:
        connection = self._connect()
        try:
            ids = [row["id"] for row in connection.execute(
                "SELECT id FROM scans WHERE owner_session_id=? AND status='running'", (session_id,)
            ).fetchall()]
        finally:
            connection.close()
        for scan_id in ids:
            try:
                self.interrupt_scan(scan_id)
            except EngineError:
                pass
        return ids

    def add_event(self, event_name: str, payload: dict[str, Any], scan_id: str | None = None) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO engine_events(scan_id, event_name, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (scan_id, event_name, json.dumps(payload, separators=(",", ":"), allow_nan=False), utc_now()),
            )
            return int(cursor.lastrowid)

    def events_since(self, sequence: int, limit: int = 200) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM engine_events WHERE sequence>? ORDER BY sequence LIMIT ?",
                (max(0, sequence), max(1, min(limit, 1000))),
            ).fetchall()
            return [
                {
                    "sequence": row["sequence"],
                    "scanId": row["scan_id"],
                    "event": row["event_name"],
                    "payload": json.loads(row["payload_json"]),
                    "createdAt": row["created_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def add_artifact(self, scan_id: str, kind: str, path: Path, media_type: str) -> dict[str, Any]:
        digest = sha256_file(path)
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO scan_artifacts(scan_id, kind, path, sha256, media_type, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id, kind) DO UPDATE SET path=excluded.path, sha256=excluded.sha256,
                    media_type=excluded.media_type, created_at=excluded.created_at
                """,
                (scan_id, kind, str(path), digest, media_type, timestamp),
            )
        return {"kind": kind, "path": str(path), "sha256": digest, "mediaType": media_type, "createdAt": timestamp}

    def artifact_records(self, scan_id: str) -> list[dict[str, Any]]:
        return self.get_scan(scan_id)["artifacts"]

    def save_manifest_digest(self, scan_id: str, digest: str) -> None:
        with self.transaction() as connection:
            connection.execute("UPDATE scans SET sealed_manifest_digest=?, updated_at=? WHERE id=?", (digest, utc_now(), scan_id))

    def complete_and_seal_scan_bundle(
        self,
        scan_id: str,
        *,
        completed_at: str,
        coverage: dict[str, Any],
        manifest_digest: str,
        artifact_records: list[dict[str, Any]],
        publish_files: Callable[[], None] | None = None,
        hardening_record: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically publish completion together with the validated sealed bundle.

        No reader can observe ``status=completed`` without the canonical
        coverage document, manifest digest, and artifact registry being present.
        Human-readable projections may be registered in this transaction for
        consistent UI visibility, but the manifest itself identifies the
        canonical sealed-artifact set and excludes those derived files.  The
        optional file publisher runs after the pending terminal update and
        before COMMIT, so no reader observes completed state without the files.
        """

        with self.transaction() as connection:
            scan = connection.execute(
                "SELECT status, phase, workspace_id, sealed_manifest_digest FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
            if scan is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if scan["status"] != "running" or scan["phase"] != "reporting":
                raise EngineError(
                    "finalizer_wrong_state",
                    "Only a running scan in the reporting phase can be atomically completed and sealed.",
                )
            if scan["sealed_manifest_digest"]:
                raise EngineError("scan_already_sealed", "The scan already has a sealed manifest digest.")
            require_status_transition(scan["status"], "completed")
            for record in artifact_records:
                connection.execute(
                    """
                    INSERT INTO scan_artifacts(scan_id, kind, path, sha256, media_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, kind) DO UPDATE SET path=excluded.path, sha256=excluded.sha256,
                        media_type=excluded.media_type, created_at=excluded.created_at
                    """,
                    (
                        scan_id, record["kind"], record["path"], record["sha256"],
                        record["mediaType"], record.get("createdAt") or completed_at,
                    ),
                )
            connection.execute(
                """
                UPDATE scans SET status='completed', failure_code=NULL, failure_message=NULL,
                    completed_at=?, owner_session_id=NULL, heartbeat_at=NULL, handoff_state='none',
                    coverage_json=?, sealed_manifest_digest=?, updated_at=?
                WHERE id=? AND status='running' AND phase='reporting'
                """,
                (
                    completed_at,
                    json.dumps(coverage, separators=(",", ":"), allow_nan=False),
                    manifest_digest,
                    completed_at,
                    scan_id,
                ),
            )
            connection.execute(
                "UPDATE scan_progress SET phase_percent=100, overall_percent=100, message='Completed', updated_at=? WHERE scan_id=?",
                (completed_at, scan_id),
            )
            connection.execute(
                "UPDATE workspaces SET active_scan_id=NULL, updated_at=? WHERE id=? AND active_scan_id=?",
                (completed_at, scan["workspace_id"], scan_id),
            )
            if hardening_record is not None:
                connection.execute(
                    """
                    INSERT INTO hardening_proposals(id, scan_id, title, summary, artifact_path, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET title=excluded.title, summary=excluded.summary,
                        artifact_path=excluded.artifact_path, updated_at=excluded.updated_at
                    """,
                    (
                        stable_id("hard", scan_id), scan_id, hardening_record["title"],
                        hardening_record["summary"], hardening_record["artifactPath"],
                        completed_at, completed_at,
                    ),
                )
            if publish_files is not None:
                publish_files()
        return self.get_scan(scan_id)

    def seal_scan_bundle(
        self,
        scan_id: str,
        *,
        coverage: dict[str, Any],
        manifest_digest: str,
        artifact_records: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Atomically register the validated bundle and its manifest digest."""

        timestamp = utc_now()
        with self.transaction() as connection:
            scan = connection.execute(
                "SELECT status, completed_at, sealed_manifest_digest FROM scans WHERE id=?",
                (scan_id,),
            ).fetchone()
            if scan is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if scan["status"] != "completed" or not scan["completed_at"]:
                raise EngineError("scan_not_completed", "The canonical bundle can be sealed only after scan completion.")
            existing_digest = scan["sealed_manifest_digest"]
            if existing_digest and existing_digest != manifest_digest:
                raise EngineError("scan_already_sealed", "The scan already has a different sealed manifest digest.")
            for record in artifact_records:
                connection.execute(
                    """
                    INSERT INTO scan_artifacts(scan_id, kind, path, sha256, media_type, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scan_id, kind) DO UPDATE SET path=excluded.path, sha256=excluded.sha256,
                        media_type=excluded.media_type, created_at=excluded.created_at
                    """,
                    (
                        scan_id, record["kind"], record["path"], record["sha256"],
                        record["mediaType"], record.get("createdAt") or timestamp,
                    ),
                )
            connection.execute(
                """
                UPDATE scans SET coverage_json=?, sealed_manifest_digest=?, updated_at=? WHERE id=?
                """,
                (
                    json.dumps(coverage, separators=(",", ":"), allow_nan=False),
                    manifest_digest, timestamp, scan_id,
                ),
            )
        return artifact_records

    def upsert_finding(self, scan_id: str, candidate: dict[str, Any]) -> dict[str, Any]:
        fingerprint = candidate["fingerprint"]
        finding_id = stable_id("kspf", fingerprint)
        occurrence_id = stable_id("occ", scan_id, finding_id)
        timestamp = utc_now()
        severity = candidate["severity"]
        confidence = candidate["confidence"]
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO findings(id, fingerprint, rule_id, identity_anchor, identity_instance, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET rule_id=excluded.rule_id, identity_anchor=excluded.identity_anchor,
                    identity_instance=excluded.identity_instance, updated_at=excluded.updated_at
                """,
                (
                    finding_id, fingerprint, candidate["ruleId"], candidate["identity"]["anchor"],
                    candidate["identity"].get("instance"), timestamp, timestamp,
                ),
            )
            existing = connection.execute(
                "SELECT id, created_at FROM finding_occurrences WHERE scan_id=? AND finding_id=?",
                (scan_id, finding_id),
            ).fetchone()
            created_at = existing["created_at"] if existing else timestamp
            connection.execute(
                """
                INSERT INTO finding_occurrences(
                    id, finding_id, scan_id, title, summary, severity, severity_score, severity_rationale,
                    confidence, confidence_rationale, category, cwe_json, remediation, details_json,
                    validation_status, triage_status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unvalidated', 'open', ?, ?)
                ON CONFLICT(scan_id, finding_id) DO UPDATE SET title=excluded.title, summary=excluded.summary,
                    severity=excluded.severity, severity_score=excluded.severity_score,
                    severity_rationale=excluded.severity_rationale, confidence=excluded.confidence,
                    confidence_rationale=excluded.confidence_rationale, category=excluded.category,
                    cwe_json=excluded.cwe_json, remediation=excluded.remediation,
                    details_json=excluded.details_json, updated_at=excluded.updated_at
                """,
                (
                    occurrence_id, finding_id, scan_id, candidate["title"], candidate["summary"], severity["level"],
                    severity.get("score"), severity.get("rationale"), confidence["level"], confidence["rationale"],
                    candidate["taxonomy"]["category"], json.dumps(candidate["taxonomy"].get("cwe", [])),
                    candidate["remediation"], json.dumps(candidate.get("details", {}), separators=(",", ":")),
                    created_at, timestamp,
                ),
            )
            connection.execute("DELETE FROM finding_locations WHERE occurrence_id=?", (occurrence_id,))
            for index, location in enumerate(candidate.get("locations", [])):
                connection.execute(
                    """
                    INSERT INTO finding_locations(occurrence_id, relative_path, start_line, end_line, role, sort_order)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        occurrence_id, location["path"], int(location["startLine"]),
                        int(location.get("endLine", location["startLine"])), location.get("role", "evidence"), index,
                    ),
                )
            connection.execute("DELETE FROM finding_evidence WHERE occurrence_id=?", (occurrence_id,))
            for index, evidence in enumerate(candidate.get("codeEvidence", [])):
                evidence_id = stable_id("ev", occurrence_id, str(index), evidence["path"], str(evidence["startLine"]))
                connection.execute(
                    """
                    INSERT INTO finding_evidence(
                        id, occurrence_id, kind, label, relative_path, start_line, end_line, language, role,
                        snippet, explanation, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id, occurrence_id, evidence.get("kind", "code"), evidence.get("label", f"Evidence {index + 1}"),
                        evidence["path"], int(evidence["startLine"]), int(evidence.get("endLine", evidence["startLine"])),
                        evidence.get("language"), evidence.get("role"), evidence.get("code", "")[:12000],
                        evidence.get("explanation", "")[:4000], timestamp,
                    ),
                )
        return self.get_finding(occurrence_id)

    def _base_finding_rows(self, scan_id: str, *, search: str | None = None) -> list[sqlite3.Row]:
        connection = self._connect()
        try:
            params: list[Any] = [scan_id]
            where = "o.scan_id=?"
            if search:
                where += " AND (o.title LIKE ? OR o.summary LIKE ? OR o.category LIKE ? OR f.rule_id LIKE ?)"
                term = f"%{search[:200]}%"
                params.extend([term, term, term, term])
            return connection.execute(
                f"""
                SELECT o.*, f.rule_id, f.fingerprint, f.identity_anchor, f.identity_instance
                FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id
                WHERE {where}
                ORDER BY CASE o.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END, o.title
                """,
                params,
            ).fetchall()
        finally:
            connection.close()

    def list_findings(self, scan_id: str, *, search: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._base_finding_rows(scan_id, search=search)[: max(1, min(limit, 2000))]
        return [self._finding_summary(row) for row in rows]

    def _finding_summary(self, row: sqlite3.Row) -> dict[str, Any]:
        connection = self._connect()
        try:
            locations = connection.execute(
                "SELECT relative_path, start_line, end_line, role FROM finding_locations WHERE occurrence_id=? ORDER BY sort_order",
                (row["id"],),
            ).fetchall()
        finally:
            connection.close()
        location_items = [
            {"path": item["relative_path"], "startLine": item["start_line"], "endLine": item["end_line"], "role": item["role"]}
            for item in locations
        ]
        return {
            "findingId": row["finding_id"],
            "occurrenceId": row["id"],
            "scanId": row["scan_id"],
            "ruleId": row["rule_id"],
            "fingerprint": row["fingerprint"],
            "identity": {"anchor": row["identity_anchor"], "instance": row["identity_instance"]},
            "title": row["title"],
            "summary": row["summary"],
            "severity": {"level": row["severity"], "score": row["severity_score"], "rationale": row["severity_rationale"]},
            "confidence": {"level": row["confidence"], "rationale": row["confidence_rationale"]},
            "taxonomy": {"category": row["category"], "cwe": json.loads(row["cwe_json"])},
            "locations": location_items,
            "remediation": row["remediation"],
            "validationStatus": row["validation_status"],
            "triageStatus": row["triage_status"],
            "updatedAt": row["updated_at"],
        }

    def get_finding(self, finding_or_occurrence_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT o.*, f.rule_id, f.fingerprint, f.identity_anchor, f.identity_instance
                FROM finding_occurrences o JOIN findings f ON f.id=o.finding_id
                WHERE o.id=? OR f.id=?
                ORDER BY o.updated_at DESC LIMIT 1
                """,
                (finding_or_occurrence_id, finding_or_occurrence_id),
            ).fetchone()
            if row is None:
                raise EngineError("finding_not_found", f"Finding not found: {finding_or_occurrence_id}")
            summary = self._finding_summary(row)
            evidence = connection.execute(
                "SELECT * FROM finding_evidence WHERE occurrence_id=? ORDER BY created_at, id", (row["id"],)
            ).fetchall()
            validation = connection.execute(
                "SELECT * FROM validation_records WHERE occurrence_id=? ORDER BY created_at DESC LIMIT 1", (row["id"],)
            ).fetchone()
            attack = connection.execute("SELECT * FROM attack_paths WHERE occurrence_id=?", (row["id"],)).fetchone()
            triage = connection.execute("SELECT * FROM triage_decisions WHERE occurrence_id=?", (row["id"],)).fetchone()
            remediation = connection.execute(
                "SELECT * FROM remediation_records WHERE occurrence_id=? ORDER BY version DESC", (row["id"],)
            ).fetchall()
            tracking = connection.execute(
                "SELECT * FROM tracking_records WHERE occurrence_id=? ORDER BY created_at DESC", (row["id"],)
            ).fetchall()
            artifacts = connection.execute(
                "SELECT kind, path, sha256, media_type, created_at FROM scan_artifacts WHERE scan_id=? ORDER BY kind",
                (row["scan_id"],),
            ).fetchall()
            related_rows = connection.execute(
                """
                SELECT other.*, f.rule_id, f.fingerprint, f.identity_anchor, f.identity_instance
                FROM finding_occurrences other JOIN findings f ON f.id=other.finding_id
                WHERE other.scan_id=? AND other.id<>? AND (other.category=? OR f.rule_id=?)
                ORDER BY CASE other.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3 ELSE 4 END, other.title LIMIT 12
                """,
                (row["scan_id"], row["id"], row["category"], row["rule_id"]),
            ).fetchall()
            summary["details"] = json.loads(row["details_json"])
            summary["codeEvidence"] = [
                {
                    "id": item["id"], "kind": item["kind"], "label": item["label"],
                    "path": item["relative_path"], "startLine": item["start_line"], "endLine": item["end_line"],
                    "language": item["language"], "role": item["role"], "code": item["snippet"],
                    "explanation": item["explanation"],
                }
                for item in evidence
            ]
            summary["validation"] = None if validation is None else {
                "id": validation["id"], "status": validation["status"], "method": validation["method"],
                "rationale": validation["rationale"], "evidence": json.loads(validation["evidence_json"]),
                "createdAt": validation["created_at"],
            }
            summary["attackPath"] = None if attack is None else {
                "id": attack["id"], "narrative": attack["narrative"], "path": json.loads(attack["path_json"]),
                "exploitability": attack["exploitability"], "impact": attack["impact"],
                "severityRationale": attack["severity_rationale"],
            }
            summary["triage"] = None if triage is None else {
                "decision": triage["decision"], "note": triage["note"], "updatedAt": triage["updated_at"]
            }
            summary["remediationRecords"] = [dict(item) for item in remediation]
            summary["trackingRecords"] = [dict(item) for item in tracking]
            summary["artifactLinks"] = [
                {
                    "kind": item["kind"], "path": item["path"], "sha256": item["sha256"],
                    "mediaType": item["media_type"], "createdAt": item["created_at"],
                }
                for item in artifacts
            ]
            summary["relatedFindings"] = [self._finding_summary(item) for item in related_rows]
            return summary
        finally:
            connection.close()

    def save_validation(self, occurrence_id: str, result: dict[str, Any]) -> dict[str, Any]:
        record_id = random_id("val")
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT id FROM finding_occurrences WHERE id=?", (occurrence_id,)).fetchone()
            if row is None:
                raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
            connection.execute(
                "INSERT INTO validation_records(id, occurrence_id, status, method, rationale, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    record_id, occurrence_id, result["status"], result.get("method", "static_trace"),
                    result["rationale"], json.dumps(result.get("evidence", []), separators=(",", ":")), timestamp,
                ),
            )
            connection.execute(
                "UPDATE finding_occurrences SET validation_status=?, updated_at=? WHERE id=?",
                (result["status"], timestamp, occurrence_id),
            )
        return self.get_finding(occurrence_id)

    def save_attack_path(self, occurrence_id: str, result: dict[str, Any]) -> dict[str, Any]:
        attack_id = stable_id("path", occurrence_id)
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO attack_paths(id, occurrence_id, narrative, path_json, exploitability, impact, severity_rationale, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(occurrence_id) DO UPDATE SET narrative=excluded.narrative, path_json=excluded.path_json,
                    exploitability=excluded.exploitability, impact=excluded.impact,
                    severity_rationale=excluded.severity_rationale, updated_at=excluded.updated_at
                """,
                (
                    attack_id, occurrence_id, result["narrative"], json.dumps(result["path"], separators=(",", ":")),
                    result["exploitability"], result["impact"], result["severityRationale"], timestamp, timestamp,
                ),
            )
        return self.get_finding(occurrence_id)

    def triage_finding(self, occurrence_id: str, decision: str, note: str | None) -> dict[str, Any]:
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute("SELECT id FROM finding_occurrences WHERE id=?", (occurrence_id,)).fetchone()
            if row is None:
                raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
            connection.execute(
                """
                INSERT INTO triage_decisions(occurrence_id, decision, note, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(occurrence_id) DO UPDATE SET decision=excluded.decision, note=excluded.note, updated_at=excluded.updated_at
                """,
                (occurrence_id, decision, note[:4000] if note else None, timestamp, timestamp),
            )
            connection.execute(
                "UPDATE finding_occurrences SET triage_status=?, updated_at=? WHERE id=?",
                (decision, timestamp, occurrence_id),
            )
        return self.get_finding(occurrence_id)

    def save_remediation(self, occurrence_id: str, summary: str, artifact_path: str | None) -> dict[str, Any]:
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM remediation_records WHERE occurrence_id=?", (occurrence_id,)
            ).fetchone()
            version = int(row["version"]) + 1
            record_id = random_id("rem")
            connection.execute(
                """
                INSERT INTO remediation_records(id, occurrence_id, state, version, summary, artifact_path, created_at, updated_at)
                VALUES (?, ?, 'generated', ?, ?, ?, ?, ?)
                """,
                (record_id, occurrence_id, version, summary[:8000], artifact_path, timestamp, timestamp),
            )
        return self.get_finding(occurrence_id)

    def save_hardening(self, scan_id: str, title: str, summary: str, artifact_path: Path) -> dict[str, Any]:
        proposal_id = stable_id("hard", scan_id)
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO hardening_proposals(id, scan_id, title, summary, artifact_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET title=excluded.title, summary=excluded.summary,
                    artifact_path=excluded.artifact_path, updated_at=excluded.updated_at
                """,
                (proposal_id, scan_id, title, summary, str(artifact_path), timestamp, timestamp),
            )
        return {"id": proposal_id, "scanId": scan_id, "title": title, "summary": summary, "artifactPath": str(artifact_path)}

    def save_export(self, scan_id: str, format_name: str, path: Path) -> dict[str, Any]:
        export_id = random_id("export")
        digest = sha256_file(path)
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO export_records(id, scan_id, format, path, sha256, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (export_id, scan_id, format_name, str(path), digest, timestamp),
            )
        return {"id": export_id, "scanId": scan_id, "format": format_name, "path": str(path), "sha256": digest, "createdAt": timestamp}

    def save_tracking_handoff(
        self, occurrence_id: str, provider: str, destination: str, payload_path: Path
    ) -> dict[str, Any]:
        record_id = random_id("track")
        digest = sha256_file(payload_path)
        timestamp = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT scan_id FROM finding_occurrences WHERE id=?", (occurrence_id,)
            ).fetchone()
            if row is None:
                raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
            connection.execute(
                """
                INSERT INTO tracking_records(
                    id, occurrence_id, provider, destination, external_id, external_url,
                    payload_sha256, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, NULL, NULL, ?, 'prepared', ?, ?)
                """,
                (record_id, occurrence_id, provider, destination, digest, timestamp, timestamp),
            )
        return {
            "id": record_id, "occurrenceId": occurrence_id, "provider": provider,
            "destination": destination, "payloadPath": str(payload_path), "payloadSha256": digest,
            "status": "prepared", "createdAt": timestamp, "updatedAt": timestamp,
        }

    def cleanup_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.get_scan(scan_id)
        if scan["status"] in ("queued", "running"):
            raise EngineError("scan_active", "Active scans must be cancelled before cleanup.")
        export_paths: list[str] = []
        with self.transaction() as connection:
            export_paths = [
                row["path"] for row in connection.execute(
                    "SELECT path FROM export_records WHERE scan_id=?", (scan_id,)
                ).fetchall()
            ]
            deleted = connection.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount
            if not deleted:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            connection.execute(
                "DELETE FROM findings WHERE id NOT IN (SELECT DISTINCT finding_id FROM finding_occurrences)"
            )

        removed: list[str] = []
        skipped: list[str] = []
        for raw in [scan["artifact_dir"], *export_paths]:
            candidate = Path(raw)
            try:
                absolute = candidate.absolute()
                relative = absolute.relative_to(self.state_dir.absolute())
                if not relative.parts:
                    raise ValueError("state directory root")
                if candidate.is_symlink() or candidate.is_file():
                    candidate.unlink(missing_ok=True)
                elif candidate.is_dir():
                    shutil.rmtree(candidate)
                removed.append(str(candidate))
            except (OSError, ValueError):
                skipped.append(str(candidate))
        return {"scanId": scan_id, "removedPaths": removed, "skippedPaths": skipped}

    def scan_counts(self, scan_id: str) -> dict[str, int]:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT COUNT(*) AS total,
                    SUM(CASE WHEN validation_status='validated' THEN 1 ELSE 0 END) AS validated,
                    SUM(CASE WHEN validation_status='needs_review' THEN 1 ELSE 0 END) AS needs_review,
                    SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) AS high_or_critical
                FROM finding_occurrences WHERE scan_id=?
                """,
                (scan_id,),
            ).fetchone()
            return {key: int(row[key] or 0) for key in ("total", "validated", "needs_review", "high_or_critical")}
        finally:
            connection.close()
