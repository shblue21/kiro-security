from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterator

from .constants import ARTIFACT_KINDS, PHASES
from .coverage import COVERAGE_DISPOSITIONS
from .errors import EngineError
from .security import random_id, sha256_bytes, sha256_file, stable_id, utc_now
from .state_machine import require_phase_transition, require_status_transition


def _sql_statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines():
        buffer = f"{buffer}\n{line}".strip()
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ""
    if buffer:
        raise ValueError("Incomplete SQLite migration statement.")
    return statements


def _sqlite_busy(error: sqlite3.OperationalError) -> bool:
    message = str(error).lower()
    return "locked" in message or "busy" in message


# A lease must safely span one native-worker batch; coordinators renew it at
# phase boundaries. Expired/crashed holders remain recoverable without tying
# the durable scan lifecycle to an Engine process.
COORDINATOR_LEASE_TTL_SECONDS = 3600


def _coordinator_lease_expiry() -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=COORDINATOR_LEASE_TTL_SECONDS)
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _coordinator_token() -> str:
    # 32 random bytes provide the required 256 bits of CSPRNG entropy.
    return secrets.token_hex(32)


def _coordinator_token_hash(token: str) -> str:
    return sha256_bytes(token.encode("utf-8"))


def _updated_after(current: str) -> str:
    """Return a workspace version timestamp strictly newer than ``current``."""
    candidate = datetime.now(timezone.utc)
    try:
        previous = datetime.fromisoformat(current.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise EngineError(
            "legacy_workspace_incompatible",
            "The workspace configuration version is invalid.",
        ) from exc
    if candidate <= previous:
        candidate = previous + timedelta(milliseconds=1)
    return candidate.isoformat(timespec="milliseconds").replace("+00:00", "Z")


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

    def _connect(self, *, foreign_keys: bool = True) -> sqlite3.Connection:
        for attempt in range(5):
            connection = sqlite3.connect(self.db_path, timeout=15, isolation_level=None)
            try:
                connection.row_factory = sqlite3.Row
                connection.execute(f"PRAGMA foreign_keys = {'ON' if foreign_keys else 'OFF'}")
                connection.execute("PRAGMA busy_timeout = 15000")
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
                return connection
            except sqlite3.OperationalError as exc:
                connection.close()
                if attempt == 4 or not _sqlite_busy(exc):
                    raise EngineError("database_error", f"Unable to open workbench database: {exc}") from exc
                time.sleep(0.05 * (2**attempt))
            except sqlite3.DatabaseError as exc:
                connection.close()
                raise EngineError("database_error", f"Unable to open workbench database: {exc}") from exc
        raise AssertionError("SQLite retry loop exhausted unexpectedly.")

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

    @staticmethod
    def _scan_child_row_counts(connection: sqlite3.Connection) -> dict[str, int]:
        counts = {"scans": int(connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0])}
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall()
        ]
        for table in tables:
            # workspaces.active_scan_id is the current-result pointer, not a
            # scan-owned child row. v13 may intentionally split legacy
            # repository workspaces by immutable scan setup.
            if table in ("scans", "workspaces"):
                continue
            if any(row[2] == "scans" for row in connection.execute(f'PRAGMA foreign_key_list("{table}")')):
                counts[table] = int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        return counts

    @staticmethod
    def _create_coordinator_lease_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_coordinator_leases (
                scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash) = 64),
                generation INTEGER NOT NULL CHECK(generation >= 1),
                holder_session_id TEXT REFERENCES engine_sessions(id) ON DELETE SET NULL,
                acquired_at TEXT NOT NULL,
                renewed_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS coordinator_leases_by_expiry ON scan_coordinator_leases(expires_at)"
        )

    @classmethod
    def _apply_scan_coordinator_lease_migration(cls, connection: sqlite3.Connection) -> None:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        legacy_columns = {
            "owner_session_id", "heartbeat_at", "handoff_state", "resumed_at", "resume_count",
        }
        table_sql = str(connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()[0])
        needs_rebuild = bool(columns & legacy_columns) or "'queued'" in table_sql or "'interrupted'" in table_sql
        if needs_rebuild:
            incompatible = {
                row["status"]: int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM scans WHERE status IN ('queued','interrupted') GROUP BY status"
                ).fetchall()
            }
            if incompatible:
                raise EngineError(
                    "legacy_scan_incompatible",
                    "Queued or interrupted legacy scans cannot be reinterpreted under the Codex lifecycle contract.",
                    {"incompatibleStatusCounts": incompatible},
                )
            before = cls._scan_child_row_counts(connection)
            objects = [
                (row[0], row[1], row[2])
                for row in connection.execute(
                    """
                    SELECT type, name, sql FROM sqlite_master
                    WHERE tbl_name='scans' AND type IN ('index','trigger') AND sql IS NOT NULL
                    ORDER BY type, name
                    """
                ).fetchall()
            ]
            connection.execute(
                """
                CREATE TABLE scans_v012 (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                    mode TEXT NOT NULL CHECK (mode IN ('diff','standard','deep')),
                    scope TEXT NOT NULL,
                    diff_target_kind TEXT CHECK (diff_target_kind IN ('working_tree','commit','range')),
                    diff_base_revision TEXT,
                    diff_head_revision TEXT,
                    status TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),
                    phase TEXT NOT NULL CHECK (phase IN ('preflight','threat_model','discovery','validation','attack_path','reporting')),
                    phase_index INTEGER NOT NULL DEFAULT 0 CHECK (phase_index BETWEEN 0 AND 5),
                    artifact_dir TEXT NOT NULL UNIQUE,
                    target_identity TEXT,
                    target_revision TEXT,
                    snapshot_digest TEXT,
                    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancellation_requested IN (0,1)),
                    failure_code TEXT,
                    failure_message TEXT,
                    started_at TEXT,
                    completed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    sealed_manifest_digest TEXT,
                    target_device INTEGER,
                    target_inode INTEGER,
                    files_total INTEGER NOT NULL DEFAULT 0,
                    files_completed INTEGER NOT NULL DEFAULT 0,
                    coverage_json TEXT,
                    capability_json TEXT
                )
                """
            )
            preserved = (
                "id,workspace_id,mode,scope,diff_target_kind,diff_base_revision,diff_head_revision,"
                "status,phase,phase_index,artifact_dir,target_identity,target_revision,snapshot_digest,"
                "cancellation_requested,failure_code,failure_message,started_at,completed_at,created_at,updated_at,"
                "sealed_manifest_digest,target_device,target_inode,files_total,files_completed,coverage_json,capability_json"
            )
            connection.execute(
                f"INSERT INTO scans_v012({preserved}) SELECT {preserved} FROM scans"
            )
            connection.execute("DROP TABLE scans")
            connection.execute("ALTER TABLE scans_v012 RENAME TO scans")
            for _object_type, _name, sql in objects:
                connection.execute(sql)
            after = cls._scan_child_row_counts(connection)
            if before != after:
                raise EngineError(
                    "migration_row_count_changed",
                    "The scan ownership migration changed scan or child-table row counts.",
                    {"before": before, "after": after},
                )
        cls._create_coordinator_lease_table(connection)

    @classmethod
    def _apply_lifecycle_authority_migration(cls, connection: sqlite3.Connection) -> None:
        """Move lifecycle configuration to workspace and scan columns.

        The legacy JSON value is consulted only to migrate the optional user
        context.  Existing mode, scope, Diff, target, and lifecycle columns are
        copied verbatim and remain authoritative throughout the rebuild.
        """

        workspace_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
        for name, declaration in (
            ("user_context", "TEXT"),
            (
                "diff_target_kind",
                "TEXT CHECK (diff_target_kind IN ('working_tree','commit','range'))",
            ),
            ("diff_base_revision", "TEXT"),
            ("diff_head_revision", "TEXT"),
        ):
            if name not in workspace_columns:
                connection.execute(
                    f'ALTER TABLE workspaces ADD COLUMN "{name}" {declaration}'
                )

        scan_columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)")}
        required_columns = {
            "id", "workspace_id", "mode", "scope", "diff_target_kind",
            "diff_base_revision", "diff_head_revision", "status", "phase",
            "phase_index", "artifact_dir", "target_identity", "target_revision",
            "snapshot_digest", "cancellation_requested", "failure_code",
            "failure_message", "started_at", "completed_at", "created_at",
            "updated_at", "sealed_manifest_digest", "target_device", "target_inode",
            "files_total", "files_completed", "coverage_json",
        }
        missing = sorted(required_columns - scan_columns)
        if missing:
            raise EngineError(
                "legacy_scan_incompatible",
                "The existing scan schema cannot be converted to column-owned lifecycle state.",
                {"missingColumns": missing},
            )

        user_contexts: dict[str, str | None] = {}
        if "capability_json" in scan_columns:
            rows = connection.execute(
                "SELECT id, capability_json FROM scans ORDER BY id"
            ).fetchall()
            for row in rows:
                raw = row["capability_json"]
                if raw is None:
                    user_contexts[row["id"]] = None
                    continue
                try:
                    value = json.loads(raw)
                except (TypeError, json.JSONDecodeError) as exc:
                    raise EngineError(
                        "legacy_scan_incompatible",
                        "A legacy scan has user context that cannot be converted safely.",
                        {"scanId": row["id"]},
                    ) from exc
                context = value.get("userContext") if isinstance(value, dict) else object()
                if context is not None and (
                    not isinstance(context, str)
                    or len(context) > 4000
                    or "\x00" in context
                ):
                    raise EngineError(
                        "legacy_scan_incompatible",
                        "A legacy scan has user context that cannot be converted safely.",
                        {"scanId": row["id"]},
                    )
                user_contexts[row["id"]] = context
        elif "user_context" in scan_columns:
            user_contexts = {
                row["id"]: row["user_context"]
                for row in connection.execute(
                    "SELECT id, user_context FROM scans ORDER BY id"
                ).fetchall()
            }
        else:
            user_contexts = {
                row["id"]: None
                for row in connection.execute("SELECT id FROM scans ORDER BY id").fetchall()
            }

        before = cls._scan_child_row_counts(connection)
        objects = [
            (row[0], row[1], row[2])
            for row in connection.execute(
                """
                SELECT type, name, sql FROM sqlite_master
                WHERE tbl_name='scans' AND type IN ('index','trigger') AND sql IS NOT NULL
                ORDER BY type, name
                """
            ).fetchall()
        ]
        connection.execute(
            """
            CREATE TABLE scans_v013 (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                mode TEXT NOT NULL CHECK (mode IN ('diff','standard','deep')),
                scope TEXT NOT NULL,
                user_context TEXT,
                diff_target_kind TEXT CHECK (diff_target_kind IN ('working_tree','commit','range')),
                diff_base_revision TEXT,
                diff_head_revision TEXT,
                diff_content_digest TEXT,
                status TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),
                phase TEXT NOT NULL CHECK (phase IN ('preflight','threat_model','discovery','validation','attack_path','reporting')),
                phase_index INTEGER NOT NULL DEFAULT 0 CHECK (phase_index BETWEEN 0 AND 5),
                artifact_dir TEXT NOT NULL UNIQUE,
                target_identity TEXT,
                target_revision TEXT,
                snapshot_digest TEXT,
                cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancellation_requested IN (0,1)),
                failure_code TEXT,
                failure_message TEXT,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                sealed_manifest_digest TEXT,
                target_device INTEGER,
                target_inode INTEGER,
                files_total INTEGER NOT NULL DEFAULT 0,
                files_completed INTEGER NOT NULL DEFAULT 0,
                coverage_json TEXT
            )
            """
        )
        source_user_context = "user_context" if "user_context" in scan_columns else "NULL"
        connection.execute(
            f"""
            INSERT INTO scans_v013(
                id,workspace_id,mode,scope,user_context,diff_target_kind,
                diff_base_revision,diff_head_revision,diff_content_digest,status,phase,phase_index,
                artifact_dir,target_identity,target_revision,snapshot_digest,
                cancellation_requested,failure_code,failure_message,started_at,
                completed_at,created_at,updated_at,sealed_manifest_digest,
                target_device,target_inode,files_total,files_completed,coverage_json
            )
            SELECT
                id,workspace_id,mode,scope,{source_user_context},diff_target_kind,
                diff_base_revision,diff_head_revision,NULL,status,phase,phase_index,
                artifact_dir,target_identity,target_revision,snapshot_digest,
                cancellation_requested,failure_code,failure_message,started_at,
                completed_at,created_at,updated_at,sealed_manifest_digest,
                target_device,target_inode,files_total,files_completed,coverage_json
            FROM scans
            """
        )
        connection.executemany(
            "UPDATE scans_v013 SET user_context=? WHERE id=?",
            [(context, scan_id) for scan_id, context in user_contexts.items()],
        )
        connection.execute("DROP TABLE scans")
        connection.execute("ALTER TABLE scans_v013 RENAME TO scans")
        for _object_type, _name, sql in objects:
            connection.execute(sql)

        # A Codex workspace is one immutable submitted setup, not a repository.
        # Legacy Kiro databases stored every setup under one root-keyed row, so
        # split its scan history by the scan-row configuration that was already
        # authoritative.  No legacy JSON value may rewrite those rows.
        legacy_workspaces = [
            dict(row) for row in connection.execute(
                "SELECT * FROM workspaces ORDER BY created_at, id"
            ).fetchall()
        ]
        connection.execute(
            """
            CREATE TABLE workspaces_v013 (
                id TEXT PRIMARY KEY,
                thread_id TEXT,
                root_path TEXT NOT NULL,
                display_name TEXT NOT NULL,
                target_summary TEXT,
                default_scope TEXT NOT NULL DEFAULT '.',
                default_mode TEXT NOT NULL DEFAULT 'standard'
                    CHECK (default_mode IN ('diff','standard','deep')),
                user_context TEXT,
                diff_target_kind TEXT
                    CHECK (diff_target_kind IN ('working_tree','commit','range')),
                diff_base_revision TEXT,
                diff_head_revision TEXT,
                diff_content_digest TEXT,
                diff_resolution_id TEXT,
                submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0,1)),
                active_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        for legacy in legacy_workspaces:
            scan_rows = [
                dict(row) for row in connection.execute(
                    "SELECT * FROM scans WHERE workspace_id=? ORDER BY created_at, id",
                    (legacy["id"],),
                ).fetchall()
            ]
            groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
            for scan in scan_rows:
                configuration = (
                    scan["mode"], scan["scope"], scan["user_context"],
                    scan["diff_target_kind"], scan["diff_base_revision"],
                    scan["diff_head_revision"], scan["diff_content_digest"],
                )
                groups.setdefault(configuration, []).append(scan)
            if not groups:
                groups[(
                    legacy["default_mode"], legacy["default_scope"],
                    legacy.get("user_context"), legacy.get("diff_target_kind"),
                    legacy.get("diff_base_revision"), legacy.get("diff_head_revision"),
                    None,
                )] = []

            owner = legacy.get("thread_id") or f"legacy:{legacy['id']}"
            for configuration, grouped_scans in groups.items():
                workspace_id = str(uuid.uuid4())
                current = next(
                    (scan for scan in grouped_scans if scan["status"] == "running"),
                    grouped_scans[-1] if grouped_scans else None,
                )
                created_at = grouped_scans[0]["created_at"] if grouped_scans else legacy["created_at"]
                updated_at = current["updated_at"] if current else legacy["updated_at"]
                connection.execute(
                    """
                    INSERT INTO workspaces_v013(
                        id,thread_id,root_path,display_name,target_summary,
                        default_mode,default_scope,user_context,diff_target_kind,
                        diff_base_revision,diff_head_revision,diff_content_digest,
                        diff_resolution_id,submitted,active_scan_id,created_at,updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id, owner, legacy["root_path"], legacy["display_name"],
                        legacy.get("target_summary"), *configuration,
                        1 if grouped_scans else int(legacy.get("submitted") or 0),
                        current["id"] if current else None, created_at, updated_at,
                    ),
                )
                if grouped_scans:
                    connection.executemany(
                        "UPDATE scans SET workspace_id=? WHERE id=?",
                        [(workspace_id, scan["id"]) for scan in grouped_scans],
                    )
        connection.execute("DROP TABLE workspaces")
        connection.execute("ALTER TABLE workspaces_v013 RENAME TO workspaces")
        connection.execute(
            "CREATE INDEX workspaces_by_root_and_updated_at ON workspaces(root_path, updated_at DESC)"
        )
        connection.execute(
            "CREATE INDEX workspaces_by_thread_and_updated_at ON workspaces(thread_id, updated_at DESC)"
        )
        after = cls._scan_child_row_counts(connection)
        if before != after:
            raise EngineError(
                "migration_row_count_changed",
                "The lifecycle-authority migration changed scan or child-table row counts.",
                {"before": before, "after": after},
            )

    def apply_migrations(self) -> None:
        migration_files = sorted(self.migrations_dir.glob("[0-9][0-9][0-9]_*.sql"))
        if not migration_files:
            raise EngineError("migration_missing", f"No migrations found in {self.migrations_dir}")
        existed = self.db_path.exists() and self.db_path.stat().st_size > 0
        # Parent-table rebuilds require this connection-local setting before
        # BEGIN. Runtime connections always restore and enforce foreign keys.
        connection = self._connect(foreign_keys=False)
        applied_any = False
        migration_name = "schema initialization"
        try:
            def begin_and_resolve_pending() -> tuple[int, list[Path]]:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
                )
                applied = {
                    int(row["version"])
                    for row in connection.execute("SELECT version FROM schema_migrations")
                }
                current_version = max(applied, default=0)
                return current_version, [
                    path for path in migration_files if int(path.name[:3]) not in applied
                ]

            current, pending = begin_and_resolve_pending()
            migration_stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + f".p{os.getpid()}"
            if pending and existed:
                connection.execute("ROLLBACK")
                backup = self.state_dir / f"workbench.pre-migration-v{current}.{migration_stamp}.sqlite"
                destination = sqlite3.connect(backup)
                try:
                    connection.backup(destination)
                finally:
                    destination.close()
                current, pending = begin_and_resolve_pending()
            for path in pending:
                version = int(path.name[:3])
                migration_name = path.name
                if version == 12:
                    self._apply_scan_coordinator_lease_migration(connection)
                elif version == 13:
                    self._apply_lifecycle_authority_migration(connection)
                else:
                    sql = path.read_text(encoding="utf-8")
                    for statement in _sql_statements(sql):
                        connection.execute(statement)
                connection.execute(
                    "INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
                    (version, path.stem, utc_now()),
                )
                applied_any = True
            self._require_workspace_scan_invariants(connection)
            foreign_key_issues = connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_key_issues:
                raise EngineError(
                    "database_foreign_key_error",
                    "SQLite foreign_key_check failed after migration.",
                    {"violations": [list(row) for row in foreign_key_issues[:20]]},
                )
            integrity = connection.execute("PRAGMA quick_check").fetchone()[0]
            if integrity != "ok":
                raise EngineError("database_corrupt", f"SQLite quick_check failed: {integrity}")
            connection.execute("COMMIT")
            if applied_any and existed:
                final_version = int(connection.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()[0])
                post_backup = self.state_dir / f"workbench.post-migration-v{final_version}.{migration_stamp}.sqlite"
                destination = sqlite3.connect(post_backup)
                try:
                    connection.backup(destination)
                finally:
                    destination.close()
        except EngineError:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass
            raise
        except (sqlite3.DatabaseError, ValueError) as exc:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.DatabaseError:
                pass
            raise EngineError(
                "migration_failed",
                f"Migration {migration_name} failed: {exc}",
                {"migration": migration_name},
            ) from exc
        finally:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.execute("PRAGMA foreign_keys = ON")
                if int(connection.execute("PRAGMA foreign_keys").fetchone()[0]) != 1:
                    raise EngineError("database_error", "Unable to restore SQLite foreign-key enforcement.")
            except sqlite3.DatabaseError:
                pass
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

    def close_session(self, session_id: str) -> None:
        timestamp = utc_now()
        with self.transaction() as connection:
            connection.execute("UPDATE engine_sessions SET closed_at=?, heartbeat_at=? WHERE id=?", (timestamp, timestamp, session_id))

    def session_is_live(self, session_id: str, stale_after_seconds: int = 20) -> bool:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=stale_after_seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT heartbeat_at, closed_at FROM engine_sessions WHERE id=?", (session_id,)
            ).fetchone()
            return bool(row is not None and row["closed_at"] is None and row["heartbeat_at"] >= cutoff)
        finally:
            connection.close()

    def release_session_leases(self, session_id: str) -> list[str]:
        """Release execution authority without changing durable scan state."""
        with self.transaction() as connection:
            scan_ids = [
                row["scan_id"]
                for row in connection.execute(
                    "SELECT scan_id FROM scan_coordinator_leases WHERE holder_session_id=? ORDER BY scan_id",
                    (session_id,),
                ).fetchall()
            ]
            connection.execute(
                "DELETE FROM scan_coordinator_leases WHERE holder_session_id=?",
                (session_id,),
            )
        return scan_ids

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

    @staticmethod
    def _sealed_artifact_mismatch(artifact_dir: Path, manifest_path: Path) -> dict[str, Any] | None:
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            artifacts = manifest["scan"]["artifacts"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            return {"path": ARTIFACT_KINDS["manifest"], "expected": None, "actual": None, "reason": str(exc)}
        if not isinstance(artifacts, list):
            return {"path": ARTIFACT_KINDS["manifest"], "expected": None, "actual": None, "reason": "invalid artifacts"}
        root = artifact_dir.resolve(strict=True)
        for artifact in artifacts:
            relative = artifact.get("path") if isinstance(artifact, dict) else None
            expected = artifact.get("sha256") if isinstance(artifact, dict) else None
            if (
                not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative
                or PurePosixPath(relative).is_absolute() or ".." in PurePosixPath(relative).parts
                or not isinstance(expected, str)
            ):
                return {"path": relative, "expected": expected, "actual": None, "reason": "unsafe manifest artifact"}
            path = artifact_dir / relative
            actual = None
            try:
                cursor = artifact_dir
                for part in PurePosixPath(relative).parts:
                    cursor /= part
                    if cursor.is_symlink():
                        raise OSError("symlinked sealed artifact")
                resolved = path.resolve(strict=True)
                if resolved != root and root not in resolved.parents:
                    raise OSError("sealed artifact escaped artifact directory")
                if path.is_file():
                    actual = sha256_file(path)
            except OSError:
                actual = None
            if actual != expected:
                return {"path": relative, "expected": expected, "actual": actual}
        return None

    def require_intact_sealed_bundle(self, scan_id: str) -> dict[str, Any]:
        scan = self.get_scan(scan_id)
        artifact_dir = Path(scan["artifact_dir"])
        manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
        digest = scan.get("sealed_manifest_digest")
        try:
            manifest_digest = None if manifest_path.is_symlink() else sha256_file(manifest_path)
        except OSError:
            manifest_digest = None
        if scan.get("status") != "completed" or not digest or manifest_digest != digest:
            raise EngineError("sealed_bundle_invalid", "The completed scan manifest is missing or does not match its durable seal.")
        mismatch = self._sealed_artifact_mismatch(artifact_dir, manifest_path)
        if mismatch is not None:
            raise EngineError("sealed_bundle_invalid", "A sealed scan artifact is missing or changed.", mismatch)
        return json.loads(manifest_path.read_text(encoding="utf-8"))

    def reconcile_finalization_integrity(self) -> list[dict[str, Any]]:
        """Detect and repair filesystem/SQLite contradictions after a hard crash.

        Official file publication happens inside the completion transaction
        but before COMMIT, so a crash in that window can leave a completed
        manifest on disk while the durable scan state rolled back.  This
        startup pass restores the invariant that an official manifest exists
        only for a completed scan whose sealed digest and sealed artifacts
        match the file:

        - non-active scans with an official manifest but no committed seal
          have the manifest and its projections quarantined, and stale
          atomic-write temp files removed;
        - completed scans whose manifest is missing, unsealed, or does not
          match the durable sealed digest are surfaced as explicit integrity
          failures. A committed terminal lifecycle row is never rewritten by
          startup recovery.
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
                    quarantined = self._quarantine_publication(artifact_dir, stamp) if manifest_present else []
                    issues.append({
                        "scanId": row["id"],
                        "code": "completed_scan_unsealed",
                        "message": (
                            "A completed scan had no sealed manifest digest; its publication was quarantined "
                            "and the terminal lifecycle row was preserved for audit."
                        ),
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
                    else:
                        mismatch = self._sealed_artifact_mismatch(artifact_dir, manifest_path)
                        if mismatch is not None:
                            quarantined = self._quarantine_publication(artifact_dir, stamp)
                            issues.append({
                                "scanId": row["id"],
                                "code": "sealed_artifact_digest_mismatch",
                                "message": "A manifest-sealed artifact is missing or changed; the publication was quarantined.",
                                **mismatch,
                                "quarantinedPaths": quarantined,
                            })
            elif row["status"] in ("failed", "cancelled"):
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

    @staticmethod
    def _new_workspace_id() -> str:
        return str(uuid.uuid4())

    def create_workspace(self, root: Path, *, thread_id: str | None = None) -> dict[str, Any]:
        timestamp = utc_now()
        workspace_id = self._new_workspace_id()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO workspaces(
                    id,thread_id,root_path,display_name,created_at,updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    workspace_id, thread_id, str(root), root.name or str(root),
                    timestamp, timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone()
        return dict(row)

    def register_workspace(self, root: Path, *, thread_id: str | None = None) -> dict[str, Any]:
        """Read/adopt a logical workspace without mutating its saved setup."""
        with self.transaction() as connection:
            row = connection.execute(
                """
                SELECT w.* FROM workspaces w
                LEFT JOIN scans s ON s.id=w.active_scan_id
                WHERE w.root_path=? AND (? IS NULL OR w.thread_id=?)
                ORDER BY CASE WHEN s.status='running' THEN 0 ELSE 1 END,
                         w.updated_at DESC, w.created_at DESC
                LIMIT 1
                """,
                (str(root), thread_id, thread_id),
            ).fetchone()
            if row is None:
                timestamp = utc_now()
                workspace_id = self._new_workspace_id()
                connection.execute(
                    """
                    INSERT INTO workspaces(
                        id,thread_id,root_path,display_name,created_at,updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        workspace_id, thread_id, str(root), root.name or str(root),
                        timestamp, timestamp,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
                ).fetchone()
        return dict(row)

    def get_workspace(
        self, workspace_id: str | None = None, *, thread_id: str | None = None
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            if workspace_id is not None:
                row = connection.execute(
                    "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT w.* FROM workspaces w
                    LEFT JOIN scans s ON s.id=w.active_scan_id
                    WHERE w.root_path=? AND (? IS NULL OR w.thread_id=?)
                    ORDER BY CASE WHEN s.status='running' THEN 0 ELSE 1 END,
                             w.updated_at DESC, w.created_at DESC
                    LIMIT 1
                    """,
                    (str(self.workspace), thread_id, thread_id),
                ).fetchone()
            if row is None:
                raise EngineError("workspace_not_found", "The logical security workspace was not found.")
            if thread_id is not None and row["thread_id"] != thread_id:
                raise EngineError(
                    "workspace_not_found",
                    "The logical security workspace does not belong to this task.",
                )
            return dict(row)
        finally:
            connection.close()

    @staticmethod
    def workspace_configuration(row: dict[str, Any] | sqlite3.Row) -> tuple[Any, ...]:
        return (
            row["default_mode"], row["default_scope"], row["user_context"],
            row["diff_target_kind"], row["diff_base_revision"], row["diff_head_revision"],
            row["diff_content_digest"],
        )

    def save_workspace(
        self,
        workspace_id: str,
        *,
        mode: str,
        scope: str,
        user_context: str | None,
        diff_target_kind: str | None,
        diff_base_revision: str | None,
        diff_head_revision: str | None,
        diff_content_digest: str | None = None,
    ) -> dict[str, Any]:
        requested = (
            mode, scope, user_context, diff_target_kind,
            diff_base_revision, diff_head_revision, diff_content_digest,
        )
        with self.transaction() as connection:
            self._require_workspace_scan_invariants(connection, workspace_id)
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise EngineError("workspace_not_found", f"Workspace not found: {workspace_id}")
            if workspace["active_scan_id"] is not None:
                raise EngineError(
                    "workspace_setup_locked",
                    "This workspace already has a scan. Open a new workspace to change setup.",
                    {"workspaceId": workspace_id, "activeScanId": workspace["active_scan_id"]},
                )
            timestamp = _updated_after(workspace["updated_at"])
            updated = connection.execute(
                """
                UPDATE workspaces
                SET default_mode=?, default_scope=?, user_context=?, diff_target_kind=?,
                    diff_base_revision=?, diff_head_revision=?, diff_content_digest=?,
                    submitted=1, updated_at=?
                WHERE id=? AND active_scan_id IS NULL
                """,
                (*requested, timestamp, workspace_id),
            )
            if updated.rowcount != 1:
                raise EngineError(
                    "workspace_setup_locked",
                    "This workspace already has a scan. Open a new workspace to change setup.",
                )
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone()
        return dict(workspace)

    # Backwards-compatible Engine name; it now has Codex save-workspace semantics.
    configure_workspace = save_workspace

    @staticmethod
    def _require_workspace_scan_invariants(
        connection: sqlite3.Connection, workspace_id: str | None = None
    ) -> str | None:
        params: tuple[Any, ...] = () if workspace_id is None else (workspace_id,)
        where = "" if workspace_id is None else "WHERE w.id=?"
        rows = connection.execute(
            f"""
            SELECT w.id, w.active_scan_id,
                (SELECT s.id FROM scans s WHERE s.workspace_id=w.id AND s.status='running' LIMIT 1) AS running_id,
                (SELECT COUNT(*) FROM scans s WHERE s.workspace_id=w.id AND s.status='running') AS running_count
            FROM workspaces w {where}
            """,
            params,
        ).fetchall()
        if workspace_id is not None and not rows:
            raise EngineError("workspace_not_found", f"Workspace not found: {workspace_id}")
        for row in rows:
            active_belongs = (
                row["active_scan_id"] is None
                or connection.execute(
                    "SELECT 1 FROM scans WHERE id=? AND workspace_id=?",
                    (row["active_scan_id"], row["id"]),
                ).fetchone() is not None
            )
            if (
                int(row["running_count"]) > 1
                or not active_belongs
                or (row["running_id"] is not None and row["active_scan_id"] != row["running_id"])
            ):
                raise EngineError(
                    "workspace_scan_invariant",
                    "The workspace current-result pointer is inconsistent with its scan rows.",
                    {
                        "workspaceId": row["id"],
                        "activeScanId": row["active_scan_id"],
                        "runningScanId": row["running_id"],
                        "runningCount": int(row["running_count"]),
                    },
                )
        return rows[0]["running_id"] if workspace_id is not None else None

    def running_scan_for_workspace(self, workspace_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            running_id = self._require_workspace_scan_invariants(connection, workspace_id)
            row = connection.execute(
                "SELECT * FROM scans WHERE id=?", (running_id,)
            ).fetchone() if running_id is not None else None
        finally:
            connection.close()
        return dict(row) if row is not None else None

    @staticmethod
    def _lease_public(
        state: str, *, generation: int | None = None, expires_at: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {"state": state}
        if generation is not None:
            result["generation"] = generation
        if expires_at is not None:
            result["expiresAt"] = expires_at
        if token is not None:
            result["token"] = token
        return result

    def _scan_with_lease_state(
        self,
        scan: dict[str, Any],
        *,
        connection: sqlite3.Connection | None = None,
    ) -> dict[str, Any]:
        owns_connection = connection is None
        connection = connection or self._connect()
        try:
            lease = connection.execute(
                "SELECT generation, expires_at FROM scan_coordinator_leases WHERE scan_id=?",
                (scan["id"],),
            ).fetchone()
        finally:
            if owns_connection:
                connection.close()
        now = utc_now()
        if lease is None or lease["expires_at"] <= now:
            public = self._lease_public("available")
        else:
            public = self._lease_public(
                "busy", generation=int(lease["generation"]), expires_at=lease["expires_at"]
            )
        return {**scan, "coordinatorLease": public}

    @classmethod
    def _require_running_scan_invariants(
        cls,
        connection: sqlite3.Connection,
        scan_id: str,
    ) -> sqlite3.Row:
        scan = connection.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if scan is None:
            raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
        if scan["status"] != "running":
            raise EngineError("scan_not_running", f"Scan {scan_id} is {scan['status']}.")
        running_id = cls._require_workspace_scan_invariants(connection, scan["workspace_id"])
        if running_id != scan_id:
            raise EngineError(
                "workspace_scan_invariant",
                "The running scan is not the workspace's active scan.",
                {
                    "workspaceId": scan["workspace_id"],
                    "activeScanId": running_id,
                    "runningScanId": scan_id,
                },
            )
        return scan

    @classmethod
    def _require_coordinator_lease(
        cls,
        connection: sqlite3.Connection,
        scan_id: str,
        token: str,
        generation: int,
    ) -> sqlite3.Row:
        scan = cls._require_running_scan_invariants(connection, scan_id)
        lease = connection.execute(
            "SELECT token_hash, generation, expires_at FROM scan_coordinator_leases WHERE scan_id=?",
            (scan_id,),
        ).fetchone()
        supplied_hash = _coordinator_token_hash(token)
        if (
            lease is None
            or not secrets.compare_digest(str(lease["token_hash"]), supplied_hash)
            or int(lease["generation"]) != generation
            or lease["expires_at"] <= utc_now()
        ):
            raise EngineError(
                "coordinator_lease_invalid",
                "A live coordinator lease with the current generation is required for this mutation.",
                {"scanId": scan_id},
            )
        return scan

    def require_coordinator_lease(self, scan_id: str, token: str, generation: int) -> None:
        with self.transaction() as connection:
            self._require_coordinator_lease(connection, scan_id, token, generation)

    def acquire_coordinator_lease(self, scan_id: str, session_id: str) -> dict[str, Any]:
        token = _coordinator_token()
        token_hash = _coordinator_token_hash(token)
        timestamp = utc_now()
        expires_at = _coordinator_lease_expiry()
        with self.transaction() as connection:
            self._require_running_scan_invariants(connection, scan_id)
            current = connection.execute(
                "SELECT generation, expires_at FROM scan_coordinator_leases WHERE scan_id=?",
                (scan_id,),
            ).fetchone()
            if current is not None and current["expires_at"] > timestamp:
                raise EngineError(
                    "coordinator_busy",
                    "Another coordinator holds the live execution lease for this scan.",
                    {"scanId": scan_id, "expiresAt": current["expires_at"]},
                )
            generation = 1 if current is None else int(current["generation"]) + 1
            connection.execute(
                """
                INSERT INTO scan_coordinator_leases(
                    scan_id, token_hash, generation, holder_session_id, acquired_at, renewed_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET token_hash=excluded.token_hash,
                    generation=excluded.generation, holder_session_id=excluded.holder_session_id,
                    acquired_at=excluded.acquired_at, renewed_at=excluded.renewed_at,
                    expires_at=excluded.expires_at
                """,
                (scan_id, token_hash, generation, session_id, timestamp, timestamp, expires_at),
            )
        return {
            **self.get_scan(scan_id),
            "coordinatorLease": self._lease_public(
                "acquired", generation=generation, expires_at=expires_at, token=token
            ),
        }

    def renew_coordinator_lease(
        self, scan_id: str, token: str, generation: int, session_id: str
    ) -> dict[str, Any]:
        timestamp = utc_now()
        expires_at = _coordinator_lease_expiry()
        token_hash = _coordinator_token_hash(token)
        next_generation = generation + 1
        with self.transaction() as connection:
            self._require_coordinator_lease(connection, scan_id, token, generation)
            updated = connection.execute(
                """
                UPDATE scan_coordinator_leases
                SET generation=?, holder_session_id=?, renewed_at=?, expires_at=?
                WHERE scan_id=? AND token_hash=? AND generation=? AND expires_at>?
                """,
                (
                    next_generation, session_id, timestamp, expires_at,
                    scan_id, token_hash, generation, timestamp,
                ),
            )
            if updated.rowcount != 1:
                raise EngineError(
                    "coordinator_lease_invalid",
                    "The coordinator lease changed before it could be renewed.",
                    {"scanId": scan_id},
                )
        return {
            "scanId": scan_id,
            "coordinatorLease": self._lease_public(
                "acquired", generation=next_generation, expires_at=expires_at
            ),
        }

    def release_coordinator_lease(self, scan_id: str, token: str, generation: int) -> dict[str, Any]:
        with self.transaction() as connection:
            self._require_coordinator_lease(connection, scan_id, token, generation)
            connection.execute("DELETE FROM scan_coordinator_leases WHERE scan_id=?", (scan_id,))
        return {"scanId": scan_id, "coordinatorLease": self._lease_public("released")}

    def _cleanup_unpublished_scan_directory(self, artifact_dir: Path, scan_id: str, owned: bool) -> None:
        if not owned or not artifact_dir.exists():
            return
        candidate = artifact_dir.absolute()
        root = self.artifacts_dir.absolute()
        if candidate.parent != root or candidate.name != scan_id:
            raise EngineError("unsafe_cleanup_path", "Unpublished scan cleanup escaped the artifact root.")
        if candidate.is_symlink():
            candidate.unlink()
        elif candidate.is_dir():
            shutil.rmtree(candidate)
        else:
            candidate.unlink()

    def create_scan(
        self,
        *,
        workspace_id: str,
        artifact_dir: Path | None,
        session_id: str,
        setup_scan: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> tuple[dict[str, Any], bool]:
        with self.transaction(immediate=False) as connection:
            running_id = self._require_workspace_scan_invariants(connection, workspace_id)
            active = connection.execute(
                "SELECT * FROM scans WHERE id=?", (running_id,)
            ).fetchone() if running_id is not None else None
            if active is not None:
                return self._scan_with_lease_state(
                    self._get_scan(connection, active["id"]), connection=connection
                ), False

        with self.transaction() as connection:
            running_id = self._require_workspace_scan_invariants(connection, workspace_id)
            active = connection.execute(
                "SELECT * FROM scans WHERE id=?", (running_id,)
            ).fetchone() if running_id is not None else None
            if active is not None:
                return self._scan_with_lease_state(
                    self._get_scan(connection, active["id"]), connection=connection
                ), False
            workspace = connection.execute(
                "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
            ).fetchone()
            if workspace is None:
                raise EngineError("workspace_not_found", f"Workspace not found: {workspace_id}")
            if not bool(workspace["submitted"]):
                raise EngineError(
                    "workspace_setup_required",
                    "Save the security workspace setup before starting a scan.",
                    {"workspaceId": workspace_id},
                )
            setup_workspace = dict(workspace)
        setup_version = setup_workspace["updated_at"]
        scan_id = random_id("scan")
        lease_token = _coordinator_token()
        lease_token_hash = _coordinator_token_hash(lease_token)
        lease_expires_at = _coordinator_lease_expiry()
        owns_artifact_dir = artifact_dir is None
        artifact_dir = artifact_dir or (self.artifacts_dir / scan_id)
        timestamp = utc_now()
        try:
            stat = self.workspace.stat()
            device, inode = int(stat.st_dev), int(stat.st_ino)
        except OSError:
            device = inode = None
        draft = {
            "id": scan_id,
            "workspace_id": workspace_id,
            "mode": setup_workspace["default_mode"],
            "scope": setup_workspace["default_scope"],
            "user_context": setup_workspace["user_context"],
            "diff_target_kind": setup_workspace["diff_target_kind"],
            "diff_base_revision": setup_workspace["diff_base_revision"],
            "diff_head_revision": setup_workspace["diff_head_revision"],
            "diff_content_digest": setup_workspace["diff_content_digest"],
            "artifact_dir": str(artifact_dir),
            "started_at": timestamp,
        }
        try:
            prepared = setup_scan(draft)
        except Exception:
            self._cleanup_unpublished_scan_directory(artifact_dir, scan_id, owns_artifact_dir)
            raise
        existing_scan: dict[str, Any] | None = None
        try:
            with self.transaction() as connection:
                running_id = self._require_workspace_scan_invariants(connection, workspace_id)
                active = connection.execute("SELECT * FROM scans WHERE id=?", (running_id,)).fetchone() if running_id else None
                if active is not None:
                    existing_scan = self._scan_with_lease_state(
                        self._get_scan(connection, active["id"]), connection=connection
                    )
                else:
                    workspace = connection.execute(
                        "SELECT * FROM workspaces WHERE id=?", (workspace_id,)
                    ).fetchone()
                    if workspace is None:
                        raise EngineError("workspace_not_found", f"Workspace not found: {workspace_id}")
                    if (
                        workspace["updated_at"] != setup_version
                        or not bool(workspace["submitted"])
                    ):
                        raise EngineError(
                            "scan_setup_changed",
                            "Workspace scan configuration changed while setup was running. Try again.",
                            {"workspaceId": workspace_id},
                        )
                    connection.execute(
                        """
                        INSERT INTO scans(
                            id, workspace_id, mode, scope, user_context,
                            diff_target_kind, diff_base_revision, diff_head_revision,
                            diff_content_digest,
                            status, phase, phase_index, artifact_dir,
                            started_at, created_at, updated_at, target_device, target_inode,
                            target_identity, target_revision, snapshot_digest, files_total, files_completed
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', 'preflight', 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                        """,
                        (
                            scan_id, workspace_id, workspace["default_mode"],
                            workspace["default_scope"], workspace["user_context"],
                            workspace["diff_target_kind"],
                            prepared.get("diffBaseRevision"), prepared.get("diffHeadRevision"),
                            workspace["diff_content_digest"],
                            str(artifact_dir), timestamp, timestamp, timestamp, device, inode,
                            prepared["targetIdentity"], prepared.get("targetRevision"), prepared["snapshotDigest"],
                            int(prepared["filesTotal"]),
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO scan_coordinator_leases(
                            scan_id, token_hash, generation, holder_session_id, acquired_at, renewed_at, expires_at
                        ) VALUES (?, ?, 1, ?, ?, ?, ?)
                        """,
                        (
                            scan_id, lease_token_hash, session_id,
                            timestamp, timestamp, lease_expires_at,
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO scan_progress(scan_id, phase_percent, overall_percent, message, updated_at)
                        VALUES (?, 100, ?, ?, ?)
                        """,
                        (scan_id, 100.0 / len(PHASES), prepared["progressMessage"], timestamp),
                    )
                    for record in prepared["artifacts"]:
                        connection.execute(
                            """
                            INSERT INTO scan_artifacts(scan_id, kind, path, sha256, media_type, created_at)
                            VALUES (?, ?, ?, ?, ?, ?)
                            """,
                            (
                                scan_id, record["kind"], record["path"], record["sha256"],
                                record["mediaType"], timestamp,
                            ),
                        )
                    connection.execute(
                        "UPDATE workspaces SET active_scan_id=?, updated_at=? WHERE id=?",
                        (scan_id, timestamp, workspace_id),
                    )
        except Exception:
            self._cleanup_unpublished_scan_directory(artifact_dir, scan_id, owns_artifact_dir)
            raise
        if existing_scan is not None:
            self._cleanup_unpublished_scan_directory(artifact_dir, scan_id, owns_artifact_dir)
            return existing_scan, False
        return {
            **self.get_scan(scan_id),
            "coordinatorLease": self._lease_public(
                "acquired", generation=1, expires_at=lease_expires_at, token=lease_token
            ),
        }, True

    @staticmethod
    def _get_scan(connection: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
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
        return result

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            return self._get_scan(connection, scan_id)
        finally:
            connection.close()

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT s.id FROM scans s
                JOIN workspaces w ON w.id=s.workspace_id
                WHERE w.root_path=?
                ORDER BY s.created_at DESC LIMIT ?
                """,
                (str(self.workspace), max(1, min(limit, 200))),
            ).fetchall()
        finally:
            connection.close()
        return [self.get_scan(row["id"]) for row in rows]

    def active_scan(self) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT s.id FROM scans s
                JOIN workspaces w ON w.id=s.workspace_id
                WHERE w.root_path=? AND s.status='running'
                ORDER BY s.created_at DESC LIMIT 1
                """,
                (str(self.workspace),),
            ).fetchone()
        finally:
            connection.close()
        return self.get_scan(row["id"]) if row else None

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
            row["receiptDigest"], timestamp, timestamp,
        )

    @staticmethod
    def _insert_coverage_row(connection: sqlite3.Connection, values: tuple[Any, ...]) -> None:
        connection.execute(
            """
            INSERT INTO coverage_ledger(
                id, scan_id, row_id, path, surface, entrypoint, root_control, sink, disposition, reason,
                evidence_refs_json, candidate_ids_json, receipt_digest, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, row_id) DO UPDATE SET
                id=excluded.id, path=excluded.path, surface=excluded.surface, entrypoint=excluded.entrypoint,
                root_control=excluded.root_control, sink=excluded.sink, disposition=excluded.disposition,
                reason=excluded.reason, evidence_refs_json=excluded.evidence_refs_json,
                candidate_ids_json=excluded.candidate_ids_json,
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
                    "receiptDigest": row["receipt_digest"],
                    "createdAt": row["created_at"],
                    "updatedAt": row["updated_at"],
                }
                for row in rows
            ]
        finally:
            connection.close()

    def update_scan_progress(
        self,
        scan_id: str,
        *,
        token: str,
        generation: int,
        phase: str | None = None,
        phase_percent: float | None = None,
        review_items_total: int | None = None,
        review_items_completed: int | None = None,
        reportable_findings_count: int | None = None,
        message: str | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            scan = self._require_coordinator_lease(connection, scan_id, token, generation)
            current = connection.execute(
                "SELECT * FROM scan_progress WHERE scan_id=?", (scan_id,)
            ).fetchone()
            if current is None:
                raise EngineError("scan_progress_missing", f"Scan progress not found: {scan_id}")
            target_phase = scan["phase"] if phase is None else phase
            if target_phase not in PHASES:
                raise EngineError("invalid_phase", f"Unknown phase: {target_phase}")
            if target_phase != scan["phase"]:
                require_phase_transition(scan["phase"], target_phase)
            phase_index = PHASES.index(target_phase)
            phase_percent_value = float(
                current["phase_percent"] if phase_percent is None else phase_percent
            )
            phase_percent_value = max(0.0, min(100.0, phase_percent_value))
            overall = ((phase_index + phase_percent_value / 100.0) / len(PHASES)) * 100.0
            values = {
                "review_items_total": int(
                    current["review_items_total"] if review_items_total is None else review_items_total
                ),
                "review_items_completed": int(
                    current["review_items_completed"] if review_items_completed is None else review_items_completed
                ),
                "reportable_findings_count": int(
                    current["reportable_findings_count"]
                    if reportable_findings_count is None else reportable_findings_count
                ),
                "message": current["message"] if message is None else message,
            }
            if values["review_items_completed"] > values["review_items_total"]:
                values["review_items_total"] = values["review_items_completed"]
            timestamp = utc_now()
            if target_phase != scan["phase"]:
                connection.execute(
                    "UPDATE scans SET phase=?, phase_index=?, updated_at=? WHERE id=?",
                    (target_phase, phase_index, timestamp, scan_id),
                )
            connection.execute(
                """
                UPDATE scan_progress SET phase_percent=?, overall_percent=?, review_items_total=?, review_items_completed=?,
                    reportable_findings_count=?, message=?, updated_at=? WHERE scan_id=?
                """,
                (
                    phase_percent_value, min(99.9, overall), values["review_items_total"], values["review_items_completed"],
                    values["reportable_findings_count"], values["message"], timestamp, scan_id,
                ),
            )
        return self.get_scan(scan_id)["progress"]

    def _finish_scan(
        self,
        scan_id: str,
        status: str,
        *,
        token: str,
        generation: int,
        failure_code: str | None = None,
        failure_message: str | None = None,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            row = connection.execute("SELECT status, workspace_id FROM scans WHERE id=?", (scan_id,)).fetchone()
            if row is None:
                raise EngineError("scan_not_found", f"Scan not found: {scan_id}")
            if row["status"] == status:
                return self.get_scan(scan_id)
            self._require_coordinator_lease(connection, scan_id, token, generation)
            require_status_transition(row["status"], status)
            timestamp = utc_now()
            connection.execute(
                """
                UPDATE scans SET status=?, cancellation_requested=?, failure_code=?, failure_message=?,
                    completed_at=?, updated_at=? WHERE id=?
                """,
                (
                    status, 1 if status == "cancelled" else 0, failure_code,
                    failure_message, timestamp, timestamp, scan_id,
                ),
            )
            connection.execute(
                "UPDATE workspaces SET updated_at=? WHERE id=? AND active_scan_id=?",
                (timestamp, row["workspace_id"], scan_id),
            )
            connection.execute("DELETE FROM scan_coordinator_leases WHERE scan_id=?", (scan_id,))
        return self.get_scan(scan_id)

    def cancel_scan(self, scan_id: str, token: str, generation: int) -> dict[str, Any]:
        return self._finish_scan(
            scan_id, "cancelled", token=token, generation=generation
        )

    def fail_scan(
        self, scan_id: str, code: str, message: str, token: str, generation: int
    ) -> dict[str, Any]:
        return self._finish_scan(
            scan_id, "failed", token=token, generation=generation,
            failure_code=code, failure_message=message[:4000],
        )

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

    @staticmethod
    def _register_artifact(
        connection: sqlite3.Connection, scan_id: str, kind: str, path: Path, media_type: str
    ) -> dict[str, Any]:
        digest = sha256_file(path)
        timestamp = utc_now()
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

    def add_artifact(self, scan_id: str, kind: str, path: Path, media_type: str) -> dict[str, Any]:
        with self.transaction() as connection:
            return self._register_artifact(connection, scan_id, kind, path, media_type)

    def artifact_records(self, scan_id: str) -> list[dict[str, Any]]:
        return self.get_scan(scan_id)["artifacts"]

    def complete_and_seal_scan_bundle(
        self,
        scan_id: str,
        *,
        coverage: dict[str, Any],
        manifest_digest: str,
        artifact_records: list[dict[str, Any]],
        finding_count: int,
        publish_files: Callable[[], None] | None = None,
        index_findings: Callable[[sqlite3.Connection, str], None] | None = None,
        hardening_record: dict[str, Any] | None = None,
        coordinator_token: str,
        coordinator_generation: int,
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
            timestamp = utc_now()
            scan = self._require_coordinator_lease(
                connection, scan_id, coordinator_token, coordinator_generation
            )
            if scan["sealed_manifest_digest"]:
                raise EngineError("scan_already_sealed", "The scan already has a sealed manifest digest.")
            require_status_transition(scan["status"], "completed")
            connection.execute("DELETE FROM scan_artifacts WHERE scan_id=?", (scan_id,))
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
                        record["mediaType"], timestamp,
                    ),
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
                        timestamp, timestamp,
                    ),
                )
            if index_findings is not None:
                index_findings(connection, timestamp)
            connection.execute(
                """UPDATE scan_progress SET phase_percent=100, overall_percent=100,
                    reportable_findings_count=?, message='Completed', updated_at=? WHERE scan_id=?""",
                (finding_count, timestamp, scan_id),
            )
            updated = connection.execute(
                """
                UPDATE scans SET status='completed', phase='reporting', phase_index=?,
                    failure_code=NULL, failure_message=NULL, completed_at=?,
                    coverage_json=?, sealed_manifest_digest=?, updated_at=?
                WHERE id=? AND status='running'
                """,
                (
                    PHASES.index("reporting"),
                    timestamp,
                    json.dumps(coverage, separators=(",", ":"), allow_nan=False),
                    manifest_digest,
                    timestamp,
                    scan_id,
                ),
            )
            if updated.rowcount != 1:
                raise EngineError("finalizer_wrong_state", "Only a running scan can be atomically completed and sealed.")
            connection.execute(
                "UPDATE workspaces SET updated_at=? WHERE id=? AND active_scan_id=?",
                (timestamp, scan["workspace_id"], scan_id),
            )
            connection.execute("DELETE FROM scan_coordinator_leases WHERE scan_id=?", (scan_id,))
            if publish_files is not None:
                publish_files()
        return self.get_scan(scan_id)

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

    def list_findings(
        self, scan_id: str, *, search: str | None = None, limit: int | None = None
    ) -> list[dict[str, Any]]:
        rows = self._base_finding_rows(scan_id, search=search)
        if limit is not None:
            rows = rows[: max(1, min(limit, 2000))]
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
            triage_assessments = connection.execute(
                "SELECT * FROM triage_assessments WHERE occurrence_id=? ORDER BY created_at DESC", (row["id"],)
            ).fetchall()
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
            canonical_details = json.loads(row["details_json"])
            summary["details"] = canonical_details
            indexed_evidence = [
                {
                    "id": item["id"], "kind": item["kind"], "label": item["label"],
                    "path": item["relative_path"], "startLine": item["start_line"], "endLine": item["end_line"],
                    "language": item["language"], "role": item["role"], "code": item["snippet"],
                    "explanation": item["explanation"],
                }
                for item in evidence
            ]
            summary["codeEvidence"] = canonical_details.get("codeEvidence", indexed_evidence)
            indexed_validation = None if validation is None else {
                "id": validation["id"], "status": validation["status"], "method": validation["method"],
                "rationale": validation["rationale"], "evidenceRefs": json.loads(validation["evidence_json"]),
                "createdAt": validation["created_at"],
            }
            indexed_attack = None if attack is None else {
                "id": attack["id"], "narrative": attack["narrative"], "path": json.loads(attack["path_json"]),
                "exploitability": attack["exploitability"], "impact": attack["impact"],
                "severityRationale": attack["severity_rationale"],
            }
            summary["validation"] = canonical_details.get("validation", indexed_validation)
            summary["attackPath"] = canonical_details.get("attackPath", indexed_attack)
            summary["triage"] = None if triage is None else {
                "decision": triage["decision"], "note": triage["note"], "updatedAt": triage["updated_at"]
            }
            summary["triageAssessments"] = [self._triage_assessment(item) for item in triage_assessments]
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

    def create_patch_remediation(
        self, record_id: str, occurrence_id: str, summary: str, artifact_path: str, patch_digest: str
    ) -> dict[str, Any]:
        timestamp = utc_now()
        with self.transaction() as connection:
            if connection.execute("SELECT 1 FROM finding_occurrences WHERE id=?", (occurrence_id,)).fetchone() is None:
                raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
            active = connection.execute(
                """
                SELECT id, state FROM remediation_records
                WHERE occurrence_id=? AND patch_digest IS NOT NULL AND state IN ('applied','verifying')
                ORDER BY version DESC LIMIT 1
                """,
                (occurrence_id,),
            ).fetchone()
            if active is not None:
                raise EngineError(
                    "remediation_busy", "An applied or verifying remediation must be resolved before preparing another patch.",
                    {"remediationId": active["id"], "state": active["state"]},
                )
            connection.execute(
                """
                UPDATE remediation_records SET state='superseded', updated_at=?
                WHERE occurrence_id=? AND patch_digest IS NOT NULL AND state='generated'
                """,
                (timestamp, occurrence_id),
            )
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM remediation_records WHERE occurrence_id=?", (occurrence_id,)
            ).fetchone()
            version = int(row["version"]) + 1
            connection.execute(
                """
                INSERT INTO remediation_records(
                    id, occurrence_id, state, version, summary, artifact_path, patch_digest, created_at, updated_at
                ) VALUES (?, ?, 'generated', ?, ?, ?, ?, ?, ?)
                """,
                (record_id, occurrence_id, version, summary[:500000], artifact_path, patch_digest, timestamp, timestamp),
            )
        return self.get_remediation_record(record_id)

    def require_patch_remediation_available(self, occurrence_id: str) -> None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT id, state FROM remediation_records
                WHERE occurrence_id=? AND patch_digest IS NOT NULL AND state IN ('applied','verifying')
                ORDER BY version DESC LIMIT 1
                """,
                (occurrence_id,),
            ).fetchone()
            if row is not None:
                raise EngineError(
                    "remediation_busy", "An applied or verifying remediation must be resolved before preparing another patch.",
                    {"remediationId": row["id"], "state": row["state"]},
                )
        finally:
            connection.close()

    def list_verifying_remediations(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT r.*, o.scan_id, o.finding_id FROM remediation_records r
                JOIN finding_occurrences o ON o.id=r.occurrence_id
                WHERE r.state='verifying' ORDER BY r.updated_at, r.id
                """
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            connection.close()

    def get_remediation_record(self, record_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT r.*, o.scan_id, o.finding_id FROM remediation_records r
                JOIN finding_occurrences o ON o.id=r.occurrence_id WHERE r.id=?
                """,
                (record_id,),
            ).fetchone()
            if row is None:
                raise EngineError("remediation_not_found", f"Remediation record not found: {record_id}")
            return dict(row)
        finally:
            connection.close()

    def transition_remediation(
        self,
        record_id: str,
        expected_version: int,
        expected_state: str,
        new_state: str,
        *,
        verification_summary: str | None = None,
        artifact: tuple[str, str, Path, str] | None = None,
    ) -> dict[str, Any]:
        if new_state not in ("generated", "applied", "verifying", "verified", "failed", "superseded"):
            raise EngineError("invalid_remediation_state", f"Unsupported remediation state: {new_state}")
        timestamp = utc_now()
        artifact_record = None
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE remediation_records SET state=?, verification_summary=COALESCE(?, verification_summary), updated_at=?
                WHERE id=? AND version=? AND state=?
                """,
                (new_state, verification_summary, timestamp, record_id, expected_version, expected_state),
            ).rowcount
            if not changed:
                row = connection.execute("SELECT version, state FROM remediation_records WHERE id=?", (record_id,)).fetchone()
                if row is None:
                    raise EngineError("remediation_not_found", f"Remediation record not found: {record_id}")
                raise EngineError(
                    "remediation_state_conflict",
                    "The remediation version or state changed before this operation.",
                    {"expectedVersion": expected_version, "expectedState": expected_state, "actualVersion": row["version"], "actualState": row["state"]},
                )
            if artifact is not None:
                artifact_record = self._register_artifact(connection, *artifact)
        result = self.get_remediation_record(record_id)
        if artifact_record is not None:
            result["_artifact"] = artifact_record
        return result

    @staticmethod
    def _triage_assessment(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"], "occurrenceId": row["occurrence_id"], "inputId": row["input_id"],
            "sourceType": row["source_type"], "status": row["status"],
            "intake": json.loads(row["intake_json"]),
            "result": None if row["result_json"] is None else json.loads(row["result_json"]),
            "resultDigest": row["result_digest"],
            "intakeArtifactPath": row["intake_artifact_path"],
            "resultArtifactPath": row["result_artifact_path"],
            "artifactPath": row["result_artifact_path"] or row["intake_artifact_path"],
            "createdAt": row["created_at"], "updatedAt": row["updated_at"],
        }

    def create_triage_assessment(
        self, assessment_id: str, intake: dict[str, Any], occurrence_id: str | None, artifact_path: str
    ) -> dict[str, Any]:
        timestamp = utc_now()
        with self.transaction() as connection:
            if occurrence_id is not None and connection.execute(
                "SELECT 1 FROM finding_occurrences WHERE id=?", (occurrence_id,)
            ).fetchone() is None:
                raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
            connection.execute(
                """
                INSERT INTO triage_assessments(
                    id, occurrence_id, input_id, source_type, status, intake_json,
                    intake_artifact_path, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                """,
                (
                    assessment_id, occurrence_id, intake["inputId"], intake["sourceType"],
                    json.dumps(intake, separators=(",", ":"), ensure_ascii=False), artifact_path, timestamp, timestamp,
                ),
            )
        return self.get_triage_assessment(assessment_id)

    def get_triage_assessment(self, assessment_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM triage_assessments WHERE id=?", (assessment_id,)).fetchone()
            if row is None:
                raise EngineError("triage_assessment_not_found", f"Triage assessment not found: {assessment_id}")
            return self._triage_assessment(row)
        finally:
            connection.close()

    def complete_triage_assessment(
        self, assessment_id: str, result: dict[str, Any], result_digest: str, artifact_path: str,
        *, artifact: tuple[str, str, Path, str] | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now()
        artifact_record = None
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE triage_assessments SET status='completed', result_json=?, result_digest=?,
                    result_artifact_path=?, updated_at=?
                WHERE id=? AND status='pending'
                """,
                (
                    json.dumps(result, separators=(",", ":"), ensure_ascii=False), result_digest,
                    artifact_path, timestamp, assessment_id,
                ),
            ).rowcount
            if not changed:
                row = connection.execute("SELECT status FROM triage_assessments WHERE id=?", (assessment_id,)).fetchone()
                if row is None:
                    raise EngineError("triage_assessment_not_found", f"Triage assessment not found: {assessment_id}")
                raise EngineError("triage_assessment_immutable", f"Triage assessment is already {row['status']}.")
            if artifact is not None:
                artifact_record = self._register_artifact(connection, *artifact)
        completed = self.get_triage_assessment(assessment_id)
        if artifact_record is not None:
            completed["_artifact"] = artifact_record
        return completed

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
        self, record_id: str, occurrence_id: str, provider: str, destination: str, payload_path: Path
    ) -> dict[str, Any]:
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
                    payload_sha256, payload_artifact_path, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, 'prepared', ?, ?)
                """,
                (record_id, occurrence_id, provider, destination, digest, str(payload_path), timestamp, timestamp),
            )
        return {
            "id": record_id, "occurrenceId": occurrence_id, "provider": provider,
            "destination": destination, "payloadPath": str(payload_path), "payloadSha256": digest,
            "status": "prepared", "createdAt": timestamp, "updatedAt": timestamp,
        }

    def get_tracking_record(self, record_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT t.*, o.scan_id, o.finding_id FROM tracking_records t
                JOIN finding_occurrences o ON o.id=t.occurrence_id WHERE t.id=?
                """,
                (record_id,),
            ).fetchone()
            if row is None:
                raise EngineError("tracking_record_not_found", f"Tracking record not found: {record_id}")
            return dict(row)
        finally:
            connection.close()

    def record_tracking_result(
        self,
        record_id: str,
        payload_sha256: str,
        status: str,
        external_id: str | None,
        external_url: str | None,
        readback_digest: str,
        readback_artifact_path: str,
        *, artifact: tuple[str, str, Path, str] | None = None,
    ) -> dict[str, Any]:
        timestamp = utc_now()
        artifact_record = None
        with self.transaction() as connection:
            changed = connection.execute(
                """
                UPDATE tracking_records SET status=?, external_id=?, external_url=?,
                    readback_digest=?, readback_artifact_path=?, updated_at=?
                WHERE id=? AND status='prepared' AND payload_sha256=?
                """,
                (
                    status, external_id, external_url, readback_digest, readback_artifact_path,
                    timestamp, record_id, payload_sha256,
                ),
            ).rowcount
            if not changed:
                row = connection.execute(
                    "SELECT status, payload_sha256 FROM tracking_records WHERE id=?", (record_id,)
                ).fetchone()
                if row is None:
                    raise EngineError("tracking_record_not_found", f"Tracking record not found: {record_id}")
                if row["payload_sha256"] != payload_sha256:
                    raise EngineError("tracking_payload_changed", "The approved tracking payload digest does not match.")
                raise EngineError("tracking_record_immutable", f"Tracking record is already {row['status']}.")
            if artifact is not None:
                artifact_record = self._register_artifact(connection, *artifact)
        completed = self.get_tracking_record(record_id)
        if artifact_record is not None:
            completed["_artifact"] = artifact_record
        return completed

    def cleanup_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.get_scan(scan_id)
        if scan["status"] == "running":
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
