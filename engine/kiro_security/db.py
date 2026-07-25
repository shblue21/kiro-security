"""SQLite connection and migration ownership."""

import os
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from .errors import WorkbenchError
from .schema import MIGRATIONS, SCHEMA_VERSION

SQLITE_RETRY_ATTEMPTS = 5


def utc_now():
    # type: () -> str
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class Database:
    """One extension-global SQLite authority outside scanned targets."""

    def __init__(self, state_root):
        # type: (Path) -> None
        candidate = Path(state_root).expanduser()
        if not candidate.is_absolute():
            raise WorkbenchError(
                "state_not_absolute",
                "Kiro Security state root must be an absolute directory path.",
            )
        self.state_root = candidate.resolve(strict=False)
        self.path = self.state_root / "workbench.sqlite3"
        self._prepare_state_root()
        with self.connect():
            pass

    def _prepare_state_root(self):
        # type: () -> None
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = self.state_root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkbenchError(
                "unsafe_state_path",
                "The Kiro Security state path must be a real local directory.",
            )
        os.chmod(self.state_root, 0o700)
        if self.path.exists():
            metadata = self.path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise WorkbenchError(
                    "unsafe_database_path",
                    "The Kiro Security database path must be a regular non-symlink file.",
                )

    @contextmanager
    def connect(self):
        # type: () -> sqlite3.Connection
        connection = None
        for attempt in range(SQLITE_RETRY_ATTEMPTS):
            try:
                connection = sqlite3.connect(
                    str(self.path),
                    timeout=5,
                    isolation_level=None,
                )
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA busy_timeout = 5000")
                connection.execute("PRAGMA journal_mode = WAL")
                self._apply_migrations(connection)
                os.chmod(self.path, 0o600)
                break
            except sqlite3.OperationalError as exc:
                if connection is not None:
                    connection.close()
                    connection = None
                if attempt == SQLITE_RETRY_ATTEMPTS - 1 or not _is_busy(exc):
                    raise
                time.sleep(0.05 * (2**attempt))
        if connection is None:
            raise AssertionError("SQLite connection retry loop exhausted")
        try:
            yield connection
        finally:
            connection.close()

    def _apply_migrations(self, connection):
        # type: (sqlite3.Connection) -> None
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                )
                """
            )
            applied_rows = connection.execute(
                "SELECT version, name FROM schema_migrations ORDER BY version"
            ).fetchall()
            expected_names = {
                version: name for version, name, _statements in MIGRATIONS
            }
            if any(row["version"] > SCHEMA_VERSION for row in applied_rows):
                raise WorkbenchError(
                    "schema_too_new",
                    "The workbench database was created by a newer Kiro Security version.",
                )
            if any(
                expected_names.get(row["version"]) != row["name"]
                for row in applied_rows
            ):
                raise WorkbenchError(
                    "unsupported_schema_history",
                    "The workbench database has an unsupported migration history.",
                )
            applied = {row["version"] for row in applied_rows}
            for version, name, statements in MIGRATIONS:
                if version in applied:
                    continue
                for statement in statements:
                    connection.execute(statement)
                connection.execute(
                    """
                    INSERT INTO schema_migrations (version, name, applied_at)
                    VALUES (?, ?, ?)
                    """,
                    (version, name, utc_now()),
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise

    def schema_version(self):
        # type: () -> int
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
            ).fetchone()
            return int(row["version"])


@contextmanager
def immediate_transaction(connection):
    # type: (sqlite3.Connection) -> sqlite3.Connection
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise


def _is_busy(error):
    # type: (sqlite3.OperationalError) -> bool
    text = str(error).lower()
    return "locked" in text or "busy" in text
