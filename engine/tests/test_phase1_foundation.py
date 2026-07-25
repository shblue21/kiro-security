"""Integration coverage for the rebuilt Phase 1 global foundation."""

import ast
import concurrent.futures
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY_ROOT / "engine"))

from kiro_security import DiffTarget, Workbench, WorkspaceSetup  # noqa: E402
from kiro_security.errors import WorkbenchError  # noqa: E402
from kiro_security.filesystem_identity import serialize_filesystem_identity  # noqa: E402


def git(repository, *args):
    completed = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return completed.stdout.strip()


def make_repository(root):
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.email", "phase1@example.invalid")
    git(root, "config", "user.name", "Phase One")
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('safe')\n", encoding="utf-8")
    git(root, "add", "src/app.py")
    git(root, "commit", "-qm", "initial")


class PhaseOneFoundationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repository"
        self.state_root = self.base / "extension-global-state"
        self.scan_root = self.base / "scan-artifacts"
        make_repository(self.root)
        self.workbench = Workbench(str(self.state_root), str(self.scan_root))
        self.setup = WorkspaceSetup(str(self.root), mode="standard")

    def tearDown(self):
        self.temporary.cleanup()

    def submitted_workspace(self, setup=None):
        selected = setup or self.setup
        draft = self.workbench.create_workspace(selected)
        self.assertFalse(draft["setup"]["submitted"])
        return self.workbench.update_workspace_setup(draft["id"], selected)

    def test_global_schema_pointer_and_storage_boundaries(self):
        state = self.workbench.schema_state()
        self.assertEqual(state["schemaVersion"], 1)
        self.assertEqual(state["stateRoot"], str(self.state_root))
        self.assertEqual(state["scanRoot"], str(self.scan_root))
        database_path = self.workbench.database.path
        self.assertEqual(database_path, self.state_root / "workbench.sqlite3")
        self.assertEqual(stat.S_IMODE(database_path.stat().st_mode), 0o600)
        self.assertFalse((self.root / ".kiro" / "security-power").exists())

        connection = sqlite3.connect(str(database_path))
        try:
            workspace_columns = {
                row[1]: row for row in connection.execute("PRAGMA table_info(workspaces)")
            }
            self.assertNotIn("owner_session_id", workspace_columns)
            self.assertEqual(workspace_columns["target_path"][3], 0)
            self.assertEqual(workspace_columns["submitted"][4], "0")
            foreign_keys = connection.execute("PRAGMA foreign_key_list(workspaces)").fetchall()
            active_pointer = next(row for row in foreign_keys if row[3] == "active_scan_id")
            self.assertEqual(active_pointer[2], "scans")
            self.assertEqual(active_pointer[4], "id")
            self.assertEqual(active_pointer[6], "SET NULL")
            index_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'index' AND name = 'scans_one_running_per_workspace'
                """
            ).fetchone()[0]
            self.assertIn("WHERE status = 'running'", index_sql)
        finally:
            connection.close()

    def test_provisional_workspace_and_unbounded_context(self):
        empty = self.workbench.create_workspace()
        self.assertIsNone(empty["targetPath"])
        self.assertFalse(empty["setup"]["submitted"])
        self.assertFalse(empty["setup"]["valid"])

        unresolved = self.workbench.create_workspace(
            WorkspaceSetup(str(self.root), mode="diff"),
        )
        self.assertFalse(unresolved["setup"]["submitted"])
        self.assertFalse(unresolved["setup"]["valid"])
        self.assertEqual(unresolved["setup"]["error"]["code"], "missing_diff_target")

        long_context = "x" * 12001
        submitted = self.workbench.update_workspace_setup(
            empty["id"],
            WorkspaceSetup(str(self.root), user_context=long_context),
        )
        self.assertTrue(submitted["setup"]["submitted"])
        self.assertTrue(submitted["setup"]["valid"])
        self.assertEqual(submitted["userContext"], long_context)

    def test_setup_locks_after_first_scan_and_pointer_survives_failure(self):
        workspace = self.submitted_workspace()
        started = self.workbench.start_scan(workspace["id"])
        scan_id = started["scanId"]
        self.assertEqual(scan_id, started["workspace"]["activeScanId"])
        self.assertEqual(started["workspace"]["currentScan"]["status"], "running")
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.update_workspace_setup(
                workspace["id"],
                WorkspaceSetup(str(self.root), mode="deep"),
            )
        self.assertEqual(raised.exception.code, "setup_locked")

        failed = self.workbench.fail_scan(scan_id, "phase 1 test")
        self.assertEqual(failed["status"], "failed")
        after_failure = self.workbench.get_workspace(workspace["id"])
        self.assertEqual(after_failure["activeScanId"], scan_id)

        rerun = self.workbench.start_scan(workspace["id"])
        self.assertNotEqual(rerun["scanId"], scan_id)
        self.assertEqual(rerun["workspace"]["currentScan"]["status"], "running")

    def test_running_start_is_idempotent_across_workbench_instances(self):
        workspace = self.submitted_workspace()

        def start():
            return Workbench(str(self.state_root), str(self.scan_root)).start_scan(
                workspace["id"]
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _index: start(), range(2)))
        scan_ids = {result["scanId"] for result in results}
        self.assertEqual(len(scan_ids), 1)

    def test_start_rejects_intervening_terminal_scan_by_workspace_version(self):
        workspace = self.submitted_workspace()
        first = Workbench(str(self.state_root), str(self.scan_root))
        entered_capture = threading.Event()
        release_capture = threading.Event()
        original_capture = first.targets.capture

        def delayed_capture(setup):
            entered_capture.set()
            if not release_capture.wait(10):
                raise AssertionError("start synchronization timed out")
            return original_capture(setup)

        first.targets.capture = delayed_capture
        outcome = {}

        def start_first():
            try:
                outcome["result"] = first.start_scan(workspace["id"])
            except WorkbenchError as exc:
                outcome["error"] = exc

        thread = threading.Thread(target=start_first)
        thread.start()
        self.assertTrue(entered_capture.wait(10))
        second = Workbench(str(self.state_root), str(self.scan_root))
        terminal_id = second.start_scan(workspace["id"])["scanId"]
        second.fail_scan(terminal_id, "fast terminal")
        release_capture.set()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertNotIn("result", outcome)
        self.assertEqual(outcome["error"].code, "setup_changed")
        self.assertEqual(
            second.get_workspace(workspace["id"])["activeScanId"],
            terminal_id,
        )

    def test_symlink_is_target_content_and_state_is_external(self):
        before = self.workbench.capture_target(self.setup).target_snapshot_digest
        (self.root / "state-alias").symlink_to(self.state_root)
        after = self.workbench.capture_target(self.setup).target_snapshot_digest
        self.assertNotEqual(before, after)
        workspace = self.submitted_workspace()
        started = self.workbench.start_scan(workspace["id"])
        self.assertTrue(Path(started["workspace"]["currentScan"]["scanDir"]).is_dir())
        self.assertFalse((self.root / ".kiro" / "security-power").exists())

    def test_working_tree_diff_rejects_content_drift(self):
        (self.root / "src" / "app.py").write_text("print('first change')\n", encoding="utf-8")
        diff_setup = WorkspaceSetup(
            str(self.root),
            mode="diff",
            diff_target=DiffTarget("working_tree"),
        )
        workspace = self.submitted_workspace(diff_setup)
        (self.root / "src" / "app.py").write_text("print('second change')\n", encoding="utf-8")
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.start_scan(workspace["id"])
        self.assertEqual(raised.exception.code, "diff_content_changed")

    def test_snapshot_rejects_dirty_nested_submodule(self):
        leaf = self.base / "leaf"
        middle = self.base / "middle"
        parent = self.base / "parent"
        for repository in (leaf, middle, parent):
            repository.mkdir()
            git(repository, "init", "-q")
            git(repository, "config", "user.email", "phase1@example.invalid")
            git(repository, "config", "user.name", "Phase One")

        (leaf / "leaf.txt").write_text("clean\n", encoding="utf-8")
        git(leaf, "add", "leaf.txt")
        git(leaf, "commit", "-qm", "leaf")
        (middle / "middle.txt").write_text("clean\n", encoding="utf-8")
        git(middle, "add", "middle.txt")
        git(middle, "commit", "-qm", "middle")
        git(
            middle,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(leaf),
            "nested/leaf",
        )
        git(middle, "commit", "-qam", "add nested submodule")
        (parent / "parent.txt").write_text("clean\n", encoding="utf-8")
        git(parent, "add", "parent.txt")
        git(parent, "commit", "-qm", "parent")
        git(
            parent,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            str(middle),
            "modules/middle",
        )
        git(parent, "commit", "-qam", "add submodule")
        git(
            parent,
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "update",
            "--init",
            "--recursive",
        )
        nested_file = parent / "modules" / "middle" / "nested" / "leaf" / "leaf.txt"
        nested_file.write_text("dirty\n", encoding="utf-8")

        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.capture_target(WorkspaceSetup(str(parent)))
        self.assertEqual(raised.exception.code, "dirty_submodule")

    def test_cancel_projects_canceled(self):
        workspace = self.submitted_workspace()
        scan_id = self.workbench.start_scan(workspace["id"])["scanId"]
        canceled = self.workbench.cancel_scan(scan_id)
        self.assertEqual(canceled["activeScanId"], scan_id)
        self.assertEqual(canceled["currentScan"]["status"], "canceled")
        self.assertEqual(canceled["currentScan"]["databaseStatus"], "failed")

    def test_deep_target_and_scope_contracts(self):
        (self.root / "src" / "nested").mkdir()
        absolute_scope = self.submitted_workspace(
            WorkspaceSetup(str(self.root), scope=str(self.root / "src")),
        )
        self.assertEqual(absolute_scope["scope"], "src")

        draft = self.workbench.create_workspace(
            WorkspaceSetup(str(self.root), mode="deep", scope="src"),
        )
        with self.assertRaises(WorkbenchError) as raised:
            self.workbench.update_workspace_setup(
                draft["id"],
                WorkspaceSetup(str(self.root), mode="deep", scope="src"),
            )
        self.assertEqual(raised.exception.code, "deep_scope")

        scoped = self.submitted_workspace(
            WorkspaceSetup(str(self.root / "src"), mode="deep"),
        )
        started = self.workbench.start_scan(scoped["id"])
        self.assertEqual(
            started["workspace"]["currentScan"]["target"]["path"],
            str((self.root / "src").resolve()),
        )
        self.assertEqual(started["workspace"]["currentScan"]["scope"], ".")

    def test_unversioned_and_unborn_directory_snapshots(self):
        directory = self.base / "plain-directory"
        directory.mkdir()
        (directory / "app.txt").write_text("content\n", encoding="utf-8")
        setup = WorkspaceSetup(str(directory))
        first = self.workbench.capture_target(setup)
        second = self.workbench.capture_target(setup)
        self.assertEqual(first.target_revision, "unversioned")
        self.assertEqual(first.target_snapshot_digest, second.target_snapshot_digest)

        unborn = self.base / "unborn"
        unborn.mkdir()
        git(unborn, "init", "-q")
        (unborn / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
        (unborn / "tracked.txt").write_text("indexed\n", encoding="utf-8")
        (unborn / "visible.txt").write_text("visible\n", encoding="utf-8")
        (unborn / "ignored.txt").write_text("first\n", encoding="utf-8")
        git(unborn, "add", ".gitignore", "tracked.txt")
        setup = WorkspaceSetup(str(unborn))
        before = self.workbench.capture_target(setup)
        (unborn / "ignored.txt").write_text("second\n", encoding="utf-8")
        after = self.workbench.capture_target(setup)
        self.assertEqual(before.target_snapshot_digest, after.target_snapshot_digest)

    def test_large_filesystem_identity(self):
        large = 1 << 80
        serialized = serialize_filesystem_identity(large)
        self.assertEqual(serialized, "stat:100000000000000000000")
        connection = sqlite3.connect(str(self.workbench.database.path))
        try:
            connection.execute("CREATE TEMP TABLE identity(value INTEGER)")
            connection.execute("INSERT INTO identity(value) VALUES (?)", (serialized,))
            self.assertEqual(
                connection.execute("SELECT value FROM identity").fetchone()[0],
                serialized,
            )
        finally:
            connection.close()
    def test_scan_root_must_stay_outside_target(self):
        inside = Workbench(
            str(self.base / "other-state"),
            str(self.root / "scan-artifacts"),
        )
        draft = inside.create_workspace(self.setup)
        workspace = inside.update_workspace_setup(draft["id"], self.setup)
        with self.assertRaises(WorkbenchError) as raised:
            inside.start_scan(workspace["id"])
        self.assertEqual(raised.exception.code, "scan_root_inside_target")

    def test_all_engine_sources_parse_as_python_3_9(self):
        for path in sorted((REPOSITORY_ROOT / "engine").rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=str(path), feature_version=(3, 9))
            except SyntaxError as exc:
                self.fail("%s is not Python 3.9 compatible: %s" % (path, exc))

    def test_module_cli_initializes_global_schema(self):
        cli_state = self.base / "cli-state"
        cli_scans = self.base / "cli-scans"
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(REPOSITORY_ROOT / "engine")
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "kiro_security",
                "--state-root",
                str(cli_state),
                "--scan-root",
                str(cli_scans),
                "init",
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertEqual(payload["schemaVersion"], 1)
        self.assertEqual(payload["databasePath"], str(cli_state / "workbench.sqlite3"))
        self.assertEqual(payload["scanRoot"], str(cli_scans))


if __name__ == "__main__":
    unittest.main()
