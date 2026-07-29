"""Global workspace authority, current-result pointer, and scan-start lifecycle."""

import hashlib
import hmac
import json
import os
import stat
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .attestation import arguments_hash, require_request_nonce, require_session_hash
from .db import Database, immediate_transaction, utc_now
from .errors import WorkbenchError
from .filesystem_identity import serialize_filesystem_identity
from .models import DIFF_TARGET_KINDS, MODES, PHASES, DiffTarget, WorkspaceSetup
from .target import TargetInspector


class Workbench:
    """One global SQLite authority shared by the Extension and Agent MCP adapter."""

    def __init__(self, state_root, scan_root=None):
        # type: (str, object) -> None
        self.database = Database(Path(state_root))
        self.scan_root = self._prepare_scan_root(
            Path(scan_root) if scan_root is not None else self.database.state_root / "scans"
        )
        self.targets = TargetInspector()

    def _prepare_scan_root(self, value):
        # type: (Path) -> Path
        candidate = value.expanduser()
        if not candidate.is_absolute():
            raise WorkbenchError(
                "scan_root_not_absolute",
                "Kiro Security scan root must be an absolute directory path.",
            )
        root = candidate.resolve(strict=False)
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkbenchError(
                "unsafe_scan_root",
                "The Kiro Security scan root must be a real local directory.",
            )
        os.chmod(root, 0o700)
        return root

    def schema_state(self):
        return {
            "databasePath": str(self.database.path),
            "scanRoot": str(self.scan_root),
            "schemaVersion": self.database.schema_version(),
            "stateRoot": str(self.database.state_root),
        }

    def inspect_setup(self, setup):
        # type: (WorkspaceSetup) -> WorkspaceSetup
        return self.targets.inspect_setup(setup)

    def capture_target(self, setup):
        # type: (WorkspaceSetup) -> object
        return self.targets.capture(setup)

    def consume_chat_attestation(self, tool_name, arguments):
        # type: (str, dict) -> str
        nonce = require_request_nonce(arguments.get("requestNonce"))
        expected_arguments_hash = arguments_hash(arguments)
        now = int(time.time())
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                attestation = connection.execute(
                    "SELECT * FROM chat_attestations WHERE nonce = ?",
                    (nonce,),
                ).fetchone()
                if attestation is None or attestation["expires_at"] <= now:
                    raise WorkbenchError(
                        "chat_attestation_invalid",
                        "Kiro chat attestation is missing, expired, or already used.",
                    )
                tool_matches = hmac.compare_digest(
                    attestation["tool_name"],
                    tool_name,
                )
                arguments_match = hmac.compare_digest(
                    attestation["arguments_hash"],
                    expected_arguments_hash,
                )
                if not tool_matches or not arguments_match:
                    raise WorkbenchError(
                        "chat_attestation_invalid",
                        "Kiro chat attestation does not match this tool call.",
                    )
                deleted = connection.execute(
                    "DELETE FROM chat_attestations WHERE nonce = ?",
                    (nonce,),
                )
                if deleted.rowcount != 1:
                    raise WorkbenchError(
                        "chat_attestation_invalid",
                        "Kiro chat attestation was already used.",
                    )
                return require_session_hash(attestation["session_hash"])

    def create_workspace(self, setup=None, owner_session_hash=None):
        # type: (object, object) -> dict
        owner_hash = require_session_hash(owner_session_hash)
        draft = setup if isinstance(setup, WorkspaceSetup) else WorkspaceSetup()
        normalized = self._normalize_draft_setup(draft)
        workspace_id = str(uuid.uuid4())
        timestamp = utc_now()
        diff = normalized.diff_target
        target_path = normalized.target_path
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                connection.execute(
                    """
                    INSERT INTO workspaces (
                        id, target_path, target_title, default_scope, default_mode,
                        user_context, diff_target_kind, diff_base_revision,
                        diff_head_revision, diff_content_digest, submitted,
                        owner_session_hash, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
                    """,
                    (
                        workspace_id,
                        target_path,
                        Path(target_path).name if target_path else None,
                        normalized.scope,
                        normalized.mode,
                        normalized.user_context,
                        diff.kind if diff else None,
                        diff.base_revision if diff else None,
                        diff.head_revision if diff else None,
                        diff.content_digest if diff else None,
                        owner_hash,
                        timestamp,
                        timestamp,
                    ),
                )
            return self._workspace_state(connection, workspace_id)

    def update_workspace_setup(self, workspace_id, setup, owner_session_hash=None):
        # type: (str, WorkspaceSetup, object) -> dict
        workspace_uuid = _require_uuid(workspace_id, "workspace")
        owner_hash = require_session_hash(owner_session_hash)
        inspected = self.targets.inspect_setup(setup)
        diff = inspected.diff_target
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                workspace = self._require_owned_workspace(
                    connection,
                    workspace_uuid,
                    owner_hash,
                )
                if workspace["active_scan_id"] is not None:
                    raise WorkbenchError(
                        "setup_locked",
                        "This logical workspace already has a scan; create a new workspace to change setup.",
                    )
                updated = connection.execute(
                    """
                    UPDATE workspaces
                    SET target_path = ?, target_title = ?, target_summary = NULL,
                        default_scope = ?, default_mode = ?, user_context = ?,
                        diff_target_kind = ?, diff_base_revision = ?,
                        diff_head_revision = ?, diff_content_digest = ?,
                        diff_resolution_id = NULL, submitted = 1,
                        setup_revision = setup_revision + 1, updated_at = ?
                    WHERE id = ? AND active_scan_id IS NULL
                    """,
                    (
                        inspected.target_path,
                        Path(str(inspected.target_path)).name,
                        inspected.scope,
                        inspected.mode,
                        inspected.user_context,
                        diff.kind if diff else None,
                        diff.base_revision if diff else None,
                        diff.head_revision if diff else None,
                        diff.content_digest if diff else None,
                        timestamp,
                        workspace_uuid,
                    ),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "setup_locked",
                        "This logical workspace changed while setup was being saved.",
                    )
            return self._workspace_state(connection, workspace_uuid)

    def get_workspace(self, workspace_id, owner_session_hash=None):
        # type: (str, object) -> dict
        workspace_uuid = _require_uuid(workspace_id, "workspace")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            self._require_owned_workspace(connection, workspace_uuid, owner_hash)
            return self._workspace_state(connection, workspace_uuid)

    def start_scan(
        self,
        workspace_id,
        expected_setup_revision=None,
        expected_setup_digest=None,
        approved_setup=None,
        owner_session_hash=None,
    ):
        # type: (str, object, object, object, object) -> dict
        workspace_uuid = _require_uuid(workspace_id, "workspace")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            workspace = self._require_owned_workspace(
                connection,
                workspace_uuid,
                owner_hash,
            )
            if not workspace["submitted"] or not workspace["target_path"]:
                raise WorkbenchError("setup_not_submitted", "Save setup before starting a scan.")
            workspace_version = workspace["updated_at"]
            setup = self._setup_from_row(workspace)
            self._verify_start_approval(
                workspace,
                setup,
                expected_setup_revision,
                expected_setup_digest,
                approved_setup,
            )
            running = self._running_scan(connection, workspace_uuid)
            if running is not None:
                return self._start_result(connection, workspace_uuid, running["id"], True)

        captured = self.targets.capture(setup)
        target = Path(captured.target_path)
        scan_id = str(uuid.uuid4())
        timestamp = utc_now()
        target_root = (self.scan_root / _safe_segment(target.name)).resolve()
        if target_root == target or target in target_root.parents:
            raise WorkbenchError(
                "scan_root_inside_target",
                "The scan artifact directory must be outside the selected target.",
            )
        target_root.mkdir(mode=0o700, parents=True, exist_ok=True)

        with self.database.connect() as connection:
            with immediate_transaction(connection):
                workspace = self._require_owned_workspace(
                    connection,
                    workspace_uuid,
                    owner_hash,
                )
                self._verify_start_approval(
                    workspace,
                    self._setup_from_row(workspace),
                    expected_setup_revision,
                    expected_setup_digest,
                    approved_setup,
                )
                running = self._running_scan(connection, workspace_uuid)
                if running is not None:
                    return self._start_result(connection, workspace_uuid, running["id"], True)
                if workspace["updated_at"] != workspace_version:
                    raise WorkbenchError(
                        "setup_changed",
                        "Workspace setup changed while the scan was starting.",
                    )
                current_target = self.targets.require_target(captured.target_path)
                current_metadata = current_target.stat()
                if (current_metadata.st_dev, current_metadata.st_ino) != (
                    captured.target_device,
                    captured.target_inode,
                ):
                    raise WorkbenchError(
                        "target_replaced",
                        "The selected target was replaced while the scan was starting.",
                    )
                scan_dir = Path(
                    tempfile.mkdtemp(
                        prefix="%s_%s_" % (
                            _safe_segment(captured.target_revision),
                            _compact_timestamp(),
                        ),
                        dir=str(target_root),
                    )
                ).resolve()
                diff = captured.setup.diff_target
                connection.execute(
                    """
                    INSERT INTO scans (
                        id, workspace_id, target_path, target_revision,
                        target_snapshot_digest, target_device, target_inode,
                        scope, mode, user_context, diff_target_kind,
                        diff_base_revision, diff_head_revision, diff_content_digest,
                        scan_dir, status, phase, started_at, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'running', 'preflight', ?, ?, ?
                    )
                    """,
                    (
                        scan_id,
                        workspace_uuid,
                        captured.target_path,
                        captured.target_revision,
                        captured.target_snapshot_digest,
                        serialize_filesystem_identity(captured.target_device),
                        serialize_filesystem_identity(captured.target_inode),
                        captured.setup.scope,
                        captured.setup.mode,
                        captured.setup.user_context,
                        diff.kind if diff else None,
                        diff.base_revision if diff else None,
                        diff.head_revision if diff else None,
                        diff.content_digest if diff else None,
                        str(scan_dir),
                        timestamp,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO scan_progress (
                        scan_id, review_items_total, review_items_completed,
                        reportable_findings_count, updated_at
                    ) VALUES (?, 0, 0, 0, ?)
                    """,
                    (scan_id, timestamp),
                )
                connection.execute(
                    """
                    UPDATE workspaces
                    SET active_scan_id = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (scan_id, timestamp, workspace_uuid),
                )
            return self._start_result(connection, workspace_uuid, scan_id, False)

    def get_scan_context(self, scan_id, owner_session_hash=None):
        # type: (str, object) -> dict
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            scan = self._require_scan(connection, scan_uuid)
            workspace = self._require_owned_workspace(
                connection,
                scan["workspace_id"],
                owner_hash,
            )
            return {
                "scanId": scan_uuid,
                "workspaceId": workspace["id"],
                "workspace": self._workspace_state(connection, workspace["id"]),
                "scan": self._scan_state(connection, scan),
                "otherRunningDeepScans": self._other_running_deep_scans(
                    connection,
                    scan_uuid,
                ),
            }

    def update_scan_progress(
        self,
        scan_id,
        phase=None,
        review_items_total=None,
        review_items_completed=None,
        reportable_findings_count=None,
        deep_review_pass=None,
        owner_session_hash=None,
    ):
        # type: (str, object, object, object, object, object, object) -> dict
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        requested_phase = _optional_phase(phase)
        requested_total = _optional_nonnegative_int(
            review_items_total,
            "reviewItemsTotal",
        )
        requested_completed = _optional_nonnegative_int(
            review_items_completed,
            "reviewItemsCompleted",
        )
        requested_findings = _optional_nonnegative_int(
            reportable_findings_count,
            "reportableFindingsCount",
        )
        requested_pass = _optional_positive_int(deep_review_pass, "deepReviewPass")
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                scan = self._require_scan(connection, scan_uuid)
                self._require_owned_workspace(
                    connection,
                    scan["workspace_id"],
                    owner_hash,
                )
                if scan["status"] != "running":
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can publish progress.",
                    )
                progress = connection.execute(
                    "SELECT * FROM scan_progress WHERE scan_id = ?",
                    (scan_uuid,),
                ).fetchone()
                if progress is None:
                    raise WorkbenchError(
                        "scan_progress_not_found",
                        "Kiro Security scan progress was not found.",
                    )

                next_phase = requested_phase or scan["phase"]
                current_phase_index = PHASES.index(scan["phase"])
                next_phase_index = PHASES.index(next_phase)
                if next_phase_index < current_phase_index:
                    raise WorkbenchError(
                        "progress_regression",
                        "Scan phase cannot move backward.",
                    )
                if (
                    scan["phase"] == "discovery"
                    and next_phase != "discovery"
                    and progress["review_items_completed"]
                    != progress["review_items_total"]
                ):
                    raise WorkbenchError(
                        "discovery_incomplete",
                        "Discovery progress must be complete before entering a later phase.",
                    )

                current_pass = progress["deep_review_pass"]
                next_pass = requested_pass if requested_pass is not None else current_pass
                new_deep_pass = (
                    requested_pass is not None
                    and (current_pass is None or requested_pass > current_pass)
                )
                if requested_pass is not None:
                    if scan["mode"] != "deep" or next_phase != "discovery":
                        raise WorkbenchError(
                            "invalid_deep_pass",
                            "Deep review passes can only be published during Deep discovery.",
                        )
                    if current_pass is not None and requested_pass < current_pass:
                        raise WorkbenchError(
                            "progress_regression",
                            "Deep review pass cannot move backward.",
                        )

                next_total = (
                    requested_total
                    if requested_total is not None
                    else progress["review_items_total"]
                )
                next_completed = (
                    requested_completed
                    if requested_completed is not None
                    else progress["review_items_completed"]
                )
                next_findings = (
                    requested_findings
                    if requested_findings is not None
                    else progress["reportable_findings_count"]
                )
                if next_completed > next_total:
                    raise WorkbenchError(
                        "invalid_progress",
                        "Completed review items cannot exceed total review items.",
                    )
                if not new_deep_pass and (
                    next_total < progress["review_items_total"]
                    or next_completed < progress["review_items_completed"]
                ):
                    raise WorkbenchError(
                        "progress_regression",
                        "Review progress must be monotonic within one pass.",
                    )
                if next_findings < progress["reportable_findings_count"]:
                    raise WorkbenchError(
                        "progress_regression",
                        "Reportable finding count cannot decrease.",
                    )

                timestamp = utc_now()
                scan_updated = connection.execute(
                    """
                    UPDATE scans
                    SET phase = ?, updated_at = ?
                    WHERE id = ? AND status = 'running'
                    """,
                    (next_phase, timestamp, scan_uuid),
                )
                if scan_updated.rowcount != 1:
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can publish progress.",
                    )
                progress_updated = connection.execute(
                    """
                    UPDATE scan_progress
                    SET review_items_total = ?, review_items_completed = ?,
                        reportable_findings_count = ?, deep_review_pass = ?,
                        updated_at = ?
                    WHERE scan_id = ?
                    """,
                    (
                        next_total,
                        next_completed,
                        next_findings,
                        next_pass,
                        timestamp,
                        scan_uuid,
                    ),
                )
                if progress_updated.rowcount != 1:
                    raise WorkbenchError(
                        "scan_progress_not_found",
                        "Kiro Security scan progress was not found.",
                    )
            return self._scan_state(
                connection,
                self._require_scan(connection, scan_uuid),
            )

    def fail_scan(self, scan_id, message=None, owner_session_hash=None):
        # type: (str, object, object) -> dict
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        failure_message = _optional_text(message, 2400)
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                scan = self._require_scan(connection, scan_uuid)
                self._require_owned_workspace(
                    connection,
                    scan["workspace_id"],
                    owner_hash,
                )
                if scan["status"] == "failed":
                    return self._scan_state(connection, scan)
                if scan["status"] == "complete":
                    raise WorkbenchError(
                        "scan_complete",
                        "A completed scan cannot be marked failed.",
                    )
                timestamp = utc_now()
                updated = connection.execute(
                    """
                    UPDATE scans
                    SET status = 'failed', failure_message = ?,
                        completed_at = ?, updated_at = ?
                    WHERE id = ? AND status = 'running'
                    """,
                    (failure_message, timestamp, timestamp, scan_uuid),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can be marked failed.",
                    )
                progress = connection.execute(
                    "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                    (timestamp, scan_uuid),
                )
                if progress.rowcount != 1:
                    raise WorkbenchError(
                        "scan_progress_not_found",
                        "Kiro Security scan progress was not found.",
                    )
            return self._scan_state(
                connection,
                self._require_scan(connection, scan_uuid),
            )

    def cancel_scan(self, scan_id, owner_session_hash=None):
        # type: (str, object) -> dict
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                scan = self._require_scan(connection, scan_uuid)
                workspace = self._require_owned_workspace(
                    connection,
                    scan["workspace_id"],
                    owner_hash,
                )
                if scan["canceled_at"] is not None:
                    return self._workspace_state(connection, workspace["id"])
                if scan["status"] != "running":
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can be canceled.",
                    )
                timestamp = utc_now()
                updated = connection.execute(
                    """
                    UPDATE scans
                    SET status = 'failed', canceled_at = ?,
                        completed_at = ?, updated_at = ?
                    WHERE id = ? AND status = 'running'
                    """,
                    (timestamp, timestamp, timestamp, scan_uuid),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can be canceled.",
                    )
                progress = connection.execute(
                    "UPDATE scan_progress SET updated_at = ? WHERE scan_id = ?",
                    (timestamp, scan_uuid),
                )
                if progress.rowcount != 1:
                    raise WorkbenchError(
                        "scan_progress_not_found",
                        "Kiro Security scan progress was not found.",
                    )
            return self._workspace_state(connection, workspace["id"])

    def _normalize_draft_setup(self, setup):
        # type: (WorkspaceSetup) -> WorkspaceSetup
        if setup.mode not in MODES:
            raise WorkbenchError("invalid_mode", "Scan mode must be diff, standard, or deep.")
        target_path = _optional_text(setup.target_path, 4096)
        scope = _optional_text(setup.scope, 4096) or "."
        user_context = _optional_text(setup.user_context)
        diff = setup.diff_target if setup.mode == "diff" else None
        if diff is not None and diff.kind not in DIFF_TARGET_KINDS:
            raise WorkbenchError("invalid_diff_target", "Unsupported Git diff target kind.")
        normalized = WorkspaceSetup(
            target_path=target_path,
            mode=setup.mode,
            scope=scope,
            user_context=user_context,
            diff_target=(
                DiffTarget(
                    diff.kind,
                    _optional_text(diff.base_revision, 512),
                    _optional_text(diff.head_revision, 512),
                    _optional_text(diff.content_digest, 128),
                )
                if diff
                else None
            ),
        )
        if target_path is None:
            return normalized
        try:
            return self.targets.inspect_setup(normalized)
        except WorkbenchError:
            return normalized

    def _start_result(self, connection, workspace_id, scan_id, reused):
        return {
            "reused": reused,
            "scanId": scan_id,
            "workspace": self._workspace_state(connection, workspace_id),
        }

    def _verify_start_approval(
        self,
        workspace,
        authoritative_setup,
        expected_revision,
        expected_digest,
        approved_setup,
    ):
        supplied = (
            expected_revision is not None,
            expected_digest is not None,
            approved_setup is not None,
        )
        if not all(supplied):
            raise WorkbenchError(
                "start_approval_incomplete",
                "Scan start requires setup revision, digest, and exact setup together.",
            )
        if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
            raise WorkbenchError(
                "start_approval_invalid",
                "Scan start setup revision must be an integer.",
            )
        if expected_revision != workspace["setup_revision"]:
            raise WorkbenchError(
                "setup_changed",
                "Workspace setup changed after scan start was prepared.",
            )
        authoritative_digest = _setup_digest(authoritative_setup)
        if not isinstance(expected_digest, str) or not hmac.compare_digest(
            expected_digest,
            authoritative_digest,
        ):
            raise WorkbenchError(
                "setup_changed",
                "Workspace setup digest does not match the approved scan start.",
            )
        if not isinstance(approved_setup, WorkspaceSetup):
            raise WorkbenchError(
                "start_approval_invalid",
                "Scan start requires an exact approved setup.",
            )
        if not hmac.compare_digest(
            _setup_digest(approved_setup),
            authoritative_digest,
        ):
            raise WorkbenchError(
                "setup_changed",
                "Approved scan setup does not match the workspace authority.",
            )

    def _workspace_state(self, connection, workspace_id):
        workspace = self._require_workspace(connection, workspace_id)
        current_scan = None
        if workspace["active_scan_id"] is not None:
            current_scan = self._scan_state(
                connection,
                self._require_scan(connection, workspace["active_scan_id"]),
            )
        setup_state = {
            "submitted": bool(workspace["submitted"]),
            "valid": False,
            "revision": workspace["setup_revision"],
        }
        setup_digest = None
        if workspace["target_path"] is not None:
            stored_setup = self._setup_from_row(workspace)
            setup_digest = _setup_digest(stored_setup)
            setup_state["digest"] = setup_digest
            setup_state["value"] = _setup_projection(stored_setup)
            try:
                self.targets.inspect_setup(stored_setup)
                setup_state["valid"] = True
            except WorkbenchError as exc:
                setup_state["error"] = {"code": exc.code, "message": str(exc)}
        return {
            "id": workspace["id"],
            "chatBound": True,
            "targetPath": workspace["target_path"],
            "targetTitle": workspace["target_title"],
            "scope": workspace["default_scope"],
            "mode": workspace["default_mode"],
            "userContext": workspace["user_context"],
            "diffTarget": _diff_from_row(workspace),
            "setup": setup_state,
            "setupRevision": workspace["setup_revision"],
            "setupDigest": setup_digest,
            "activeScanId": workspace["active_scan_id"],
            "currentScan": current_scan,
            "createdAt": workspace["created_at"],
            "updatedAt": workspace["updated_at"],
        }

    def _scan_state(self, connection, scan):
        progress = connection.execute(
            "SELECT * FROM scan_progress WHERE scan_id = ?",
            (scan["id"],),
        ).fetchone()
        if progress is None:
            raise WorkbenchError(
                "scan_progress_not_found",
                "Kiro Security scan progress was not found.",
            )
        status = "canceled" if scan["canceled_at"] is not None else scan["status"]
        return {
            "id": scan["id"],
            "workspaceId": scan["workspace_id"],
            "status": status,
            "databaseStatus": scan["status"],
            "phase": scan["phase"],
            "target": {
                "targetId": self.targets.stable_target_id(Path(scan["target_path"])),
                "path": scan["target_path"],
                "revision": scan["target_revision"],
                "snapshotDigest": scan["target_snapshot_digest"],
                "device": scan["target_device"],
                "inode": scan["target_inode"],
            },
            "scope": scan["scope"],
            "mode": scan["mode"],
            "userContext": scan["user_context"],
            "diffTarget": _diff_from_row(scan),
            "scanDir": scan["scan_dir"],
            "failureMessage": scan["failure_message"],
            "canceledAt": scan["canceled_at"],
            "startedAt": scan["started_at"],
            "completedAt": scan["completed_at"],
            "updatedAt": scan["updated_at"],
            "progress": {
                "reviewItemsTotal": progress["review_items_total"],
                "reviewItemsCompleted": progress["review_items_completed"],
                "reportableFindingsCount": progress["reportable_findings_count"],
                "deepReviewPass": progress["deep_review_pass"],
                "updatedAt": progress["updated_at"],
            },
        }

    @staticmethod
    def _other_running_deep_scans(connection, scan_id):
        rows = connection.execute(
            """
            SELECT id, workspace_id, target_path, phase, started_at, updated_at
            FROM scans
            WHERE status = 'running' AND mode = 'deep' AND id != ?
            ORDER BY updated_at DESC, created_at DESC
            """,
            (scan_id,),
        ).fetchall()
        return [
            {
                "scanId": row["id"],
                "workspaceId": row["workspace_id"],
                "targetPath": row["target_path"],
                "phase": row["phase"],
                "startedAt": row["started_at"],
                "updatedAt": row["updated_at"],
            }
            for row in rows
        ]

    def _setup_from_row(self, row):
        target_path = row["target_path"]
        if target_path is None:
            raise WorkbenchError("setup_not_submitted", "Save setup before starting a scan.")
        return WorkspaceSetup(
            target_path=target_path,
            mode=row["default_mode"],
            scope=row["default_scope"],
            user_context=row["user_context"],
            diff_target=(
                DiffTarget(
                    row["diff_target_kind"],
                    row["diff_base_revision"],
                    row["diff_head_revision"],
                    row["diff_content_digest"],
                )
                if row["diff_target_kind"]
                else None
            ),
        )

    @staticmethod
    def _require_workspace(connection, workspace_id):
        row = connection.execute(
            "SELECT * FROM workspaces WHERE id = ?",
            (workspace_id,),
        ).fetchone()
        if row is None:
            raise WorkbenchError("workspace_not_found", "Logical workspace was not found.")
        return row

    @classmethod
    def _require_owned_workspace(cls, connection, workspace_id, owner_session_hash):
        workspace = cls._require_workspace(connection, workspace_id)
        if not hmac.compare_digest(
            workspace["owner_session_hash"],
            owner_session_hash,
        ):
            raise WorkbenchError(
                "workspace_not_owned",
                "Logical workspace does not belong to this Kiro chat.",
            )
        return workspace

    @staticmethod
    def _require_scan(connection, scan_id):
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            raise WorkbenchError("scan_not_found", "Scan was not found.")
        return row

    @staticmethod
    def _running_scan(connection, workspace_id):
        return connection.execute(
            """
            SELECT * FROM scans
            WHERE workspace_id = ? AND status = 'running'
            """,
            (workspace_id,),
        ).fetchone()


def _setup_projection(setup):
    # type: (WorkspaceSetup) -> dict
    diff = setup.diff_target
    return {
        "targetPath": setup.target_path,
        "mode": setup.mode,
        "scope": setup.scope,
        "userContext": setup.user_context,
        "diffTarget": (
            {
                "kind": diff.kind,
                "baseRevision": diff.base_revision,
                "headRevision": diff.head_revision,
                "contentDigest": diff.content_digest,
            }
            if diff is not None
            else None
        ),
    }


def _setup_digest(setup):
    # type: (WorkspaceSetup) -> str
    canonical = json.dumps(
        _setup_projection(setup),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def _require_uuid(value, label):
    try:
        normalized = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WorkbenchError("invalid_%s_id" % label, "%s ID must be a UUID." % label) from exc
    return normalized


def _optional_text(value, maximum=None):
    if value is None:
        return None
    if not isinstance(value, str):
        raise WorkbenchError("invalid_text", "Text input must be a string.")
    normalized = value.strip()
    if not normalized:
        return None
    if maximum is not None and len(normalized) > maximum:
        raise WorkbenchError("text_too_long", "Text input exceeds the supported length.")
    return normalized


def _optional_phase(value):
    if value is None:
        return None
    if not isinstance(value, str) or value not in PHASES:
        raise WorkbenchError(
            "invalid_phase",
            "Scan phase must be one of the supported lifecycle phases.",
        )
    return value


def _optional_nonnegative_int(value, name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkbenchError(
            "invalid_progress",
            "%s must be a non-negative integer." % name,
        )
    return value


def _optional_positive_int(value, name):
    result = _optional_nonnegative_int(value, name)
    if result == 0:
        raise WorkbenchError(
            "invalid_progress",
            "%s must be a positive integer." % name,
        )
    return result


def _diff_from_row(row):
    if row["diff_target_kind"] is None:
        return None
    result = {
        "kind": row["diff_target_kind"],
        "baseRevision": row["diff_base_revision"],
        "headRevision": row["diff_head_revision"],
    }
    if row["diff_content_digest"] is not None:
        result["contentDigest"] = row["diff_content_digest"]
    return result


def _safe_segment(value):
    segment = "".join(
        character if character.isalnum() or character in "._-" else "-"
        for character in value
    )
    return segment.strip("-") or "scan"


def _compact_timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
