"""Global workspace authority, current-result pointer, and scan-start lifecycle."""

import hashlib
import hmac
import json
import os
import shutil
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .artifacts import (
    ArtifactContractError,
    finalize_scan,
    verify_seal,
    write_csv_projection,
    write_sarif_projection,
)
from .attestation import arguments_hash, require_request_nonce, require_session_hash
from .db import Database, immediate_transaction, utc_now
from .errors import WorkbenchError
from .filesystem_identity import serialize_filesystem_identity
from .followup import FollowupStore
from .models import DIFF_TARGET_KINDS, MODES, PHASES, DiffTarget, WorkspaceSetup
from .semantic_artifacts import SemanticArtifactStore, coverage_mode
from .target import Git, TargetInspector


class Workbench:
    """One global SQLite authority shared by the Extension and Agent MCP adapter."""

    def __init__(self, state_root, scan_root=None):
        # type: (str, object) -> None
        self.database = Database(Path(state_root))
        self.scan_root = self._prepare_scan_root(
            Path(scan_root) if scan_root is not None else self.database.state_root / "scans"
        )
        self.targets = TargetInspector()
        self.semantic_artifacts = SemanticArtifactStore()
        self.followup = FollowupStore(self.database)

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
                        id, workspace_id, owner_session_hash,
                        target_path, target_revision,
                        target_snapshot_digest, target_device, target_inode,
                        scope, mode, user_context, diff_target_kind,
                        diff_base_revision, diff_head_revision, diff_content_digest,
                        scan_dir, status, phase, started_at, created_at, updated_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        'running', 'preflight', ?, ?, ?
                    )
                    """,
                    (
                        scan_id,
                        workspace_uuid,
                        owner_hash,
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

    def get_scan_context(
        self,
        scan_id,
        recovery_request_id=None,
        recovery_token=None,
        expected_version=None,
        owner_session_hash=None,
    ):
        # type: (str, object, object, object, object) -> dict
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        recovery_values = (
            recovery_request_id,
            recovery_token,
            expected_version,
        )
        if any(value is not None for value in recovery_values):
            if not all(value is not None for value in recovery_values):
                raise WorkbenchError(
                    "recovery_incomplete",
                    "Recovery context requires request, token, and expected version.",
                )
            delivered = self.followup.deliver_scan_recovery(
                recovery_request_id,
                recovery_token,
                expected_version,
                owner_hash,
                scan_uuid,
            )
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            workspace = self._require_workspace(connection, scan["workspace_id"])
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
                scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
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
                if next_phase_index > current_phase_index + 1:
                    raise WorkbenchError(
                        "phase_skipped",
                        "Scan phases must advance one semantic phase at a time.",
                    )
                if next_phase_index == current_phase_index + 1:
                    self.semantic_artifacts.require_phase_exit(
                        scan,
                        scan["phase"],
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
                scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
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
                scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
                workspace = self._require_workspace(connection, scan["workspace_id"])
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

    def get_scan_artifact_contract(self, scan_id, owner_session_hash=None):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            return self.semantic_artifacts.contract(scan)

    def write_scan_artifact(
        self,
        scan_id,
        descriptor,
        content,
        expected_digest=None,
        owner_session_hash=None,
    ):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        expected = _optional_digest(expected_digest)
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            artifact = self.semantic_artifacts.write(
                scan,
                descriptor,
                content,
                expected,
            )
            contract = self.semantic_artifacts.contract(scan)
            return {"artifact": artifact, "closure": contract["closure"]}

    def complete_scan(self, scan_id, owner_session_hash=None):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            scan_dir = Path(scan["scan_dir"])
        with _scan_lock(scan_dir):
            with self.database.connect() as connection:
                scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
                if scan["status"] == "failed":
                    raise WorkbenchError(
                        "scan_failed",
                        "A failed or canceled scan cannot be completed.",
                    )
                if scan["status"] == "complete":
                    try:
                        result = verify_seal(Path(scan["scan_dir"]))
                    except ArtifactContractError as exc:
                        raise WorkbenchError("seal_invalid", str(exc))
                    if scan["seal_manifest_digest"] != result.manifest_digest:
                        raise WorkbenchError(
                            "seal_invalid",
                            "Database manifest pin does not match the sealed scan.",
                        )
                    return self._completion_state(connection, scan, result)
                if scan["phase"] != "reporting":
                    raise WorkbenchError(
                        "scan_phase_incomplete",
                        "Scan must enter reporting before completion.",
                    )
                progress = connection.execute(
                    "SELECT * FROM scan_progress WHERE scan_id = ?",
                    (scan_uuid,),
                ).fetchone()
                if (
                    progress is None
                    or progress["review_items_completed"]
                    != progress["review_items_total"]
                ):
                    raise WorkbenchError(
                        "scan_progress_incomplete",
                        "All review items must be closed before completion.",
                    )
                canonical = self.semantic_artifacts.read(
                    scan,
                    "canonical-result",
                )
                canonical_findings = canonical.get("findings", {}).get(
                    "findings",
                )
                if (
                    not isinstance(canonical_findings, list)
                    or progress["reportable_findings_count"]
                    != len(canonical_findings)
                ):
                    raise WorkbenchError(
                        "finding_count_mismatch",
                        "Progress finding count must match canonical findings.",
                    )
                self._verify_completion_target(scan)
                sealed_manifest = _has_sealed_manifest(Path(scan["scan_dir"]))
                if sealed_manifest:
                    try:
                        result = verify_seal(Path(scan["scan_dir"]))
                    except ArtifactContractError as exc:
                        raise WorkbenchError("seal_invalid", str(exc))
                else:
                    completed_at = utc_now()
                    self.semantic_artifacts.materialize_finalizer_inputs(
                        scan,
                        completed_at,
                        self.targets.stable_target_id(Path(scan["target_path"])),
                    )
                    try:
                        result = finalize_scan(
                            Path(scan["scan_dir"]),
                            source_root=Path(scan["target_path"]),
                            expected_coverage_mode=coverage_mode(scan),
                        )
                    except ArtifactContractError as exc:
                        raise WorkbenchError("finalization_failed", str(exc))
                self._verify_completion_target(scan)

            with self.database.connect() as connection:
                with immediate_transaction(connection):
                    scan = self._require_owned_scan(
                        connection,
                        scan_uuid,
                        owner_hash,
                    )
                    if scan["status"] == "complete":
                        if scan["seal_manifest_digest"] != result.manifest_digest:
                            raise WorkbenchError(
                                "seal_invalid",
                                "Concurrent completion published another seal.",
                            )
                        return self._completion_state(connection, scan, result)
                    if scan["status"] != "running":
                        raise WorkbenchError(
                            "scan_not_running",
                            "Only a running scan can be completed.",
                        )
                    self._replace_finding_index(
                        connection,
                        scan,
                        result.findings,
                    )
                    timestamp = result.manifest["scan"]["completedAt"]
                    connection.execute(
                        "DELETE FROM scan_artifacts WHERE scan_id = ?",
                        (scan_uuid,),
                    )
                    for kind, path in (
                        ("coverage", "coverage.json"),
                        ("findings", "findings.json"),
                        ("manifest", "scan-manifest.json"),
                        ("markdownReport", "report.md"),
                    ):
                        connection.execute(
                            """
                            INSERT INTO scan_artifacts (
                                scan_id, kind, path, created_at
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (
                                scan_uuid,
                                kind,
                                str(Path(scan["scan_dir"]) / path),
                                timestamp,
                            ),
                        )
                    updated = connection.execute(
                        """
                        UPDATE scans
                        SET status = 'complete', phase = 'reporting',
                            seal_manifest_digest = ?, completed_at = ?,
                            updated_at = ?
                        WHERE id = ? AND status = 'running'
                        """,
                        (
                            result.manifest_digest,
                            timestamp,
                            timestamp,
                            scan_uuid,
                        ),
                    )
                    if updated.rowcount != 1:
                        raise WorkbenchError(
                            "scan_changed",
                            "Scan changed during completion publication.",
                        )
                scan = self._require_scan(connection, scan_uuid)
                return self._completion_state(connection, scan, result)

    def export_scan(self, scan_id, export_format, owner_session_hash=None):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        if export_format not in ("json", "sarif", "csv"):
            raise WorkbenchError(
                "invalid_export_format",
                "Export format must be json, sarif, or csv.",
            )
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            return self._export_scan_projection(
                connection,
                scan,
                export_format,
            )

    def export_scan_local(self, scan_id, export_format):
        scan_uuid = _require_uuid(scan_id, "scan")
        if export_format not in ("json", "sarif", "csv"):
            raise WorkbenchError(
                "invalid_export_format",
                "Export format must be json, sarif, or csv.",
            )
        with self.database.connect() as connection:
            return self._export_scan_projection(
                connection,
                self._require_scan(connection, scan_uuid),
                export_format,
            )

    def _export_scan_projection(self, connection, scan, export_format):
        scan_uuid = scan["id"]
        if scan["status"] != "complete":
            raise WorkbenchError(
                "scan_not_complete",
                "Only a completed scan can be exported.",
            )
        try:
            result = verify_seal(Path(scan["scan_dir"]))
        except ArtifactContractError as exc:
            raise WorkbenchError("seal_invalid", str(exc))
        if result.manifest_digest != scan["seal_manifest_digest"]:
            raise WorkbenchError(
                "seal_invalid",
                "Database manifest pin does not match the sealed scan.",
            )
        if export_format == "json":
            path = Path(scan["scan_dir"]) / "findings.json"
        elif export_format == "sarif":
            try:
                path = write_sarif_projection(
                    Path(scan["scan_dir"]),
                    Path(scan["target_path"]),
                )
            except ArtifactContractError as exc:
                raise WorkbenchError("export_failed", str(exc))
        else:
            triage = self._triage_mapping(connection, scan_uuid)
            try:
                path = write_csv_projection(
                    Path(scan["scan_dir"]),
                    triage,
                    deep_scan=scan["mode"] == "deep",
                )
            except ArtifactContractError as exc:
                raise WorkbenchError("export_failed", str(exc))
        return {
            "scanId": scan_uuid,
            "format": export_format,
            "path": str(path),
        }

    def claim_scan_recovery(
        self,
        request_id,
        expected_version,
        owner_session_hash=None,
    ):
        return self.followup.claim_scan_recovery(
            request_id,
            expected_version,
            require_session_hash(owner_session_hash),
        )

    def release_scan_recovery(
        self,
        request_id,
        recovery_token,
        expected_version,
        owner_session_hash=None,
    ):
        return self.followup.release_scan_recovery(
            request_id,
            recovery_token,
            expected_version,
            require_session_hash(owner_session_hash),
        )

    def claim_remediation_action(
        self,
        request_id,
        expected_version,
        owner_session_hash=None,
    ):
        return self.followup.claim_remediation(
            request_id,
            expected_version,
            require_session_hash(owner_session_hash),
        )

    def claim_tracking_request(
        self,
        request_id,
        expected_version,
        owner_session_hash=None,
    ):
        return self.followup.claim_tracking(
            request_id,
            expected_version,
            require_session_hash(owner_session_hash),
        )

    def get_tracking_context(
        self,
        request_id,
        tracking_token,
        expected_version,
        owner_session_hash=None,
    ):
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT s.* FROM finding_tracking_requests t
                JOIN finding_occurrences o ON o.id = t.occurrence_id
                JOIN scans s ON s.id = o.scan_id
                WHERE t.id = ?
                """,
                (_require_uuid(request_id, "tracking request"),),
            ).fetchone()
            if row is None:
                raise WorkbenchError(
                    "tracking_not_found",
                    "Kiro Security tracking request was not found.",
                )
            self._verify_scan_seal(row)
        context = self.followup.get_tracking_context(
            request_id,
            tracking_token,
            expected_version,
            require_session_hash(owner_session_hash),
        )
        scan = context["scan"]
        self._verify_scan_seal(scan)
        with self.database.connect() as connection:
            context["scan"] = self._scan_state(
                connection,
                self._require_scan(connection, scan["id"]),
            )
        return context

    def get_remediation_context(
        self,
        request_id,
        action_token,
        expected_version,
        owner_session_hash=None,
    ):
        return self.followup.get_remediation_context(
            request_id,
            action_token,
            expected_version,
            require_session_hash(owner_session_hash),
        )

    def set_finding_remediation(
        self,
        occurrence_id,
        request_id,
        expected_version,
        action_token,
        state,
        patch_path=None,
        patch_digest=None,
        applied_content_digest=None,
        summary=None,
        verification_summary=None,
        owner_session_hash=None,
    ):
        with self.database.connect() as connection:
            attempt = connection.execute(
                """
                SELECT r.*, o.scan_id
                FROM finding_remediation_attempts r
                JOIN finding_occurrences o ON o.id = r.occurrence_id
                WHERE r.request_id = ?
                """,
                (_require_uuid(request_id, "remediation request"),),
            ).fetchone()
            if attempt is None:
                raise WorkbenchError(
                    "remediation_not_found",
                    "Kiro Security remediation request was not found.",
                )
            scan = self._require_scan(connection, attempt["scan_id"])
            if state == "generated":
                self._verify_remediation_checkout(
                    scan,
                    scan["target_snapshot_digest"],
                )
                self._verify_remediation_patch(
                    scan,
                    patch_path,
                    patch_digest,
                )
            elif state == "applied":
                self._verify_applied_remediation_checkout(
                    scan,
                    applied_content_digest,
                )
                self._verify_remediation_patch_application(
                    scan,
                    attempt["patch_path"],
                    reverse=True,
                )
                if (
                    not attempt["expected_applied_content_digest"]
                    or self._portable_tree_digest(Path(scan["target_path"]))
                    != attempt["expected_applied_content_digest"]
                ):
                    raise WorkbenchError(
                        "remediation_unrelated_change",
                        "Checkout differs from the exact digest-bound patch result.",
                    )
            elif state == "verified":
                if not attempt["applied_content_digest"]:
                    raise WorkbenchError(
                        "remediation_digest_missing",
                        "Verified remediation requires an applied content digest.",
                    )
                self._verify_applied_remediation_checkout(
                    scan,
                    attempt["applied_content_digest"],
                )
        return self.followup.set_remediation(
            occurrence_id,
            request_id,
            expected_version,
            action_token,
            state,
            require_session_hash(owner_session_hash),
            patch_path,
            patch_digest,
            applied_content_digest,
            summary,
            verification_summary,
        )

    def release_remediation_claim(
        self,
        request_id,
        expected_version,
        action_token,
        owner_session_hash=None,
    ):
        return self.followup.release_remediation(
            request_id,
            expected_version,
            action_token,
            require_session_hash(owner_session_hash),
        )

    def create_scan_recovery_request(self, scan_id):
        return self.followup.create_scan_recovery(scan_id)

    def cancel_scan_recovery_request(self, request_id):
        return self.followup.cancel_scan_recovery(request_id)

    def create_finding_tracking_request(self, occurrence_id):
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT s.* FROM finding_occurrences o
                JOIN scans s ON s.id = o.scan_id
                WHERE o.id = ?
                """,
                (occurrence_id,),
            ).fetchone()
            if row is None:
                raise WorkbenchError(
                    "finding_not_found",
                    "Kiro Security finding occurrence was not found.",
                )
            self._verify_scan_seal(row)
        return self.followup.create_tracking(occurrence_id)

    @staticmethod
    def _verify_scan_seal(scan):
        try:
            result = verify_seal(Path(scan["scan_dir"]))
        except ArtifactContractError as exc:
            raise WorkbenchError("seal_invalid", str(exc))
        if result.manifest_digest != scan["seal_manifest_digest"]:
            raise WorkbenchError(
                "seal_invalid",
                "Database manifest pin does not match the sealed scan.",
            )
        return result

    def request_finding_remediation(
        self,
        occurrence_id,
        action,
        request_id=None,
    ):
        with self.database.connect() as connection:
            occurrence = connection.execute(
                "SELECT scan_id FROM finding_occurrences WHERE id = ?",
                (occurrence_id,),
            ).fetchone()
            if occurrence is None:
                raise WorkbenchError(
                    "finding_not_found",
                    "Kiro Security finding occurrence was not found.",
                )
            scan = self._require_scan(connection, occurrence["scan_id"])
            remediation_target = None
            expected_applied_digest = None
            if action == "generate":
                remediation_target = self._capture_remediation_target(scan)
                self._verify_remediation_identity(scan, remediation_target)
            elif request_id is not None:
                attempt = connection.execute(
                    """
                    SELECT * FROM finding_remediation_attempts
                    WHERE request_id = ?
                    """,
                    (_require_uuid(request_id, "remediation request"),),
                ).fetchone()
                if attempt is None:
                    raise WorkbenchError(
                        "remediation_not_found",
                        "Kiro Security remediation request was not found.",
                    )
                if action == "apply":
                    self._verify_remediation_checkout(
                        scan,
                        attempt["base_content_digest"],
                    )
                    patch = self._verify_remediation_patch(
                        scan,
                        attempt["patch_path"],
                        attempt["patch_digest"],
                    )
                    self._verify_remediation_patch_application(
                        scan,
                        str(patch),
                        reverse=False,
                    )
                    expected_applied_digest = self._expected_patch_tree_digest(
                        scan,
                        patch,
                    )
                elif action == "verify":
                    self._verify_applied_remediation_checkout(
                        scan,
                        attempt["applied_content_digest"],
                    )
        return self.followup.request_remediation(
            occurrence_id,
            action,
            request_id,
            (
                remediation_target.target_revision
                if remediation_target is not None
                else None
            ),
            (
                remediation_target.target_snapshot_digest
                if remediation_target is not None
                else None
            ),
            expected_applied_digest,
        )

    def set_finding_triage(
        self,
        occurrence_id,
        status,
        close_reason=None,
        note=None,
    ):
        if status == "closed" and close_reason == "already_fixed":
            with self.database.connect() as connection:
                latest = connection.execute(
                    """
                    SELECT r.*, o.scan_id
                    FROM finding_remediation_attempts r
                    JOIN finding_occurrences o ON o.id = r.occurrence_id
                    WHERE r.occurrence_id = ?
                    ORDER BY r.created_at DESC LIMIT 1
                    """,
                    (occurrence_id,),
                ).fetchone()
                if (
                    latest is not None
                    and latest["state"] == "verified"
                    and latest["applied_content_digest"] is not None
                ):
                    self._verify_applied_remediation_checkout(
                        self._require_scan(connection, latest["scan_id"]),
                        latest["applied_content_digest"],
                    )
        return self.followup.set_triage(
            occurrence_id,
            status,
            close_reason,
            note,
        )

    def dashboard_projection(self):
        with self.database.connect() as connection:
            scans = connection.execute(
                "SELECT id FROM scans ORDER BY updated_at DESC, created_at DESC"
            ).fetchall()
            findings = self._finding_projection(connection)
            recovery = connection.execute(
                """
                SELECT id, scan_id, status, version, claimed_at, delivered_at,
                       created_at, updated_at
                FROM scan_recovery_requests r
                WHERE r.id = (
                    SELECT latest.id FROM scan_recovery_requests latest
                    WHERE latest.scan_id = r.scan_id
                    ORDER BY latest.updated_at DESC, latest.created_at DESC
                    LIMIT 1
                )
                ORDER BY updated_at DESC, created_at DESC
                """
            ).fetchall()
            remediation = connection.execute(
                """
                SELECT * FROM finding_remediation_attempts r
                WHERE r.request_id = (
                    SELECT latest.request_id
                    FROM finding_remediation_attempts latest
                    WHERE latest.occurrence_id = r.occurrence_id
                    ORDER BY latest.updated_at DESC, latest.created_at DESC
                    LIMIT 1
                )
                ORDER BY updated_at DESC, created_at DESC
                """
            ).fetchall()
            return {
                "scans": [
                    self._scan_state(
                        connection,
                        self._require_scan(connection, row["id"]),
                    )
                    for row in scans
                ],
                "findings": findings,
                "recoveryRequests": [
                    {
                        "id": row["id"],
                        "scanId": row["scan_id"],
                        "status": row["status"],
                        "version": row["version"],
                        "claimedAt": row["claimed_at"],
                        "deliveredAt": row["delivered_at"],
                        "createdAt": row["created_at"],
                        "updatedAt": row["updated_at"],
                    }
                    for row in recovery
                ],
                "remediationRequests": [
                    self.followup_state_remediation(row)
                    for row in remediation
                ],
            }

    @staticmethod
    def followup_state_remediation(row):
        return {
            "requestId": row["request_id"],
            "occurrenceId": row["occurrence_id"],
            "state": row["state"],
            "version": row["version"],
            "pendingAction": row["pending_action"],
            "patchPath": row["patch_path"],
            "summary": row["summary"],
            "verificationSummary": row["verification_summary"],
            "createdAt": row["created_at"],
            "updatedAt": row["updated_at"],
        }

    def _completion_state(self, connection, scan, result):
        return {
            "scan": self._scan_state(connection, scan),
            "manifestPath": str(Path(scan["scan_dir"]) / "scan-manifest.json"),
            "findingsPath": str(Path(scan["scan_dir"]) / "findings.json"),
            "coveragePath": str(Path(scan["scan_dir"]) / "coverage.json"),
            "reportPath": str(result.report_path),
            "sarifPath": str(result.sarif_path) if result.sarif_path else None,
            "manifestDigest": result.manifest_digest,
            "reusedSeal": result.reused_seal,
        }

    def _verify_completion_target(self, scan):
        if scan["mode"] == "diff" and scan["diff_target_kind"] in (
            "commit",
            "range",
        ):
            return
        setup = WorkspaceSetup(
            target_path=scan["target_path"],
            mode=scan["mode"],
            scope=scan["scope"],
            user_context=scan["user_context"],
            diff_target=(
                DiffTarget(
                    scan["diff_target_kind"],
                    scan["diff_base_revision"],
                    scan["diff_head_revision"],
                    scan["diff_content_digest"],
                )
                if scan["diff_target_kind"]
                else None
            ),
        )
        current = self.targets.capture(setup)
        if (
            current.target_revision != scan["target_revision"]
            or current.target_snapshot_digest != scan["target_snapshot_digest"]
        ):
            raise WorkbenchError(
                "target_changed",
                "Target changed after the immutable scan snapshot was captured.",
            )

    def _verify_remediation_checkout(self, scan, expected_content_digest):
        current = self._capture_remediation_target(scan)
        self._verify_remediation_identity(scan, current)
        if (
            expected_content_digest is not None
            and current.target_snapshot_digest != expected_content_digest
        ):
            raise WorkbenchError(
                "remediation_content_changed",
                "Remediation checkout content does not match the expected digest.",
            )
        return current

    def _verify_applied_remediation_checkout(self, scan, expected_digest):
        current = self._capture_remediation_target(scan)
        self._verify_remediation_identity(scan, current)
        actual = self._portable_tree_digest(Path(scan["target_path"]))
        if (
            not isinstance(expected_digest, str)
            or not hmac.compare_digest(actual, expected_digest)
        ):
            raise WorkbenchError(
                "remediation_content_changed",
                "Remediation checkout content does not match the applied digest.",
            )
        return current

    @staticmethod
    def _verify_remediation_identity(scan, current):
        if (
            str(current.target_device) != str(scan["target_device"])
            or str(current.target_inode) != str(scan["target_inode"])
            or current.target_revision != scan["target_revision"]
        ):
            raise WorkbenchError(
                "remediation_target_changed",
                "Remediation checkout identity or revision changed after the scan.",
            )

    def _capture_remediation_target(self, scan):
        return self.targets.capture(
            WorkspaceSetup(
                target_path=scan["target_path"],
                mode="standard",
                scope=scan["scope"],
                user_context=scan["user_context"],
                diff_target=None,
            )
        )

    @staticmethod
    def _verify_remediation_patch(scan, patch_path, patch_digest):
        expected_digest = _optional_digest(patch_digest)
        if not isinstance(patch_path, str) or expected_digest is None:
            raise WorkbenchError(
                "remediation_patch_required",
                "Remediation patch path and digest are required.",
            )
        try:
            scan_dir = Path(scan["scan_dir"]).resolve(strict=True)
            candidate = Path(patch_path).resolve(strict=True)
            candidate.relative_to(scan_dir)
        except (OSError, RuntimeError, ValueError) as exc:
            raise WorkbenchError(
                "remediation_patch_unsafe",
                "Remediation patch must stay inside the scan directory.",
            ) from exc
        metadata = candidate.lstat()
        if (
            candidate.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > 2 * 1024 * 1024
        ):
            raise WorkbenchError(
                "remediation_patch_unsafe",
                "Remediation patch must be a regular file no larger than 2 MiB.",
            )
        actual = hashlib.sha256(candidate.read_bytes()).hexdigest()
        if not hmac.compare_digest(actual, expected_digest):
            raise WorkbenchError(
                "remediation_patch_changed",
                "Remediation patch digest does not match.",
            )
        return candidate

    @staticmethod
    def _verify_remediation_patch_application(scan, patch_path, reverse):
        arguments = ["apply", "--check"]
        if reverse:
            arguments.append("--reverse")
        arguments.append(str(patch_path))
        completed = Git.run(
            Path(scan["target_path"]),
            arguments,
            True,
        )
        if completed.returncode != 0:
            raise WorkbenchError(
                "remediation_patch_not_applied"
                if reverse
                else "remediation_patch_not_applicable",
                "The digest-bound remediation patch is not in the required checkout state.",
            )

    def _expected_patch_tree_digest(self, scan, patch_path):
        target = Path(scan["target_path"])
        with tempfile.TemporaryDirectory(prefix="kiro-security-remediation-") as value:
            copy_root = Path(value) / "target"
            copy_root.mkdir(mode=0o700)
            for source in self.targets._directory_snapshot_paths(target):
                relative = source.relative_to(target)
                destination = copy_root / relative
                metadata = source.lstat()
                if stat.S_ISDIR(metadata.st_mode):
                    destination.mkdir(mode=stat.S_IMODE(metadata.st_mode), parents=True, exist_ok=True)
                elif stat.S_ISLNK(metadata.st_mode):
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.symlink(os.readlink(source), destination)
                elif stat.S_ISREG(metadata.st_mode):
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copy2(source, destination, follow_symlinks=False)
            completed = Git.run(
                copy_root,
                ["apply", "--recount", str(patch_path)],
                True,
            )
            if completed.returncode != 0:
                raise WorkbenchError(
                    "remediation_patch_not_applicable",
                    "Could not derive the exact post-patch checkout.",
                )
            return self._portable_tree_digest(copy_root, use_git_inventory=False)

    def _portable_tree_digest(self, root, use_git_inventory=True):
        paths = (
            self.targets._directory_snapshot_paths(root)
            if use_git_inventory
            else sorted(
                root.rglob("*"),
                key=lambda item: item.relative_to(root).as_posix(),
            )
        )
        digest = hashlib.sha256()
        digest.update(b"kiro-security-remediation-tree/v1\0")
        for path in paths:
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            relative = path.relative_to(root).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(4, "big"))
            digest.update(relative)
            mode = str(stat.S_IMODE(metadata.st_mode)).encode("ascii")
            digest.update(len(mode).to_bytes(2, "big"))
            digest.update(mode)
            if stat.S_ISLNK(metadata.st_mode):
                content = os.fsencode(os.readlink(path))
                kind = b"symlink"
            elif stat.S_ISREG(metadata.st_mode):
                content = path.read_bytes()
                kind = b"file"
            else:
                raise WorkbenchError(
                    "unsupported_target_file",
                    "Remediation snapshots do not support special files.",
                )
            digest.update(len(kind).to_bytes(1, "big"))
            digest.update(kind)
            digest.update(len(content).to_bytes(8, "big"))
            digest.update(content)
        return digest.hexdigest()

    def _replace_finding_index(self, connection, scan, findings_document):
        connection.execute(
            "DELETE FROM finding_occurrences WHERE scan_id = ?",
            (scan["id"],),
        )
        timestamp = utc_now()
        for finding in findings_document["findings"]:
            identity = finding["identity"]
            connection.execute(
                """
                INSERT INTO findings (
                    id, fingerprint, rule_id, identity_anchor,
                    identity_instance, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    rule_id = excluded.rule_id,
                    identity_anchor = excluded.identity_anchor,
                    identity_instance = excluded.identity_instance,
                    updated_at = excluded.updated_at
                """,
                (
                    finding["findingId"],
                    finding["fingerprints"]["primary"],
                    finding["ruleId"],
                    identity["anchor"],
                    identity.get("instance"),
                    timestamp,
                    timestamp,
                ),
            )
            connection.execute(
                """
                INSERT INTO finding_occurrences (
                    id, finding_id, scan_id, title, summary, severity,
                    confidence, remediation, details_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding["occurrenceId"],
                    finding["findingId"],
                    scan["id"],
                    finding["title"],
                    finding["summary"],
                    finding["severity"]["level"],
                    finding["confidence"]["level"],
                    finding["remediation"],
                    json.dumps(
                        finding,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    timestamp,
                ),
            )
            for index, location in enumerate(finding["locations"]):
                connection.execute(
                    """
                    INSERT INTO finding_locations (
                        occurrence_id, relative_path, start_line, end_line,
                        role, sort_order
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding["occurrenceId"],
                        location["path"],
                        location["startLine"],
                        location.get("endLine", location["startLine"]),
                        location.get("role"),
                        index,
                    ),
                )

    def _finding_projection(self, connection):
        rows = connection.execute(
            """
            SELECT o.*, t.status AS triage_status,
                   t.close_reason, t.note, t.updated_at AS triage_updated_at
            FROM finding_occurrences o
            LEFT JOIN finding_triage t ON t.occurrence_id = o.id
            ORDER BY
                CASE o.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    WHEN 'low' THEN 3
                    ELSE 4
                END,
                o.id
            """
        ).fetchall()
        values = []
        for row in rows:
            locations = connection.execute(
                """
                SELECT relative_path, start_line, end_line, role, sort_order
                FROM finding_locations WHERE occurrence_id = ?
                ORDER BY sort_order
                """,
                (row["id"],),
            ).fetchall()
            values.append(
                {
                    "occurrenceId": row["id"],
                    "findingId": row["finding_id"],
                    "scanId": row["scan_id"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "severity": row["severity"],
                    "confidence": row["confidence"],
                    "remediation": row["remediation"],
                    "locations": [
                        {
                            "path": location["relative_path"],
                            "startLine": location["start_line"],
                            "endLine": location["end_line"],
                            "role": location["role"],
                        }
                        for location in locations
                    ],
                    "triage": {
                        "status": row["triage_status"] or "open",
                        "closeReason": row["close_reason"],
                        "note": row["note"],
                        "updatedAt": row["triage_updated_at"],
                    },
                }
            )
        return values

    def _triage_mapping(self, connection, scan_id):
        rows = connection.execute(
            """
            SELECT o.id, t.status, t.close_reason, t.note
            FROM finding_occurrences o
            LEFT JOIN finding_triage t ON t.occurrence_id = o.id
            WHERE o.scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
        return {
            row["id"]: {
                "status": row["status"] or "open",
                "closeReason": row["close_reason"],
                "note": row["note"],
            }
            for row in rows
        }

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

    @classmethod
    def _require_owned_scan(cls, connection, scan_id, owner_session_hash):
        scan = cls._require_scan(connection, scan_id)
        if not hmac.compare_digest(
            scan["owner_session_hash"],
            owner_session_hash,
        ):
            raise WorkbenchError(
                "scan_not_owned",
                "Scan does not belong to this Kiro chat.",
            )
        return scan

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


def _optional_digest(value):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WorkbenchError(
            "invalid_digest",
            "Expected digest must be a lowercase SHA-256 value.",
        )
    return value


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


def _has_sealed_manifest(scan_dir):
    path = scan_dir / "scan-manifest.json"
    if not path.is_file() or path.is_symlink():
        return False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    return (
        isinstance(value, dict)
        and isinstance(value.get("scan"), dict)
        and value["scan"].get("sealedAt") is not None
        and value["scan"].get("artifacts") is not None
    )


@contextmanager
def _scan_lock(scan_dir):
    root = scan_dir.resolve(strict=True)
    lock_path = root / ".completion.lock"
    descriptor = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
