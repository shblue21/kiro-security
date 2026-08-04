"""Global workspace authority, current-result pointer, and scan-start lifecycle."""

import hmac
import os
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .artifacts import (
    ArtifactContractError,
    verify_seal,
    write_csv_projection,
    write_sarif_projection,
)
from .attestation import arguments_hash, require_request_nonce, require_session_hash
from .db import Database, immediate_transaction, utc_now
from .errors import WorkbenchError
from .followup import FollowupStore
from .models import DIFF_TARGET_KINDS, MODES, DiffTarget, WorkspaceSetup
from .remediation_integrity import RemediationIntegrity
from .scan_lifecycle import ScanLifecycleDependencies, ScanLifecycleService
from .semantic_artifacts import SemanticArtifactStore
from .target import TargetInspector
from .workbench_contract import (
    optional_digest as _optional_digest,
    optional_text as _optional_text,
    require_uuid as _require_uuid,
    setup_digest as _setup_digest,
    setup_projection as _setup_projection,
)


class Workbench:
    """One global SQLite authority shared by the Extension and Agent MCP adapter."""

    def __init__(self, state_root, scan_root=None):
        # type: (str, object) -> None
        self.database = Database(Path(state_root))
        self.scan_root = self._prepare_scan_root(
            Path(scan_root) if scan_root is not None else self.database.state_root / "scans"
        )
        self.targets = TargetInspector()
        self.remediation_integrity = RemediationIntegrity(self.targets)
        self.semantic_artifacts = SemanticArtifactStore()
        self.followup = FollowupStore(self.database)
        self.scan_lifecycle = ScanLifecycleService(
            ScanLifecycleDependencies(
                database=self.database,
                scan_root=self.scan_root,
                targets=self.targets,
                semantic_artifacts=self.semantic_artifacts,
                followup=self.followup,
                other_running_deep_scans=self._other_running_deep_scans,
                owned_scan_lock=self._owned_scan_lock,
                require_owned_scan=self._require_owned_scan,
                require_owned_workspace=self._require_owned_workspace,
                require_scan=self._require_scan,
                require_workspace=self._require_workspace,
                running_scan=self._running_scan,
                scan_lock_for_id=self._scan_lock_for_id,
                scan_state=self._scan_state,
                setup_from_row=self._setup_from_row,
                workspace_state=self._workspace_state,
            )
        )

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
        return self.scan_lifecycle.start_scan(
            workspace_id,
            expected_setup_revision,
            expected_setup_digest,
            approved_setup,
            owner_session_hash,
        )

    def get_scan_context(
        self,
        scan_id,
        recovery_request_id=None,
        recovery_token=None,
        expected_version=None,
        owner_session_hash=None,
    ):
        # type: (str, object, object, object, object) -> dict
        return self.scan_lifecycle.get_scan_context(
            scan_id,
            recovery_request_id,
            recovery_token,
            expected_version,
            owner_session_hash,
        )

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
        return self.scan_lifecycle.update_scan_progress(
            scan_id,
            phase,
            review_items_total,
            review_items_completed,
            reportable_findings_count,
            deep_review_pass,
            owner_session_hash,
        )

    def fail_scan(self, scan_id, message=None, owner_session_hash=None):
        # type: (str, object, object) -> dict
        return self.scan_lifecycle.fail_scan(
            scan_id,
            message,
            owner_session_hash,
        )

    def cancel_scan(self, scan_id, owner_session_hash=None):
        # type: (str, object) -> dict
        return self.scan_lifecycle.cancel_scan(
            scan_id,
            owner_session_hash,
        )

    def get_scan_artifact_contract(self, scan_id, owner_session_hash=None):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            return self.semantic_artifacts.contract(scan)

    def read_scan_artifact(
        self,
        scan_id,
        descriptor,
        expected_digest,
        owner_session_hash=None,
    ):
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        expected = _optional_digest(expected_digest)
        if expected is None:
            raise WorkbenchError(
                "artifact_digest_required",
                "Reading an artifact requires its current expected digest.",
            )
        with self._owned_scan_lock(
            scan_uuid,
            owner_hash,
        ), self.database.connect() as connection:
            scan = self._require_owned_scan(connection, scan_uuid, owner_hash)
            return self.semantic_artifacts.read_for_agent(
                scan,
                descriptor,
                expected,
            )

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
        with self._owned_scan_lock(
            scan_uuid,
            owner_hash,
        ), self.database.connect() as connection:
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
        return self.scan_lifecycle.complete_scan(
            scan_id,
            owner_session_hash,
        )

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
                self.remediation_integrity.verify_checkout(
                    scan,
                    scan["target_snapshot_digest"],
                )
                self.remediation_integrity.verify_patch(
                    scan,
                    patch_path,
                    patch_digest,
                )
            elif state == "applied":
                self.remediation_integrity.verify_applied_checkout(
                    scan,
                    applied_content_digest,
                )
                self.remediation_integrity.verify_patch_application(
                    scan,
                    attempt["patch_path"],
                    reverse=True,
                )
                if (
                    not attempt["expected_applied_content_digest"]
                    or self.remediation_integrity.portable_tree_digest(
                        Path(scan["target_path"])
                    )
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
                self.remediation_integrity.verify_applied_checkout(
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
                remediation_target = self.remediation_integrity.capture_target(scan)
                self.remediation_integrity.verify_identity(scan, remediation_target)
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
                    self.remediation_integrity.verify_checkout(
                        scan,
                        attempt["base_content_digest"],
                    )
                    patch = self.remediation_integrity.verify_patch(
                        scan,
                        attempt["patch_path"],
                        attempt["patch_digest"],
                    )
                    self.remediation_integrity.verify_patch_application(
                        scan,
                        str(patch),
                        reverse=False,
                    )
                    expected_applied_digest = (
                        self.remediation_integrity.expected_patch_tree_digest(
                            scan,
                            patch,
                        )
                    )
                elif action == "verify":
                    self.remediation_integrity.verify_applied_checkout(
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
                    self.remediation_integrity.verify_applied_checkout(
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

    def _owned_scan_lock(self, scan_id, owner_session_hash):
        with self.database.connect() as connection:
            scan = self._require_owned_scan(
                connection,
                scan_id,
                owner_session_hash,
            )
            scan_dir = Path(scan["scan_dir"])
        return _scan_lock(scan_dir)

    def _scan_lock_for_id(self, scan_id):
        with self.database.connect() as connection:
            scan = self._require_scan(connection, scan_id)
            scan_dir = Path(scan["scan_dir"])
        return _scan_lock(scan_dir)

    @staticmethod
    def _running_scan(connection, workspace_id):
        return connection.execute(
            """
            SELECT * FROM scans
            WHERE workspace_id = ? AND status = 'running'
            """,
            (workspace_id,),
        ).fetchone()


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
