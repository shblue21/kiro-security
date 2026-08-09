"""Ordered scan lifecycle operations behind the Workbench façade."""

import hmac
import json
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .artifacts import ArtifactContractError, finalize_scan, verify_seal
from .attestation import require_session_hash
from .db import immediate_transaction, utc_now
from .errors import WorkbenchError
from .filesystem_identity import serialize_filesystem_identity
from .models import DiffTarget, PHASES, WorkspaceSetup
from .semantic_contract import coverage_mode
from .workbench_contract import (
    optional_nonnegative_int as _optional_nonnegative_int,
    optional_phase as _optional_phase,
    optional_positive_int as _optional_positive_int,
    optional_text as _optional_text,
    require_uuid as _require_uuid,
    setup_digest as _setup_digest,
)


@dataclass(frozen=True)
class ScanLifecycleDependencies:
    database: Any
    scan_root: Any
    targets: Any
    semantic_artifacts: Any
    followup: Any
    other_running_deep_scans: Any
    owned_scan_lock: Any
    require_owned_scan: Any
    require_owned_workspace: Any
    require_scan: Any
    require_workspace: Any
    running_scan: Any
    scan_lock_for_id: Any
    scan_state: Any
    setup_from_row: Any
    workspace_state: Any


class ScanLifecycleService:
    """Execute scan state transitions without changing their lock ordering."""

    def __init__(self, dependencies):
        self._dependencies = dependencies

    def start_scan(
        self,
        workspace_id,
        expected_setup_revision=None,
        expected_setup_digest=None,
        approved_setup=None,
        owner_session_hash=None,
    ):
        # type: (str, object, object, object, object) -> dict
        deps = self._dependencies
        workspace_uuid = _require_uuid(workspace_id, "workspace")
        owner_hash = require_session_hash(owner_session_hash)
        with deps.database.connect() as connection:
            workspace = deps.require_owned_workspace(
                connection,
                workspace_uuid,
                owner_hash,
            )
            if not workspace["submitted"] or not workspace["target_path"]:
                raise WorkbenchError("setup_not_submitted", "Save setup before starting a scan.")
            workspace_version = workspace["updated_at"]
            setup = deps.setup_from_row(workspace)
            self._verify_start_approval(
                workspace,
                setup,
                expected_setup_revision,
                expected_setup_digest,
                approved_setup,
            )
            running = deps.running_scan(connection, workspace_uuid)
            if running is not None:
                return self._start_result(connection, workspace_uuid, running["id"], True)

        captured = deps.targets.capture(setup)
        target = Path(captured.target_path)
        scan_id = str(uuid.uuid4())
        timestamp = utc_now()
        target_root = (deps.scan_root / _safe_segment(target.name)).resolve()
        if target_root == target or target in target_root.parents:
            raise WorkbenchError(
                "scan_root_inside_target",
                "The scan artifact directory must be outside the selected target.",
            )
        target_root.mkdir(mode=0o700, parents=True, exist_ok=True)

        # Preserve Start ordering: transaction, then target identity revalidation,
        # then scan publication in that same transaction.
        with deps.database.connect() as connection:
            with immediate_transaction(connection):
                workspace = deps.require_owned_workspace(
                    connection,
                    workspace_uuid,
                    owner_hash,
                )
                self._verify_start_approval(
                    workspace,
                    deps.setup_from_row(workspace),
                    expected_setup_revision,
                    expected_setup_digest,
                    approved_setup,
                )
                running = deps.running_scan(connection, workspace_uuid)
                if running is not None:
                    return self._start_result(
                        connection,
                        workspace_uuid,
                        running["id"],
                        True,
                    )
                if workspace["updated_at"] != workspace_version:
                    raise WorkbenchError(
                        "setup_changed",
                        "Workspace setup changed while the scan was starting.",
                    )
                current_target = deps.targets.require_target(captured.target_path)
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
        deps = self._dependencies
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
            # Recovery ownership transfer is serialized with every scan writer.
            with deps.scan_lock_for_id(scan_uuid):
                deps.followup.deliver_scan_recovery(
                    recovery_request_id,
                    recovery_token,
                    expected_version,
                    owner_hash,
                    scan_uuid,
                )
        with deps.database.connect() as connection:
            scan = deps.require_owned_scan(connection, scan_uuid, owner_hash)
            workspace = deps.require_workspace(connection, scan["workspace_id"])
            return {
                "scanId": scan_uuid,
                "workspaceId": workspace["id"],
                "workspace": deps.workspace_state(connection, workspace["id"]),
                "scan": deps.scan_state(connection, scan),
                "otherRunningDeepScans": deps.other_running_deep_scans(
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
        deps = self._dependencies
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
        # Preserve Progress ordering: scan lock, immediate transaction, closure.
        with deps.owned_scan_lock(
            scan_uuid,
            owner_hash,
        ), deps.database.connect() as connection:
            with immediate_transaction(connection):
                scan = deps.require_owned_scan(connection, scan_uuid, owner_hash)
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
                if next_phase != scan["phase"]:
                    deps.semantic_artifacts.require_phase_exit(
                        scan,
                        scan["phase"],
                    )
                    allowed_next = deps.semantic_artifacts.allowed_next_phases(scan)
                    if next_phase not in allowed_next:
                        raise WorkbenchError(
                            "phase_skipped",
                            "The authoritative %s %s phase can advance only to: %s."
                            % (
                                scan["mode"],
                                scan["phase"],
                                ", ".join(allowed_next) or "no later phase",
                            ),
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
                    else (
                        0
                        if current_phase_index < PHASES.index("validation")
                        and next_phase_index >= PHASES.index("validation")
                        else progress["reportable_findings_count"]
                    )
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
            return deps.scan_state(
                connection,
                deps.require_scan(connection, scan_uuid),
            )

    def fail_scan(self, scan_id, message=None, owner_session_hash=None):
        # type: (str, object, object) -> dict
        deps = self._dependencies
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        failure_message = _optional_text(message, 2400)
        with deps.owned_scan_lock(
            scan_uuid,
            owner_hash,
        ), deps.database.connect() as connection:
            with immediate_transaction(connection):
                scan = deps.require_owned_scan(connection, scan_uuid, owner_hash)
                if scan["status"] == "failed":
                    return deps.scan_state(connection, scan)
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
            return deps.scan_state(
                connection,
                deps.require_scan(connection, scan_uuid),
            )

    def cancel_scan(self, scan_id, owner_session_hash=None):
        # type: (str, object) -> dict
        deps = self._dependencies
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        with deps.owned_scan_lock(
            scan_uuid,
            owner_hash,
        ), deps.database.connect() as connection:
            with immediate_transaction(connection):
                scan = deps.require_owned_scan(connection, scan_uuid, owner_hash)
                workspace = deps.require_workspace(connection, scan["workspace_id"])
                if scan["canceled_at"] is not None:
                    return deps.workspace_state(connection, workspace["id"])
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
            return deps.workspace_state(connection, workspace["id"])

    def complete_scan(self, scan_id, owner_session_hash=None):
        deps = self._dependencies
        scan_uuid = _require_uuid(scan_id, "scan")
        owner_hash = require_session_hash(owner_session_hash)
        # The scan lock covers both filesystem sealing and the later DB publish.
        with deps.owned_scan_lock(scan_uuid, owner_hash):
            with deps.database.connect() as connection:
                scan = deps.require_owned_scan(connection, scan_uuid, owner_hash)
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
                canonical = deps.semantic_artifacts.read(
                    scan,
                    "canonical-result",
                )
                canonical_findings = canonical.get("findings", {}).get(
                    "findings",
                )
                deps.semantic_artifacts.require_candidate_finding_binding(
                    scan,
                    canonical,
                )
                if not isinstance(canonical_findings, list):
                    raise WorkbenchError(
                        "invalid_canonical_result",
                        "Canonical findings must contain a findings array.",
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
                    deps.semantic_artifacts.materialize_finalizer_inputs(
                        scan,
                        completed_at,
                        deps.targets.stable_target_id(Path(scan["target_path"])),
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

            with deps.database.connect() as connection:
                with immediate_transaction(connection):
                    scan = deps.require_owned_scan(
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
                    canonical_finding_count = len(
                        result.findings.get("findings", [])
                    )
                    progress_updated = connection.execute(
                        """
                        UPDATE scan_progress
                        SET reportable_findings_count = ?, updated_at = ?
                        WHERE scan_id = ?
                        """,
                        (
                            canonical_finding_count,
                            timestamp,
                            scan_uuid,
                        ),
                    )
                    if progress_updated.rowcount != 1:
                        raise WorkbenchError(
                            "scan_progress_not_found",
                            "Kiro Security scan progress was not found.",
                        )
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
                scan = deps.require_scan(connection, scan_uuid)
                return self._completion_state(connection, scan, result)


    def _completion_state(self, connection, scan, result):
        deps = self._dependencies
        return {
            "scan": deps.scan_state(connection, scan),
            "manifestPath": str(Path(scan["scan_dir"]) / "scan-manifest.json"),
            "findingsPath": str(Path(scan["scan_dir"]) / "findings.json"),
            "coveragePath": str(Path(scan["scan_dir"]) / "coverage.json"),
            "reportPath": str(result.report_path),
            "sarifPath": str(result.sarif_path) if result.sarif_path else None,
            "manifestDigest": result.manifest_digest,
            "reusedSeal": result.reused_seal,
        }

    def _verify_completion_target(self, scan):
        deps = self._dependencies
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
        current = deps.targets.capture(setup)
        if (
            current.target_revision != scan["target_revision"]
            or current.target_snapshot_digest != scan["target_snapshot_digest"]
        ):
            raise WorkbenchError(
                "target_changed",
                "Target changed after the immutable scan snapshot was captured.",
            )

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

    def _start_result(self, connection, workspace_id, scan_id, reused):
        deps = self._dependencies
        return {
            "reused": reused,
            "scanId": scan_id,
            "workspace": deps.workspace_state(connection, workspace_id),
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
