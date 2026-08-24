"""Kiro chat recovery and finding follow-up lifecycle."""

import json
import time
import uuid

from .attestation import require_session_hash
from .db import immediate_transaction, utc_now
from .errors import WorkbenchError

RECOVERY_CLAIM_SECONDS = 120
REMEDIATION_CLAIM_SECONDS = 120
REMEDIATION_WORKER_SECONDS = 900
TRIAGE_CLOSE_REASONS = ("already_fixed", "wont_fix", "false_positive")
REMEDIATION_ACTIONS = ("generate", "apply", "verify")


class FollowupStore:
    """Durable App-like requests and CAS claims in the shared database."""

    def __init__(self, database):
        self.database = database

    def create_scan_recovery(self, scan_id):
        scan_uuid = _require_uuid(scan_id, "scan")
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                scan = _require_scan(connection, scan_uuid)
                if scan["status"] != "running":
                    raise WorkbenchError(
                        "scan_not_running",
                        "Only a running scan can be resumed.",
                    )
                existing = connection.execute(
                    """
                    SELECT * FROM scan_recovery_requests
                    WHERE scan_id = ? AND status IN ('pending', 'claimed')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (scan_uuid,),
                ).fetchone()
                if existing is not None:
                    return _recovery_state(existing)
                request_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO scan_recovery_requests (
                        id, scan_id, status, version, created_at, updated_at
                    ) VALUES (?, ?, 'pending', 1, ?, ?)
                    """,
                    (request_id, scan_uuid, timestamp, timestamp),
                )
            return _recovery_state(_require_recovery(connection, request_id))

    def claim_scan_recovery(
        self,
        request_id,
        expected_version,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "recovery request")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_recovery(connection, request_uuid)
                if (
                    request["status"] == "claimed"
                    and request["version"] == version + 1
                    and request["claimed_session_hash"] == owner_hash
                    and request["claimed_at"] is not None
                    and now - request["claimed_at"] < RECOVERY_CLAIM_SECONDS
                ):
                    return _recovery_state(request, include_token=True)
                if request["version"] != version:
                    raise WorkbenchError(
                        "recovery_changed",
                        "Recovery request version does not match.",
                    )
                if request["status"] == "claimed":
                    if (
                        request["claimed_session_hash"] == owner_hash
                        and request["claimed_at"] is not None
                        and now - request["claimed_at"] < RECOVERY_CLAIM_SECONDS
                    ):
                        return _recovery_state(request, include_token=True)
                    if (
                        request["claimed_at"] is not None
                        and now - request["claimed_at"] < RECOVERY_CLAIM_SECONDS
                    ):
                        raise WorkbenchError(
                            "recovery_already_claimed",
                            "Recovery request has an active claim.",
                        )
                elif request["status"] != "pending":
                    raise WorkbenchError(
                        "recovery_not_claimable",
                        "Recovery request is no longer claimable.",
                    )
                token = str(uuid.uuid4())
                updated = connection.execute(
                    """
                    UPDATE scan_recovery_requests
                    SET status = 'claimed', claimed_session_hash = ?,
                        claim_token = ?, claimed_at = ?, delivered_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE id = ? AND version = ?
                    """,
                    (
                        owner_hash,
                        token,
                        now,
                        timestamp,
                        request_uuid,
                        version,
                    ),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "recovery_changed",
                        "Recovery request changed during claim.",
                    )
            return _recovery_state(
                _require_recovery(connection, request_uuid),
                include_token=True,
            )

    def deliver_scan_recovery(
        self,
        request_id,
        recovery_token,
        expected_version,
        session_hash,
        expected_scan_id,
    ):
        request_uuid = _require_uuid(request_id, "recovery request")
        token = _require_uuid(recovery_token, "recovery token")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_recovery(connection, request_uuid)
                if request["scan_id"] != expected_scan_id:
                    raise WorkbenchError(
                        "recovery_scan_mismatch",
                        "Recovery request belongs to another scan.",
                    )
                if (
                    request["status"] == "delivered"
                    and request["version"] == version + 1
                    and request["claimed_session_hash"] == owner_hash
                    and request["claim_token"] == token
                    and request["delivered_at"] is not None
                    and now - request["delivered_at"] < RECOVERY_CLAIM_SECONDS
                ):
                    return _recovery_state(request)
                _require_recovery_claim(request, token, version, owner_hash, now)
                updated = connection.execute(
                    """
                    UPDATE scan_recovery_requests
                    SET status = 'delivered', delivered_at = ?,
                        version = version + 1, updated_at = ?
                    WHERE id = ? AND status = 'claimed' AND version = ?
                    """,
                    (now, timestamp, request_uuid, version),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "recovery_changed",
                        "Recovery request changed before delivery.",
                    )
                transferred = connection.execute(
                    """
                    UPDATE scans
                    SET owner_session_hash = ?, updated_at = ?
                    WHERE id = ? AND status = 'running'
                    """,
                    (owner_hash, timestamp, request["scan_id"]),
                )
                if transferred.rowcount != 1:
                    raise WorkbenchError(
                        "scan_not_running",
                        "Recovery scan is no longer running.",
                    )
            return _recovery_state(_require_recovery(connection, request_uuid))

    def release_scan_recovery(
        self,
        request_id,
        recovery_token,
        expected_version,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "recovery request")
        token = _require_uuid(recovery_token, "recovery token")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_recovery(connection, request_uuid)
                if (
                    request["status"] != "claimed"
                    or request["version"] != version
                    or request["claimed_session_hash"] != owner_hash
                    or request["claim_token"] != token
                ):
                    raise WorkbenchError(
                        "recovery_claim_invalid",
                        "Recovery claim is invalid or changed.",
                    )
                updated = connection.execute(
                    """
                    UPDATE scan_recovery_requests
                    SET status = 'pending', claimed_session_hash = NULL,
                        claim_token = NULL, claimed_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE id = ? AND version = ?
                    """,
                    (timestamp, request_uuid, version),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "recovery_changed",
                        "Recovery request changed during release.",
                    )
            return _recovery_state(_require_recovery(connection, request_uuid))

    def cancel_scan_recovery(self, request_id):
        request_uuid = _require_uuid(request_id, "recovery request")
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_recovery(connection, request_uuid)
                if request["status"] == "delivered":
                    raise WorkbenchError(
                        "recovery_delivered",
                        "A delivered recovery request cannot be canceled.",
                    )
                connection.execute(
                    """
                    UPDATE scan_recovery_requests
                    SET status = 'canceled', claimed_session_hash = NULL,
                        claim_token = NULL, claimed_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (timestamp, request_uuid),
                )
            return _recovery_state(_require_recovery(connection, request_uuid))

    def request_remediation(
        self,
        occurrence_id,
        action,
        request_id=None,
        base_revision=None,
        base_content_digest=None,
        expected_applied_content_digest=None,
    ):
        occurrence_uuid = _require_occurrence_id(occurrence_id)
        if action not in REMEDIATION_ACTIONS:
            raise WorkbenchError(
                "invalid_remediation_action",
                "Remediation action must be generate, apply, or verify.",
            )
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                occurrence = _require_occurrence(connection, occurrence_uuid)
                scan = _require_scan(connection, occurrence["scan_id"])
                if scan["status"] != "complete" or not scan["seal_manifest_digest"]:
                    raise WorkbenchError(
                        "scan_not_sealed",
                        "Remediation requires a completed and sealed scan.",
                    )
                triage = connection.execute(
                    "SELECT status FROM finding_triage WHERE occurrence_id = ?",
                    (occurrence_uuid,),
                ).fetchone()
                if triage is not None and triage["status"] == "closed":
                    raise WorkbenchError(
                        "finding_closed",
                        "Reopen a closed finding before remediation.",
                    )
                if action == "generate":
                    prior = connection.execute(
                        """
                        SELECT * FROM finding_remediation_attempts
                        WHERE occurrence_id = ?
                        ORDER BY created_at DESC LIMIT 1
                        """,
                        (occurrence_uuid,),
                    ).fetchone()
                    if prior is not None and prior["state"] in (
                        "requested",
                        "verifying",
                    ):
                        raise WorkbenchError(
                            "remediation_pending",
                            "This finding already has a pending remediation action.",
                        )
                    if prior is not None and prior["state"] in ("generated", "applied"):
                        connection.execute(
                            """
                            UPDATE finding_remediation_attempts
                            SET state = 'superseded', pending_action = NULL,
                                version = version + 1, updated_at = ?
                            WHERE request_id = ?
                            """,
                            (timestamp, prior["request_id"]),
                        )
                    remediation_id = str(uuid.uuid4())
                    connection.execute(
                        """
                        INSERT INTO finding_remediation_attempts (
                            request_id, occurrence_id, state, version,
                            base_revision, base_content_digest, pending_action,
                            created_at, updated_at
                        ) VALUES (?, ?, 'requested', 1, ?, ?, 'generate', ?, ?)
                        """,
                        (
                            remediation_id,
                            occurrence_uuid,
                            base_revision or scan["target_revision"],
                            base_content_digest or scan["target_snapshot_digest"],
                            timestamp,
                            timestamp,
                        ),
                    )
                    return _remediation_state(
                        _require_remediation(connection, remediation_id)
                    )
                remediation_id = _require_uuid(request_id, "remediation request")
                attempt = _require_remediation(connection, remediation_id)
                if attempt["occurrence_id"] != occurrence_uuid:
                    raise WorkbenchError(
                        "remediation_identity_mismatch",
                        "Remediation request belongs to another finding.",
                    )
                required_state = "generated" if action == "apply" else "applied"
                if attempt["state"] != required_state or attempt["pending_action"] is not None:
                    raise WorkbenchError(
                        "remediation_state_invalid",
                        "%s requires remediation state %s." % (action, required_state),
                    )
                connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET state = ?, pending_action = ?,
                        expected_applied_content_digest = COALESCE(
                            ?, expected_applied_content_digest
                        ),
                        version = version + 1, updated_at = ?
                    WHERE request_id = ? AND version = ?
                    """,
                    (
                        required_state,
                        action,
                        expected_applied_content_digest,
                        timestamp,
                        remediation_id,
                        attempt["version"],
                    ),
                )
            return _remediation_state(
                _require_remediation(connection, remediation_id)
            )

    def claim_remediation(
        self,
        request_id,
        expected_version,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "remediation request")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                attempt = _require_remediation(connection, request_uuid)
                reference = (
                    attempt["pending_action_delivered_at"]
                    if attempt["pending_action_delivered_at"] is not None
                    else attempt["pending_action_claimed_at"]
                )
                ttl = (
                    REMEDIATION_WORKER_SECONDS
                    if attempt["pending_action_delivered_at"] is not None
                    else REMEDIATION_CLAIM_SECONDS
                )
                if (
                    attempt["pending_action_claim_token"] is not None
                    and attempt["pending_action"] is not None
                    and attempt["version"] == version + 1
                    and attempt["claimed_session_hash"] == owner_hash
                    and reference is not None
                    and now - reference < ttl
                ):
                    return _remediation_state(attempt, include_token=True)
                if attempt["version"] != version or attempt["pending_action"] is None:
                    raise WorkbenchError(
                        "remediation_changed",
                        "Remediation action version or state does not match.",
                    )
                if attempt["pending_action_claim_token"] is not None:
                    if (
                        attempt["claimed_session_hash"] == owner_hash
                        and reference is not None
                        and now - reference < ttl
                    ):
                        return _remediation_state(attempt, include_token=True)
                    if reference is not None and now - reference < ttl:
                        raise WorkbenchError(
                            "remediation_already_claimed",
                            "Remediation action has an active worker.",
                        )
                token = str(uuid.uuid4())
                updated = connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET claimed_session_hash = ?,
                        pending_action_claim_token = ?,
                        pending_action_claimed_at = ?,
                        pending_action_delivered_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE request_id = ? AND version = ?
                    """,
                    (
                        owner_hash,
                        token,
                        now,
                        timestamp,
                        request_uuid,
                        version,
                    ),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "remediation_changed",
                        "Remediation action changed during claim.",
                    )
            return _remediation_state(
                _require_remediation(connection, request_uuid),
                include_token=True,
            )

    def get_remediation_context(
        self,
        request_id,
        action_token,
        expected_version,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "remediation request")
        token = _require_uuid(action_token, "action token")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                attempt = _require_remediation(connection, request_uuid)
                _require_remediation_claim(
                    attempt,
                    token,
                    version,
                    owner_hash,
                    now,
                    allow_delivered=True,
                )
                if attempt["pending_action_delivered_at"] is None:
                    connection.execute(
                        """
                        UPDATE finding_remediation_attempts
                        SET pending_action_delivered_at = ?,
                            version = version + 1, updated_at = ?
                        WHERE request_id = ? AND version = ?
                        """,
                        (now, timestamp, request_uuid, version),
                    )
            attempt = _require_remediation(connection, request_uuid)
            occurrence = _require_occurrence(connection, attempt["occurrence_id"])
            locations = connection.execute(
                """
                SELECT relative_path, start_line, end_line, role, sort_order
                FROM finding_locations WHERE occurrence_id = ?
                ORDER BY sort_order
                """,
                (attempt["occurrence_id"],),
            ).fetchall()
            return {
                "request": _remediation_state(attempt),
                "occurrence": _occurrence_state(occurrence, locations),
                "scan": dict(_require_scan(connection, occurrence["scan_id"])),
            }

    def set_remediation(
        self,
        occurrence_id,
        request_id,
        expected_version,
        action_token,
        state,
        session_hash,
        patch_path=None,
        patch_digest=None,
        applied_content_digest=None,
        summary=None,
        verification_summary=None,
    ):
        occurrence_uuid = _require_occurrence_id(occurrence_id)
        request_uuid = _require_uuid(request_id, "remediation request")
        version = _require_version(expected_version)
        token = _require_uuid(action_token, "action token")
        owner_hash = require_session_hash(session_hash)
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                attempt = _require_remediation(connection, request_uuid)
                if attempt["occurrence_id"] != occurrence_uuid:
                    raise WorkbenchError(
                        "remediation_identity_mismatch",
                        "Remediation request belongs to another finding.",
                    )
                _require_remediation_claim(
                    attempt,
                    token,
                    version,
                    owner_hash,
                    int(time.time()),
                    require_delivered=True,
                )
                action = attempt["pending_action"]
                allowed = {
                    "generate": ("generated", "failed"),
                    "apply": ("applied", "failed"),
                    "verify": ("verified", "failed"),
                }
                if action not in allowed or state not in allowed[action]:
                    raise WorkbenchError(
                        "remediation_transition_invalid",
                        "Remediation result does not match the pending action.",
                    )
                patch_path_value = _optional_text(patch_path, "patchPath", 4096)
                patch_digest_value = _optional_digest(patch_digest, "patchDigest")
                applied_digest_value = _optional_digest(
                    applied_content_digest,
                    "appliedContentDigest",
                )
                if state == "generated" and (
                    patch_path_value is None or patch_digest_value is None
                ):
                    raise WorkbenchError(
                        "remediation_patch_required",
                        "Generated remediation requires patch path and digest.",
                    )
                if state == "applied" and applied_digest_value is None:
                    raise WorkbenchError(
                        "remediation_digest_required",
                        "Applied remediation requires the resulting content digest.",
                    )
                connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET state = ?, patch_path = COALESCE(?, patch_path),
                        patch_digest = COALESCE(?, patch_digest),
                        applied_content_digest = COALESCE(?, applied_content_digest),
                        summary = COALESCE(?, summary),
                        verification_summary = COALESCE(?, verification_summary),
                        pending_action = NULL, claimed_session_hash = NULL,
                        pending_action_claim_token = NULL,
                        pending_action_claimed_at = NULL,
                        pending_action_delivered_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE request_id = ? AND version = ?
                    """,
                    (
                        state,
                        patch_path_value,
                        patch_digest_value,
                        applied_digest_value,
                        _optional_text(summary, "summary", 4000),
                        _optional_text(
                            verification_summary,
                            "verificationSummary",
                            8000,
                        ),
                        timestamp,
                        request_uuid,
                        version,
                    ),
                )
            return _remediation_state(
                _require_remediation(connection, request_uuid)
            )

    def create_tracking(self, occurrence_id):
        occurrence_uuid = _require_occurrence_id(occurrence_id)
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                occurrence = _require_occurrence(connection, occurrence_uuid)
                scan = _require_scan(connection, occurrence["scan_id"])
                if scan["status"] != "complete" or not scan["seal_manifest_digest"]:
                    raise WorkbenchError(
                        "scan_not_sealed",
                        "Tracking requires a completed and sealed scan.",
                    )
                existing = connection.execute(
                    """
                    SELECT * FROM finding_tracking_requests
                    WHERE occurrence_id = ? AND status IN ('pending', 'claimed')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (occurrence_uuid,),
                ).fetchone()
                if existing is not None:
                    return _tracking_state(existing)
                request_id = str(uuid.uuid4())
                connection.execute(
                    """
                    INSERT INTO finding_tracking_requests (
                        id, occurrence_id, status, version, created_at, updated_at
                    ) VALUES (?, ?, 'pending', 1, ?, ?)
                    """,
                    (request_id, occurrence_uuid, timestamp, timestamp),
                )
            return _tracking_state(_require_tracking(connection, request_id))

    def claim_tracking(self, request_id, expected_version, session_hash):
        request_uuid = _require_uuid(request_id, "tracking request")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_tracking(connection, request_uuid)
                if (
                    request["status"] == "claimed"
                    and request["version"] == version + 1
                    and request["claimed_session_hash"] == owner_hash
                    and request["claimed_at"] is not None
                    and now - request["claimed_at"] < RECOVERY_CLAIM_SECONDS
                ):
                    return _tracking_state(request, include_token=True)
                if request["version"] != version:
                    raise WorkbenchError(
                        "tracking_changed",
                        "Tracking request version does not match.",
                    )
                if request["status"] == "claimed":
                    active = (
                        request["claimed_at"] is not None
                        and now - request["claimed_at"] < RECOVERY_CLAIM_SECONDS
                    )
                    if active and request["claimed_session_hash"] == owner_hash:
                        return _tracking_state(request, include_token=True)
                    if active:
                        raise WorkbenchError(
                            "tracking_already_claimed",
                            "Tracking request has an active claim.",
                        )
                elif request["status"] != "pending":
                    raise WorkbenchError(
                        "tracking_not_claimable",
                        "Tracking request is no longer claimable.",
                    )
                token = str(uuid.uuid4())
                updated = connection.execute(
                    """
                    UPDATE finding_tracking_requests
                    SET status = 'claimed', claimed_session_hash = ?,
                        claim_token = ?, claimed_at = ?,
                        version = version + 1, updated_at = ?
                    WHERE id = ? AND version = ?
                    """,
                    (owner_hash, token, now, timestamp, request_uuid, version),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "tracking_changed",
                        "Tracking request changed during claim.",
                    )
            return _tracking_state(
                _require_tracking(connection, request_uuid),
                include_token=True,
            )

    def get_tracking_context(
        self,
        request_id,
        tracking_token,
        expected_version,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "tracking request")
        token = _require_uuid(tracking_token, "tracking token")
        version = _require_version(expected_version)
        owner_hash = require_session_hash(session_hash)
        now = int(time.time())
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                request = _require_tracking(connection, request_uuid)
                if request["status"] == "delivered":
                    if (
                        request["version"] not in (version, version + 1)
                        or request["claimed_session_hash"] != owner_hash
                        or request["claim_token"] != token
                    ):
                        raise WorkbenchError(
                            "tracking_claim_invalid",
                            "Tracking delivery identity is invalid or changed.",
                        )
                    occurrence = _require_occurrence(
                        connection,
                        request["occurrence_id"],
                    )
                    scan = _require_scan(connection, occurrence["scan_id"])
                    locations = connection.execute(
                        """
                        SELECT relative_path, start_line, end_line, role, sort_order
                        FROM finding_locations WHERE occurrence_id = ?
                        ORDER BY sort_order
                        """,
                        (occurrence["id"],),
                    ).fetchall()
                    return {
                        "request": _tracking_state(request),
                        "occurrence": _occurrence_state(occurrence, locations),
                        "scan": dict(scan),
                    }
                if (
                    request["status"] != "claimed"
                    or request["version"] != version
                    or request["claimed_session_hash"] != owner_hash
                    or request["claim_token"] != token
                    or request["claimed_at"] is None
                    or now - request["claimed_at"] >= RECOVERY_CLAIM_SECONDS
                ):
                    raise WorkbenchError(
                        "tracking_claim_invalid",
                        "Tracking claim is invalid, expired, or changed.",
                    )
                updated = connection.execute(
                    """
                    UPDATE finding_tracking_requests
                    SET status = 'delivered', delivered_at = ?,
                        version = version + 1, updated_at = ?
                    WHERE id = ? AND status = 'claimed' AND version = ?
                    """,
                    (now, timestamp, request_uuid, version),
                )
                if updated.rowcount != 1:
                    raise WorkbenchError(
                        "tracking_changed",
                        "Tracking request changed before delivery.",
                    )
                occurrence = _require_occurrence(
                    connection,
                    request["occurrence_id"],
                )
                scan = _require_scan(connection, occurrence["scan_id"])
                locations = connection.execute(
                    """
                    SELECT relative_path, start_line, end_line, role, sort_order
                    FROM finding_locations WHERE occurrence_id = ?
                    ORDER BY sort_order
                    """,
                    (occurrence["id"],),
                ).fetchall()
                return {
                    "request": _tracking_state(
                        _require_tracking(connection, request_uuid)
                    ),
                    "occurrence": _occurrence_state(occurrence, locations),
                    "scan": dict(scan),
                }

    def release_remediation(
        self,
        request_id,
        expected_version,
        action_token,
        session_hash,
    ):
        request_uuid = _require_uuid(request_id, "remediation request")
        version = _require_version(expected_version)
        token = _require_uuid(action_token, "action token")
        owner_hash = require_session_hash(session_hash)
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                attempt = _require_remediation(connection, request_uuid)
                if attempt["pending_action_delivered_at"] is not None:
                    raise WorkbenchError(
                        "remediation_delivered",
                        "A delivered remediation worker cannot release its claim.",
                    )
                _require_remediation_claim(
                    attempt,
                    token,
                    version,
                    owner_hash,
                    int(time.time()),
                )
                connection.execute(
                    """
                    UPDATE finding_remediation_attempts
                    SET claimed_session_hash = NULL,
                        pending_action_claim_token = NULL,
                        pending_action_claimed_at = NULL,
                        version = version + 1, updated_at = ?
                    WHERE request_id = ? AND version = ?
                    """,
                    (timestamp, request_uuid, version),
                )
            return _remediation_state(
                _require_remediation(connection, request_uuid)
            )

    def set_triage(self, occurrence_id, status, close_reason=None, note=None):
        occurrence_uuid = _require_occurrence_id(occurrence_id)
        if status not in ("open", "closed"):
            raise WorkbenchError(
                "invalid_triage_status",
                "Triage status must be open or closed.",
            )
        reason = _optional_text(close_reason, "closeReason", 64)
        note_value = _optional_text(note, "note", 4000)
        if status == "open":
            reason = None
        elif reason not in TRIAGE_CLOSE_REASONS:
            raise WorkbenchError(
                "invalid_close_reason",
                "Closed findings require a supported close reason.",
            )
        if reason == "wont_fix" and not (note_value and note_value.strip()):
            raise WorkbenchError(
                "triage_note_required",
                "wont_fix requires a note.",
            )
        timestamp = utc_now()
        with self.database.connect() as connection:
            with immediate_transaction(connection):
                _require_occurrence(connection, occurrence_uuid)
                if status == "closed":
                    pending = connection.execute(
                        """
                        SELECT request_id FROM finding_remediation_attempts
                        WHERE occurrence_id = ?
                          AND state IN ('requested', 'generated', 'applied', 'verifying')
                        LIMIT 1
                        """,
                        (occurrence_uuid,),
                    ).fetchone()
                    if pending is not None:
                        raise WorkbenchError(
                            "remediation_pending",
                            "A finding with pending remediation cannot be closed.",
                        )
                connection.execute(
                    """
                    INSERT INTO finding_triage (
                        occurrence_id, status, close_reason, note, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(occurrence_id) DO UPDATE SET
                        status = excluded.status,
                        close_reason = excluded.close_reason,
                        note = excluded.note,
                        updated_at = excluded.updated_at
                    """,
                    (occurrence_uuid, status, reason, note_value, timestamp),
                )
            row = connection.execute(
                "SELECT * FROM finding_triage WHERE occurrence_id = ?",
                (occurrence_uuid,),
            ).fetchone()
            return _triage_state(row)


def _require_recovery_claim(request, token, version, owner_hash, now):
    if (
        request["status"] != "claimed"
        or request["version"] != version
        or request["claimed_session_hash"] != owner_hash
        or request["claim_token"] != token
        or request["claimed_at"] is None
        or now - request["claimed_at"] >= RECOVERY_CLAIM_SECONDS
    ):
        raise WorkbenchError(
            "recovery_claim_invalid",
            "Recovery claim is invalid, expired, or changed.",
        )


def _require_remediation_claim(
    attempt,
    token,
    version,
    owner_hash,
    now,
    allow_delivered=False,
    require_delivered=False,
):
    delivered = attempt["pending_action_delivered_at"] is not None
    reference = (
        attempt["pending_action_delivered_at"]
        if delivered
        else attempt["pending_action_claimed_at"]
    )
    ttl = REMEDIATION_WORKER_SECONDS if delivered else REMEDIATION_CLAIM_SECONDS
    version_matches = attempt["version"] == version or (
        allow_delivered
        and delivered
        and attempt["version"] == version + 1
    )
    if (
        not version_matches
        or attempt["claimed_session_hash"] != owner_hash
        or attempt["pending_action_claim_token"] != token
        or reference is None
        or now - reference >= ttl
        or (require_delivered and not delivered)
        or (delivered and not allow_delivered and not require_delivered)
    ):
        raise WorkbenchError(
            "remediation_claim_invalid",
            "Remediation claim is invalid, expired, or changed.",
        )


def _recovery_state(row, include_token=False):
    state = {
        "id": row["id"],
        "scanId": row["scan_id"],
        "status": row["status"],
        "version": row["version"],
        "claimedAt": row["claimed_at"],
        "deliveredAt": row["delivered_at"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }
    if include_token:
        state["recoveryToken"] = row["claim_token"]
    return state


def _remediation_state(row, include_token=False):
    state = {
        "requestId": row["request_id"],
        "occurrenceId": row["occurrence_id"],
        "state": row["state"],
        "version": row["version"],
        "baseRevision": row["base_revision"],
        "baseContentDigest": row["base_content_digest"],
        "expectedAppliedContentDigest": row["expected_applied_content_digest"],
        "appliedContentDigest": row["applied_content_digest"],
        "pendingAction": row["pending_action"],
        "patchPath": row["patch_path"],
        "patchDigest": row["patch_digest"],
        "summary": row["summary"],
        "verificationSummary": row["verification_summary"],
        "claimedAt": row["pending_action_claimed_at"],
        "deliveredAt": row["pending_action_delivered_at"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }
    if include_token:
        state["actionToken"] = row["pending_action_claim_token"]
    return state


def _tracking_state(row, include_token=False):
    state = {
        "requestId": row["id"],
        "occurrenceId": row["occurrence_id"],
        "status": row["status"],
        "version": row["version"],
        "claimedAt": row["claimed_at"],
        "deliveredAt": row["delivered_at"],
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }
    if include_token:
        state["trackingToken"] = row["claim_token"]
    return state


def _occurrence_state(row, locations):
    return {
        "occurrenceId": row["id"],
        "findingId": row["finding_id"],
        "scanId": row["scan_id"],
        "title": row["title"],
        "summary": row["summary"],
        "severity": row["severity"],
        "confidence": row["confidence"],
        "remediation": row["remediation"],
        "details": json.loads(row["details_json"]),
        "locations": [
            {
                "path": location["relative_path"],
                "startLine": location["start_line"],
                "endLine": location["end_line"],
                "role": location["role"],
            }
            for location in locations
        ],
    }


def _triage_state(row):
    if row is None:
        return {
            "status": "open",
            "closeReason": None,
            "note": None,
            "updatedAt": None,
        }
    return {
        "status": row["status"],
        "closeReason": row["close_reason"],
        "note": row["note"],
        "updatedAt": row["updated_at"],
    }


def _require_scan(connection, scan_id):
    row = connection.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        raise WorkbenchError("scan_not_found", "Kiro Security scan not found.")
    return row


def _require_recovery(connection, request_id):
    row = connection.execute(
        "SELECT * FROM scan_recovery_requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise WorkbenchError(
            "recovery_not_found",
            "Kiro Security recovery request was not found.",
        )
    return row


def _require_occurrence(connection, occurrence_id):
    row = connection.execute(
        "SELECT * FROM finding_occurrences WHERE id = ?",
        (occurrence_id,),
    ).fetchone()
    if row is None:
        raise WorkbenchError(
            "finding_not_found",
            "Kiro Security finding occurrence was not found.",
        )
    return row


def _require_remediation(connection, request_id):
    row = connection.execute(
        "SELECT * FROM finding_remediation_attempts WHERE request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise WorkbenchError(
            "remediation_not_found",
            "Kiro Security remediation request was not found.",
        )
    return row


def _require_tracking(connection, request_id):
    row = connection.execute(
        "SELECT * FROM finding_tracking_requests WHERE id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise WorkbenchError(
            "tracking_not_found",
            "Kiro Security tracking request was not found.",
        )
    return row


def _require_version(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise WorkbenchError(
            "invalid_expected_version",
            "expectedVersion must be a positive integer.",
        )
    return value


def _require_uuid(value, label):
    if not isinstance(value, str):
        raise WorkbenchError("invalid_identity", "%s must be a UUID." % label)
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise WorkbenchError("invalid_identity", "%s must be a UUID." % label)


def _require_occurrence_id(value):
    if not isinstance(value, str) or not value.startswith("occ_") or len(value) != 28:
        raise WorkbenchError(
            "invalid_occurrence_identity",
            "occurrenceId must be a canonical Kiro Security occurrence id.",
        )
    if any(character not in "0123456789abcdef" for character in value[4:]):
        raise WorkbenchError(
            "invalid_occurrence_identity",
            "occurrenceId must be a canonical Kiro Security occurrence id.",
        )
    return value


def _optional_text(value, label, maximum):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum:
        raise WorkbenchError(
            "invalid_%s" % label.lower(),
            "%s must be a bounded string." % label,
        )
    return value


def _optional_digest(value, label):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WorkbenchError(
            "invalid_%s" % label.lower(),
            "%s must be a lowercase SHA-256 digest." % label,
        )
    return value
