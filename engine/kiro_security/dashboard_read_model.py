"""Read-only Dashboard projection for the Extension UI."""


class DashboardReadModel:
    """Project global scan and finding state without mutating authority."""

    def __init__(self, database):
        self.database = database

    def projection(self, scan_state, require_scan):
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
                    scan_state(
                        connection,
                        require_scan(connection, row["id"]),
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
                    _remediation_state(row) for row in remediation
                ],
            }

    @staticmethod
    def _finding_projection(connection):
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


def _remediation_state(row):
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
