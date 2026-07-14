from __future__ import annotations

from pathlib import Path
from typing import Any

from .security import write_json

TRACKING_PROVIDERS = ("manual", "github", "linear", "jira")


def create_tracking_handoff(
    finding: dict[str, Any],
    *,
    provider: str,
    destination: str,
    output_path: Path,
    stable_link: str | None = None,
) -> dict[str, Any]:
    """Create an approval-ready payload without performing an external write."""
    sink = next((item for item in finding.get("locations", []) if item.get("role") == "sink"), None)
    payload = {
        "documentType": "KiroSecurityTrackingHandoff",
        "schemaVersion": "1.0",
        "status": "prepared",
        "provider": provider,
        "destination": destination,
        "externalWritePerformed": False,
        "finding": {
            "findingId": finding["findingId"],
            "occurrenceId": finding["occurrenceId"],
            "scanId": finding["scanId"],
            "stableLink": stable_link,
            "title": finding["title"],
            "summary": finding["summary"],
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "validationStatus": finding.get("validationStatus"),
            "triageStatus": finding.get("triageStatus"),
            "taxonomy": finding.get("taxonomy", {}),
            "location": sink,
            "remediation": finding.get("remediation"),
        },
        "approvalRequired": True,
        "instructions": (
            "Review this payload, check for an existing external issue, obtain approval, and use an explicitly "
            "configured connector to create or update the tracking item. Kiro Security Power did not contact an external service."
        ),
    }
    write_json(output_path, payload)
    return payload
