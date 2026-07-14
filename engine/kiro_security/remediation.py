from __future__ import annotations

from pathlib import Path
from typing import Any

from .security import atomic_write

_REMEDIATION_EXAMPLES = {
    "command-injection": "Use a fixed executable and argument array. Validate each variable argument against an allowlist; do not enable a shell.",
    "code-injection": "Parse a constrained data format and dispatch through an explicit operation map rather than eval/exec.",
    "sql-injection": "Keep SQL syntax static and bind values through placeholders supported by the database driver.",
    "path-traversal": "Resolve against an approved root, reject absolute/traversal inputs, and verify the canonical result remains inside the root.",
    "authorization": "Add authentication and a deny-by-default action/resource authorization check at the route boundary.",
    "unsafe-deserialization": "Replace the object loader with a schema-validated data-only parser or a strict safe loader/type allowlist.",
    "secret-exposure": "Revoke and rotate the value, remove it from source history, and read the replacement from an approved secret store.",
    "transport-security": "Restore certificate verification and configure an approved trust store instead of disabling verification.",
}


def create_remediation_artifact(finding: dict[str, Any], artifact_dir: Path) -> tuple[str, Path]:
    category = finding["taxonomy"]["category"]
    guidance = _REMEDIATION_EXAMPLES.get(category, finding["remediation"])
    sink = next((item for item in finding.get("locations", []) if item.get("role") == "sink"), None)
    path = artifact_dir / "remediations" / f"{finding['findingId']}.md"
    lines = [
        f"# Remediation: {finding['title']}",
        "",
        f"Finding: `{finding['findingId']}`  ",
        f"Occurrence: `{finding['occurrenceId']}`",
        "",
        "## Required security property",
        "",
        guidance,
        "",
        "## Repository-local implementation steps",
        "",
        "1. Confirm the source and sink evidence against the current revision.",
        "2. Introduce the smallest repository-native control that closes the boundary.",
        "3. Add a negative test proving the original attacker-controlled value cannot reach the sink.",
        "4. Run existing unit, integration, and security checks before marking the remediation verified.",
        "",
        "## Affected location",
        "",
        f"- `{sink['path']}:{sink['startLine']}`" if sink else "- No canonical sink location recorded.",
        "",
        "## Verification gate",
        "",
        "Re-run targeted validation and a repository scan. Mark this remediation verified only when the finding is rejected because the control is present, not merely because the line moved.",
        "",
    ]
    atomic_write(path, "\n".join(lines))
    return guidance, path
