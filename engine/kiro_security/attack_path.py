from __future__ import annotations

from typing import Any

_IMPACTS = {
    "command-injection": "Arbitrary command execution with the privileges of the application process.",
    "code-injection": "Arbitrary code execution in the application runtime.",
    "sql-injection": "Unauthorized database reads or writes and possible privilege escalation through database features.",
    "path-traversal": "Read, overwrite, or create files outside the intended storage boundary.",
    "authorization": "Unauthorized state changes or cross-user/cross-tenant access.",
    "unsafe-deserialization": "Object construction side effects, code execution, or integrity loss.",
    "secret-exposure": "Credential theft and unauthorized access to dependent systems.",
    "transport-security": "Machine-in-the-middle interception or endpoint impersonation.",
}


def build_attack_path(finding: dict[str, Any]) -> dict[str, Any]:
    locations = finding.get("locations", [])
    source = next((item for item in locations if item.get("role") == "source"), None)
    sink = next((item for item in locations if item.get("role") == "sink"), locations[-1] if locations else None)
    path: list[dict[str, Any]] = []
    if source:
        path.append({"kind": "source", "label": "Attacker-controlled input", **source})
    path.append({"kind": "transform", "label": "Application data flow without a proven boundary"})
    if sink:
        path.append({"kind": "sink", "label": finding["title"], **sink})
    validation = finding.get("validation") or {}
    exploitability = "high" if validation.get("status") == "validated" and source else "medium"
    category = finding["taxonomy"]["category"]
    impact = _IMPACTS.get(category, "Violation of the repository's confidentiality, integrity, or availability objectives.")
    if source and sink:
        narrative = (
            f"An attacker controls data at {source['path']}:{source['startLine']}. The value crosses application logic without a "
            f"demonstrated validation or authorization boundary and reaches {sink['path']}:{sink['startLine']}, where it triggers {category}."
        )
    elif sink:
        narrative = (
            f"The sink at {sink['path']}:{sink['startLine']} exposes a {category} primitive. The exact attacker-controlled source or "
            "global mitigating control still requires confirmation."
        )
    else:
        narrative = "The finding has insufficient location data to build a complete attack path."
    severity = finding["severity"]["level"]
    severity_rationale = (
        f"Severity remains {severity} because the identified primitive can cause: {impact} "
        f"Exploitability is assessed as {exploitability} from the available static evidence."
    )
    return {
        "narrative": narrative,
        "path": path,
        "exploitability": exploitability,
        "impact": impact,
        "severityRationale": severity_rationale,
    }
