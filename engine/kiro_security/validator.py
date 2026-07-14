from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .security import resolve_within


def validate_finding(workspace: Path, finding: dict[str, Any]) -> dict[str, Any]:
    sink = next((location for location in finding.get("locations", []) if location.get("role") == "sink"), None)
    if sink is None:
        return {
            "status": "needs_review",
            "method": "static_trace",
            "rationale": "The finding has no canonical sink location to re-evaluate.",
            "evidence": [],
        }
    try:
        path = resolve_within(workspace, sink["path"], must_exist=True)
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {
            "status": "rejected",
            "method": "static_trace",
            "rationale": "The referenced source file no longer exists or is outside the workspace boundary.",
            "evidence": [{"path": sink["path"], "line": sink["startLine"], "result": "missing"}],
        }
    line_number = int(sink["startLine"])
    if line_number < 1 or line_number > len(lines):
        return {
            "status": "rejected",
            "method": "static_trace",
            "rationale": "The referenced sink line no longer exists in the current workspace snapshot.",
            "evidence": [{"path": sink["path"], "line": line_number, "result": "line-missing"}],
        }
    start = max(0, line_number - 12)
    end = min(len(lines), line_number + 12)
    context = "\n".join(lines[start:end])
    category = finding["taxonomy"]["category"]
    details = finding.get("details", {})
    source_to_sink = bool(details.get("sourceToSink"))

    mitigated = False
    still_sink = True
    rationale = ""
    if category == "command-injection":
        still_sink = bool(re.search(r"os\.system|shell\s*=\s*True|(?:exec|execSync)\s*\(", context))
        mitigated = bool(re.search(r"shell\s*=\s*False|shlex\.quote|spawn\s*\([^\n]+\[[^\]]*\]", context))
        rationale = "The current source still contains a shell-capable sink and no argument-array or allowlist boundary is visible."
    elif category == "sql-injection":
        still_sink = bool(re.search(r"\.(?:execute|query|raw)\s*\(", context))
        dynamic = bool(re.search(r"f['\"]|\$\{|\.format\s*\(|['\"].*\+", context))
        parameterized = bool(re.search(r"\?(?:['\"])?\s*,|%s(?:['\"])?\s*,|:\w+", context))
        mitigated = parameterized and not dynamic
        still_sink = still_sink and dynamic
        rationale = "The query remains dynamically constructed rather than passed through a parameter-binding API."
    elif category == "path-traversal":
        still_sink = bool(re.search(r"extractall|(?:open|readFile|writeFile|send_file|sendFile)\s*\(", context))
        mitigated = bool(re.search(r"resolve\(|realpath|relative_to|commonpath|startsWith\s*\(|startswith\s*\(|is_relative_to", context))
        rationale = "The filesystem sink remains and no canonical containment check is visible in the local control flow."
    elif category == "authorization":
        still_sink = True
        mitigated = bool(re.search(r"auth|authorize|permission|isAdmin|login_required|require_role|Depends\s*\(", context, re.IGNORECASE))
        rationale = "No route-local authentication or authorization guard is visible; global middleware must be confirmed separately."
    elif category == "unsafe-deserialization":
        still_sink = bool(re.search(r"pickle\.(?:load|loads)|yaml\.load", context))
        mitigated = bool(re.search(r"safe_load|SafeLoader", context))
        rationale = "The current source still uses a general-purpose object loader without a safe loader or type allowlist."
    elif category == "code-injection":
        still_sink = bool(re.search(r"\b(?:eval|exec)\s*\(", context))
        mitigated = bool(re.search(r"literal_eval|json\.loads|allowlist", context, re.IGNORECASE))
        rationale = "The current source still evaluates externally controlled text as code."
    elif category == "transport-security":
        still_sink = bool(re.search(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED", context, re.IGNORECASE))
        rationale = "Certificate verification remains explicitly disabled."
    elif category == "secret-exposure":
        return {
            "status": "needs_review",
            "method": "static_trace",
            "rationale": "The credential-shaped literal remains in source, but only the owner can determine whether it is active or intentionally synthetic.",
            "evidence": [{"path": sink["path"], "line": line_number, "result": "literal-present"}],
        }
    else:
        return {
            "status": "needs_review",
            "method": "static_trace",
            "rationale": "The static validator has no category-specific proof rule for this finding.",
            "evidence": [{"path": sink["path"], "line": line_number, "result": "manual-review"}],
        }

    if not still_sink:
        status = "rejected"
        rationale = "The originally identified sink pattern is no longer present at the referenced location."
    elif mitigated:
        status = "rejected"
        rationale = "A category-specific mitigation is visible in the current source near the sink."
    elif category == "authorization" and not source_to_sink:
        status = "needs_review"
    else:
        status = "validated" if source_to_sink or category in {"unsafe-deserialization", "code-injection", "transport-security"} else "needs_review"
    return {
        "status": status,
        "method": "static_trace",
        "rationale": rationale,
        "evidence": [{"path": sink["path"], "line": line_number, "result": status, "contextStartLine": start + 1, "contextEndLine": end}],
    }
