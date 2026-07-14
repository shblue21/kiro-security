from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .scanner import Inventory
from .security import atomic_write


def build_threat_model(workspace: Path, inventory: Inventory, output_path: Path) -> dict[str, Any]:
    languages = Counter(source.language for source in inventory.files)
    joined = "\n".join(source.text[:20000] for source in inventory.files[:200])
    surfaces: list[str] = []
    if any(token in joined for token in ("app.route", "router.get", "router.post", "FastAPI(", "express(")):
        surfaces.append("HTTP request handlers and API routes")
    if any(token in joined for token in ("subprocess.", "child_process", "os.system", "exec(")):
        surfaces.append("Operating-system command execution")
    if any(token in joined for token in ("execute(", ".query(", "SELECT ", "INSERT ")):
        surfaces.append("Database query and persistence boundary")
    if any(token in joined for token in ("open(", "readFile", "writeFile", "extractall", "send_file")):
        surfaces.append("Filesystem and archive-processing boundary")
    if any(token in joined for token in ("jwt", "oauth", "session", "authorization", "permission", "role")):
        surfaces.append("Authentication, session, and authorization boundary")
    if not surfaces:
        surfaces.append("Repository-defined library and application entry points")

    assets = [
        "Repository source integrity and release artifacts",
        "Credentials, tokens, and configuration secrets",
        "User and tenant data processed by the application",
        "Host filesystem and process execution privileges",
    ]
    trust_boundaries = [
        "External request, CLI, file, or message input entering application code",
        "Application code crossing into databases, filesystems, subprocesses, or network services",
        "Administrative or tenant-scoped actions crossing an authorization decision",
    ]
    attacker_capabilities = [
        "Supply syntactically valid request parameters, payloads, filenames, and headers",
        "Influence repository-supported import, upload, archive, or command workflows",
        "Replay requests and attempt cross-user or cross-tenant object access",
    ]
    objectives = [
        "Keep untrusted data out of command, code, and query syntax",
        "Contain filesystem access within approved roots",
        "Enforce authentication and authorization at every sensitive boundary",
        "Preserve cryptographic peer verification and secret confidentiality",
    ]
    assumptions = [
        "Static analysis does not execute repository build scripts or dynamic proof-of-concept payloads.",
        "Global framework middleware may provide controls not visible in a local source excerpt.",
    ]
    summary = (
        f"Kiro Security Power inventoried {len(inventory.files)} supported source files in {workspace.name}. "
        f"Primary languages: {', '.join(f'{name} ({count})' for name, count in languages.most_common(5)) or 'unknown'}."
    )
    model = {
        "summary": summary,
        "assets": assets,
        "trustBoundaries": trust_boundaries,
        "attackerCapabilities": attacker_capabilities,
        "securityObjectives": objectives,
        "assumptions": assumptions,
        "surfaces": surfaces,
        "languages": dict(languages),
    }
    markdown = [
        "# Threat model",
        "",
        summary,
        "",
        "## Product surfaces",
        *[f"- {item}" for item in surfaces],
        "",
        "## Assets",
        *[f"- {item}" for item in assets],
        "",
        "## Trust boundaries",
        *[f"- {item}" for item in trust_boundaries],
        "",
        "## Attacker capabilities",
        *[f"- {item}" for item in attacker_capabilities],
        "",
        "## Security objectives",
        *[f"- {item}" for item in objectives],
        "",
        "## Assumptions and limitations",
        *[f"- {item}" for item in assumptions],
        "",
    ]
    atomic_write(output_path, "\n".join(markdown))
    return model
