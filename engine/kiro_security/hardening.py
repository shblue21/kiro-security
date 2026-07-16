from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .security import atomic_write

_CONTROL_BY_CATEGORY = {
    "command-injection": ("Typed process execution boundary", "Replace shell strings with a single wrapper that accepts an executable identifier and validated argument array."),
    "code-injection": ("Remove dynamic evaluation", "Replace eval/exec dispatch with explicit parsers and allowlisted operation maps."),
    "sql-injection": ("Central parameterized query layer", "Route data access through prepared statements or a repository-native query builder that cannot accept raw user fragments."),
    "path-traversal": ("Canonical filesystem capability", "Centralize path resolution, symlink policy, containment checks, and safe archive extraction behind one audited API."),
    "authorization": ("Policy enforcement point", "Require route declarations to name an action/resource policy and deny by default when no policy is registered."),
    "unsafe-deserialization": ("Data-only interchange", "Ban general object deserializers at trust boundaries and enforce schema-validated data formats."),
    "secret-exposure": ("Secret lifecycle automation", "Move credentials to an approved secret store and add pre-commit/repository scanning plus rotation runbooks."),
    "transport-security": ("Central TLS client policy", "Provide one client factory with verification on, approved roots, timeouts, and no per-call disable switch."),
}

_MODEL_PORTFOLIOS: dict[str, dict[str, Any]] = {}


def register_model_hardening(scan_id: str, portfolio: dict[str, Any]) -> None:
    _MODEL_PORTFOLIOS[scan_id] = portfolio


def render_model_hardening(portfolio: dict[str, Any]) -> dict[str, Any]:
    lines = [f"# {portfolio['title']}", "", portfolio["summary"], "", "## Architecture and security boundaries", ""]
    lines.extend(f"- {item}" for item in portfolio["architectureBoundaries"])
    lines.extend(["", "## Viable options", ""])
    for option in portfolio["options"]:
        lines.extend([
            f"### {option['title']} (`{option['id']}`)", "", option["description"], "", "Advantages:",
            *[f"- {item}" for item in option["advantages"]], "", "Disadvantages:",
            *[f"- {item}" for item in option["disadvantages"]], "", f"Tradeoffs: {option['tradeoffs']}", "",
            "Evidence:", *[f"- {item}" for item in option["evidenceRefs"]], "",
        ])
    lines.extend([
        "## Recommendation", "", f"Selected option: `{portfolio['recommendedOptionId']}`", "",
        portfolio["recommendationRationale"], "", "## Migration", "",
        *[f"{index}. {item}" for index, item in enumerate(portfolio["migrationSteps"], start=1)],
        "", "## Rollout", "", *[f"- {item}" for item in portfolio["rolloutPlan"]],
        "", "## Rollback", "", *[f"- {item}" for item in portfolio["rollbackPlan"]],
        "", "## Success metrics", "", *[f"- {item}" for item in portfolio["successMetrics"]],
        "", "## Work packages", "",
    ])
    for package in portfolio["workPackages"]:
        lines.extend([
            f"### {package['title']} (`{package['id']}`)", "",
            "Dependencies: " + (", ".join(package["dependencies"]) or "none"), "",
            *[f"- {item}" for item in package["deliverables"]], "",
        ])
    lines.extend(["## Before and after", "", "```text", portfolio["diagram"], "```", "", "## Evidence references", ""])
    lines.extend(f"- {item}" for item in portfolio["evidenceReferences"])
    return {"title": portfolio["title"], "summary": portfolio["summary"], "content": "\n".join(lines) + "\n"}


def render_hardening_proposal(scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    if scan_id in _MODEL_PORTFOLIOS:
        return render_model_hardening(_MODEL_PORTFOLIOS[scan_id])
    counts = Counter(item["taxonomy"]["category"] for item in findings if item.get("validationStatus") != "rejected")
    title = "Kiro Security Power hardening portfolio"
    lines = [f"# {title}", "", f"Scan: `{scan_id}`", "", "## Executive summary", ""]
    if not counts:
        summary = "No reportable finding category currently requires a structural hardening proposal."
        lines.append(summary)
    else:
        summary = f"The portfolio prioritizes {len(counts)} recurring security boundary categories across {sum(counts.values())} findings."
        lines.extend([summary, "", "## Recommended controls", ""])
        for rank, (category, count) in enumerate(counts.most_common(), start=1):
            control, description = _CONTROL_BY_CATEGORY.get(category, ("Repository security invariant", "Centralize and test the affected security boundary."))
            lines.extend([
                f"### {rank}. {control}",
                "",
                f"- Evidence: {count} finding(s) in category `{category}`.",
                f"- Proposed change: {description}",
                "- Alternative: retain local controls but add shared tests and lint rules; this costs less initially but leaves policy drift risk.",
                "- Rollout: inventory callers, introduce the safe abstraction, migrate highest-risk paths, add negative tests, then block new bypasses.",
                "- Success measure: all affected call sites use the approved boundary and category-specific regression tests pass.",
                "",
            ])
        lines.extend([
            "## Before and after",
            "",
            "```text",
            "Before: untrusted input -> ad hoc local handling -> privileged sink",
            "After:  untrusted input -> validated typed boundary -> policy/containment check -> privileged sink",
            "```",
            "",
            "## Decision and ownership",
            "",
            "Assign one engineering owner per control, record compatibility constraints, and ship migrations behind repository-native tests.",
        ])
    return {"title": title, "summary": summary, "content": "\n".join(lines) + "\n"}


def create_hardening_proposal(scan_id: str, findings: list[dict[str, Any]], output_path: Path) -> dict[str, Any]:
    rendered = render_hardening_proposal(scan_id, findings)
    atomic_write(output_path, rendered["content"])
    return {
        "title": rendered["title"],
        "summary": rendered["summary"],
        "artifactPath": str(output_path),
    }
