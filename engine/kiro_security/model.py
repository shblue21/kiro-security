"""Thin deterministic facade for the Kiro Security Power model scan.

Semantic analysis belongs to the Kiro Power coordinator and its native
subagents.  This module only binds a scan to immutable target/worklist inputs,
adapts the direct Codex Security 0.1.11 deterministic contract port, and
publishes its sealed canonical result to the durable workbench.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import sqlite3
from pathlib import Path
from typing import Any

from . import __version__
from .codex_contract import (
    completion_lock,
    finalize_scan_contract,
    generate_rank_input,
    resolve_security_md,
    workbench_target,
)
from .db import Workbench
from .errors import EngineError
from .security import atomic_write, resolve_within, sha256_file, stable_id, stable_target_id

_PHASE_DIRECTORIES = (
    "artifacts/01_context",
    "artifacts/02_discovery",
    "artifacts/03_coverage",
    "artifacts/04_reconciliation",
    "artifacts/05_findings",
    "deep_discovery",
    "findings",
    "hardening",
    "exports",
)
_SETUP_ARTIFACTS = {
    "securityGuidance": "artifacts/01_context/security_guidance.md",
    "rankInput": "artifacts/02_discovery/rank_input.jsonl",
}
_DIFF_CONTEXT = "artifacts/01_context/diff_context.json"
_DEEP_INPUT = "artifacts/02_discovery/deep_review_input.jsonl"


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _engine_error(code: str, message: str, exc: Exception) -> EngineError:
    return EngineError(code, message, {"detail": str(exc)[:2000]})


def _scope_path(workspace: Path, scope: str) -> Path:
    try:
        return resolve_within(workspace, scope, must_exist=True)
    except EngineError:
        raise
    except OSError as exc:
        raise _engine_error("target_unavailable", "The requested scan scope is unavailable.", exc) from exc


def _target_snapshot(workspace: Path, state_root: Path) -> tuple[str | None, str]:
    """Use the direct-port target helper without any repository interpretation."""
    try:
        metadata = workbench_target.git_target_metadata(workspace)
        if metadata.get("isWorktree"):
            return metadata.get("revision"), workbench_target.kiro_workspace_content_digest(workspace, state_root)
        return None, workbench_target.directory_content_digest(
            workspace, excluded=(workspace / ".kiro" / "security-power",)
        )
    except (OSError, SystemExit, ValueError) as exc:
        raise _engine_error("target_snapshot_failed", "Unable to calculate the immutable scan target snapshot.", exc) from exc


def _git_revision(workspace: Path, value: str, field: str) -> str:
    try:
        resolved = workbench_target.git_output(workspace, "rev-parse", "--verify", f"{value}^{{commit}}")
    except (OSError, ValueError) as exc:
        raise _engine_error("invalid_diff_target", f"Unable to resolve {field}.", exc) from exc
    if not resolved:
        raise EngineError("invalid_diff_target", f"{field} must resolve to a Git commit.")
    return resolved


def _diff_target(
    scan: dict[str, Any], workspace: Path, state_root: Path
) -> tuple[str, str, str, dict[str, Any]]:
    kind = scan.get("diff_target_kind") or "working_tree"
    requested_base = scan.get("diff_base_revision")
    requested_head = scan.get("diff_head_revision")
    if kind == "working_tree":
        head = _git_revision(workspace, "HEAD", "HEAD")
        if requested_base and _git_revision(workspace, requested_base, "diffBaseRevision") != head:
            raise EngineError("invalid_diff_target", "Working-tree diffBaseRevision must match current HEAD.")
        if requested_head and _git_revision(workspace, requested_head, "diffHeadRevision") != head:
            raise EngineError("invalid_diff_target", "Working-tree diffHeadRevision must match current HEAD.")
        return "local-patch", head, head, {
            "kind": kind, "baseRevision": head, "headRevision": head, "scope": scan["scope"],
        }
    if kind == "commit":
        head = _git_revision(workspace, requested_head or "HEAD", "diffHeadRevision")
        base = _git_revision(workspace, requested_base or f"{head}^", "diffBaseRevision")
    elif kind == "range":
        if not requested_base or not requested_head:
            raise EngineError("invalid_diff_target", "Range Diff requires base and head revisions.")
        base = _git_revision(workspace, requested_base, "diffBaseRevision")
        head = _git_revision(workspace, requested_head, "diffHeadRevision")
    else:
        raise EngineError("invalid_diff_target", f"Unsupported Diff target kind: {kind}")

    current = _git_revision(workspace, "HEAD", "HEAD")
    if head != current:
        raise EngineError(
            "diff_target_not_checked_out",
            "Commit and range Diff heads must be the checked-out HEAD so source evidence matches the immutable target.",
        )
    if workbench_target.kiro_workspace_content_digest(workspace, state_root) != workbench_target.clean_worktree_content_digest():
        raise EngineError(
            "diff_target_dirty",
            "Commit and range Diffs require a clean worktree outside .kiro/security-power.",
        )
    return "revisions", base, head, {
        "kind": kind, "baseRevision": base, "headRevision": head, "scope": scan["scope"],
    }


def _write_rank_input(
    scan: dict[str, Any], workspace: Path, state_root: Path, output: Path
) -> dict[str, Any] | None:
    limits = scan.get("capabilities") or {}
    preview_bytes = min(int(limits.get("maxFileBytes") or 1_048_576), 1_048_576)
    if scan["mode"] != "diff":
        scope = _scope_path(workspace, scan["scope"])
        if not scope.is_dir():
            raise EngineError("invalid_scope", "Standard and Deep scan scopes must be directories.")
        args = argparse.Namespace(
            repo=str(workspace), scope=scan["scope"], out=str(output), area="", preview_bytes=preview_bytes,
        )
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                generate_rank_input.make_repo_rank_input(args)
        except (OSError, SystemExit, ValueError) as exc:
            raise _engine_error("rank_input_failed", "Unable to create deterministic rank input.", exc) from exc
        return None

    diff_mode, base, head, diff_context = _diff_target(scan, workspace, state_root)
    args = argparse.Namespace(
        repo=str(workspace), base=base, head=head, mode=diff_mode, out=str(output),
        area="diff", preview_bytes=preview_bytes,
    )
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            generate_rank_input.make_diff_rank_input(args)
    except (OSError, SystemExit, ValueError) as exc:
        raise _engine_error("rank_input_failed", "Unable to create deterministic Diff rank input.", exc) from exc
    return diff_context


def _copy_exhaustive_input(rank_input: Path, deep_input: Path) -> None:
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            generate_rank_input.copy_deep_review_input(
                argparse.Namespace(rank_input=str(rank_input), out=str(deep_input))
            )
    except (OSError, SystemExit, ValueError) as exc:
        raise _engine_error("deep_worklist_failed", "Unable to create the exhaustive Deep review worklist.", exc) from exc


def _setup_expected(scan: dict[str, Any]) -> dict[str, str]:
    expected = dict(_SETUP_ARTIFACTS)
    if scan["mode"] == "diff":
        expected["diffContext"] = _DIFF_CONTEXT
    if scan["mode"] in {"diff", "deep"}:
        expected["deepReviewInput"] = _DEEP_INPUT
    return expected


def _prepared_artifact_record(kind: str, root: Path, relative: str, media_type: str) -> dict[str, Any]:
    path = resolve_within(root, relative, must_exist=True)
    if path.is_symlink() or not path.is_file():
        raise EngineError("unsafe_artifact_path", f"Deterministic setup artifact is not a regular file: {relative}")
    return {
        "kind": kind,
        "path": str(path),
        "sha256": sha256_file(path),
        "mediaType": media_type,
    }


def _validate_setup_artifacts(workbench: Workbench, scan: dict[str, Any]) -> None:
    root = Path(scan["artifact_dir"])
    recorded = {item["kind"]: item for item in scan.get("artifacts") or []}
    for kind, relative in _setup_expected(scan).items():
        path = resolve_within(root, relative, must_exist=True)
        record = recorded.get(kind)
        if (
            record is None
            or path.is_symlink()
            or not path.is_file()
            or Path(record["path"]).resolve(strict=True) != path.resolve(strict=True)
            or record["sha256"] != sha256_file(path)
        ):
            raise EngineError("model_setup_artifact_changed", f"Immutable setup artifact is missing or changed: {relative}")


def setup_model_scan(workbench: Workbench, scan: dict[str, Any]) -> dict[str, Any]:
    """Prepare immutable setup files before the running scan is published."""
    root = Path(scan["artifact_dir"])
    root.mkdir(parents=True, exist_ok=True)
    for relative in _PHASE_DIRECTORIES:
        resolve_within(root, relative).mkdir(parents=True, exist_ok=True)

    revision, snapshot_digest = _target_snapshot(workbench.workspace, workbench.state_dir)
    rank_input = resolve_within(root, _SETUP_ARTIFACTS["rankInput"])
    diff_context = _write_rank_input(scan, workbench.workspace, workbench.state_dir, rank_input)
    scope = _scope_path(workbench.workspace, scan["scope"])
    try:
        guidance = resolve_security_md.resolve_security_md(workbench.workspace, scope)
    except (OSError, resolve_security_md.ResolutionError) as exc:
        raise _engine_error("security_guidance_failed", "Unable to resolve applicable SECURITY.md guidance.", exc) from exc
    atomic_write(resolve_within(root, _SETUP_ARTIFACTS["securityGuidance"]), guidance)

    if diff_context is not None:
        atomic_write(resolve_within(root, _DIFF_CONTEXT), _json_bytes({
            "documentType": "kiro-security-power.diff-context",
            "schemaVersion": "1.0",
            "target": diff_context,
        }))

    if scan["mode"] in {"diff", "deep"}:
        _copy_exhaustive_input(rank_input, resolve_within(root, _DEEP_INPUT))

    artifact_records: list[dict[str, Any]] = []
    for kind, relative in _setup_expected(scan).items():
        media_type = "text/markdown" if relative.endswith(".md") else (
            "application/x-ndjson" if relative.endswith(".jsonl") else "application/json"
        )
        artifact_records.append(_prepared_artifact_record(kind, root, relative, media_type))
    line_count = sum(1 for line in rank_input.read_text(encoding="utf-8").splitlines() if line)
    return {
        "targetIdentity": stable_target_id(workbench.workspace),
        "targetRevision": revision,
        "snapshotDigest": snapshot_digest,
        "diffBaseRevision": diff_context["baseRevision"] if diff_context is not None else scan.get("diff_base_revision"),
        "diffHeadRevision": diff_context["headRevision"] if diff_context is not None else scan.get("diff_head_revision"),
        "artifacts": artifact_records,
        "filesTotal": line_count,
        "progressMessage": "Immutable target, SECURITY.md guidance, and deterministic rank input are ready.",
    }


def _expected_target(workbench: Workbench, scan: dict[str, Any]) -> dict[str, Any]:
    target = {
        "kind": "git_diff" if scan["mode"] == "diff" else (
            "git_worktree" if scan.get("target_revision") else "directory_snapshot"
        ),
        "targetId": scan["target_identity"],
        "displayName": workbench.workspace.name,
        "snapshotDigest": scan["snapshot_digest"],
    }
    if scan.get("target_revision"):
        target["revision"] = scan["target_revision"]
    if scan["mode"] == "diff":
        if scan.get("diff_base_revision"):
            target["baseRevision"] = scan["diff_base_revision"]
        if scan.get("diff_head_revision"):
            target["headRevision"] = scan["diff_head_revision"]
    return target


def get_model_context(workbench: Workbench, scan_id: str) -> dict[str, Any]:
    scan = workbench.get_scan(scan_id)
    root = Path(scan["artifact_dir"])
    deep_input = resolve_within(root, _DEEP_INPUT)
    other_deep = [
        {"scanId": item["id"], "status": item["status"], "scope": item["scope"], "startedAt": item["started_at"]}
        for item in workbench.list_scans(200)
        if item["id"] != scan_id and item["mode"] == "deep" and item["status"] == "running"
    ]
    return {
        "scanId": scan_id,
        "mode": scan["mode"],
        "scope": scan["scope"],
        "target": {"root": str(workbench.workspace), **_expected_target(workbench, scan)},
        "artifactRoot": str(root),
        "producer": {"name": "kiro-security-power", "version": __version__},
        "userContext": (scan.get("capabilities") or {}).get("userContext"),
        "artifactDirectories": {name: str(resolve_within(root, name)) for name in _PHASE_DIRECTORIES},
        "inputs": {
            "securityGuidance": str(resolve_within(root, _SETUP_ARTIFACTS["securityGuidance"])),
            "rankInput": str(resolve_within(root, _SETUP_ARTIFACTS["rankInput"])),
            "deepReviewInput": str(deep_input),
            "deepReviewInputReady": deep_input.is_file(),
            "diffContext": str(resolve_within(root, _DIFF_CONTEXT)) if scan["mode"] == "diff" else None,
        },
        "canonicalOutputs": {
            "manifest": str(resolve_within(root, "scan-manifest.json")),
            "findings": str(resolve_within(root, "findings.json")),
            "coverage": str(resolve_within(root, "coverage.json")),
            "report": str(resolve_within(root, "report.md")),
            "sarif": str(resolve_within(root, "exports/results.sarif")),
        },
        "lifecycle": {
            "status": scan["status"], "phase": scan["phase"], "startedAt": scan["started_at"],
            "progress": scan.get("progress"),
        },
        "otherRunningDeepScans": other_deep,
    }


def revalidate_model_target(workbench: Workbench, scan_id: str) -> None:
    scan = workbench.get_scan(scan_id)
    revision, snapshot_digest = _target_snapshot(workbench.workspace, workbench.state_dir)
    if scan.get("target_identity") != stable_target_id(workbench.workspace):
        raise EngineError("target_changed", "The stable repository/workspace identity changed after setup.")
    if scan.get("target_revision") != revision:
        raise EngineError("target_changed", "The Git revision changed after setup.")
    if scan.get("snapshot_digest") != snapshot_digest:
        raise EngineError("target_changed", "The reviewed target snapshot changed after setup.", {
            "expected": scan.get("snapshot_digest"), "actual": snapshot_digest,
        })
    _validate_setup_artifacts(workbench, scan)


def _read_json(root: Path, relative: str) -> dict[str, Any]:
    path = resolve_within(root, relative, must_exist=True)
    if path.is_symlink() or not path.is_file():
        raise EngineError("unsafe_artifact_path", f"Canonical artifact must be a regular file: {relative}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _engine_error("canonical_document_invalid", f"Unable to read {relative}.", exc) from exc
    if not isinstance(value, dict):
        raise EngineError("canonical_document_invalid", f"{relative} must contain a JSON object.")
    return value


def _verify_manifest_binding(workbench: Workbench, scan: dict[str, Any], root: Path) -> None:
    manifest = _read_json(root, "scan-manifest.json")
    authored = manifest.get("scan")
    if (
        manifest.get("documentType") != "kiro-security-power.scan-manifest"
        or not isinstance(authored, dict)
        or authored.get("id") != scan["id"]
        or authored.get("target") != _expected_target(workbench, scan)
        or authored.get("coverageRef") != "coverage.json"
        or authored.get("findingsRef") != "findings.json"
    ):
        raise EngineError("canonical_target_mismatch", "The authored canonical manifest is not bound to this immutable scan target.")


def _coverage_mode(scan: dict[str, Any]) -> str:
    if scan["mode"] == "deep":
        return "deep_repository" if scan["scope"] == "." else "scoped_path"
    if scan["mode"] == "standard":
        return "repository" if scan["scope"] == "." else "scoped_path"
    return {
        "working_tree": "working_tree",
        "commit": "commit",
        "range": "branch_diff",
    }[scan.get("diff_target_kind") or "working_tree"]


def _index_callback(scan_id: str, findings: list[dict[str, Any]]):
    """Project sealed canonical findings into SQLite without adding analysis."""
    def apply(connection: sqlite3.Connection, timestamp: str) -> None:
        connection.execute("DELETE FROM finding_occurrences WHERE scan_id=?", (scan_id,))
        for item in findings:
            fingerprint = item["fingerprints"]["primary"]
            finding_id = item["findingId"]
            occurrence_id = item["occurrenceId"]
            identity = item["identity"]
            connection.execute(
                """INSERT INTO findings(id,fingerprint,rule_id,identity_anchor,identity_instance,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET fingerprint=excluded.fingerprint,
                   rule_id=excluded.rule_id,identity_anchor=excluded.identity_anchor,
                   identity_instance=excluded.identity_instance,updated_at=excluded.updated_at""",
                (finding_id, fingerprint, item["ruleId"], identity["anchor"], identity.get("instance"), timestamp, timestamp),
            )
            validation = item.get("validation") if isinstance(item.get("validation"), dict) else {}
            validation_status = validation.get("status") if validation.get("status") in {
                "unvalidated", "validated", "rejected", "needs_review"
            } else "unvalidated"
            details = {key: value for key, value in item.items() if key not in {
                "findingId", "occurrenceId", "ruleId", "identity", "fingerprints", "title", "summary",
                "severity", "confidence", "taxonomy", "locations", "remediation",
            }}
            connection.execute(
                """INSERT INTO finding_occurrences(id,finding_id,scan_id,title,summary,severity,severity_score,
                   severity_rationale,confidence,confidence_rationale,category,cwe_json,remediation,details_json,
                   validation_status,triage_status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?)""",
                (occurrence_id, finding_id, scan_id, item["title"], item["summary"], item["severity"]["level"],
                 item["severity"].get("score"), item["severity"].get("rationale"), item["confidence"]["level"],
                 item["confidence"]["rationale"], item["taxonomy"]["category"],
                 json.dumps(item["taxonomy"].get("cwe") or [], separators=(",", ":"), allow_nan=False),
                 item["remediation"], json.dumps(details, separators=(",", ":"), allow_nan=False),
                 validation_status, timestamp, timestamp),
            )
            for order, location in enumerate(item["locations"]):
                connection.execute(
                    "INSERT INTO finding_locations(occurrence_id,relative_path,start_line,end_line,role,sort_order) VALUES(?,?,?,?,?,?)",
                    (occurrence_id, location["path"], location["startLine"],
                     location.get("endLine", location["startLine"]), location.get("role", "evidence"), order),
                )
            for order, evidence in enumerate(item.get("codeEvidence") or []):
                connection.execute(
                    """INSERT INTO finding_evidence(id,occurrence_id,kind,label,relative_path,start_line,end_line,language,role,snippet,explanation,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (stable_id("ev", occurrence_id, str(order)), occurrence_id, "code", evidence["label"], evidence["path"],
                     evidence["startLine"], evidence.get("endLine", evidence["startLine"]), evidence.get("language"),
                     evidence.get("role"), evidence["code"][:12000], evidence["explanation"][:4000], timestamp),
                )
            if validation:
                connection.execute(
                    "INSERT INTO validation_records(id,occurrence_id,status,method,rationale,evidence_json,created_at) VALUES(?,?,?,?,?,?,?)",
                    (stable_id("val", occurrence_id), occurrence_id, validation_status,
                     str(validation.get("method") or "not_recorded"), str(validation.get("rationale") or "Not recorded."),
                     json.dumps(validation.get("evidenceRefs") or [], separators=(",", ":"), allow_nan=False), timestamp),
                )
            attack = item.get("attackPath") if isinstance(item.get("attackPath"), dict) else None
            if attack:
                severity = attack.get("severity") if isinstance(attack.get("severity"), dict) else {}
                connection.execute(
                    """INSERT INTO attack_paths(id,occurrence_id,narrative,path_json,exploitability,impact,severity_rationale,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (stable_id("path", occurrence_id), occurrence_id, str(attack.get("narrative") or "Not recorded."),
                     json.dumps(attack.get("crossFilePath") or attack.get("path") or [], separators=(",", ":"), allow_nan=False),
                     str(attack.get("exploitability") or "Not recorded."), str(attack.get("impact") or "Not recorded."),
                     str(severity.get("rationale") or ""), timestamp, timestamp),
                )
    return apply


def _records_from_sealed_bundle(root: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    scan = manifest["scan"]
    records: list[dict[str, Any]] = []
    for index, artifact in enumerate(scan["artifacts"]):
        relative = artifact["path"]
        path = resolve_within(root, relative, must_exist=True)
        actual = None if path.is_symlink() or not path.is_file() else sha256_file(path)
        if actual != artifact["sha256"]:
            raise EngineError(
                "canonical_publication_changed",
                "A manifest-sealed artifact changed while the scan was being published.",
                {"path": relative, "expected": artifact["sha256"], "actual": actual},
            )
        records.append({
            "kind": {"findings.json": "findings", "coverage.json": "coverage"}.get(relative, f"sealedReceipt:{index}"),
            "path": str(path), "sha256": artifact["sha256"], "mediaType": artifact["mediaType"],
        })
    for kind, relative, media_type in (
        ("manifest", "scan-manifest.json", "application/json"),
        ("markdownReport", "report.md", "text/markdown"),
        ("sarifReport", "exports/results.sarif", "application/sarif+json"),
    ):
        path = resolve_within(root, relative)
        if path.is_file() and not path.is_symlink():
            records.append({
                "kind": kind, "path": str(path), "sha256": sha256_file(path),
                "mediaType": media_type,
            })
    return records


def _finalize(root: Path, scan: dict[str, Any], workspace: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    schemas = Path(__file__).resolve().parent.parent / "schemas"
    try:
        return finalize_scan_contract.finalize_scan(
            root, schemas, workspace, expected_coverage_mode=_coverage_mode(scan)
        )
    except (OSError, ValueError, finalize_scan_contract.ContractError) as exc:
        raise _engine_error("canonical_finalization_failed", "The canonical scan contract could not be finalized.", exc) from exc


def _published_manifest_digest(root: Path, manifest: dict[str, Any]) -> str:
    path = resolve_within(root, "scan-manifest.json", must_exist=True)
    if path.is_symlink() or not path.is_file():
        raise EngineError("canonical_publication_changed", "The sealed scan manifest is not a regular file.")
    canonical = (json.dumps(manifest, allow_nan=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    expected = hashlib.sha256(canonical).hexdigest()
    actual = sha256_file(path)
    if actual != expected:
        raise EngineError(
            "canonical_publication_changed",
            "The sealed scan manifest changed while it was being published.",
            {"expected": expected, "actual": actual},
        )
    return expected


def _complete_model_scan_locked(
    workbench: Workbench, scan_id: str, coordinator_token: str, coordinator_generation: int
) -> dict[str, Any]:
    workbench.require_coordinator_lease(scan_id, coordinator_token, coordinator_generation)
    scan = workbench.get_scan(scan_id)
    root = Path(scan["artifact_dir"])
    if scan["status"] != "running":
        raise EngineError("scan_not_running", f"Scan {scan_id} is {scan['status']}.")
    revalidate_model_target(workbench, scan_id)
    _verify_manifest_binding(workbench, scan, root)
    manifest, findings, coverage = _finalize(root, scan, workbench.workspace)
    _verify_manifest_binding(workbench, scan, root)
    artifact_records = _records_from_sealed_bundle(root, manifest)
    manifest_digest = _published_manifest_digest(root, manifest)
    revalidate_model_target(workbench, scan_id)
    return workbench.complete_and_seal_scan_bundle(
        scan_id,
        coverage=coverage,
        manifest_digest=manifest_digest,
        artifact_records=artifact_records,
        finding_count=len(findings["findings"]),
        index_findings=_index_callback(scan_id, findings["findings"]),
        coordinator_token=coordinator_token,
        coordinator_generation=coordinator_generation,
    )


def complete_model_scan(
    workbench: Workbench, scan_id: str, coordinator_token: str, coordinator_generation: int
) -> dict[str, Any]:
    with completion_lock.scan_completion_lock(workbench.state_dir, scan_id):
        return _complete_model_scan_locked(
            workbench, scan_id, coordinator_token, coordinator_generation
        )
