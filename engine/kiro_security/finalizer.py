from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from . import __version__
from .constants import ARTIFACT_KINDS
from .coverage import coverage_receipt_digest, expected_coverage_frontier
from .db import Workbench
from .errors import EngineError
from .hardening import render_hardening_proposal
from .schema_validation import validate_against_schema
from .security import atomic_write, sha256_bytes, sha256_file, utc_now

_MEDIA_TYPES = {
    "manifest": "application/json",
    "coverage": "application/json",
    "findings": "application/json",
    "discovery": "application/json",
    "validation": "application/json",
    "attackPath": "application/json",
    "inventory": "application/json",
    "threatModel": "text/markdown",
    "markdownReport": "text/markdown",
    "hardening": "text/markdown",
}
_CANONICAL_KINDS = ("coverage", "findings", "discovery", "validation", "attackPath")
# Sealed order: canonical documents first, then supporting evidence.
_SEALED_KINDS = (*_CANONICAL_KINDS, "inventory", "threatModel")


def _safe_relative(artifact_dir: Path, path: Path) -> str:
    if path.is_symlink():
        raise EngineError("unsafe_artifact_path", f"Refusing to seal symlink artifact: {path}")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise EngineError("artifact_missing", f"Required artifact is missing: {path}") from exc
    root = artifact_dir.resolve(strict=True)
    if resolved != root and root not in resolved.parents:
        raise EngineError("artifact_path_escape", f"Artifact escapes the scan directory: {path}")
    return resolved.relative_to(root).as_posix()


def _schema_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "schemas"


def _artifact_snapshot(
    kind: str,
    path: Path,
    artifact_dir: Path,
    *,
    role: str,
    parse_json: bool = True,
) -> dict[str, Any]:
    """Read an artifact exactly once into an immutable byte snapshot.

    Every downstream consumer (schema validation, semantic validation, the
    manifest artifact entry, the DB artifact registry, and the pre-commit
    integrity verification) must use this snapshot's bytes and SHA-256 so a
    file mutated mid-seal can never be published under a stale digest.
    """

    relative = _safe_relative(artifact_dir, path)
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise EngineError("artifact_missing", f"Unable to read artifact {relative}: {exc}") from exc
    snapshot: dict[str, Any] = {
        "kind": kind,
        "path": path,
        "relativePath": relative,
        "bytes": payload,
        "sha256": sha256_bytes(payload),
        "mediaType": _MEDIA_TYPES[kind],
        "role": role,
        "document": None,
    }
    if parse_json:
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EngineError("canonical_document_invalid", f"Unable to parse {relative}: {exc}") from exc
        if not isinstance(value, dict):
            raise EngineError("canonical_document_invalid", f"{relative} must contain a JSON object.")
        snapshot["document"] = value
    return snapshot


def _load_snapshots(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    artifact_dir = Path(bundle["artifactDir"])
    snapshots: dict[str, dict[str, Any]] = {}
    for kind in _CANONICAL_KINDS:
        snapshots[kind] = _artifact_snapshot(kind, Path(bundle["paths"][kind]), artifact_dir, role="canonical")
    inventory_path = Path(bundle["paths"].get("inventory") or artifact_dir / "inventory.json")
    snapshots["inventory"] = _artifact_snapshot("inventory", inventory_path, artifact_dir, role="supporting")
    threat_path = artifact_dir / ARTIFACT_KINDS["threatModel"]
    if threat_path.exists():
        snapshots["threatModel"] = _artifact_snapshot(
            "threatModel", threat_path, artifact_dir, role="supporting", parse_json=False
        )
    return snapshots


def _validate_inventory_document(document: dict[str, Any]) -> None:
    for key in ("files", "deferred"):
        items = document.get(key)
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise EngineError(
                "canonical_document_invalid",
                f"inventory.json {key} must be an array of objects.",
            )


def _validate_coverage_semantics(
    workbench: Workbench,
    scan: dict[str, Any],
    coverage: dict[str, Any],
    inventory_data: dict[str, Any],
) -> None:
    scan_id = coverage["scanId"]
    ledger_rows = workbench.list_coverage_rows(scan_id)
    ledger = {row["rowId"]: row for row in ledger_rows}
    surfaces = coverage.get("surfaces") or []
    unclosed = coverage.get("unclosedRows") or []
    for surface in surfaces:
        row_id = surface["rowId"]
        ledger_row = ledger.get(row_id)
        if ledger_row is None:
            raise EngineError("coverage_receipt_missing", f"Coverage surface {row_id} has no durable ledger row.")
        expected = coverage_receipt_digest(
            row_id=row_id,
            disposition=surface["disposition"],
            reason=surface["reason"],
            evidence_refs=surface.get("evidenceRefs") or [],
            candidate_ids=surface.get("candidateIds") or [],
        )
        if surface["receiptDigest"] != expected or ledger_row["receiptDigest"] != expected:
            raise EngineError(
                "coverage_receipt_digest_mismatch",
                f"Coverage receipt digest mismatch for row {row_id}.",
                {"rowId": row_id},
            )
        if surface.get("receiptRefs") != [expected]:
            raise EngineError(
                "coverage_receipt_reference_invalid",
                f"Coverage surface {row_id} must reference its durable receipt digest exactly once.",
            )

    # Authoritative frontier reconstruction. The coverage document's own
    # counts and row lists are treated as claims, never as the source.
    frontier = expected_coverage_frontier(workbench, scan, inventory_data)
    expected_ids = set(frontier["all"])
    surface_id_list = [str(item["rowId"]) for item in surfaces]
    surface_ids = set(surface_id_list)
    unclosed_ids = {str(item["rowId"]) for item in unclosed}
    if len(surface_id_list) != len(surface_ids) or len(unclosed) != len(unclosed_ids):
        raise EngineError("coverage_frontier_mismatch", "Coverage rows must be unique across surfaces and unclosed rows.")
    overlap = surface_ids & unclosed_ids
    if overlap:
        raise EngineError(
            "coverage_frontier_mismatch",
            "A coverage row cannot be both closed and unclosed.",
            {"rowIds": sorted(overlap)[:20]},
        )
    claimed_ids = surface_ids | unclosed_ids
    if claimed_ids != expected_ids:
        raise EngineError(
            "coverage_frontier_mismatch",
            "Coverage must account for every authoritative inventory/worklist row exactly once.",
            {
                "missingRowIds": sorted(expected_ids - claimed_ids)[:20],
                "unexpectedRowIds": sorted(claimed_ids - expected_ids)[:20],
            },
        )
    if set(ledger) != surface_ids:
        raise EngineError(
            "coverage_ledger_projection_mismatch",
            "The coverage surface projection must match the durable ledger rows exactly.",
            {
                "ledgerOnlyRowIds": sorted(set(ledger) - surface_ids)[:20],
                "surfaceOnlyRowIds": sorted(surface_ids - set(ledger))[:20],
            },
        )
    if coverage["supportedFileCount"] != len(frontier["supported"]):
        raise EngineError("coverage_count_mismatch", "supportedFileCount must equal the authoritative supported row count.")
    if coverage["inScopeRowCount"] != len(expected_ids):
        raise EngineError("coverage_count_mismatch", "inScopeRowCount must equal the authoritative frontier row count.")
    if coverage["closedRowCount"] != len(surfaces):
        raise EngineError("coverage_count_mismatch", "closedRowCount must equal the projected durable surface count.")
    if coverage["inScopeRowCount"] != coverage["closedRowCount"] + len(unclosed):
        raise EngineError("coverage_count_mismatch", "inScopeRowCount must equal closed plus unclosed rows.")
    deferred_doc_ids = {str(item["rowId"]) for item in coverage.get("deferred") or []}
    deferred_surface_ids = {str(item["rowId"]) for item in surfaces if item.get("disposition") == "deferred"}
    if deferred_doc_ids != deferred_surface_ids:
        raise EngineError(
            "coverage_frontier_mismatch",
            "The coverage deferred list must match the deferred surface receipts exactly.",
        )
    if coverage["completeness"] == "complete":
        if coverage["supportedFileCount"] < 1 or len(frontier["supported"]) < 1:
            raise EngineError("false_complete_coverage", "Coverage cannot be complete when no supported files were reviewed.")
        if coverage.get("unclosedRows") or coverage.get("deferred"):
            raise EngineError("false_complete_coverage", "Complete coverage cannot contain unclosed or deferred rows.")
        if deferred_surface_ids:
            raise EngineError("false_complete_coverage", "Complete coverage cannot contain a deferred surface receipt.")
        if coverage.get("deepStatus") == "capped":
            raise EngineError("false_complete_coverage", "A capped Deep scan can never claim complete coverage.")
        if surface_ids != expected_ids:
            raise EngineError("false_complete_coverage", "Complete coverage must close every authoritative frontier row.")



def _validate_auxiliary_documents(documents: dict[str, dict[str, Any]], scan_id: str) -> None:
    """Validate sealed supporting JSON that does not yet have a WS-I schema.

    WS-A keeps the dependency-light engine and limits schema expansion to
    coverage/findings/manifest.  These explicit assertions prevent malformed
    discovery, validation, or attack-path JSON from entering the sealed set
    before WS-I supplies their full schemas.
    """

    contracts = {
        "discovery": ("kiro-security-power.discovery", "candidates"),
        "validation": ("kiro-security-power.validation", "records"),
        "attackPath": ("kiro-security-power.attack-paths", "paths"),
    }
    for kind, (document_type, collection_key) in contracts.items():
        document = documents[kind]
        expected_keys = {"documentType", "schemaVersion", "scanId", collection_key}
        unexpected = sorted(set(document) - expected_keys)
        missing = sorted(expected_keys - set(document))
        if missing or unexpected:
            raise EngineError(
                "canonical_document_invalid",
                f"{kind}.json has an invalid top-level contract.",
                {"missing": missing, "unexpected": unexpected},
            )
        if document.get("documentType") != document_type or document.get("schemaVersion") != "1.0":
            raise EngineError("canonical_document_invalid", f"{kind}.json has an unsupported document contract.")
        if document.get("scanId") != scan_id:
            raise EngineError("canonical_scan_mismatch", f"{kind}.json scanId does not match the active scan.")
        items = document.get(collection_key)
        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
            raise EngineError(
                "canonical_document_invalid",
                f"{kind}.json {collection_key} must be an array of objects.",
            )

def _validation_mode(scan: dict[str, Any]) -> str:
    if scan["mode"] == "deep":
        return "agent-assisted-discovery+deterministic-static-validation"
    if scan["mode"] == "diff":
        return "deterministic-diff-static-analysis"
    return "deterministic-static-analysis"


def _runtime_status(scan: dict[str, Any]) -> str:
    return "agent-assisted-static" if scan["mode"] == "deep" else "static-only"


def _canonical_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    snapshots = bundle["snapshots"]
    entries = []
    for kind in _SEALED_KINDS:
        snapshot = snapshots.get(kind)
        if snapshot is None:
            continue
        entries.append(
            {
                "path": snapshot["relativePath"],
                "sha256": snapshot["sha256"],
                "mediaType": snapshot["mediaType"],
                "role": snapshot["role"],
            }
        )
    return entries


def _derived_descriptors(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    result = [
        {
            "path": ARTIFACT_KINDS["markdownReport"],
            "mediaType": _MEDIA_TYPES["markdownReport"],
            "generatedFrom": [ARTIFACT_KINDS["coverage"], ARTIFACT_KINDS["findings"]],
        },
        {
            "path": ARTIFACT_KINDS["hardening"],
            "mediaType": _MEDIA_TYPES["hardening"],
            "generatedFrom": [ARTIFACT_KINDS["findings"]],
        },
    ]
    for finding_id, path in sorted((bundle.get("writeupPaths") or {}).items()):
        result.append(
            {
                "path": path,
                "mediaType": "text/markdown",
                "generatedFrom": [ARTIFACT_KINDS["findings"]],
                "findingId": finding_id,
            }
        )
    return result


def _manifest_document(
    workbench: Workbench,
    scan: dict[str, Any],
    bundle: dict[str, Any],
    *,
    completed_at: str,
    sealed_at: str,
) -> dict[str, Any]:
    coverage = bundle["documents"]["coverage"]
    limitations = [item["question"] for item in coverage.get("openQuestions") or []]
    artifacts = _canonical_entries(bundle)
    derived = _derived_descriptors(bundle)
    return {
        "documentType": "kiro-security-power.scan-manifest",
        "schemaVersion": "1.0",
        "scan": {
            "id": scan["id"],
            "producer": {"name": "kiro-security-power", "version": __version__},
            "status": scan["status"],
            "startedAt": scan["started_at"],
            "completedAt": completed_at,
            "sealedAt": sealed_at,
            "target": {
                "kind": "git_diff" if scan["mode"] == "diff" else ("git_worktree" if scan.get("target_revision") else "directory_snapshot"),
                "targetId": scan.get("snapshot_digest") or scan["id"],
                "displayName": workbench.workspace.name,
                "revision": scan.get("target_revision"),
                "baseRevision": scan.get("diff_base_revision"),
                "headRevision": scan.get("diff_head_revision"),
                "snapshotDigest": scan.get("snapshot_digest"),
            },
            "scope": {
                "includePaths": coverage["includePaths"],
                "excludePaths": coverage["excludePaths"],
                "summary": f"{scan['mode']} scan of {scan['scope']}",
                "artifactsReviewed": [item["receiptDigest"] for item in coverage.get("surfaces") or []],
                "runtimeStatus": _runtime_status(scan),
                "validationMode": _validation_mode(scan),
                "limitations": limitations,
            },
            "threatModel": bundle["threatModel"],
            "hardening": {"portfolioPath": ARTIFACT_KINDS["hardening"]},
            "coverageRef": ARTIFACT_KINDS["coverage"],
            "findingsRef": ARTIFACT_KINDS["findings"],
            "artifacts": artifacts,
            "derivedArtifacts": derived,
        },
    }


def _validate_manifest_cross_references(manifest: dict[str, Any]) -> None:
    scan = manifest["scan"]
    artifacts = scan["artifacts"]
    paths = [item["path"] for item in artifacts]
    if len(paths) != len(set(paths)):
        raise EngineError("manifest_duplicate_artifact", "Manifest artifact paths must be unique.")
    if paths.count(scan["coverageRef"]) != 1 or paths.count(scan["findingsRef"]) != 1:
        raise EngineError(
            "manifest_canonical_cardinality",
            "Manifest must contain exactly one coverage artifact and exactly one findings artifact.",
        )
    derived_paths = {item["path"] for item in scan.get("derivedArtifacts") or []}
    if derived_paths.intersection(paths):
        raise EngineError("manifest_projection_sealed", "Derived projections must not appear in the sealed artifact list.")
    forbidden = {ARTIFACT_KINDS["markdownReport"], ARTIFACT_KINDS["hardening"]}
    if forbidden.intersection(paths):
        raise EngineError("manifest_projection_sealed", "report.md and hardening.md must remain derived projections.")


def prepare_finalization(workbench: Workbench, bundle: dict[str, Any]) -> dict[str, Any]:
    scan_id = str(bundle.get("scanId") or "")
    scan = workbench.get_scan(scan_id)
    if scan["status"] != "running" or scan["phase"] != "reporting":
        raise EngineError("finalizer_wrong_state", "Canonical documents may be prepared only during the running reporting phase.")
    snapshots = _load_snapshots(bundle)
    documents = {kind: snapshots[kind]["document"] for kind in _CANONICAL_KINDS}
    inventory_document = snapshots["inventory"]["document"]
    _validate_inventory_document(inventory_document)
    registered_inventory = next((item for item in scan.get("artifacts") or [] if item.get("kind") == "inventory"), None)
    if registered_inventory and registered_inventory.get("sha256") != snapshots["inventory"]["sha256"]:
        raise EngineError(
            "canonical_artifact_changed",
            "inventory.json no longer matches the durable artifact registry digest recorded for this scan.",
        )
    bundle = {**bundle, "documents": documents, "snapshots": snapshots, "inventory": inventory_document}
    schemas = _schema_dir()
    validate_against_schema(documents["coverage"], schemas / "coverage.schema.json", "coverage.json")
    validate_against_schema(documents["findings"], schemas / "findings.schema.json", "findings.json")
    if documents["coverage"].get("scanId") != scan_id or documents["findings"].get("scanId") != scan_id:
        raise EngineError("canonical_scan_mismatch", "Canonical document scanId does not match the active scan.")
    _validate_coverage_semantics(workbench, scan, documents["coverage"], inventory_document)
    _validate_auxiliary_documents(documents, scan_id)

    preview_time = utc_now()
    preview_scan = {**scan, "status": "completed"}
    preview = _manifest_document(
        workbench,
        preview_scan,
        bundle,
        completed_at=preview_time,
        sealed_at=preview_time,
    )
    validate_against_schema(preview, schemas / "scan-manifest.schema.json", "scan-manifest.json")
    _validate_manifest_cross_references(preview)
    return bundle


def _projection_findings(findings_document: dict[str, Any]) -> list[dict[str, Any]]:
    result = []
    for finding in findings_document.get("findings") or []:
        extensions = finding.get("extensions") if isinstance(finding.get("extensions"), dict) else {}
        result.append(
            {
                **finding,
                "validationStatus": extensions.get("validationStatus"),
                "triageStatus": extensions.get("triageStatus"),
            }
        )
    return result


def _project_report(scan: dict[str, Any], findings_document: dict[str, Any], coverage: dict[str, Any]) -> str:
    findings = _projection_findings(findings_document)
    reportable = [
        item
        for item in findings
        if item.get("validationStatus") != "rejected"
        and item.get("triageStatus") not in ("false_positive", "already_fixed")
    ]
    counts = Counter(item["severity"]["level"] for item in reportable)
    lines = [
        "# Kiro Security Power report",
        "",
        f"- Scan ID: `{scan['id']}`",
        f"- Mode: `{scan['mode']}`",
        f"- Scope: `{scan['scope']}`",
        f"- Revision: `{scan.get('target_revision') or 'filesystem snapshot'}`",
        f"- Coverage: `{coverage['completeness']}` ({coverage['closedRowCount']}/{coverage['inScopeRowCount']} rows closed)",
        "",
        "## Executive summary",
        "",
    ]
    if reportable:
        summary = ", ".join(
            f"{level} {counts[level]}"
            for level in ("critical", "high", "medium", "low", "informational")
            if counts[level]
        )
        lines.append(f"The canonical findings document contains {len(reportable)} reportable or review-required finding(s): {summary}.")
    else:
        lines.append("The canonical findings document contains no reportable findings. This does not prove the repository is vulnerability-free.")
    lines.extend(["", "## Findings", ""])
    for index, item in enumerate(reportable, start=1):
        sink = next((location for location in item.get("locations") or [] if location.get("role") == "sink"), None)
        lines.extend(
            [
                f"### {index}. {item['title']}",
                "",
                f"- ID: `{item['findingId']}`",
                f"- Severity: `{item['severity']['level']}`",
                f"- Confidence: `{item['confidence']['level']}`",
                f"- Validation: `{item.get('validationStatus')}`",
                f"- Location: `{sink['path']}:{sink['startLine']}`" if sink else "- Location: unavailable",
                "",
                item["summary"],
                "",
                f"**Remediation:** {item['remediation']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Coverage and limitations",
            "",
            f"Supported files reviewed: {coverage['supportedFileCount']}. Deferred rows: {len(coverage['deferred'])}. Unclosed rows: {len(coverage['unclosedRows'])}.",
            "",
        ]
    )
    for item in coverage.get("openQuestions") or []:
        lines.append(f"- {item['question']}")
    lines.extend(
        [
            "",
            "This report is a projection of the sealed canonical JSON. Its absence or later modification does not alter the sealed findings and coverage digests.",
            "",
        ]
    )
    return "\n".join(lines)


def _artifact_record(kind: str, path: Path, media_type: str, created_at: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": str(path),
        "sha256": sha256_file(path),
        "mediaType": media_type,
        "createdAt": created_at,
    }


def _artifact_record_payload(
    kind: str,
    path: Path,
    media_type: str,
    created_at: str,
    payload: str | bytes,
) -> dict[str, Any]:
    encoded = payload.encode("utf-8") if isinstance(payload, str) else payload
    return {
        "kind": kind,
        "path": str(path),
        "sha256": sha256_bytes(encoded),
        "mediaType": media_type,
        "createdAt": created_at,
    }


def finalize_scan(workbench: Workbench, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate, seal canonical JSON, project, then publish atomically.

    Every sealed artifact is read exactly once into an immutable snapshot.
    The manifest entries, DB artifact registry, and manifest digest are all
    derived from those snapshot bytes, and the on-disk files are re-verified
    against the snapshots inside the completion transaction immediately
    before publication, so a completed scan can never carry mismatched
    manifest/file/registry digests.
    """

    # Re-read every canonical file immediately before seal.  A caller cannot
    # prepare a valid bundle, mutate a file, and then seal stale in-memory data.
    bundle = prepare_finalization(workbench, bundle)
    scan_id = str(bundle.get("scanId") or "")
    scan = workbench.get_scan(scan_id)
    artifact_dir = Path(bundle["artifactDir"])
    snapshots = bundle["snapshots"]
    coverage = bundle["documents"]["coverage"]
    findings_document = bundle["documents"]["findings"]

    completed_at = utc_now()
    sealed_at = utc_now()
    projected_scan = {**scan, "status": "completed", "completed_at": completed_at}
    manifest = _manifest_document(
        workbench,
        projected_scan,
        bundle,
        completed_at=completed_at,
        sealed_at=sealed_at,
    )
    schemas = _schema_dir()
    validate_against_schema(manifest, schemas / "scan-manifest.schema.json", "scan-manifest.json")
    _validate_manifest_cross_references(manifest)
    if manifest["scan"]["status"] != "completed" or manifest["scan"]["completedAt"] != completed_at:
        raise EngineError("manifest_status_mismatch", "Manifest completion fields do not match the pending atomic completion state.")

    manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
    manifest_payload = json.dumps(manifest, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    manifest_digest = sha256_bytes(manifest_payload.encode("utf-8"))

    # Canonical seal boundary.  Only validated canonical/supporting artifacts
    # are named in manifest.scan.artifacts.  Registry records reuse the exact
    # snapshot digests already fixed in the manifest; nothing is re-hashed.
    sealed_snapshots = [snapshots[kind] for kind in _SEALED_KINDS if kind in snapshots]
    sealed_records = [
        {
            "kind": snapshot["kind"],
            "path": str(snapshot["path"]),
            "sha256": snapshot["sha256"],
            "mediaType": snapshot["mediaType"],
            "createdAt": sealed_at,
        }
        for snapshot in sealed_snapshots
    ]
    sealed_records.append(
        _artifact_record_payload("manifest", manifest_path, _MEDIA_TYPES["manifest"], sealed_at, manifest_payload)
    )

    # Projection boundary.  These bytes are reproducible from sealed canonical
    # JSON and never enter manifest.scan.artifacts.
    report_path = artifact_dir / ARTIFACT_KINDS["markdownReport"]
    report_payload = _project_report(scan, findings_document, coverage) + "\n"
    hardening_path = artifact_dir / ARTIFACT_KINDS["hardening"]
    hardening = render_hardening_proposal(scan_id, _projection_findings(findings_document))
    hardening_payload = str(hardening["content"])
    derived_records: list[dict[str, Any]] = [
        _artifact_record_payload("markdownReport", report_path, _MEDIA_TYPES["markdownReport"], sealed_at, report_payload),
        _artifact_record_payload("hardening", hardening_path, _MEDIA_TYPES["hardening"], sealed_at, hardening_payload),
    ]
    for finding_id, relative in sorted((bundle.get("writeupPaths") or {}).items()):
        path = artifact_dir / relative
        if path.exists():
            derived_records.append(_artifact_record(f"writeup:{finding_id}", path, "text/markdown", sealed_at))

    def verify_sealed_snapshots() -> None:
        # Integrity gate: every sealed file on disk must still be byte-identical
        # to the snapshot fixed in the manifest and registry.
        for snapshot in sealed_snapshots:
            try:
                actual = sha256_file(snapshot["path"])
            except OSError:
                actual = None
            if actual != snapshot["sha256"]:
                raise EngineError(
                    "canonical_artifact_changed",
                    f"Sealed artifact changed during finalization: {snapshot['relativePath']}",
                    {
                        "path": snapshot["relativePath"],
                        "expected": snapshot["sha256"],
                        "actual": actual,
                    },
                )

    def publish_files() -> None:
        # A mutation between snapshot capture and publication aborts the
        # transaction before any official file is written.
        verify_sealed_snapshots()
        # Manifest is written last.  A failed projection leaves diagnostic files
        # but never a completed DB state or an official completed manifest.
        atomic_write(report_path, report_payload)
        atomic_write(hardening_path, hardening_payload)
        atomic_write(manifest_path, manifest_payload)
        if sha256_file(manifest_path) != manifest_digest:
            raise EngineError("manifest_digest_mismatch", "Published manifest bytes do not match the pending seal digest.")
        # Re-verify immediately before returning control to the transaction:
        # a canonical file mutated while the projections and manifest were
        # being written must also roll back the completion instead of
        # committing a seal whose digests no longer match the disk.
        verify_sealed_snapshots()

    all_records = sealed_records + derived_records
    try:
        completed = workbench.complete_and_seal_scan_bundle(
            scan_id,
            completed_at=completed_at,
            coverage=coverage,
            manifest_digest=manifest_digest,
            artifact_records=all_records,
            publish_files=publish_files,
            hardening_record={
                "title": hardening["title"],
                "summary": hardening["summary"],
                "artifactPath": str(hardening_path),
            },
        )
    except Exception:
        # If SQLite rolls back after file publication, remove only the exact
        # projection/manifest bytes produced by this attempt.  The canonical
        # JSON inputs remain for diagnosis and retry, but no completed manifest
        # is left behind to imply a successful seal.
        expected_payloads = (
            (manifest_path, manifest_payload),
            (report_path, report_payload),
            (hardening_path, hardening_payload),
        )
        for path, payload in expected_payloads:
            try:
                expected = sha256_bytes(payload.encode("utf-8"))
                if path.is_file() and not path.is_symlink() and sha256_file(path) == expected:
                    path.unlink()
            except OSError:
                pass
        raise
    if completed["status"] != "completed" or completed["completed_at"] != completed_at:
        raise EngineError("atomic_completion_failed", "The durable scan state did not match the sealed manifest completion timestamp.")
    return all_records


# Backward-compatible import seam for older callers; semantics are now atomic.
finalize_completed_scan = finalize_scan
