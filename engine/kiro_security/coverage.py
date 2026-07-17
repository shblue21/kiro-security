from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .errors import EngineError
from .constants import is_model_scan
from .security import sha256_bytes, stable_id

COVERAGE_DISPOSITIONS = ("reportable", "suppressed", "not_applicable", "deferred")


def coverage_row_id(path: str, surface: str) -> str:
    """Return the stable inventory/worklist row id used by WS-A.

    The identity deliberately excludes finding fingerprints. WS-F can replace the
    finding reference adapter below without changing coverage row identity.
    """

    return stable_id("coverage-row", str(path), str(surface))


def coverage_finding_reference(finding: dict[str, Any]) -> str:
    """Single seam for coverage -> finding identity references.

    WS-F will replace the current finding-id scheme. Coverage code must call this
    adapter instead of reaching into fingerprint/occurrence fields directly.
    """

    value = finding.get("findingId")
    if not isinstance(value, str) or not value:
        raise EngineError("invalid_coverage_finding_reference", "Coverage finding reference is missing findingId.")
    return value


def _sorted_strings(values: Iterable[Any] | None) -> list[str]:
    if values is None:
        return []
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or "\x00" in value:
            raise EngineError("invalid_coverage_reference", "Coverage references must be non-empty strings.")
        result.add(value)
    return sorted(result)


def coverage_receipt_digest(
    *,
    row_id: str,
    disposition: str,
    reason: str,
    evidence_refs: Iterable[Any] | None = None,
    candidate_ids: Iterable[Any] | None = None,
) -> str:
    if disposition not in COVERAGE_DISPOSITIONS:
        raise EngineError("invalid_coverage_disposition", f"Unsupported coverage disposition: {disposition}")
    if not isinstance(row_id, str) or not row_id:
        raise EngineError("invalid_coverage_row", "Coverage rowId is required.")
    if not isinstance(reason, str) or not reason.strip():
        raise EngineError("invalid_coverage_reason", "Coverage disposition reason is required.")
    payload = {
        "rowId": row_id,
        "disposition": disposition,
        "reason": reason.strip(),
        "evidenceRefs": _sorted_strings(evidence_refs),
        "candidateIds": _sorted_strings(candidate_ids),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return sha256_bytes(encoded.encode("utf-8", "surrogatepass"))


def make_coverage_row(
    *,
    row_id: str,
    path: str,
    surface: str,
    disposition: str,
    reason: str,
    evidence_refs: Iterable[Any] | None = None,
    candidate_ids: Iterable[Any] | None = None,
    entrypoint: str | None = None,
    root_control: str | None = None,
    sink: str | None = None,
    worker_id: str | None = None,
) -> dict[str, Any]:
    if disposition not in COVERAGE_DISPOSITIONS:
        raise EngineError("invalid_coverage_disposition", f"Unsupported coverage disposition: {disposition}")
    if not isinstance(path, str) or not path or "\x00" in path:
        raise EngineError("invalid_coverage_path", "Coverage path is required.")
    if Path(path).is_absolute():
        raise EngineError("invalid_coverage_path", "Coverage paths must be workspace-relative.")
    if not isinstance(surface, str) or not surface.strip():
        raise EngineError("invalid_coverage_surface", "Coverage surface is required.")
    reason_value = reason.strip() if isinstance(reason, str) else ""
    if not reason_value:
        raise EngineError("invalid_coverage_reason", "Coverage disposition reason is required.")
    evidence = _sorted_strings(evidence_refs)
    candidates = _sorted_strings(candidate_ids)
    if disposition == "reportable" and not candidates:
        raise EngineError(
            "reportable_coverage_without_candidate",
            "A reportable coverage receipt must reference at least one candidate or finding.",
            {"rowId": row_id},
        )
    digest = coverage_receipt_digest(
        row_id=row_id,
        disposition=disposition,
        reason=reason_value,
        evidence_refs=evidence,
        candidate_ids=candidates,
    )
    return {
        "id": stable_id("coverage-receipt", row_id, digest),
        "rowId": row_id,
        "path": path,
        "surface": surface.strip(),
        "entrypoint": entrypoint.strip() if isinstance(entrypoint, str) and entrypoint.strip() else None,
        "rootControl": root_control.strip() if isinstance(root_control, str) and root_control.strip() else None,
        "sink": sink.strip() if isinstance(sink, str) and sink.strip() else None,
        "disposition": disposition,
        "reason": reason_value,
        "evidenceRefs": evidence,
        "candidateIds": candidates,
        "workerId": worker_id,
        "receiptDigest": digest,
    }


def deferred_inventory_row(scan_scope: str, item: dict[str, Any]) -> dict[str, Any]:
    path = str(item.get("path") or item.get("id") or scan_scope)
    surface = str(item.get("surface") or item.get("kind") or "inventory_deferred")
    row_id = str(item.get("rowId") or coverage_row_id(path, surface))
    reason = str(item.get("reason") or "The in-scope item was not reviewed.")
    return make_coverage_row(
        row_id=row_id,
        path=path,
        surface=surface,
        disposition="deferred",
        reason=reason,
    )


def expected_coverage_frontier(
    workbench: Any,
    scan: dict[str, Any],
    inventory_data: dict[str, Any],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Reconstruct the authoritative in-scope row frontier for a scan.

    The frontier is derived only from authoritative sources: the durable Deep
    worklist for Deep scans, and the inventory's supported and deferred rows
    for Standard/Diff scans. Coverage documents are projections of this
    frontier and must never be trusted for it.
    """

    supported: dict[str, dict[str, Any]] = {}
    if is_model_scan(scan):
        state = workbench.get_deep_scan_state(scan["id"])
        if state and state.get("worklist"):
            for item in state["worklist"]:
                row = dict(item)
                supported[str(row["rowId"])] = row
    if not supported:
        for item in inventory_data.get("files") or []:
            path = str(item.get("path") or "")
            if not path:
                continue
            surface = str(item.get("surface") or f"source_review:{item.get('language') or 'text'}")
            row_id = str(item.get("rowId") or coverage_row_id(path, surface))
            supported[row_id] = {
                "rowId": row_id,
                "path": path,
                "surface": surface,
                "language": item.get("language"),
                "size": int(item.get("size") or 0),
            }
    deferred: dict[str, dict[str, Any]] = {}
    for item in inventory_data.get("deferred") or []:
        row = deferred_inventory_row(scan["scope"], dict(item))
        deferred[str(row["rowId"])] = row
    return {
        "supported": supported,
        "deferred": deferred,
        "all": {**supported, **deferred},
    }
