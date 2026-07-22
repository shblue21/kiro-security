from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import EngineError
from .security import redact, sha256_bytes, write_json

TRACKING_PROVIDERS = ("manual", "github", "linear", "jira")
TRIAGE_SOURCE_TYPES = (
    "sarif", "cve", "advisory", "scanner_ticket", "bug_bounty",
    "kiro_security_finding", "freeform", "unknown",
)
TRACKING_OUTCOMES = ("created", "updated", "reused", "blocked", "failed", "uncertain")


def _text(value: Any, field: str, limit: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value or (not allow_empty and not value.strip()):
        raise EngineError("invalid_workflow_result", f"{field} must be a bounded string.")
    return redact(value.strip())


def _strings(value: Any, field: str, *, maximum: int = 100) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise EngineError("invalid_workflow_result", f"{field} must be an array with at most {maximum} items.")
    return [_text(item, f"{field} item", 4000) for item in value]


def _json_bytes(value: Any, field: str, limit: int) -> bytes:
    try:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EngineError("invalid_workflow_result", f"{field} must be finite JSON data.") from exc
    if len(payload) > limit:
        raise EngineError("invalid_workflow_result", f"{field} exceeds the {limit}-byte limit.")
    return payload


def _redact_json(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            name = str(key)
            if re.search(r"(?i)(?:api[_-]?key|token|secret|password|authorization)", name):
                result[name] = "<redacted>"
            else:
                result[name] = _redact_json(item)
        return result
    return value


def normalize_triage_intake(source_type: Any, input_id: Any, raw_input: Any) -> dict[str, Any]:
    if source_type not in TRIAGE_SOURCE_TYPES:
        raise EngineError("invalid_triage_source", "Unsupported triage source type.")
    if not isinstance(raw_input, dict):
        raise EngineError("invalid_triage_intake", "input must be an object.")
    sanitized_input = _redact_json(raw_input)
    _json_bytes(sanitized_input, "input", 200_000)
    return {
        "documentType": "kiro-security-power.triage-intake",
        "schemaVersion": "1.0",
        "sourceType": source_type,
        "inputId": _text(input_id, "inputId", 512),
        "untrustedSourceData": True,
        "input": sanitized_input,
    }


def normalize_triage_result(raw: Any, intake: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("inputId") != intake["inputId"]:
        raise EngineError("triage_subject_mismatch", "Triage result inputId must match the durable intake.")
    verdict = raw.get("verdict")
    confidence = raw.get("confidence")
    if verdict not in ("confirmed", "not_actionable", "needs_review") or confidence not in ("high", "medium", "low"):
        raise EngineError("invalid_triage_result", "Triage verdict or confidence is invalid.")
    boundary = raw.get("boundaryAssessment")
    rank = raw.get("exploitabilityStackRank")
    locations = raw.get("affectedLocations")
    if not isinstance(boundary, dict) or not isinstance(rank, dict) or not isinstance(locations, list) or len(locations) > 100:
        raise EngineError("invalid_triage_result", "Boundary, rank, and affected location proof are required.")
    crossed = boundary.get("boundaryCrossed")
    if crossed not in (True, False, None):
        raise EngineError("invalid_triage_result", "boundaryCrossed must be true, false, or null.")
    normalized_locations = []
    for item in locations:
        if not isinstance(item, dict):
            raise EngineError("invalid_triage_result", "Each affected location must be an object.")
        path = _text(item.get("path"), "affected location path", 4096)
        if path.startswith(("/", "\\")) or "\\" in path or any(part == ".." for part in path.split("/")):
            raise EngineError("invalid_triage_result", "Affected locations must be safe workspace-relative paths.")
        start = item.get("startLine")
        end = item.get("endLine", start)
        if isinstance(start, bool) or not isinstance(start, int) or isinstance(end, bool) or not isinstance(end, int) or start < 1 or end < start:
            raise EngineError("invalid_triage_result", "Affected location lines are invalid.")
        normalized_locations.append({
            "path": path, "startLine": start, "endLine": end,
            "role": _text(item.get("role"), "affected location role", 128),
            "detail": _text(item.get("detail"), "affected location detail", 4000),
        })
    rank_queue = rank.get("rankQueue")
    rank_value = rank.get("rank")
    reachable_path = _strings(raw.get("reachablePath"), "reachablePath")
    evidence = _strings(raw.get("evidence"), "evidence")
    counterevidence = _strings(raw.get("counterevidence"), "counterevidence")
    if verdict == "not_actionable":
        if rank_queue is not None or rank_value is not None:
            raise EngineError("invalid_triage_result", "not_actionable findings may not receive an exploitability rank.")
        if not evidence and not counterevidence:
            raise EngineError("invalid_triage_result", "not_actionable results require evidence or counterevidence.")
    elif rank_queue != verdict or isinstance(rank_value, bool) or not isinstance(rank_value, int) or rank_value < 1:
        raise EngineError("invalid_triage_result", "Exploitability rank must match the verdict queue.")
    if verdict in ("confirmed", "needs_review") and (
        not normalized_locations or not reachable_path or not evidence
    ):
        raise EngineError(
            "invalid_triage_result",
            "confirmed and needs_review results require locations, a reachable path, and evidence.",
        )
    if verdict == "confirmed" and crossed is None:
        raise EngineError("invalid_triage_result", "confirmed results require an explicit boundaryCrossed decision.")
    result = {
        "documentType": "kiro-security-power.triage-result",
        "schemaVersion": "1.0",
        "method": "static_repository_analysis",
        "inputId": intake["inputId"],
        "sourceType": intake["sourceType"],
        "verdict": verdict,
        "confidence": confidence,
        "rationale": _text(raw.get("rationale"), "rationale", 12000),
        "source": _text(raw.get("source"), "source", 4000),
        "control": _text(raw.get("control"), "control", 4000),
        "sink": _text(raw.get("sink"), "sink", 4000),
        "affectedLocations": normalized_locations,
        "reachablePath": reachable_path,
        "boundaryAssessment": {
            "productSurface": _text(boundary.get("productSurface"), "productSurface", 2000),
            "sourceTrust": _text(boundary.get("sourceTrust"), "sourceTrust", 2000),
            "boundaryCrossed": crossed,
            "policyBasis": _text(boundary.get("policyBasis"), "policyBasis", 4000),
        },
        "exploitabilityStackRank": {
            "rankQueue": rank_queue,
            "rank": rank_value,
            "rationale": _text(rank.get("rationale"), "rank rationale", 4000),
            "drivers": _strings(rank.get("drivers"), "rank drivers", maximum=20),
        },
        "evidence": evidence,
        "counterevidence": counterevidence,
        "proofGaps": _strings(raw.get("proofGaps"), "proofGaps"),
        "recommendedNextStep": _text(raw.get("recommendedNextStep"), "recommendedNextStep", 4000),
    }
    _json_bytes(result, "triage result", 500_000)
    return result


def _tracking_proof(raw: Any, provider: str, destination: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EngineError("invalid_tracking_proof", "trackingProof must be an object.")
    connector = raw.get("connector")
    duplicate = raw.get("duplicateSearch")
    if not isinstance(connector, dict) or not isinstance(duplicate, dict):
        raise EngineError("invalid_tracking_proof", "Connector and duplicate search proof are required.")
    if connector.get("provider") != provider:
        raise EngineError("invalid_tracking_proof", "Connector provider must match the handoff provider.")
    connector_host = _text(connector.get("host"), "connector host", 253).lower()
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", connector_host):
        raise EngineError("invalid_tracking_proof", "connector host must be a bounded DNS host.")
    if (
        (provider == "github" and connector_host != "github.com")
        or (provider == "linear" and connector_host != "linear.app")
        or (provider == "jira" and not connector_host.endswith(".atlassian.net"))
    ):
        raise EngineError("invalid_tracking_proof", "connector host does not match the selected provider.")
    visibility = raw.get("visibility")
    if visibility not in ("private", "internal", "public"):
        raise EngineError("invalid_tracking_proof", "visibility must be private, internal, or public.")
    audience = _strings(raw.get("audience"), "audience", maximum=20)
    if not audience:
        raise EngineError("invalid_tracking_proof", "audience must identify at least one approved audience.")
    duplicate_status = duplicate.get("status")
    if duplicate_status not in ("none", "existing"):
        raise EngineError("invalid_tracking_proof", "duplicateSearch.status must be none or existing.")
    duplicate_query = _text(duplicate.get("query"), "duplicate search query", 4000)
    candidates = _strings(duplicate.get("candidateIds") or [], "duplicate candidateIds", maximum=25)
    if duplicate_status == "existing" and not candidates:
        raise EngineError("invalid_tracking_proof", "An existing duplicate search result requires candidateIds.")
    if duplicate_status == "none" and candidates:
        raise EngineError("invalid_tracking_proof", "A duplicate search with status none may not list candidateIds.")
    parsed_destination = urlsplit(destination)
    if parsed_destination.scheme:
        if (
            parsed_destination.scheme != "https" or not parsed_destination.hostname
            or parsed_destination.username or parsed_destination.password
            or parsed_destination.hostname.lower() != connector_host
            or parsed_destination.query or parsed_destination.fragment
        ):
            raise EngineError(
                "invalid_tracking_proof",
                "URL destinations must be credential-free HTTPS on the connector host without query or fragment.",
            )
    proof = {
        "connector": {
            "provider": provider,
            "host": connector_host,
            "identity": _text(connector.get("identity"), "connector identity", 512),
        },
        "duplicateSearch": {
            "status": duplicate_status,
            "query": duplicate_query,
            "queryDigest": sha256_bytes(duplicate_query.encode("utf-8")),
            "candidateIds": candidates,
        },
        "destination": {
            "value": destination,
            "digest": sha256_bytes(destination.encode("utf-8")),
            "query": "",
            "fragment": "",
        },
        "visibility": visibility,
        "audience": audience,
        "audienceDigest": sha256_bytes(_json_bytes(audience, "audience", 20_000)),
    }
    return proof


def create_tracking_handoff(
    finding: dict[str, Any],
    *,
    provider: str,
    destination: str,
    output_path: Path | None,
    record_id: str,
    tracking_proof: Any,
    stable_link: str | None = None,
    source_seal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an approval-ready payload without performing an external write."""
    sink = next((item for item in finding.get("locations", []) if item.get("role") == "sink"), None)
    title = redact(f"[{finding['severity']['level'].upper()}] {finding['title']}")
    location = "unknown"
    if sink:
        location = f"{sink['path']}:{sink['startLine']}-{sink.get('endLine', sink['startLine'])}"
    body = redact("\n".join([
        finding["summary"], "", f"Finding ID: {finding['findingId']}",
        f"Fingerprint: {finding['fingerprint']}", f"Location: {location}", "",
        "Remediation:", str(finding.get("remediation") or "Not recorded."),
    ]))
    destination = _text(destination, "destination", 512)
    preview = {
        "title": title,
        "body": body,
        "metadata": {"severity": finding["severity"]["level"], "provider": provider, "destination": destination},
    }
    preview_digest = sha256_bytes(_json_bytes(preview, "tracking preview", 100_000))
    routing_proof = _tracking_proof(tracking_proof, provider, destination)
    payload = {
        "documentType": "KiroSecurityTrackingHandoff",
        "schemaVersion": "1.0",
        "status": "prepared",
        "recordId": record_id,
        "provider": provider,
        "destination": destination,
        "externalWritePerformed": False,
        "finding": {
            "findingId": finding["findingId"],
            "fingerprint": finding["fingerprint"],
            "occurrenceId": finding["occurrenceId"],
            "scanId": finding["scanId"],
            "stableLink": None if stable_link is None else redact(stable_link),
            "title": redact(finding["title"]),
            "summary": redact(finding["summary"]),
            "severity": finding["severity"],
            "confidence": finding["confidence"],
            "validationStatus": finding.get("validationStatus"),
            "triageStatus": finding.get("triageStatus"),
            "taxonomy": finding.get("taxonomy", {}),
            "location": sink,
            "remediation": None if finding.get("remediation") is None else redact(str(finding["remediation"])),
        },
        "sourceSeal": source_seal or {"status": "unavailable"},
        "writePreview": {
            **preview,
            "titleDigest": sha256_bytes(title.encode("utf-8")),
            "bodyDigest": sha256_bytes(body.encode("utf-8")),
            "previewDigest": preview_digest,
        },
        "routingProof": routing_proof,
        "approvalRequired": True,
        "instructions": (
            "Review this payload, check for an existing external issue, obtain approval, and use an explicitly "
            "configured connector to create or update the tracking item. Kiro Security Power did not contact an external service."
        ),
    }
    if output_path is not None:
        write_json(output_path, payload)
    return payload


def normalize_tracking_readback(raw: Any, handoff: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("outcome") not in TRACKING_OUTCOMES:
        raise EngineError("invalid_tracking_result", "Tracking result outcome is invalid.")
    outcome = raw["outcome"]
    external_id = raw.get("externalId")
    external_url = raw.get("externalUrl")
    readback = raw.get("readback")
    mutation = raw.get("externalMutationPerformed")
    if not isinstance(mutation, bool):
        raise EngineError("invalid_tracking_result", "externalMutationPerformed must be explicit.")
    verified_outcome = outcome in ("created", "updated", "reused")
    if handoff["provider"] == "manual" and verified_outcome:
        raise EngineError("invalid_tracking_result", "Manual handoffs cannot assert a verified provider outcome.")
    if verified_outcome:
        approval = raw.get("approval")
        if not isinstance(approval, dict) or approval.get("approved") is not True:
            raise EngineError("invalid_tracking_result", "Verified outcomes require explicit exact-preview approval.")
        approval_proof = {
            "approved": True,
            "approvedPreviewDigest": _text(
                approval.get("approvedPreviewDigest"), "approvedPreviewDigest", 64
            ),
            "approvedPayloadSha256": _text(
                approval.get("approvedPayloadSha256"), "approvedPayloadSha256", 64
            ),
            "approvedBy": _text(approval.get("approvedBy"), "approvedBy", 512),
            "approvedAt": _text(approval.get("approvedAt"), "approvedAt", 128),
            "scope": _text(approval.get("scope"), "approval scope", 2000),
        }
        if approval_proof["approvedPreviewDigest"] != handoff["writePreview"]["previewDigest"]:
            raise EngineError("tracking_readback_mismatch", "Approval does not bind the exact durable preview.")
        if approval_proof["approvedPayloadSha256"] != raw.get("payloadSha256"):
            raise EngineError("tracking_readback_mismatch", "Approval does not bind the complete durable handoff.")
        approval_digest = sha256_bytes(_json_bytes(approval_proof, "approval proof", 20_000))
        external_id = _text(external_id, "externalId", 512)
        duplicate = handoff["routingProof"]["duplicateSearch"]
        if outcome == "created" and duplicate["status"] != "none":
            raise EngineError("tracking_readback_mismatch", "A created item requires duplicateSearch.status=none.")
        if outcome in ("reused", "updated") and (
            duplicate["status"] != "existing" or external_id not in duplicate["candidateIds"]
        ):
            raise EngineError(
                "tracking_readback_mismatch",
                "A reused or updated item must match an existing duplicate-search candidate.",
            )
        external_url = _text(external_url, "externalUrl", 4096)
        parsed = urlsplit(external_url)
        if (
            parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password
            or parsed.query or parsed.fragment
        ):
            raise EngineError(
                "invalid_tracking_result",
                "externalUrl must be canonical credential-free HTTPS without query or fragment.",
            )
        if not isinstance(readback, dict):
            raise EngineError("invalid_tracking_result", "Verified connector outcomes require sanitized readback proof.")
        preview = handoff["writePreview"]
        expected = {
            "bindingFindingId": handoff["finding"]["findingId"],
            "bindingFingerprint": handoff["finding"]["fingerprint"],
            "externalId": external_id,
            "externalUrl": external_url,
            "titleDigest": preview["titleDigest"],
            "bodyDigest": preview["bodyDigest"],
            "previewDigest": preview["previewDigest"],
            "approvalDigest": approval_digest,
            "connectorHost": handoff["routingProof"]["connector"]["host"],
            "duplicateQueryDigest": handoff["routingProof"]["duplicateSearch"]["queryDigest"],
            "destinationDigest": handoff["routingProof"]["destination"]["digest"],
            "visibility": handoff["routingProof"]["visibility"],
            "audienceDigest": handoff["routingProof"]["audienceDigest"],
        }
        if any(readback.get(key) != value for key, value in expected.items()):
            raise EngineError("tracking_readback_mismatch", "Connector readback does not match the approved finding payload.")
        destination = handoff["routingProof"]["destination"]
        if (
            parsed.hostname is None or parsed.hostname.lower() != expected["connectorHost"]
            or parsed.query != destination["query"] or parsed.fragment != destination["fragment"]
        ):
            raise EngineError("tracking_readback_mismatch", "Connector host, query, or fragment changed after approval.")
        if outcome == "reused" and mutation:
            raise EngineError("invalid_tracking_result", "A reused item must not claim an external mutation.")
        if outcome in ("created", "updated") and not mutation:
            raise EngineError("invalid_tracking_result", "Created or updated outcomes must report the approved mutation.")
    elif outcome in ("blocked", "failed", "uncertain") and mutation:
        raise EngineError("invalid_tracking_result", "Non-verified outcomes may not claim an external mutation.")
    result = {
        "documentType": "kiro-security-power.tracking-readback",
        "schemaVersion": "1.0",
        "recordId": _text(raw.get("recordId"), "recordId", 256),
        "provider": handoff["provider"],
        "destination": handoff["destination"],
        "payloadSha256": _text(raw.get("payloadSha256"), "payloadSha256", 64),
        "outcome": outcome,
        "externalMutationPerformed": mutation,
        "externalId": external_id if verified_outcome else None,
        "externalUrl": external_url if verified_outcome else None,
        "readbackVerified": verified_outcome,
        "readback": None if not verified_outcome else {key: readback[key] for key in expected},
        "approval": None if not verified_outcome else {**approval_proof, "approvalDigest": approval_digest},
        "reason": _text(raw.get("reason") or ("Connector readback matched the approved payload." if verified_outcome else "External tracking did not complete."), "reason", 4000),
    }
    _json_bytes(result, "tracking readback", 100_000)
    return result
