"""Pure descriptor schemas and payload validation for semantic artifacts."""

import hashlib
import re

from .artifacts import ArtifactContractError, canonical_json_bytes
from .errors import WorkbenchError


BASE_DESCRIPTORS = (
    "brief",
    "threat-model",
    "discovery",
    "validation",
    "attack-path",
    "coverage",
    "canonical-result",
    "derived-writeup",
    "derived-hardening",
)
DEEP_WORKERS_PER_ROUND = 4
DEEP_WORKER_SCHEMA_KEY = "discovery-round-<1..10>-worker-<1..4>"
DEEP_CHECKPOINT_SCHEMA_KEY = (
    "discovery-round-<1..10>-worker-<1..4>-checkpoint"
)
DEEP_WORKER_RE = re.compile(
    r"^discovery-round-(10|[1-9])-worker-([1-%d])$" % DEEP_WORKERS_PER_ROUND
)
DEEP_CHECKPOINT_RE = re.compile(
    r"^discovery-round-(10|[1-9])-worker-([1-%d])-checkpoint$"
    % DEEP_WORKERS_PER_ROUND
)
DEEP_MERGE_RE = re.compile(r"^discovery-round-(10|[1-9])-merge$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


def descriptor_schemas(mode):
    common = {
        "brief": (
            _deep_brief_schema()
            if mode == "deep"
            else _schema(("scanId", "mode", "target", "scope"))
        ),
        "threat-model": _schema(("scanId", "summary")),
        "discovery": _schema(
            (
                "scanId",
                "candidates",
                "roundsCompleted",
                "termination",
            )
            if mode == "deep"
            else ("scanId", "candidates")
        ),
        "validation": _schema(("scanId", "results")),
        "attack-path": _schema(("scanId", "results")),
        "coverage": _schema(
            (
                "documentType",
                "schemaVersion",
                "scanId",
                "mode",
                "completeness",
                "inventoryStrategy",
                "includePaths",
                "excludePaths",
                "surfaces",
                "deferred",
            )
        ),
        "canonical-result": _schema(("scanId", "manifest", "findings")),
        "derived-writeup": _schema(("scanId", "outputs")),
        "derived-hardening": _schema(("scanId", "outputs")),
    }
    if mode == "deep":
        common[DEEP_WORKER_SCHEMA_KEY] = _deep_worker_schema()
        common[DEEP_CHECKPOINT_SCHEMA_KEY] = _deep_checkpoint_schema()
        common["discovery-round-<1..10>-merge"] = _deep_merge_schema()
    return common


def validate_content(scan, descriptor, content):
    if not isinstance(content, dict):
        raise WorkbenchError("invalid_artifact", "Artifact content must be an object.")
    if content.get("scanId") != scan["id"]:
        raise WorkbenchError(
            "artifact_scan_mismatch",
            "Artifact scanId must match the authoritative scan.",
        )
    schema_key = descriptor_schema_key(descriptor)
    schema = descriptor_schemas(scan["mode"])[schema_key]
    missing = [key for key in schema["required"] if key not in content]
    if missing:
        raise WorkbenchError(
            "invalid_artifact",
            "Artifact is missing required fields: %s." % ", ".join(missing),
        )
    if descriptor == "canonical-result":
        if not isinstance(content.get("manifest"), dict) or not isinstance(
            content.get("findings"),
            dict,
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "canonical-result requires manifest and findings objects.",
            )
    if descriptor == "brief" and scan["mode"] == "deep":
        worklist_ids(content.get("worklist"))
    if descriptor == "coverage":
        surfaces = content.get("surfaces")
        if not isinstance(surfaces, list):
            raise WorkbenchError(
                "invalid_artifact",
                "coverage.surfaces must be an array.",
            )
        for surface in surfaces:
            if not isinstance(surface, dict) or not isinstance(
                surface.get("receipt"),
                dict,
            ):
                raise WorkbenchError(
                    "invalid_artifact",
                    "Every coverage surface requires an embedded receipt object.",
                )
            receipt = surface["receipt"]
            if receipt.get("closed") is not True or not isinstance(
                receipt.get("reviewedPaths"),
                list,
            ):
                raise WorkbenchError(
                    "invalid_artifact",
                    "Every coverage receipt must be closed and list reviewedPaths.",
                )
    if descriptor == "discovery":
        record_ids(content.get("candidates"), "discovery.candidates")
    if descriptor == "validation":
        record_ids(
            content.get("results"),
            "validation.results",
            key="candidateId",
        )
    if descriptor == "attack-path":
        record_ids(
            content.get("results"),
            "attack-path.results",
            key="candidateId",
        )
    worker_match = DEEP_WORKER_RE.fullmatch(descriptor)
    if worker_match and (
        content.get("round") != int(worker_match.group(1))
        or content.get("worker") != int(worker_match.group(2))
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep worker payload round/worker must match its descriptor.",
        )
    if worker_match and (
        not isinstance(content.get("inputDigest"), str)
        or not DIGEST_RE.fullmatch(content["inputDigest"])
        or not isinstance(content.get("threatModel"), dict)
        or not isinstance(content.get("candidates"), list)
        or not isinstance(content.get("coverage"), dict)
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep worker payload requires an input digest, threatModel, candidates, "
            "and coverage.",
        )
    if worker_match:
        _validate_deep_threat_model(content["threatModel"])
        record_ids(content.get("candidates"), "worker.candidates")
        coverage = content["coverage"]
        if (
            coverage.get("closed") is not True
            or not isinstance(coverage.get("worklistDigest"), str)
            or not DIGEST_RE.fullmatch(coverage["worklistDigest"])
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep worker coverage must be closed and include its worklist digest.",
            )
        coverage_receipts(coverage.get("receipts"))
    checkpoint_match = DEEP_CHECKPOINT_RE.fullmatch(descriptor)
    if checkpoint_match and (
        isinstance(content.get("round"), bool)
        or not isinstance(content.get("round"), int)
        or content.get("round") != int(checkpoint_match.group(1))
        or isinstance(content.get("worker"), bool)
        or not isinstance(content.get("worker"), int)
        or content.get("worker") != int(checkpoint_match.group(2))
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint payload round/worker must match its descriptor.",
        )
    if checkpoint_match:
        validate_deep_checkpoint(content)
    merge_match = DEEP_MERGE_RE.fullmatch(descriptor)
    if merge_match and content.get("round") != int(merge_match.group(1)):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep merge payload round must match its descriptor.",
        )
    if merge_match and (
        not isinstance(content.get("mergedCandidateIds"), list)
        or not isinstance(content.get("lineage"), list)
        or isinstance(content.get("newCanonicalCandidateCount"), bool)
        or not isinstance(content.get("newCanonicalCandidateCount"), int)
        or content["newCanonicalCandidateCount"] < 0
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep merge payload requires candidate ids and a non-negative novelty count.",
        )
    if merge_match:
        string_ids(
            content.get("mergedCandidateIds"),
            "merge.mergedCandidateIds",
        )
    if descriptor in ("derived-writeup", "derived-hardening"):
        outputs = content.get("outputs")
        if not isinstance(outputs, list):
            raise WorkbenchError(
                "invalid_artifact",
                "%s.outputs must be an array." % descriptor,
            )
        output_paths = set()
        for output in outputs:
            if (
                not isinstance(output, dict)
                or not isinstance(output.get("path"), str)
                or not isinstance(output.get("markdown"), str)
            ):
                raise WorkbenchError(
                    "invalid_artifact",
                    "%s outputs require path and markdown strings." % descriptor,
                )
            if output["path"] in output_paths:
                raise WorkbenchError(
                    "invalid_artifact",
                    "%s output paths must be unique." % descriptor,
                )
            output_paths.add(output["path"])
    try:
        canonical_json_bytes(content)
    except ArtifactContractError as exc:
        raise WorkbenchError("invalid_artifact", str(exc))


def record_ids(value, context, key="id"):
    if not isinstance(value, list):
        raise WorkbenchError(
            "invalid_artifact",
            "%s must be an array." % context,
        )
    result = set()
    for index, item in enumerate(value):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get(key), str)
            or not item[key].strip()
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "%s[%d].%s must be a non-empty string."
                % (context, index, key),
            )
        if item[key] in result:
            raise WorkbenchError(
                "invalid_artifact",
                "%s contains duplicate %s values." % (context, key),
            )
        result.add(item[key])
    return result


def worklist_ids(value):
    if not isinstance(value, list) or not value:
        raise WorkbenchError(
            "invalid_artifact",
            "Deep brief worklist must be a non-empty array.",
        )
    result = set()
    for index, item in enumerate(value):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str)
            or not item["id"].strip()
            or not isinstance(item.get("path"), str)
            or not item["path"].strip()
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep brief worklist[%d] requires non-empty id and path strings."
                % index,
            )
        if item["id"] in result:
            raise WorkbenchError(
                "invalid_artifact",
                "Deep brief worklist contains duplicate ids.",
            )
        result.add(item["id"])
    return result


def validate_deep_checkpoint(content):
    attempt = content.get("attempt")
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint attempt must be a positive integer.",
        )
    for key in ("inputDigest", "worklistDigest"):
        value = content.get(key)
        if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep checkpoint %s must be a SHA-256 digest." % key,
            )
    status = content.get("status")
    if status not in ("in_progress", "failed"):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint status must be in_progress or failed.",
        )
    failure = content.get("failure")
    if status == "failed" and (
        not isinstance(failure, str) or not failure.strip()
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "A failed Deep checkpoint requires a failure description.",
        )
    if status == "in_progress" and failure is not None:
        raise WorkbenchError(
            "invalid_artifact",
            "An in-progress Deep checkpoint cannot report a failure.",
        )
    partial = content.get("partial")
    if not isinstance(partial, dict) or not partial:
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint partial must contain worker progress.",
        )
    allowed = {"threatModel", "candidates", "coverage"}
    if set(partial) - allowed:
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint partial contains unsupported fields.",
        )
    threat_model = partial.get("threatModel")
    if threat_model is not None:
        _validate_partial_deep_threat_model(threat_model)
    if "candidates" in partial:
        record_ids(partial["candidates"], "checkpoint.partial.candidates")
    coverage = partial.get("coverage")
    if coverage is not None:
        if not isinstance(coverage, dict) or not isinstance(
            coverage.get("receipts"),
            list,
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep checkpoint partial coverage requires a receipts array.",
            )
        if "closed" in coverage and not isinstance(coverage["closed"], bool):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep checkpoint partial coverage.closed must be boolean.",
            )
        coverage_receipts(coverage["receipts"])


def coverage_receipts(value):
    if not isinstance(value, list):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep worker coverage.receipts must be an array.",
        )
    result = {}
    for index, item in enumerate(value):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("worklistId"), str)
            or not item["worklistId"].strip()
            or item.get("disposition") not in ("reviewed", "deferred")
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "Deep coverage receipt %d requires worklistId and disposition."
                % index,
            )
        worklist_id = item["worklistId"]
        if worklist_id in result:
            raise WorkbenchError(
                "invalid_artifact",
                "Deep coverage receipts contain duplicate worklist ids.",
            )
        if item["disposition"] == "reviewed":
            _nonempty_string_list(
                item.get("evidence"),
                "worker.coverage.receipts[%d].evidence" % index,
            )
        elif not isinstance(item.get("reason"), str) or not item["reason"].strip():
            raise WorkbenchError(
                "invalid_artifact",
                "Deferred Deep coverage receipts require a non-empty reason.",
            )
        result[worklist_id] = item
    return result


def canonical_digest(value):
    try:
        encoded = canonical_json_bytes(value)
    except ArtifactContractError as exc:
        raise WorkbenchError("invalid_artifact", str(exc))
    return hashlib.sha256(encoded).hexdigest()


def string_ids(value, context):
    if not isinstance(value, list):
        raise WorkbenchError(
            "invalid_artifact",
            "%s must be an array." % context,
        )
    result = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise WorkbenchError(
                "invalid_artifact",
                "%s[%d] must be a non-empty string." % (context, index),
            )
        if item in result:
            raise WorkbenchError(
                "invalid_artifact",
                "%s contains duplicate values." % context,
            )
        result.add(item)
    return result


def deep_worker_descriptor(round_number, worker_number):
    return "discovery-round-%d-worker-%d" % (round_number, worker_number)


def deep_merge_descriptor(round_number):
    return "discovery-round-%d-merge" % round_number


def has_deep_artifact_after(present, round_number):
    for descriptor in present:
        worker_match = DEEP_WORKER_RE.fullmatch(descriptor)
        merge_match = DEEP_MERGE_RE.fullmatch(descriptor)
        if worker_match and int(worker_match.group(1)) > round_number:
            return True
        if merge_match and int(merge_match.group(1)) > round_number:
            return True
    return False


def canonical_findings(canonical):
    findings = canonical.get("findings", {}).get("findings")
    if not isinstance(findings, list):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical findings must contain a findings array.",
        )
    return findings


def coverage_mode(scan):
    if scan["mode"] == "deep":
        return "deep_repository"
    if scan["mode"] == "standard":
        return "repository" if scan["scope"] == "." else "scoped_path"
    kind = scan["diff_target_kind"]
    return {
        "working_tree": "working_tree",
        "commit": "commit",
        "range": "branch_diff",
    }[kind]


def require_descriptor(value, mode):
    if not isinstance(value, str):
        raise WorkbenchError(
            "invalid_artifact_descriptor",
            "Artifact descriptor must be a string.",
        )
    if value in BASE_DESCRIPTORS:
        return value
    if mode == "deep" and (
        DEEP_WORKER_RE.fullmatch(value)
        or DEEP_CHECKPOINT_RE.fullmatch(value)
        or DEEP_MERGE_RE.fullmatch(value)
    ):
        return value
    raise WorkbenchError(
        "invalid_artifact_descriptor",
        "Artifact descriptor is not allowed for this scan.",
    )


def descriptor_schema_key(descriptor):
    if DEEP_WORKER_RE.fullmatch(descriptor):
        return DEEP_WORKER_SCHEMA_KEY
    if DEEP_CHECKPOINT_RE.fullmatch(descriptor):
        return DEEP_CHECKPOINT_SCHEMA_KEY
    if DEEP_MERGE_RE.fullmatch(descriptor):
        return "discovery-round-<1..10>-merge"
    return descriptor


def _schema(required):
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": True,
    }


def _deep_brief_schema():
    schema = _schema(("scanId", "mode", "target", "scope", "worklist"))
    schema["properties"] = {
        "worklist": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["id", "path"],
                "additionalProperties": True,
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "path": {"type": "string", "minLength": 1},
                },
            },
        }
    }
    return schema


def _deep_worker_schema():
    schema = _schema(
        (
            "scanId",
            "round",
            "worker",
            "inputDigest",
            "threatModel",
            "candidates",
            "coverage",
        )
    )
    schema["properties"] = {
        "inputDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "threatModel": {
            "type": "object",
            "required": [
                "summary",
                "assets",
                "trustBoundaries",
                "attackerCapabilities",
                "securityInvariants",
                "evidence",
            ],
        },
        "coverage": {
            "type": "object",
            "required": ["closed", "worklistDigest", "receipts"],
            "properties": {
                "closed": {"const": True},
                "worklistDigest": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$",
                },
                "receipts": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["worklistId", "disposition"],
                    },
                },
            },
        },
    }
    return schema


def _deep_checkpoint_schema():
    schema = _schema(
        (
            "scanId",
            "round",
            "worker",
            "attempt",
            "inputDigest",
            "worklistDigest",
            "status",
            "partial",
        )
    )
    schema["properties"] = {
        "attempt": {"type": "integer", "minimum": 1},
        "inputDigest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "worklistDigest": {
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
        },
        "status": {"enum": ["in_progress", "failed"]},
        "partial": {
            "type": "object",
            "properties": {
                "threatModel": {"type": "object"},
                "candidates": {"type": "array"},
                "coverage": {"type": "object"},
            },
        },
    }
    return schema


def _deep_merge_schema():
    schema = _schema(
        (
            "scanId",
            "round",
            "mergedCandidateIds",
            "newCanonicalCandidateCount",
            "lineage",
        )
    )
    schema["properties"] = {
        "lineage": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["worker", "candidateId", "canonicalCandidateId"],
            },
        }
    }
    return schema


def _validate_deep_threat_model(value):
    if not isinstance(value.get("summary"), str) or not value["summary"].strip():
        raise WorkbenchError(
            "invalid_artifact",
            "Deep worker threatModel requires a non-empty summary.",
        )
    for key in (
        "assets",
        "trustBoundaries",
        "attackerCapabilities",
        "securityInvariants",
        "evidence",
    ):
        _nonempty_string_list(value.get(key), "worker.threatModel.%s" % key)


def _validate_partial_deep_threat_model(value):
    if not isinstance(value, dict) or not value:
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint threatModel must contain partial worker progress.",
        )
    known = {
        "summary",
        "assets",
        "trustBoundaries",
        "attackerCapabilities",
        "securityInvariants",
        "evidence",
    }
    if not set(value).intersection(known):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint threatModel requires a recognized field.",
        )
    if "summary" in value and (
        not isinstance(value["summary"], str) or not value["summary"].strip()
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep checkpoint threatModel.summary must be non-empty.",
        )
    for key in known - {"summary"}:
        if key in value:
            _nonempty_string_list(
                value[key],
                "checkpoint.partial.threatModel.%s" % key,
            )


def _nonempty_string_list(value, context):
    if not isinstance(value, list) or not value:
        raise WorkbenchError(
            "invalid_artifact",
            "%s must be a non-empty string array." % context,
        )
    seen = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise WorkbenchError(
                "invalid_artifact",
                "%s[%d] must be a non-empty string." % (context, index),
            )
        if item in seen:
            raise WorkbenchError(
                "invalid_artifact",
                "%s contains duplicate values." % context,
            )
        seen.add(item)
    return value
