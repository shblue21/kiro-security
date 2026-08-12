"""Pure descriptor schemas and payload validation for semantic artifacts."""

import hashlib
import re

from .artifacts import (
    COMPLETENESS,
    CONFIDENCES,
    DISPOSITIONS,
    INVENTORY_STRATEGIES,
    REPORTABLE_SEVERITIES,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    ArtifactContractError,
    canonical_json_bytes,
    validate_finding_authoring,
)
from .errors import WorkbenchError
from .scan_files import validate_scan_relative_path


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
VALIDATION_INSTANCE_DISPOSITIONS = frozenset(
    ("survived", "suppressed", "uncertain")
)
ATTACK_PATH_INSTANCE_DISPOSITIONS = frozenset(
    ("reportable", "ignored", "deferred")
)


def descriptor_schemas(scan):
    mode = scan["mode"]
    common = {
        "brief": _brief_schema(scan),
        "threat-model": _threat_model_schema(),
        "discovery": _schema(
            (
                "scanId",
                "candidates",
                "roundsCompleted",
                "termination",
            )
            if mode == "deep"
            else ("scanId", "candidates"),
            {"candidates": _record_array_schema("id")},
        ),
        "validation": _schema(
            ("scanId", "results"),
            {
                "results": _phase_result_array_schema(
                    VALIDATION_INSTANCE_DISPOSITIONS
                )
            },
        ),
        "attack-path": _schema(
            ("scanId", "results"),
            {
                "results": _phase_result_array_schema(
                    ATTACK_PATH_INSTANCE_DISPOSITIONS
                )
            },
        ),
        "coverage": _coverage_schema(scan),
        "canonical-result": _canonical_schema(),
        "derived-writeup": _derived_schema("derived-writeup"),
        "derived-hardening": _derived_schema("derived-hardening"),
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
    schema = descriptor_schemas(scan)[schema_key]
    missing = [key for key in schema["required"] if key not in content]
    if missing:
        raise WorkbenchError(
            "invalid_artifact",
            "Artifact is missing required fields: %s." % ", ".join(missing),
        )
    if descriptor == "canonical-result":
        _validate_canonical_result(content)
    if descriptor == "brief":
        _validate_brief(scan, content)
    if descriptor == "threat-model":
        _validate_threat_model(content)
    if descriptor == "coverage":
        _validate_coverage(scan, content)
    if descriptor == "discovery":
        record_ids(content.get("candidates"), "discovery.candidates")
    if descriptor == "validation":
        phase_result_instances(
            content.get("results"),
            "validation.results",
            VALIDATION_INSTANCE_DISPOSITIONS,
        )
    if descriptor == "attack-path":
        phase_result_instances(
            content.get("results"),
            "attack-path.results",
            ATTACK_PATH_INSTANCE_DISPOSITIONS,
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
                or not output["path"].strip()
                or not output["markdown"].strip()
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


def _validate_canonical_result(content):
    manifest = content.get("manifest")
    findings = content.get("findings")
    if not isinstance(manifest, dict) or not isinstance(findings, dict):
        raise WorkbenchError(
            "invalid_artifact",
            "canonical-result requires manifest and findings objects.",
        )
    if not isinstance(manifest.get("scan"), dict):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical manifest requires a scan object.",
        )
    seen = set()
    bindings = set()
    for index, finding in enumerate(canonical_findings(content)):
        context = "findings.findings[%d]" % index
        required_sections = ["rootCause", "validation", "attackPath"]
        if finding.get("severity", {}).get("level") in REPORTABLE_SEVERITIES:
            required_sections.append("writeup")
        for key in required_sections:
            if key not in finding:
                raise WorkbenchError(
                    "invalid_canonical_result",
                    "%s.%s is required." % (context, key),
                )
        root_cause = finding["rootCause"]
        if not isinstance(root_cause, (dict, str)) or (
            isinstance(root_cause, str) and not root_cause.strip()
        ):
            raise WorkbenchError(
                "invalid_canonical_result",
                "%s.rootCause must be a non-empty string or object." % context,
            )
        for key in ("validation", "attackPath"):
            if not isinstance(finding[key], dict):
                raise WorkbenchError(
                    "invalid_canonical_result",
                    "%s.%s must be an object." % (context, key),
                )
        if "writeup" in finding and not isinstance(finding["writeup"], dict):
            raise WorkbenchError(
                "invalid_canonical_result",
                "%s.writeup must be an object." % context,
            )
        extensions = finding.get("extensions")
        if not isinstance(extensions, dict):
            raise WorkbenchError(
                "invalid_canonical_result",
                "%s.extensions must be an object." % context,
            )
        candidate_id = extensions.get("candidateId")
        instance_id = extensions.get("candidateInstanceId")
        if (
            not isinstance(candidate_id, str)
            or not candidate_id.strip()
            or not isinstance(instance_id, str)
            or not instance_id.strip()
        ):
            raise WorkbenchError(
                "invalid_canonical_result",
                "%s.extensions requires candidateId and candidateInstanceId."
                % context,
            )
        binding = (candidate_id, instance_id)
        if binding in bindings:
            raise WorkbenchError(
                "invalid_canonical_result",
                "Canonical findings contain duplicate candidate instance bindings.",
            )
        bindings.add(binding)
        try:
            identity = validate_finding_authoring(finding, context)
        except ArtifactContractError as exc:
            raise WorkbenchError("invalid_canonical_result", str(exc)) from exc
        if identity.fingerprint in seen:
            raise WorkbenchError(
                "invalid_canonical_result",
                "Canonical findings contain duplicate logical identities.",
            )
        seen.add(identity.fingerprint)


def _validate_coverage(scan, content):
    if content.get("documentType", "codex-security.coverage") != (
        "codex-security.coverage"
    ):
        _invalid("coverage.documentType must be codex-security.coverage.")
    if content.get("schemaVersion", SCHEMA_VERSION) != SCHEMA_VERSION:
        _invalid("coverage.schemaVersion must be %s." % SCHEMA_VERSION)
    if content.get("mode") != coverage_mode(scan):
        _invalid("coverage.mode must match the authoritative scan mode.")
    if content.get("completeness") not in COMPLETENESS:
        _invalid("coverage.completeness is unsupported.")
    if content.get("inventoryStrategy") not in INVENTORY_STRATEGIES:
        _invalid("coverage.inventoryStrategy is unsupported.")
    include_paths = _string_array(content.get("includePaths"), "coverage.includePaths")
    exclude_paths = _string_array(content.get("excludePaths"), "coverage.excludePaths")
    if include_paths != [scan["scope"]]:
        _invalid("coverage.includePaths must match the authoritative scan scope.")
    for context, paths in (
        ("coverage.includePaths", include_paths),
        ("coverage.excludePaths", exclude_paths),
    ):
        for index, path in enumerate(paths):
            _validate_relative(path, "%s[%d]" % (context, index), allow_dot=True)

    surfaces = content.get("surfaces")
    if not isinstance(surfaces, list):
        _invalid("coverage.surfaces must be an array.")
    surface_ids = set()
    receipt_slugs = set()
    needs_follow_up = False
    for index, surface in enumerate(surfaces):
        context = "coverage.surfaces[%d]" % index
        if not isinstance(surface, dict):
            _invalid("%s must be an object." % context)
        surface_id = _nonempty_string(surface.get("id"), "%s.id" % context)
        _nonempty_string(surface.get("label"), "%s.label" % context)
        if surface_id in surface_ids:
            _invalid("%s.id is duplicated." % context)
        surface_ids.add(surface_id)
        slug = re.sub(r"[^a-z0-9._-]+", "-", surface_id.lower()).strip("-")
        if not slug or slug in receipt_slugs:
            _invalid("Coverage surface ids must produce unique safe receipt names.")
        receipt_slugs.add(slug)
        disposition = surface.get("disposition")
        if disposition not in DISPOSITIONS:
            _invalid("%s.disposition is unsupported." % context)
        needs_follow_up = needs_follow_up or disposition == "needs_follow_up"
        for key in ("riskArea", "notes"):
            if key in surface:
                _nonempty_string(surface[key], "%s.%s" % (context, key))
        receipt = surface.get("receipt")
        if not isinstance(receipt, dict):
            _invalid("%s.receipt must be an object." % context)
        if receipt.get("closed") is not True:
            _invalid("%s.receipt.closed must be true." % context)
        reviewed = _string_array(
            receipt.get("reviewedPaths"),
            "%s.receipt.reviewedPaths" % context,
        )
        for path_index, path in enumerate(reviewed):
            _validate_relative(
                path,
                "%s.receipt.reviewedPaths[%d]" % (context, path_index),
            )

    exclusions = content.get("explicitExclusions")
    if not isinstance(exclusions, list):
        _invalid("coverage.explicitExclusions must be an array.")
    for index, exclusion in enumerate(exclusions):
        context = "coverage.explicitExclusions[%d]" % index
        if not isinstance(exclusion, dict):
            _invalid("%s must be an object." % context)
        _nonempty_string(exclusion.get("pattern"), "%s.pattern" % context)
        _nonempty_string(exclusion.get("reason"), "%s.reason" % context)

    deferred = content.get("deferred")
    if not isinstance(deferred, list):
        _invalid("coverage.deferred must be an array.")
    for index, item in enumerate(deferred):
        context = "coverage.deferred[%d]" % index
        if not isinstance(item, dict):
            _invalid("%s must be an object." % context)
        _nonempty_string(item.get("id"), "%s.id" % context)
        _nonempty_string(item.get("reason"), "%s.reason" % context)
        if "paths" in item:
            for path_index, path in enumerate(
                _string_array(item["paths"], "%s.paths" % context)
            ):
                _validate_relative(path, "%s.paths[%d]" % (context, path_index))
        if "surfaceIds" in item:
            _string_array(item["surfaceIds"], "%s.surfaceIds" % context)
    if content["completeness"] == "complete" and (
        needs_follow_up or deferred
    ):
        _invalid("Complete coverage cannot contain deferred work.")

    questions = content.get("openQuestions", [])
    if not isinstance(questions, list):
        _invalid("coverage.openQuestions must be an array.")
    for index, question in enumerate(questions):
        context = "coverage.openQuestions[%d]" % index
        if not isinstance(question, dict):
            _invalid("%s must be an object." % context)
        _nonempty_string(question.get("question"), "%s.question" % context)
        if "followUpPrompt" in question:
            _nonempty_string(
                question["followUpPrompt"],
                "%s.followUpPrompt" % context,
            )


def _string_array(value, context):
    if not isinstance(value, list):
        _invalid("%s must be an array." % context)
    for index, item in enumerate(value):
        _nonempty_string(item, "%s[%d]" % (context, index))
    return value


def _nonempty_string(value, context):
    if not isinstance(value, str) or not value.strip():
        _invalid("%s must be a non-empty string." % context)
    return value


def _validate_relative(value, context, allow_dot=False):
    try:
        validate_scan_relative_path(value, context, allow_dot=allow_dot)
    except ArtifactContractError as exc:
        raise WorkbenchError("invalid_artifact", str(exc)) from exc


def _invalid(message):
    raise WorkbenchError("invalid_artifact", message)


def _validate_brief(scan, content):
    if (
        content.get("mode") != scan["mode"]
        or content.get("target") != scan["target_path"]
        or content.get("scope") != scan["scope"]
    ):
        raise WorkbenchError(
            "brief_scan_mismatch",
            "Brief mode, target, and scope must match the authoritative scan.",
        )
    status = content.get("status")
    if status not in ("ready", "blocked", "incomplete"):
        _invalid("brief.status must be ready, blocked, or incomplete.")
    capabilities = content.get("capabilities")
    if not isinstance(capabilities, dict) or not isinstance(
        capabilities.get("sourceInspection"),
        bool,
    ):
        _invalid("brief.capabilities.sourceInspection must be a boolean.")
    if status == "ready" and capabilities["sourceInspection"] is not True:
        _invalid("A ready brief requires sourceInspection to be true.")
    if scan["mode"] == "deep":
        worklist_ids(content.get("worklist"))


def _validate_threat_model(content):
    _nonempty_string(content.get("summary"), "threat-model.summary")
    for key in (
        "assets",
        "trustBoundaries",
        "attackerCapabilities",
        "securityObjectives",
        "assumptions",
    ):
        if key not in content:
            continue
        value = content[key]
        if not isinstance(value, list):
            _invalid("threat-model.%s must be an array." % key)
        for index, item in enumerate(value):
            context = "threat-model.%s[%d]" % (key, index)
            if isinstance(item, str):
                _nonempty_string(item, context)
                continue
            if not isinstance(item, dict):
                _invalid("%s must be a non-empty string or named object." % context)
            _nonempty_string(item.get("name"), "%s.name" % context)
            for field in ("sensitivity", "description"):
                if field in item:
                    _nonempty_string(item[field], "%s.%s" % (context, field))


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


def phase_result_instances(value, context, allowed_dispositions):
    if not isinstance(value, list):
        raise WorkbenchError(
            "invalid_artifact",
            "%s must be an array." % context,
        )
    result = {}
    for result_index, item in enumerate(value):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("candidateId"), str)
            or not item["candidateId"].strip()
        ):
            raise WorkbenchError(
                "invalid_artifact",
                "%s[%d].candidateId must be a non-empty string."
                % (context, result_index),
            )
        candidate_id = item["candidateId"]
        if candidate_id in result:
            raise WorkbenchError(
                "invalid_artifact",
                "%s contains duplicate candidateId values." % context,
            )
        instances = item.get("instances")
        if not isinstance(instances, list) or not instances:
            raise WorkbenchError(
                "invalid_artifact",
                "%s[%d].instances must be a non-empty array."
                % (context, result_index),
            )
        instance_map = {}
        for instance_index, instance in enumerate(instances):
            if (
                not isinstance(instance, dict)
                or not isinstance(instance.get("instanceId"), str)
                or not instance["instanceId"].strip()
                or instance.get("disposition") not in allowed_dispositions
            ):
                raise WorkbenchError(
                    "invalid_artifact",
                    "%s[%d].instances[%d] requires a non-empty instanceId and "
                    "supported disposition."
                    % (context, result_index, instance_index),
                )
            instance_id = instance["instanceId"]
            if instance_id in instance_map:
                raise WorkbenchError(
                    "invalid_artifact",
                    "%s[%d].instances contains duplicate instanceId values."
                    % (context, result_index),
                )
            instance_map[instance_id] = instance["disposition"]
        result[candidate_id] = instance_map
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


def _schema(required, properties=None):
    schema = {
        "type": "object",
        "required": list(required),
        "additionalProperties": True,
    }
    if properties:
        schema["properties"] = properties
    return schema


def _record_array_schema(key):
    return {
        "type": "array",
        "items": {
            "type": "object",
            "required": [key],
            "properties": {key: {"type": "string", "minLength": 1}},
            "additionalProperties": True,
        },
    }


def _phase_result_array_schema(allowed_dispositions):
    text = {"type": "string", "minLength": 1}
    return {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["candidateId", "instances"],
            "properties": {
                "candidateId": text,
                "instances": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "required": ["instanceId", "disposition"],
                        "properties": {
                            "instanceId": text,
                            "disposition": {
                                "enum": sorted(allowed_dispositions)
                            },
                        },
                        "additionalProperties": True,
                    },
                },
            },
            "additionalProperties": True,
        },
    }


def _string_array_schema():
    return {
        "type": "array",
        "items": {"type": "string", "minLength": 1},
    }


def _threat_model_schema():
    text = {"type": "string", "minLength": 1}
    named = {
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": text,
            "sensitivity": text,
            "description": text,
        },
        "additionalProperties": True,
    }
    item_array = {
        "type": "array",
        "items": {"oneOf": [text, named]},
    }
    return _schema(
        ("scanId", "summary"),
        {
            "summary": text,
            "assets": item_array,
            "trustBoundaries": item_array,
            "attackerCapabilities": item_array,
            "securityObjectives": item_array,
            "assumptions": item_array,
        },
    )


def _coverage_schema(scan):
    text = {"type": "string", "minLength": 1}
    receipt = {
        "type": "object",
        "required": ["closed", "reviewedPaths"],
        "properties": {
            "closed": {"const": True},
            "reviewedPaths": _string_array_schema(),
        },
        "additionalProperties": True,
    }
    surface = {
        "type": "object",
        "required": ["id", "label", "disposition", "receipt"],
        "properties": {
            "id": text,
            "label": text,
            "disposition": {"enum": sorted(DISPOSITIONS)},
            "riskArea": text,
            "notes": text,
            "receipt": receipt,
        },
        "additionalProperties": True,
    }
    deferred = {
        "type": "object",
        "required": ["id", "reason"],
        "properties": {
            "id": text,
            "reason": text,
            "paths": _string_array_schema(),
            "surfaceIds": _string_array_schema(),
        },
        "additionalProperties": True,
    }
    exclusion = {
        "type": "object",
        "required": ["pattern", "reason"],
        "properties": {"pattern": text, "reason": text},
        "additionalProperties": True,
    }
    question = {
        "type": "object",
        "required": ["question"],
        "properties": {"question": text, "followUpPrompt": text},
        "additionalProperties": True,
    }
    return _schema(
        (
            "scanId",
            "mode",
            "completeness",
            "inventoryStrategy",
            "includePaths",
            "excludePaths",
            "surfaces",
            "explicitExclusions",
            "deferred",
        ),
        {
            "documentType": {"const": "codex-security.coverage"},
            "schemaVersion": {"const": SCHEMA_VERSION},
            "mode": {"const": coverage_mode(scan)},
            "completeness": {"enum": sorted(COMPLETENESS)},
            "inventoryStrategy": {"enum": sorted(INVENTORY_STRATEGIES)},
            "includePaths": {
                "const": [scan["scope"]],
            },
            "excludePaths": _string_array_schema(),
            "surfaces": {"type": "array", "items": surface},
            "explicitExclusions": {"type": "array", "items": exclusion},
            "deferred": {"type": "array", "items": deferred},
            "openQuestions": {"type": "array", "items": question},
        },
    )


def _canonical_schema():
    text = {"type": "string", "minLength": 1}
    location = {
        "type": "object",
        "required": ["path", "startLine"],
        "properties": {
            "path": text,
            "startLine": {"type": "integer", "minimum": 1},
            "endLine": {"type": "integer", "minimum": 1},
            "role": text,
        },
        "additionalProperties": True,
    }
    finding = {
        "type": "object",
        "required": [
            "ruleId",
            "identity",
            "title",
            "summary",
            "severity",
            "confidence",
            "taxonomy",
            "locations",
            "rootCause",
            "validation",
            "attackPath",
            "remediation",
            "provenance",
            "extensions",
        ],
        "properties": {
            "ruleId": text,
            "identity": {
                "type": "object",
                "required": ["anchor"],
                "properties": {"anchor": text, "instance": text},
                "additionalProperties": True,
            },
            "title": text,
            "summary": text,
            "severity": {
                "type": "object",
                "required": ["level"],
                "properties": {
                    "level": {"enum": sorted(SEVERITY_ORDER)},
                    "score": {"type": "number", "minimum": 0, "maximum": 10},
                    "scoringSystem": text,
                    "vector": text,
                    "rationale": text,
                    "changeConditions": text,
                },
                "additionalProperties": True,
            },
            "confidence": {
                "type": "object",
                "required": ["level", "rationale"],
                "properties": {
                    "level": {"enum": sorted(CONFIDENCES)},
                    "rationale": text,
                },
                "additionalProperties": True,
            },
            "taxonomy": {
                "type": "object",
                "required": ["category", "cwe"],
                "properties": {
                    "category": text,
                    "cwe": {
                        "type": "array",
                        "minItems": 1,
                        "items": text,
                    },
                },
                "additionalProperties": True,
            },
            "locations": {"type": "array", "minItems": 1, "items": location},
            "rootCause": {
                "anyOf": [
                    text,
                    {
                        "type": "object",
                        "required": ["summary"],
                        "properties": {"summary": text},
                        "additionalProperties": True,
                    },
                ]
            },
            "validation": {"type": "object"},
            "attackPath": {"type": "object"},
            "remediation": text,
            "provenance": {
                "type": "object",
                "required": ["source"],
                "properties": {"source": text},
                "additionalProperties": True,
            },
            "writeup": {
                "type": "object",
                "required": ["reportPath"],
                "properties": {
                    "reportPath": {
                        "type": "string",
                        "pattern": r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$",
                    }
                },
                "additionalProperties": True,
            },
            "extensions": {
                "type": "object",
                "required": ["candidateId", "candidateInstanceId"],
                "properties": {
                    "candidateId": text,
                    "candidateInstanceId": text,
                },
                "additionalProperties": True,
            },
        },
        "additionalProperties": True,
    }
    return _schema(
        ("scanId", "manifest", "findings"),
        {
            "manifest": {
                "type": "object",
                "required": ["scan"],
                "properties": {"scan": {"type": "object"}},
                "additionalProperties": True,
            },
            "findings": {
                "type": "object",
                "required": ["findings"],
                "properties": {
                    "findings": {"type": "array", "items": finding},
                },
                "additionalProperties": True,
            },
        },
    )


def _derived_schema(descriptor):
    path = (
        {"const": "hardening/hardening.md"}
        if descriptor == "derived-hardening"
        else {
            "type": "string",
            "pattern": r"^findings/([a-z0-9][a-z0-9._-]*)/\1\.md$",
        }
    )
    outputs = {
        "type": "array",
        "items": {
            "type": "object",
            "required": ["path", "markdown"],
            "properties": {
                "path": path,
                "markdown": {"type": "string", "minLength": 1},
            },
            "additionalProperties": False,
        },
    }
    if descriptor == "derived-hardening":
        outputs.update({"minItems": 1, "maxItems": 1})
    return _schema(("scanId", "outputs"), {"outputs": outputs})


def _brief_schema(scan):
    deep = scan["mode"] == "deep"
    required = [
        "scanId",
        "mode",
        "target",
        "scope",
        "status",
        "capabilities",
    ]
    properties = {
        "mode": {"const": scan["mode"]},
        "target": {"const": scan["target_path"]},
        "scope": {"const": scan["scope"]},
        "status": {"enum": ["ready", "blocked", "incomplete"]},
        "capabilities": {
            "type": "object",
            "required": ["sourceInspection"],
            "properties": {"sourceInspection": {"type": "boolean"}},
            "additionalProperties": True,
        },
    }
    if deep:
        required.append("worklist")
        properties["worklist"] = {
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
    return _schema(required, properties)


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
