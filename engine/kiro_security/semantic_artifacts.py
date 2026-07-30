"""Validated scan-local semantic artifact staging for Kiro Agent workflows."""

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path

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
REQUIRED_COMMON = (
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
PHASE_BY_DESCRIPTOR = {
    "brief": "preflight",
    "threat-model": "threat_model",
    "discovery": "discovery",
    "validation": "validation",
    "attack-path": "attack_path",
    "coverage": "reporting",
    "canonical-result": "reporting",
    "derived-writeup": "reporting",
    "derived-hardening": "reporting",
}
PHASE_ORDER = (
    "preflight",
    "threat_model",
    "discovery",
    "validation",
    "attack_path",
    "reporting",
)
DEEP_WORKER_RE = re.compile(
    r"^discovery-round-(10|[1-9])-worker-([1-6])$"
)
DEEP_MERGE_RE = re.compile(r"^discovery-round-(10|[1-9])-merge$")


class SemanticArtifactStore:
    """Schema-bounded CAS writes outside the scanned target."""

    def contract(self, scan):
        root = _scan_dir(scan)
        persisted = self._persisted(root, scan["mode"])
        return {
            "schemaVersion": "1.0",
            "scanId": scan["id"],
            "mode": scan["mode"],
            "scanDir": str(root),
            "requiredDescriptors": list(REQUIRED_COMMON),
            "descriptorSchemas": _descriptor_schemas(scan["mode"]),
            "deep": {
                "workersPerRound": 6,
                "maximumRounds": 10,
                "workerDescriptor": "discovery-round-<1..10>-worker-<1..6>",
                "mergeDescriptor": "discovery-round-<1..10>-merge",
            }
            if scan["mode"] == "deep"
            else None,
            "persisted": persisted,
            "closure": self.closure(scan, persisted),
        }

    def write(self, scan, descriptor, content, expected_digest=None):
        if scan["status"] != "running":
            raise WorkbenchError(
                "scan_not_running",
                "Semantic artifacts can only be written for a running scan.",
            )
        normalized = _require_descriptor(descriptor, scan["mode"])
        _validate_content(scan, normalized, content)
        required_phase = _descriptor_phase(normalized)
        if PHASE_ORDER.index(scan["phase"]) < PHASE_ORDER.index(required_phase):
            raise WorkbenchError(
                "artifact_phase_not_active",
                "Artifact descriptor belongs to a later scan phase.",
            )
        root = _semantic_root(_scan_dir(scan))
        destination = root / ("%s.json" % normalized)
        current_digest = _regular_digest(destination)
        if current_digest is not None:
            if expected_digest is None:
                encoded = canonical_json_bytes(content)
                supplied_digest = hashlib.sha256(encoded).hexdigest()
                if supplied_digest == current_digest:
                    return _artifact_state(normalized, destination, current_digest)
                raise WorkbenchError(
                    "artifact_digest_required",
                    "Replacing an artifact requires its current expectedDigest.",
                )
            if expected_digest != current_digest:
                raise WorkbenchError(
                    "artifact_changed",
                    "Artifact changed before compare-and-swap write.",
                )
        elif expected_digest is not None:
            raise WorkbenchError(
                "artifact_missing",
                "Artifact does not exist for compare-and-swap replacement.",
            )
        encoded = canonical_json_bytes(content)
        _atomic_write(destination, encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        return _artifact_state(normalized, destination, digest)

    def read(self, scan, descriptor):
        normalized = _require_descriptor(descriptor, scan["mode"])
        path = _semantic_root(_scan_dir(scan)) / ("%s.json" % normalized)
        data = _read_json(path)
        return data

    def closure(self, scan, persisted=None):
        values = persisted if persisted is not None else self._persisted(
            _scan_dir(scan),
            scan["mode"],
        )
        present = {item["descriptor"] for item in values}
        missing = [descriptor for descriptor in REQUIRED_COMMON if descriptor not in present]
        deep = None
        if scan["mode"] == "deep" and "discovery" in present:
            discovery = self.read(scan, "discovery")
            rounds = discovery.get("roundsCompleted")
            termination = discovery.get("termination")
            deep_missing = []
            if isinstance(rounds, int) and 1 <= rounds <= 10:
                novelty = []
                for round_number in range(1, rounds + 1):
                    for worker_number in range(1, 7):
                        descriptor = "discovery-round-%d-worker-%d" % (
                            round_number,
                            worker_number,
                        )
                        if descriptor not in present:
                            deep_missing.append(descriptor)
                    merge = "discovery-round-%d-merge" % round_number
                    if merge not in present:
                        deep_missing.append(merge)
                    else:
                        merge_content = self.read(scan, merge)
                        novelty.append(
                            merge_content.get("newCanonicalCandidateCount")
                        )
                if termination == "capped" and rounds != 10:
                    deep_missing.append("deep-cap-requires-10-rounds")
                if termination == "saturated":
                    if not novelty or novelty[-1] != 0:
                        deep_missing.append("saturated-requires-zero-novelty")
                    if any(value == 0 for value in novelty[:-1]):
                        deep_missing.append("deep-must-stop-at-first-zero-novelty")
                if termination == "capped" and any(
                    not isinstance(value, int) or value <= 0
                    for value in novelty
                ):
                    deep_missing.append("capped-requires-novelty-through-round-10")
            else:
                deep_missing.append("discovery.roundsCompleted")
            if termination not in ("saturated", "capped"):
                deep_missing.append("discovery.termination")
            missing.extend(deep_missing)
            deep = {
                "roundsCompleted": rounds,
                "termination": termination,
                "missing": deep_missing,
            }
        if all(
            descriptor in present
            for descriptor in ("discovery", "validation", "attack-path")
        ):
            missing.extend(self._semantic_chain_missing(scan))
        return {
            "complete": not missing,
            "missing": missing,
            "deep": deep,
        }

    def require_phase_exit(self, scan, phase):
        descriptor = {
            "preflight": "brief",
            "threat_model": "threat-model",
            "discovery": "discovery",
            "validation": "validation",
            "attack_path": "attack-path",
        }.get(phase)
        if descriptor is None:
            return
        present = {
            item["descriptor"]
            for item in self._persisted(_scan_dir(scan), scan["mode"])
        }
        if descriptor not in present:
            raise WorkbenchError(
                "phase_artifact_missing",
                "%s must be written before leaving %s." % (descriptor, phase),
            )
        if phase == "discovery" and scan["mode"] == "deep":
            closure = self.closure(scan)
            deep_missing = (closure.get("deep") or {}).get("missing") or []
            if deep_missing:
                raise WorkbenchError(
                    "deep_round_incomplete",
                    "Deep discovery is incomplete: %s."
                    % ", ".join(deep_missing),
                )

    def materialize_finalizer_inputs(self, scan, completed_at, target_id):
        closure = self.closure(scan)
        if not closure["complete"]:
            raise WorkbenchError(
                "artifact_closure_incomplete",
                "Required semantic artifacts are missing: %s."
                % ", ".join(closure["missing"]),
            )
        canonical = self.read(scan, "canonical-result")
        coverage = self.read(scan, "coverage")
        manifest = canonical["manifest"]
        findings = canonical["findings"]
        threat_model = self.read(scan, "threat-model")
        writeups = self.read(scan, "derived-writeup")
        hardening = self.read(scan, "derived-hardening")
        _bind_finalizer_inputs(
            scan,
            manifest,
            findings,
            coverage,
            completed_at,
            target_id,
            threat_model,
        )
        _materialize_derived_outputs(
            _scan_dir(scan),
            findings,
            manifest,
            writeups,
            hardening,
        )
        _materialize_coverage_receipts(_scan_dir(scan), coverage)
        root = _scan_dir(scan)
        _atomic_write(root / "findings.json", canonical_json_bytes(findings))
        _atomic_write(root / "coverage.json", canonical_json_bytes(coverage))
        _atomic_write(root / "scan-manifest.json", canonical_json_bytes(manifest))
        return manifest, findings, coverage

    def _semantic_chain_missing(self, scan):
        discovery = self.read(scan, "discovery")
        validation = self.read(scan, "validation")
        attack_path = self.read(scan, "attack-path")
        candidate_ids = _record_ids(discovery.get("candidates"), "discovery.candidates")
        validation_ids = _record_ids(
            validation.get("results"),
            "validation.results",
            key="candidateId",
        )
        attack_ids = _record_ids(
            attack_path.get("results"),
            "attack-path.results",
            key="candidateId",
        )
        missing = []
        if candidate_ids != validation_ids:
            missing.append("validation-results-must-cover-every-candidate")
        if validation_ids != attack_ids:
            missing.append("attack-path-results-must-cover-every-validation")
        return missing

    def _persisted(self, root, mode):
        semantic_root = _semantic_root(root)
        if not semantic_root.exists():
            return []
        metadata = semantic_root.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise WorkbenchError(
                "unsafe_artifact_path",
                "Semantic artifact directory is unsafe.",
            )
        values = []
        for path in sorted(semantic_root.iterdir(), key=lambda item: item.name):
            if path.suffix != ".json":
                continue
            descriptor = path.stem
            _require_descriptor(descriptor, mode)
            digest = _regular_digest(path)
            if digest is None:
                raise WorkbenchError(
                    "unsafe_artifact_path",
                    "Semantic artifact must be a regular non-symlink file.",
                )
            values.append(_artifact_state(descriptor, path, digest))
        return values


def _descriptor_schemas(mode):
    common = {
        "brief": _schema(("scanId", "mode", "target", "scope")),
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
        common["discovery-round-<1..10>-worker-<1..6>"] = _schema(
            ("scanId", "round", "worker", "candidates", "coverage")
        )
        common["discovery-round-<1..10>-merge"] = _schema(
            (
                "scanId",
                "round",
                "mergedCandidateIds",
                "newCanonicalCandidateCount",
            )
        )
    return common


def _schema(required):
    return {
        "type": "object",
        "required": list(required),
        "additionalProperties": True,
    }


def _validate_content(scan, descriptor, content):
    if not isinstance(content, dict):
        raise WorkbenchError("invalid_artifact", "Artifact content must be an object.")
    if content.get("scanId") != scan["id"]:
        raise WorkbenchError(
            "artifact_scan_mismatch",
            "Artifact scanId must match the authoritative scan.",
        )
    schema_key = descriptor
    if DEEP_WORKER_RE.fullmatch(descriptor):
        schema_key = "discovery-round-<1..10>-worker-<1..6>"
    elif DEEP_MERGE_RE.fullmatch(descriptor):
        schema_key = "discovery-round-<1..10>-merge"
    schema = _descriptor_schemas(scan["mode"])[schema_key]
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
        _record_ids(content.get("candidates"), "discovery.candidates")
    if descriptor == "validation":
        _record_ids(
            content.get("results"),
            "validation.results",
            key="candidateId",
        )
    if descriptor == "attack-path":
        _record_ids(
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
        not isinstance(content.get("candidates"), list)
        or not isinstance(content.get("coverage"), dict)
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep worker payload requires candidates and coverage objects.",
        )
    merge_match = DEEP_MERGE_RE.fullmatch(descriptor)
    if merge_match and content.get("round") != int(merge_match.group(1)):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep merge payload round must match its descriptor.",
        )
    if merge_match and (
        not isinstance(content.get("mergedCandidateIds"), list)
        or isinstance(content.get("newCanonicalCandidateCount"), bool)
        or not isinstance(content.get("newCanonicalCandidateCount"), int)
        or content["newCanonicalCandidateCount"] < 0
    ):
        raise WorkbenchError(
            "invalid_artifact",
            "Deep merge payload requires candidate ids and a non-negative novelty count.",
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


def _bind_finalizer_inputs(
    scan,
    manifest,
    findings,
    coverage,
    completed_at,
    target_id,
    threat_model,
):
    if not isinstance(manifest, dict) or not isinstance(findings, dict):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical manifest and findings must be objects.",
        )
    scan_manifest = manifest.get("scan")
    if not isinstance(scan_manifest, dict):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical manifest requires a scan object.",
        )
    scan_manifest["id"] = scan["id"]
    scan_manifest["status"] = "completed"
    scan_manifest["startedAt"] = scan["started_at"]
    scan_manifest["completedAt"] = completed_at
    scan_manifest.pop("sealedAt", None)
    scan_manifest.pop("artifacts", None)
    scan_manifest["coverageRef"] = "coverage.json"
    scan_manifest["findingsRef"] = "findings.json"
    scan_manifest["producer"] = {"name": "Kiro Security", "version": "0.1.0"}
    target = {
        "targetId": target_id,
        "displayName": Path(scan["target_path"]).name,
    }
    if scan["mode"] == "diff":
        target.update(
            {
                "kind": "git_diff",
                "snapshotDigest": scan["target_snapshot_digest"],
                "baseRevision": scan["diff_base_revision"],
                "headRevision": scan["diff_head_revision"],
            }
        )
    elif scan["target_revision"] == "unversioned":
        target.update(
            {
                "kind": "directory_snapshot",
                "snapshotDigest": scan["target_snapshot_digest"],
            }
        )
    else:
        target.update(
            {
                "kind": "git_worktree",
                "revision": scan["target_revision"],
                "snapshotDigest": scan["target_snapshot_digest"],
            }
        )
    scan_manifest["target"] = target
    include_paths = coverage.get("includePaths")
    exclude_paths = coverage.get("excludePaths")
    if include_paths != [scan["scope"]] or not isinstance(exclude_paths, list):
        raise WorkbenchError(
            "coverage_scope_mismatch",
            "Coverage include/exclude paths must match the authoritative scan scope.",
        )
    scan_manifest["scope"] = {
        "includePaths": include_paths,
        "excludePaths": exclude_paths,
        "summary": "Kiro Security %s scan." % scan["mode"],
    }
    scan_manifest["threatModel"] = {
        key: value
        for key, value in threat_model.items()
        if key
        in (
            "summary",
            "assets",
            "trustBoundaries",
            "attackerCapabilities",
            "securityObjectives",
            "assumptions",
        )
    }
    manifest["documentType"] = "codex-security.scan-manifest"
    manifest["schemaVersion"] = "1.0"
    findings["documentType"] = "codex-security.findings"
    findings["schemaVersion"] = "1.0"
    findings["scanId"] = scan["id"]
    coverage["documentType"] = "codex-security.coverage"
    coverage["schemaVersion"] = "1.0"
    coverage["scanId"] = scan["id"]
    expected_mode = coverage_mode(scan)
    if coverage.get("mode") != expected_mode:
        raise WorkbenchError(
            "coverage_mode_mismatch",
            "Coverage mode must match the authoritative scan mode.",
        )


def _materialize_coverage_receipts(root, coverage):
    seen = set()
    for index, surface in enumerate(coverage["surfaces"]):
        surface_id = surface.get("id")
        if not isinstance(surface_id, str) or not surface_id.strip():
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface requires an id.",
            )
        slug = re.sub(r"[^a-z0-9._-]+", "-", surface_id.lower()).strip("-")
        if not slug or slug in seen:
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface ids must produce unique safe receipt names.",
            )
        seen.add(slug)
        receipt = surface.pop("receipt", None)
        if not isinstance(receipt, dict):
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface requires an embedded receipt object.",
            )
        receipt["surfaceId"] = surface_id
        relative = "artifacts/03_coverage/%03d-%s.json" % (index + 1, slug)
        _atomic_write(root / relative, canonical_json_bytes(receipt))
        surface["receiptRefs"] = [relative]


def _materialize_derived_outputs(root, findings, manifest, writeups, hardening):
    finding_values = findings.get("findings", [])
    if any(
        not isinstance(finding.get("writeup"), dict)
        or not isinstance(finding["writeup"].get("reportPath"), str)
        for finding in finding_values
    ):
        raise WorkbenchError(
            "derived_writeup_missing",
            "Every canonical finding requires a derived writeup reference.",
        )
    writeup_paths = {
        finding["writeup"]["reportPath"]
        for finding in finding_values
    }
    supplied_writeups = {
        output["path"]: output["markdown"]
        for output in writeups["outputs"]
    }
    if set(supplied_writeups) != writeup_paths:
        raise WorkbenchError(
            "derived_writeup_mismatch",
            "Derived writeup outputs must exactly match canonical finding references.",
        )
    for relative, markdown in supplied_writeups.items():
        if (
            not relative.startswith("findings/")
            or len(Path(relative).parts) != 3
            or Path(relative).name != ("%s.md" % Path(relative).parent.name)
            or ".." in Path(relative).parts
        ):
            raise WorkbenchError(
                "invalid_derived_path",
                "Finding writeups must use findings/<slug>/<slug>.md.",
            )
        _atomic_write(root / relative, markdown.encode("utf-8"))
    hardening_outputs = hardening["outputs"]
    if len(hardening_outputs) != 1 or hardening_outputs[0]["path"] != (
        "hardening/hardening.md"
    ):
        raise WorkbenchError(
            "derived_hardening_mismatch",
            "Derived hardening must provide hardening/hardening.md.",
        )
    _atomic_write(
        root / "hardening" / "hardening.md",
        hardening_outputs[0]["markdown"].encode("utf-8"),
    )
    manifest["scan"]["hardening"] = {
        "portfolioPath": "hardening/hardening.md",
    }


def _record_ids(value, context, key="id"):
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


def _require_descriptor(value, mode):
    if not isinstance(value, str):
        raise WorkbenchError(
            "invalid_artifact_descriptor",
            "Artifact descriptor must be a string.",
        )
    if value in BASE_DESCRIPTORS:
        return value
    if mode == "deep" and (
        DEEP_WORKER_RE.fullmatch(value) or DEEP_MERGE_RE.fullmatch(value)
    ):
        return value
    raise WorkbenchError(
        "invalid_artifact_descriptor",
        "Artifact descriptor is not allowed for this scan.",
    )


def _descriptor_phase(descriptor):
    if descriptor.startswith("discovery-round-"):
        return "discovery"
    return PHASE_BY_DESCRIPTOR[descriptor]


def _scan_dir(scan):
    root = Path(scan["scan_dir"]).resolve(strict=True)
    metadata = root.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise WorkbenchError(
            "unsafe_scan_directory",
            "Scan directory must be a regular local directory.",
        )
    return root


def _semantic_root(root):
    path = root / "artifacts" / "semantic"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def _regular_digest(path):
    if not path.exists():
        return None
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WorkbenchError(
            "unsafe_artifact_path",
            "Artifact path must be a regular non-symlink file.",
        )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path):
    digest = _regular_digest(path)
    if digest is None:
        raise WorkbenchError("artifact_missing", "Required semantic artifact is missing.")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda token: (_raise_nonfinite(token)),
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise WorkbenchError("invalid_artifact", "Semantic artifact JSON is invalid.") from exc
    if not isinstance(value, dict):
        raise WorkbenchError("invalid_artifact", "Semantic artifact must be an object.")
    return value


def _raise_nonfinite(token):
    raise ValueError("non-finite JSON number: %s" % token)


def _atomic_write(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise WorkbenchError("unsafe_artifact_path", "Artifact parent is unsafe.")
    descriptor = None
    if path.exists():
        descriptor = path.lstat()
        if stat.S_ISLNK(descriptor.st_mode) or not stat.S_ISREG(descriptor.st_mode):
            raise WorkbenchError(
                "unsafe_artifact_path",
                "Artifact destination must be a regular non-symlink file.",
            )
    handle, temporary_name = tempfile.mkstemp(
        prefix=".%s." % path.name,
        suffix=".tmp",
        dir=str(parent),
    )
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _artifact_state(descriptor, path, digest):
    return {
        "descriptor": descriptor,
        "path": str(path),
        "digest": digest,
        "sizeBytes": path.stat().st_size,
    }
