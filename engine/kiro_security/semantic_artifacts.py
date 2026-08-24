"""Validated scan-local semantic artifact staging for Kiro Agent workflows."""

import hashlib
import hmac
import json
import stat
from pathlib import Path

from .artifacts import (
    ArtifactContractError,
    canonical_json_bytes,
    has_sealed_manifest,
)
from .deep_scan_rules import DeepScanRules
from .errors import WorkbenchError
from .phase_contracts import build_phase_contract
from .scan_files import read_regular_file
from .semantic_contract import (
    ATTACK_PATH_INSTANCE_DISPOSITIONS,
    DEEP_CHECKPOINT_RE,
    DEEP_CHECKPOINT_SCHEMA_KEY,
    DEEP_MERGE_RE,
    DEEP_WORKER_RE,
    DEEP_WORKER_SCHEMA_KEY,
    DEEP_WORKERS_PER_ROUND,
    VALIDATION_INSTANCE_DISPOSITIONS,
    canonical_digest as _canonical_digest,
    canonical_findings as _canonical_findings,
    deep_merge_descriptor as _deep_merge_descriptor,
    descriptor_schema_key as _descriptor_schema_key,
    descriptor_schemas as _descriptor_schemas,
    has_deep_artifact_after as _has_deep_artifact_after,
    phase_result_instances as _phase_result_instances,
    record_ids as _record_ids,
    require_descriptor as _require_descriptor,
    string_ids as _string_ids,
    validate_content as _validate_content,
    worklist_ids as _worklist_ids,
)
from .semantic_materialization import (
    bind_finalizer_inputs as _bind_finalizer_inputs,
    findings_with_writeups as _findings_with_writeups,
    is_reportable_finding as _is_reportable_finding,
    materialize_coverage_receipts as _materialize_coverage_receipts,
    materialize_derived_hardening as _materialize_derived_hardening,
    materialize_derived_writeups as _materialize_derived_writeups,
    reportable_findings as _reportable_findings,
    validate_derived_hardening as _validate_derived_hardening,
    validate_derived_writeups as _validate_derived_writeups,
    write_output as _atomic_write,
)


class SemanticArtifactStore(DeepScanRules):
    """Schema-bounded CAS writes outside the scanned target."""

    def contract(self, scan):
        root = _scan_dir(scan)
        sealed = has_sealed_manifest(root)
        persisted = self._persisted(root, scan["mode"])
        present = {item["descriptor"] for item in persisted}
        next_phases = (
            self.allowed_next_phases(scan, present)
            if scan["status"] == "running" and not sealed
            else ()
        )
        return {
            "schemaVersion": "1.0",
            "scanId": scan["id"],
            "mode": scan["mode"],
            "scanDir": str(root),
            "requiredDescriptors": self._required_descriptors(scan, present),
            "descriptorSchemas": (
                self._current_descriptor_schemas(scan, persisted)
                if scan["status"] == "running" and not sealed
                else {}
            ),
            "deep": self._deep_contract(scan, persisted)
            if scan["mode"] == "deep"
            else None,
            "persisted": persisted,
            "closure": self.closure(scan, persisted),
            "phaseContract": build_phase_contract(scan, next_phases),
        }

    def allowed_next_phases(self, scan, present=None):
        phase = scan["phase"]
        mode = scan["mode"]
        if phase == "preflight":
            return ("discovery",) if mode == "deep" else ("threat_model",)
        if phase == "threat_model":
            return ("discovery",)
        if phase == "discovery":
            values = present
            if values is None:
                values = {
                    item["descriptor"]
                    for item in self._persisted(_scan_dir(scan), mode)
                }
            if mode == "deep":
                if "discovery" not in values or "threat-model" not in values:
                    return ()
                deep = self._deep_discovery_closure(scan, values)
                if deep is None or deep["missing"]:
                    return ()
            if "discovery" not in values:
                return (
                    ("validation", "reporting")
                    if mode == "diff"
                    else ("validation",)
                )
            return (
                ("reporting",)
                if mode in ("diff", "deep") and self._skip_candidate_tail(scan)
                else ("validation",)
            )
        if phase == "validation":
            return ("attack_path",)
        if phase == "attack_path":
            return ("reporting",)
        return ()

    def write(self, scan, descriptor, content, expected_digest=None):
        if scan["status"] != "running":
            raise WorkbenchError(
                "scan_not_running",
                "Semantic artifacts can only be written for a running scan.",
            )
        if has_sealed_manifest(_scan_dir(scan)):
            raise WorkbenchError(
                "scan_sealed",
                "Semantic artifacts cannot be changed after the scan is sealed.",
            )
        normalized = _require_descriptor(descriptor, scan["mode"])
        persisted = None
        present = None
        if scan["mode"] == "deep" and scan["phase"] == "discovery":
            persisted = self._persisted(_scan_dir(scan), scan["mode"])
            present = {item["descriptor"] for item in persisted}
        schema_key = _descriptor_schema_key(normalized)
        if schema_key not in self._current_descriptor_schemas(scan, persisted):
            if scan["phase"] == "reporting" and normalized in (
                "derived-writeup",
                "derived-hardening",
            ):
                raise WorkbenchError(
                    "artifact_phase_not_active",
                    "Derived reporting artifacts are not writable until "
                    "canonical-result is persisted. Wait for the canonical-result "
                    "write to succeed, reload the artifact contract, and use the "
                    "newly exposed derived schema.",
                )
            raise WorkbenchError(
                "artifact_phase_not_active",
                "Artifact descriptor is not writable in the current scan phase. "
                "Reload the scan context and artifact contract; closed-phase "
                "artifacts require a new scan to change.",
            )
        _validate_content(scan, normalized, content)
        if normalized == "validation":
            self._require_validation_binding(scan, content)
        elif normalized == "attack-path":
            self._require_attack_path_binding(scan, content)
        elif normalized == "canonical-result":
            self.require_candidate_finding_binding(scan, content)
        if present is not None:
            self._require_deep_write_order(scan, normalized, content, present)
        if normalized == "derived-writeup":
            _validate_derived_writeups(
                self.read(scan, "canonical-result")["findings"],
                content,
            )
        elif normalized == "derived-hardening":
            _validate_derived_hardening(content)
        scan_root = _scan_dir(scan)
        root = _semantic_root(scan_root)
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
        _atomic_write(
            scan_root,
            "artifacts/semantic/%s.json" % normalized,
            encoded,
        )
        digest = hashlib.sha256(encoded).hexdigest()
        return _artifact_state(normalized, destination, digest)

    def read(self, scan, descriptor):
        normalized = _require_descriptor(descriptor, scan["mode"])
        path = _semantic_root(_scan_dir(scan)) / ("%s.json" % normalized)
        data = _read_json(path)
        return data

    def read_for_agent(self, scan, descriptor, expected_digest):
        normalized = _require_descriptor(descriptor, scan["mode"])
        root = _scan_dir(scan)
        persisted = {
            item["descriptor"]: item
            for item in self._persisted(root, scan["mode"])
        }
        artifact = persisted.get(normalized)
        if artifact is None:
            raise WorkbenchError(
                "artifact_missing",
                "Requested semantic artifact does not exist.",
            )
        if not hmac.compare_digest(artifact["digest"], expected_digest):
            raise WorkbenchError(
                "artifact_changed",
                "Artifact changed after its contract was read.",
            )
        try:
            encoded = read_regular_file(
                root,
                "artifacts/semantic/%s.json" % normalized,
            )
        except ArtifactContractError as exc:
            raise WorkbenchError(
                "unsafe_artifact_path",
                "Semantic artifact path is missing or unsafe.",
            ) from exc
        actual_digest = hashlib.sha256(encoded).hexdigest()
        if not hmac.compare_digest(actual_digest, expected_digest):
            raise WorkbenchError(
                "artifact_changed",
                "Artifact changed while it was being read.",
            )
        content = _decode_json(encoded)
        _validate_content(scan, normalized, content)
        if DEEP_WORKER_RE.fullmatch(normalized):
            self._require_deep_worker_receipt(scan, content)
        elif DEEP_CHECKPOINT_RE.fullmatch(normalized):
            self._require_deep_checkpoint_binding(scan, content)
        elif DEEP_MERGE_RE.fullmatch(normalized):
            round_number = int(DEEP_MERGE_RE.fullmatch(normalized).group(1))
            self._require_deep_merge_binding(scan, round_number, content)
        elif normalized == "validation":
            self._require_validation_binding(scan, content)
        elif normalized == "attack-path":
            self._require_attack_path_binding(scan, content)
        elif normalized == "canonical-result":
            self.require_candidate_finding_binding(scan, content)
        return {
            "artifact": {
                "descriptor": normalized,
                "digest": actual_digest,
                "sizeBytes": len(encoded),
            },
            "content": content,
        }

    def _deep_contract(self, scan, persisted):
        brief = next(
            (
                item
                for item in persisted
                if item["descriptor"] == "brief"
            ),
            None,
        )
        worklist_digest = None
        if brief is not None:
            worklist = self.read(scan, "brief").get("worklist")
            _worklist_ids(worklist)
            worklist_digest = _canonical_digest(worklist)
        return {
            "workersPerRound": DEEP_WORKERS_PER_ROUND,
            "maximumRounds": 10,
            "workerDescriptor": DEEP_WORKER_SCHEMA_KEY,
            "checkpointDescriptor": DEEP_CHECKPOINT_SCHEMA_KEY,
            "mergeDescriptor": "discovery-round-<1..10>-merge",
            "inputDigest": brief["digest"] if brief is not None else None,
            "worklistDigest": worklist_digest,
        }

    def _current_descriptor_schemas(self, scan, persisted=None):
        if scan["mode"] == "deep" and scan["phase"] == "discovery":
            values = persisted if persisted is not None else self._persisted(
                _scan_dir(scan),
                scan["mode"],
            )
            present = {item["descriptor"] for item in values}
            return _current_descriptor_schemas(
                scan,
                self._deep_writable_schema_keys(scan, present),
            )
        return _current_descriptor_schemas(scan)

    def _deep_writable_schema_keys(self, scan, present):
        if "discovery" in present:
            deep = self._deep_discovery_closure(scan, present)
            return ("threat-model",) if deep is not None and not deep["missing"] else ()
        terminal = self._deep_terminal_state(scan, present)
        if terminal is not None:
            return ("discovery",)
        round_number = self._deep_open_round(scan, present)
        if round_number is None or _has_deep_artifact_after(present, round_number):
            return ()
        keys = [DEEP_WORKER_SCHEMA_KEY]
        if not self._deep_workers_complete(scan, round_number, present):
            keys.append(DEEP_CHECKPOINT_SCHEMA_KEY)
        if self._deep_workers_complete(scan, round_number, present):
            keys.append("discovery-round-<1..10>-merge")
        return tuple(keys)

    @staticmethod
    def _brief_digest(scan):
        return _regular_digest(_semantic_root(_scan_dir(scan)) / "brief.json")

    def closure(self, scan, persisted=None):
        values = persisted if persisted is not None else self._persisted(
            _scan_dir(scan),
            scan["mode"],
        )
        present = {item["descriptor"] for item in values}
        required = self._required_descriptors(scan, present)
        missing = [
            descriptor
            for descriptor in required
            if descriptor not in present
        ]
        valid = {}
        for descriptor in required:
            if descriptor not in present:
                continue
            try:
                content = self.read(scan, descriptor)
                _validate_content(scan, descriptor, content)
                valid[descriptor] = content
            except WorkbenchError:
                missing.append("%s.invalid" % descriptor)
        deep = self._deep_discovery_closure(scan, present)
        if deep is not None:
            missing.extend(deep["missing"])
        if all(
            descriptor in valid
            for descriptor in ("discovery", "validation", "attack-path")
        ):
            missing.extend(self._semantic_chain_missing(scan))
        canonical = valid.get("canonical-result")
        if "discovery" in valid and canonical is not None:
            try:
                if self._candidate_finding_mismatch(scan, canonical):
                    missing.append(
                        "canonical-findings-must-match-reportable-attack-path"
                    )
            except WorkbenchError:
                missing.append("canonical-finding-binding.invalid")
        if canonical is not None and "derived-writeup" in valid:
            try:
                _validate_derived_writeups(
                    {"findings": _findings_with_writeups(canonical["findings"])},
                    valid["derived-writeup"],
                )
            except WorkbenchError:
                missing.append("derived-writeup.invalid")
        if "derived-hardening" in valid:
            try:
                _validate_derived_hardening(valid["derived-hardening"])
            except WorkbenchError:
                missing.append("derived-hardening.invalid")
        return {
            "complete": not missing,
            "missing": missing,
            "deep": deep,
        }

    def _deep_discovery_closure(self, scan, present):
        if scan["mode"] != "deep" or "discovery" not in present:
            return None
        discovery = self.read(scan, "discovery")
        rounds = discovery.get("roundsCompleted")
        termination = discovery.get("termination")
        missing = []
        if isinstance(rounds, int) and 1 <= rounds <= 10:
            novelty = []
            for round_number in range(1, rounds + 1):
                for worker_number in range(1, DEEP_WORKERS_PER_ROUND + 1):
                    descriptor = "discovery-round-%d-worker-%d" % (
                        round_number,
                        worker_number,
                    )
                    if descriptor not in present:
                        missing.append(descriptor)
                    else:
                        worker = self.read(scan, descriptor)
                        try:
                            self._require_deep_worker_receipt(scan, worker)
                        except WorkbenchError:
                            missing.append("%s.coverage.closed" % descriptor)
                merge = "discovery-round-%d-merge" % round_number
                if merge not in present:
                    missing.append(merge)
                else:
                    merge_content = self.read(scan, merge)
                    novelty.append(
                        merge_content.get("newCanonicalCandidateCount")
                    )
                    try:
                        self._require_deep_merge_binding(
                            scan,
                            round_number,
                            merge_content,
                        )
                    except WorkbenchError:
                        missing.append("%s.binding" % merge)
            if termination == "capped" and rounds != 10:
                missing.append("deep-cap-requires-10-rounds")
            if termination == "saturated":
                if not novelty or novelty[-1] != 0:
                    missing.append("saturated-requires-zero-novelty")
                if any(
                    not isinstance(value, int) or isinstance(value, bool) or value <= 0
                    for value in novelty[:-1]
                ):
                    missing.append("deep-must-stop-at-first-zero-novelty")
            if termination == "capped" and any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
                for value in novelty
            ):
                missing.append("capped-requires-novelty-through-round-10")
        else:
            missing.append("discovery.roundsCompleted")
        if termination not in ("saturated", "capped"):
            missing.append("discovery.termination")
        if isinstance(rounds, int) and _has_deep_artifact_after(present, rounds):
            missing.append("deep-artifact-after-terminal-round")
        terminal = self._deep_terminal_state(scan, present)
        if terminal != (rounds, termination):
            missing.append("deep-terminal-state-mismatch")
        if isinstance(rounds, int) and 1 <= rounds <= 10:
            merge_descriptor = _deep_merge_descriptor(rounds)
            if merge_descriptor in present:
                merge = self.read(scan, merge_descriptor)
                discovery_ids = set(
                    _record_ids(
                        discovery.get("candidates"),
                        "discovery.candidates",
                    )
                )
                merge_ids = set(
                    _string_ids(
                        merge.get("mergedCandidateIds"),
                        "merge.mergedCandidateIds",
                    )
                )
                if discovery_ids != merge_ids:
                    missing.append("deep-terminal-candidate-mismatch")
        return {
            "roundsCompleted": rounds,
            "termination": termination,
            "missing": missing,
        }

    def _required_descriptors(self, scan, present):
        required = ["brief", "threat-model", "discovery"]
        if not (
            "discovery" in present
            and scan["mode"] in ("diff", "deep")
            and self._skip_candidate_tail(scan)
        ):
            required.extend(("validation", "attack-path"))
        required.extend(("coverage", "canonical-result"))
        if "canonical-result" in present:
            if self._canonical_writeup_reference_count_or_zero(scan) > 0:
                required.append("derived-writeup")
            if self._canonical_reportable_finding_count_or_zero(scan) > 0:
                required.append("derived-hardening")
        return required

    def _skip_candidate_tail(self, scan):
        discovery = self.read(scan, "discovery")
        return not _record_ids(
            discovery.get("candidates"),
            "discovery.candidates",
        )

    def _canonical_reportable_finding_count_or_zero(self, scan):
        try:
            canonical = self.read(scan, "canonical-result")
            return len(_reportable_findings(canonical["findings"]))
        except WorkbenchError:
            return 0

    def _canonical_writeup_reference_count_or_zero(self, scan):
        try:
            canonical = self.read(scan, "canonical-result")
            return len(_findings_with_writeups(canonical["findings"]))
        except WorkbenchError:
            return 0

    def _candidate_finding_mismatch(self, scan, canonical):
        discovery = self.read(scan, "discovery")
        candidates = _record_ids(
            discovery.get("candidates"),
            "discovery.candidates",
        )
        findings = _canonical_findings(canonical)
        if not candidates:
            return bool(findings)
        attack_results = self.read(scan, "attack-path").get("results")
        attack_instances = _phase_result_instances(
            attack_results,
            "attack-path.results",
            ATTACK_PATH_INSTANCE_DISPOSITIONS,
        )
        expected_reportable = {
            (result["candidateId"], instance["instanceId"]): instance["finalSeverity"]
            for result in attack_results
            for instance in result["instances"]
            if instance["disposition"] == "reportable"
        }
        actual_reportable = {
            (
                finding["extensions"]["candidateId"],
                finding["extensions"]["candidateInstanceId"],
            ): finding["severity"]["level"]
            for finding in findings
            if _is_reportable_finding(finding)
        }
        nonreportable = {
            (candidate_id, instance_id)
            for candidate_id, instances in attack_instances.items()
            for instance_id, disposition in instances.items()
            if disposition in ("ignored", "deferred")
        }
        informational = {
            (
                finding["extensions"]["candidateId"],
                finding["extensions"]["candidateInstanceId"],
            )
            for finding in findings
            if not _is_reportable_finding(finding)
        }
        return (
            actual_reportable != expected_reportable
            or not informational.issubset(nonreportable)
        )

    def require_candidate_finding_binding(self, scan, canonical=None):
        value = canonical if canonical is not None else self.read(
            scan,
            "canonical-result",
        )
        discovery = self.read(scan, "discovery")
        candidates = _record_ids(
            discovery.get("candidates"),
            "discovery.candidates",
        )
        if not candidates and bool(_canonical_findings(value)):
            raise WorkbenchError(
                "canonical_discovery_mismatch",
                "A scan without discovery candidates cannot contain canonical findings.",
            )
        _validate_content(scan, "canonical-result", value)
        if self._candidate_finding_mismatch(scan, value):
            raise WorkbenchError(
                "canonical_attack_path_mismatch",
                "Canonical findings and severity levels must exactly match reportable "
                "attack-path instances and finalSeverity values.",
            )

    def _require_validation_binding(self, scan, validation):
        candidates = _record_ids(
            self.read(scan, "discovery").get("candidates"),
            "discovery.candidates",
        )
        instances = _phase_result_instances(
            validation.get("results"),
            "validation.results",
            VALIDATION_INSTANCE_DISPOSITIONS,
        )
        if set(instances) != candidates:
            raise WorkbenchError(
                "validation_discovery_mismatch",
                "Validation results must exactly cover discovery candidate ids.",
            )

    def _require_attack_path_binding(self, scan, attack_path):
        validation_instances = _phase_result_instances(
            self.read(scan, "validation").get("results"),
            "validation.results",
            VALIDATION_INSTANCE_DISPOSITIONS,
        )
        attack_instances = _phase_result_instances(
            attack_path.get("results"),
            "attack-path.results",
            ATTACK_PATH_INSTANCE_DISPOSITIONS,
        )
        if set(attack_instances) != set(validation_instances) or any(
            set(attack_instances[candidate_id])
            != set(validation_instances[candidate_id])
            for candidate_id in validation_instances
        ):
            raise WorkbenchError(
                "attack_path_validation_mismatch",
                "Attack-path results must exactly cover validated candidate instances.",
            )

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
        if phase == "preflight":
            brief = self.read(scan, "brief")
            if brief.get("status") != "ready" or (
                brief.get("capabilities", {}).get("sourceInspection") is not True
            ):
                raise WorkbenchError(
                    "preflight_not_ready",
                    "Preflight must be ready with target source inspection available.",
                )
        elif phase == "validation":
            self._require_validation_binding(scan, self.read(scan, "validation"))
        elif phase == "attack_path":
            self._require_attack_path_binding(scan, self.read(scan, "attack-path"))
        if phase == "discovery" and scan["mode"] == "deep":
            closure = self.closure(scan)
            deep_missing = (closure.get("deep") or {}).get("missing") or []
            if deep_missing:
                raise WorkbenchError(
                    "deep_round_incomplete",
                    "Deep discovery is incomplete: %s."
                    % ", ".join(deep_missing),
                )
            if "threat-model" not in present:
                raise WorkbenchError(
                    "phase_artifact_missing",
                    "Deep discovery must synthesize its canonical threat-model "
                    "after the terminal round.",
                )

    def materialize_finalizer_inputs(self, scan, completed_at, target_id):
        canonical = self.read(scan, "canonical-result")
        self.require_candidate_finding_binding(scan, canonical)
        closure = self.closure(scan)
        if not closure["complete"]:
            raise WorkbenchError(
                "artifact_closure_incomplete",
                "Required semantic artifacts are missing: %s."
                % ", ".join(closure["missing"]),
            )
        coverage = self.read(scan, "coverage")
        manifest = canonical["manifest"]
        findings = canonical["findings"]
        threat_model = self.read(scan, "threat-model")
        _bind_finalizer_inputs(
            scan,
            manifest,
            findings,
            coverage,
            completed_at,
            target_id,
            threat_model,
        )
        finding_values = findings.get("findings")
        if not isinstance(finding_values, list):
            raise WorkbenchError(
                "invalid_canonical_result",
                "Canonical findings must contain a findings array.",
            )
        severity_counts = {}
        for finding in finding_values:
            level = finding["severity"]["level"]
            severity_counts[level] = severity_counts.get(level, 0) + 1
        manifest["totalFindings"] = len(finding_values)
        manifest["severityCounts"] = severity_counts
        reportable_findings = {"findings": _reportable_findings(findings)}
        writeup_findings = {"findings": _findings_with_writeups(findings)}
        if writeup_findings["findings"]:
            _materialize_derived_writeups(
                _scan_dir(scan),
                writeup_findings,
                self.read(scan, "derived-writeup"),
            )
        if reportable_findings["findings"]:
            _materialize_derived_hardening(
                _scan_dir(scan),
                manifest,
                self.read(scan, "derived-hardening"),
            )
        else:
            manifest["scan"].pop("hardening", None)
        _materialize_coverage_receipts(_scan_dir(scan), coverage)
        root = _scan_dir(scan)
        _atomic_write(root, "findings.json", canonical_json_bytes(findings))
        _atomic_write(root, "coverage.json", canonical_json_bytes(coverage))
        _atomic_write(root, "scan-manifest.json", canonical_json_bytes(manifest))
        return manifest, findings, coverage

    def _semantic_chain_missing(self, scan):
        discovery = self.read(scan, "discovery")
        validation = self.read(scan, "validation")
        attack_path = self.read(scan, "attack-path")
        candidate_ids = _record_ids(discovery.get("candidates"), "discovery.candidates")
        validation_instances = _phase_result_instances(
            validation.get("results"),
            "validation.results",
            VALIDATION_INSTANCE_DISPOSITIONS,
        )
        attack_instances = _phase_result_instances(
            attack_path.get("results"),
            "attack-path.results",
            ATTACK_PATH_INSTANCE_DISPOSITIONS,
        )
        missing = []
        if candidate_ids != set(validation_instances):
            missing.append("validation-results-must-cover-every-candidate")
        if set(validation_instances) != set(attack_instances):
            missing.append("attack-path-results-must-cover-every-validation")
        elif any(
            set(validation_instances[candidate_id])
            != set(attack_instances[candidate_id])
            for candidate_id in validation_instances
        ):
            missing.append("attack-path-must-cover-every-validated-instance")
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


def _current_descriptor_schemas(scan, deep_keys=None):
    schemas = _descriptor_schemas(scan)
    phase = scan["phase"]
    keys = {
        "preflight": ("brief",),
        "threat_model": ("threat-model",),
        "discovery": ("discovery",),
        "validation": ("validation",),
        "attack_path": ("attack-path",),
        "reporting": ("coverage", "canonical-result"),
    }[phase]
    if phase == "discovery" and scan["mode"] == "deep":
        keys = tuple(deep_keys or ())
    if phase == "reporting":
        canonical_path = _semantic_root(_scan_dir(scan)) / "canonical-result.json"
        if canonical_path.exists() and _canonical_findings(_read_json(canonical_path)):
            keys = keys + ("derived-writeup", "derived-hardening")
    return {key: schemas[key] for key in keys}


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
    return root / "artifacts" / "semantic"


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
        return _decode_json(path.read_bytes())
    except OSError as exc:
        raise WorkbenchError("invalid_artifact", "Semantic artifact JSON is invalid.") from exc


def _decode_json(content):
    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_constant=lambda token: (_raise_nonfinite(token)),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise WorkbenchError(
            "invalid_artifact",
            "Semantic artifact JSON is invalid.",
        ) from exc
    if not isinstance(value, dict):
        raise WorkbenchError("invalid_artifact", "Semantic artifact must be an object.")
    return value


def _raise_nonfinite(token):
    raise ValueError("non-finite JSON number: %s" % token)


def _artifact_state(descriptor, path, digest):
    return {
        "descriptor": descriptor,
        "path": str(path),
        "digest": digest,
        "sizeBytes": path.stat().st_size,
    }
