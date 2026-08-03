"""Validated scan-local semantic artifact staging for Kiro Agent workflows."""

import hashlib
import json
import re
import stat
from pathlib import Path

from .artifacts import (
    ArtifactContractError,
    _atomic_write as _write_scan_file,
    canonical_json_bytes,
)
from .errors import WorkbenchError
from .phase_contracts import build_phase_contract

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
    r"^discovery-round-(10|[1-9])-worker-([1-4])$"
)
DEEP_CHECKPOINT_RE = re.compile(
    r"^discovery-round-(10|[1-9])-worker-([1-4])-checkpoint$"
)
DEEP_MERGE_RE = re.compile(r"^discovery-round-(10|[1-9])-merge$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class SemanticArtifactStore:
    """Schema-bounded CAS writes outside the scanned target."""

    def contract(self, scan):
        root = _scan_dir(scan)
        persisted = self._persisted(root, scan["mode"])
        present = {item["descriptor"] for item in persisted}
        next_phases = (
            self.allowed_next_phases(scan, present)
            if scan["status"] == "running"
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
                if scan["status"] == "running"
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
        normalized = _require_descriptor(descriptor, scan["mode"])
        _validate_content(scan, normalized, content)
        persisted = None
        present = None
        if scan["mode"] == "deep" and scan["phase"] == "discovery":
            persisted = self._persisted(_scan_dir(scan), scan["mode"])
            present = {item["descriptor"] for item in persisted}
        schema_key = _descriptor_schema_key(normalized)
        if schema_key not in self._current_descriptor_schemas(scan, persisted):
            raise WorkbenchError(
                "artifact_phase_not_active",
                "Artifact descriptor is not writable in the current scan phase. "
                "Reload the scan context and artifact contract; closed-phase "
                "artifacts require a new scan to change.",
            )
        if present is not None:
            self._require_deep_write_order(scan, normalized, content, present)
        if normalized == "canonical-result":
            self.require_candidate_finding_binding(scan, content)
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

    def _require_deep_write_order(self, scan, descriptor, content, present):
        worker_match = DEEP_WORKER_RE.fullmatch(descriptor)
        checkpoint_match = DEEP_CHECKPOINT_RE.fullmatch(descriptor)
        merge_match = DEEP_MERGE_RE.fullmatch(descriptor)
        if worker_match:
            expected_round = self._deep_open_round(scan, present)
            if expected_round != int(worker_match.group(1)):
                raise WorkbenchError(
                    "deep_artifact_order",
                    "Deep workers can be written only for the current open round.",
                )
            self._require_deep_worker_receipt(scan, content)
            if descriptor in present and _canonical_digest(
                self.read(scan, descriptor)
            ) != _canonical_digest(content):
                raise WorkbenchError(
                    "deep_worker_closed",
                    "A completed Deep worker artifact is immutable.",
                )
            return
        if checkpoint_match:
            round_number = int(checkpoint_match.group(1))
            worker_number = int(checkpoint_match.group(2))
            if self._deep_open_round(scan, present) != round_number:
                raise WorkbenchError(
                    "deep_artifact_order",
                    "Deep checkpoints can be written only for the current open round.",
                )
            complete_descriptor = _deep_worker_descriptor(
                round_number,
                worker_number,
            )
            if complete_descriptor in present:
                raise WorkbenchError(
                    "deep_worker_closed",
                    "A completed Deep worker slot cannot change its checkpoint.",
                )
            self._require_deep_checkpoint_binding(scan, content)
            if descriptor in present:
                self._require_deep_checkpoint_update(
                    self.read(scan, descriptor),
                    content,
                )
            return
        if merge_match:
            round_number = int(merge_match.group(1))
            if self._deep_open_round(scan, present) != round_number or not all(
                _deep_worker_descriptor(round_number, worker_number) in present
                for worker_number in range(1, DEEP_WORKERS_PER_ROUND + 1)
            ):
                raise WorkbenchError(
                    "deep_artifact_order",
                    "A Deep round can be merged only after all 4 workers complete.",
                )
            self._require_deep_merge_binding(scan, round_number, content)
            return
        if descriptor == "discovery":
            terminal = self._deep_terminal_state(scan, present)
            if terminal is None:
                raise WorkbenchError(
                    "deep_artifact_order",
                    "Terminal Deep discovery requires saturated or capped rounds.",
                )
            rounds, termination = terminal
            if (
                content.get("roundsCompleted") != rounds
                or content.get("termination") != termination
            ):
                raise WorkbenchError(
                    "deep_terminal_mismatch",
                    "Deep discovery does not match the terminal round state.",
                )
            merge = self.read(scan, _deep_merge_descriptor(rounds))
            discovery_ids = set(
                _record_ids(content.get("candidates"), "discovery.candidates")
            )
            merge_ids = set(
                _string_ids(
                    merge.get("mergedCandidateIds"),
                    "merge.mergedCandidateIds",
                )
            )
            if discovery_ids != merge_ids:
                raise WorkbenchError(
                    "deep_terminal_mismatch",
                    "Deep discovery candidate ids must match the terminal merge.",
                )

    def _require_deep_merge_binding(self, scan, round_number, content):
        worker_ids = {}
        for worker_number in range(1, DEEP_WORKERS_PER_ROUND + 1):
            worker = self.read(
                scan,
                _deep_worker_descriptor(round_number, worker_number),
            )
            self._require_deep_worker_receipt(scan, worker)
            worker_ids[worker_number] = _record_ids(
                worker.get("candidates"),
                "worker.candidates",
            )
        previous_ids = set()
        if round_number > 1:
            previous = self.read(scan, _deep_merge_descriptor(round_number - 1))
            previous_ids.update(
                _string_ids(
                    previous.get("mergedCandidateIds"),
                    "merge.mergedCandidateIds",
                )
            )
        merged_ids = set(
            _string_ids(
                content.get("mergedCandidateIds"),
                "merge.mergedCandidateIds",
            )
        )
        source_ids = {
            (worker_number, candidate_id)
            for worker_number, candidates in worker_ids.items()
            for candidate_id in candidates
        }
        lineage_sources = set()
        lineage_targets = set()
        for index, item in enumerate(content.get("lineage", [])):
            if not isinstance(item, dict):
                raise WorkbenchError(
                    "deep_merge_mismatch",
                    "Deep merge lineage entries must be objects.",
                )
            worker_number = item.get("worker")
            candidate_id = item.get("candidateId")
            canonical_id = item.get("canonicalCandidateId")
            source = (worker_number, candidate_id)
            if (
                worker_number not in range(1, DEEP_WORKERS_PER_ROUND + 1)
                or not isinstance(candidate_id, str)
                or not candidate_id.strip()
                or not isinstance(canonical_id, str)
                or not canonical_id.strip()
                or source not in source_ids
            ):
                raise WorkbenchError(
                    "deep_merge_mismatch",
                    "Deep merge lineage entry %d does not match a worker candidate."
                    % index,
                )
            if source in lineage_sources:
                raise WorkbenchError(
                    "deep_merge_mismatch",
                    "Every worker candidate must appear exactly once in merge lineage.",
                )
            lineage_sources.add(source)
            lineage_targets.add(canonical_id)
        if lineage_sources != source_ids:
            raise WorkbenchError(
                "deep_merge_mismatch",
                "Deep merge lineage must account for every worker candidate.",
            )
        if merged_ids != previous_ids | lineage_targets:
            raise WorkbenchError(
                "deep_merge_mismatch",
                "Deep merge ids must exactly preserve prior ids and lineage targets.",
            )
        if content.get("newCanonicalCandidateCount") != len(
            merged_ids - previous_ids
        ):
            raise WorkbenchError(
                "deep_merge_mismatch",
                "Deep merge novelty must match its canonical candidate ids.",
            )

    def _require_deep_worker_receipt(self, scan, content):
        brief_path = _semantic_root(_scan_dir(scan)) / "brief.json"
        brief_digest = _regular_digest(brief_path)
        if content.get("inputDigest") != brief_digest:
            raise WorkbenchError(
                "deep_worker_input_mismatch",
                "Deep worker inputDigest must match the canonical brief.",
            )
        brief = self.read(scan, "brief")
        worklist_ids = _worklist_ids(brief.get("worklist"))
        worklist_digest = _canonical_digest(brief["worklist"])
        coverage = content.get("coverage", {})
        if coverage.get("worklistDigest") != worklist_digest:
            raise WorkbenchError(
                "deep_worker_input_mismatch",
                "Deep worker coverage must match the authoritative worklist.",
            )
        receipts = _coverage_receipts(coverage.get("receipts"))
        if set(receipts) != worklist_ids:
            raise WorkbenchError(
                "deep_worker_incomplete",
                "Deep worker receipts must cover every authoritative worklist row.",
            )

    def _require_deep_checkpoint_binding(self, scan, content):
        brief_path = _semantic_root(_scan_dir(scan)) / "brief.json"
        brief_digest = _regular_digest(brief_path)
        if content.get("inputDigest") != brief_digest:
            raise WorkbenchError(
                "deep_worker_input_mismatch",
                "Deep checkpoint inputDigest must match the canonical brief.",
            )
        brief = self.read(scan, "brief")
        worklist_ids = _worklist_ids(brief.get("worklist"))
        worklist_digest = _canonical_digest(brief["worklist"])
        if content.get("worklistDigest") != worklist_digest:
            raise WorkbenchError(
                "deep_worker_input_mismatch",
                "Deep checkpoint must match the authoritative worklist.",
            )
        coverage = content.get("partial", {}).get("coverage")
        if coverage is None:
            return
        receipts = _coverage_receipts(coverage.get("receipts"))
        if not set(receipts).issubset(worklist_ids):
            raise WorkbenchError(
                "deep_worker_input_mismatch",
                "Deep checkpoint receipts must belong to the authoritative worklist.",
            )
        if coverage.get("closed") is True and set(receipts) != worklist_ids:
            raise WorkbenchError(
                "deep_worker_incomplete",
                "A closed Deep checkpoint coverage object must cover the worklist.",
            )

    @staticmethod
    def _require_deep_checkpoint_update(previous, content):
        _validate_deep_checkpoint(previous)
        if _canonical_digest(previous) == _canonical_digest(content):
            return
        for key in (
            "scanId",
            "round",
            "worker",
            "inputDigest",
            "worklistDigest",
        ):
            if content.get(key) != previous.get(key):
                raise WorkbenchError(
                    "deep_checkpoint_binding_changed",
                    "Deep checkpoint identity and input bindings are immutable.",
                )
        previous_attempt = previous.get("attempt")
        attempt = content.get("attempt")
        if attempt not in (previous_attempt, previous_attempt + 1):
            raise WorkbenchError(
                "deep_checkpoint_attempt_invalid",
                "Deep checkpoint attempt can remain current or advance by one.",
            )
        if attempt == previous_attempt and previous.get("status") == "failed":
            raise WorkbenchError(
                "deep_checkpoint_attempt_closed",
                "A failed Deep checkpoint requires a new attempt.",
            )

    def _deep_open_round(self, scan, present):
        for round_number in range(1, 11):
            merge_descriptor = _deep_merge_descriptor(round_number)
            if merge_descriptor not in present:
                return round_number
            merge = self.read(scan, merge_descriptor)
            novelty = merge.get("newCanonicalCandidateCount")
            if (
                not isinstance(novelty, int)
                or isinstance(novelty, bool)
                or novelty < 0
            ):
                return None
            if novelty == 0:
                return None
        return None

    def _deep_terminal_state(self, scan, present):
        for round_number in range(1, 11):
            merge_descriptor = _deep_merge_descriptor(round_number)
            if not self._deep_round_complete(scan, round_number, present):
                return None
            merge = self.read(scan, merge_descriptor)
            novelty = merge.get("newCanonicalCandidateCount")
            if (
                not isinstance(novelty, int)
                or isinstance(novelty, bool)
                or novelty < 0
            ):
                return None
            if novelty == 0:
                if _has_deep_artifact_after(present, round_number):
                    return None
                return round_number, "saturated"
            if round_number == 10:
                return 10, "capped"
        return None

    def _deep_workers_complete(self, scan, round_number, present):
        for worker_number in range(1, DEEP_WORKERS_PER_ROUND + 1):
            descriptor = _deep_worker_descriptor(round_number, worker_number)
            if descriptor not in present:
                return False
            worker = self.read(scan, descriptor)
            try:
                self._require_deep_worker_receipt(scan, worker)
            except WorkbenchError:
                return False
        return True

    def _deep_round_complete(self, scan, round_number, present):
        merge_descriptor = _deep_merge_descriptor(round_number)
        if (
            merge_descriptor not in present
            or not self._deep_workers_complete(scan, round_number, present)
        ):
            return False
        try:
            self._require_deep_merge_binding(
                scan,
                round_number,
                self.read(scan, merge_descriptor),
            )
        except WorkbenchError:
            return False
        return True

    def closure(self, scan, persisted=None):
        values = persisted if persisted is not None else self._persisted(
            _scan_dir(scan),
            scan["mode"],
        )
        present = {item["descriptor"] for item in values}
        missing = [
            descriptor
            for descriptor in self._required_descriptors(scan, present)
            if descriptor not in present
        ]
        deep = self._deep_discovery_closure(scan, present)
        if deep is not None:
            missing.extend(deep["missing"])
        if all(
            descriptor in present
            for descriptor in ("discovery", "validation", "attack-path")
        ):
            missing.extend(self._semantic_chain_missing(scan))
        if "discovery" in present and "canonical-result" in present:
            canonical = self.read(scan, "canonical-result")
            if self._candidate_finding_mismatch(scan, canonical):
                missing.append("canonical-findings-require-discovery-candidates")
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
        if (
            "canonical-result" in present
            and self._canonical_finding_count(scan) > 0
        ):
            required.extend(("derived-writeup", "derived-hardening"))
        return required

    def _skip_candidate_tail(self, scan):
        discovery = self.read(scan, "discovery")
        return not _record_ids(
            discovery.get("candidates"),
            "discovery.candidates",
        )

    def _canonical_finding_count(self, scan):
        canonical = self.read(scan, "canonical-result")
        return len(_canonical_findings(canonical))

    def _candidate_finding_mismatch(self, scan, canonical):
        discovery = self.read(scan, "discovery")
        candidates = _record_ids(
            discovery.get("candidates"),
            "discovery.candidates",
        )
        return not candidates and bool(_canonical_findings(canonical))

    def require_candidate_finding_binding(self, scan, canonical=None):
        value = canonical if canonical is not None else self.read(
            scan,
            "canonical-result",
        )
        if self._candidate_finding_mismatch(scan, value):
            raise WorkbenchError(
                "canonical_discovery_mismatch",
                "A scan without discovery candidates cannot contain canonical findings.",
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
        if finding_values:
            _materialize_derived_outputs(
                _scan_dir(scan),
                findings,
                manifest,
                self.read(scan, "derived-writeup"),
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


def _current_descriptor_schemas(scan, deep_keys=None):
    schemas = _descriptor_schemas(scan["mode"])
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
        canonical_path = (
            _semantic_root(_scan_dir(scan)) / "canonical-result.json"
        )
        if canonical_path.exists() and _canonical_findings(_read_json(canonical_path)):
            keys = keys + ("derived-writeup", "derived-hardening")
    return {key: schemas[key] for key in keys}


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


def _validate_content(scan, descriptor, content):
    if not isinstance(content, dict):
        raise WorkbenchError("invalid_artifact", "Artifact content must be an object.")
    if content.get("scanId") != scan["id"]:
        raise WorkbenchError(
            "artifact_scan_mismatch",
            "Artifact scanId must match the authoritative scan.",
        )
    schema_key = _descriptor_schema_key(descriptor)
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
    if descriptor == "brief" and scan["mode"] == "deep":
        _worklist_ids(content.get("worklist"))
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
        _record_ids(content.get("candidates"), "worker.candidates")
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
        _coverage_receipts(coverage.get("receipts"))
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
        _validate_deep_checkpoint(content)
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
        _string_ids(
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
        _atomic_write(root, relative, canonical_json_bytes(receipt))
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
        _atomic_write(root, relative, markdown.encode("utf-8"))
    hardening_outputs = hardening["outputs"]
    if len(hardening_outputs) != 1 or hardening_outputs[0]["path"] != (
        "hardening/hardening.md"
    ):
        raise WorkbenchError(
            "derived_hardening_mismatch",
            "Derived hardening must provide hardening/hardening.md.",
        )
    _atomic_write(
        root,
        "hardening/hardening.md",
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


def _worklist_ids(value):
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


def _validate_deep_checkpoint(content):
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
        _record_ids(partial["candidates"], "checkpoint.partial.candidates")
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
        _coverage_receipts(coverage["receipts"])


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


def _coverage_receipts(value):
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


def _canonical_digest(value):
    try:
        encoded = canonical_json_bytes(value)
    except ArtifactContractError as exc:
        raise WorkbenchError("invalid_artifact", str(exc))
    return hashlib.sha256(encoded).hexdigest()


def _string_ids(value, context):
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


def _deep_worker_descriptor(round_number, worker_number):
    return "discovery-round-%d-worker-%d" % (round_number, worker_number)


def _deep_merge_descriptor(round_number):
    return "discovery-round-%d-merge" % round_number


def _has_deep_artifact_after(present, round_number):
    for descriptor in present:
        worker_match = DEEP_WORKER_RE.fullmatch(descriptor)
        merge_match = DEEP_MERGE_RE.fullmatch(descriptor)
        if worker_match and int(worker_match.group(1)) > round_number:
            return True
        if merge_match and int(merge_match.group(1)) > round_number:
            return True
    return False


def _canonical_findings(canonical):
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


def _require_descriptor(value, mode):
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


def _descriptor_schema_key(descriptor):
    if DEEP_WORKER_RE.fullmatch(descriptor):
        return DEEP_WORKER_SCHEMA_KEY
    if DEEP_CHECKPOINT_RE.fullmatch(descriptor):
        return DEEP_CHECKPOINT_SCHEMA_KEY
    if DEEP_MERGE_RE.fullmatch(descriptor):
        return "discovery-round-<1..10>-merge"
    return descriptor


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


def _atomic_write(root, relative, content):
    try:
        _write_scan_file(root, relative, content)
    except ArtifactContractError as exc:
        raise WorkbenchError(
            "unsafe_artifact_path",
            "Artifact output must stay under the scan directory.",
        ) from exc


def _artifact_state(descriptor, path, digest):
    return {
        "descriptor": descriptor,
        "path": str(path),
        "digest": digest,
        "sizeBytes": path.stat().st_size,
    }
