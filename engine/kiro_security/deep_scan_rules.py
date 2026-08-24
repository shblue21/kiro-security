"""Deep-mode round ordering and binding rules for semantic scan artifacts."""

from .errors import WorkbenchError
from .semantic_contract import (
    DEEP_CHECKPOINT_RE,
    DEEP_MERGE_RE,
    DEEP_WORKER_RE,
    DEEP_WORKERS_PER_ROUND,
    canonical_digest as _canonical_digest,
    coverage_receipts as _coverage_receipts,
    deep_merge_descriptor as _deep_merge_descriptor,
    deep_worker_descriptor as _deep_worker_descriptor,
    has_deep_artifact_after as _has_deep_artifact_after,
    record_ids as _record_ids,
    string_ids as _string_ids,
    validate_deep_checkpoint as _validate_deep_checkpoint,
    worklist_ids as _worklist_ids,
)


class DeepScanRules:
    """Deep write-order authority mixed into the semantic artifact store.

    The host must provide ``read(scan, descriptor)`` for validated artifact
    reads and ``_brief_digest(scan)`` for the canonical brief file digest.
    """

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
        brief_digest = self._brief_digest(scan)
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
        brief_digest = self._brief_digest(scan)
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
