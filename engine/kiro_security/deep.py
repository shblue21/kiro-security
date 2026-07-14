from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .db import Workbench
from .errors import EngineError
from .security import random_id, stable_id, utc_now, write_json

WORKERS_PER_ROUND = 6
MAX_ROUNDS = 10
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_ALLOWED_CONFIDENCE = {"high", "medium", "low"}


class DeepCoordinator:
    """Durable, Agent-driven Deep Security Scan orchestration.

    The Python engine owns the worklist, round barriers, receipts, semantic-merge
    contract and convergence state. The selected Kiro model performs independent
    repository review and submits evidence through MCP; there is no silent local
    regex fallback for Deep mode.
    """

    def __init__(self, workbench: Workbench) -> None:
        self.workbench = workbench

    def ensure(self, scan: dict[str, Any], inventory_data: dict[str, Any]) -> dict[str, Any]:
        existing = self._state_row(scan["id"])
        if existing:
            return self.status(scan["id"])
        files = inventory_data.get("files") or []
        if not files:
            raise EngineError(
                "deep_no_supported_files",
                "Deep Scan cannot prove coverage because the resolved scope contains no supported source files.",
            )
        worklist = []
        for item in files:
            path = str(item.get("path") or "")
            if not path:
                continue
            worklist.append(
                {
                    "rowId": stable_id("deep-row", scan["id"], path),
                    "path": path,
                    "language": item.get("language"),
                    "size": int(item.get("size") or 0),
                }
            )
        if not worklist:
            raise EngineError("deep_no_supported_files", "Deep Scan worklist is empty after inventory normalization.")
        worklist.sort(key=lambda row: row["path"])
        encoded = json.dumps(worklist, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        digest = hashlib.sha256(encoded.encode("utf-8", "surrogatepass")).hexdigest()
        now = utc_now()
        with self.workbench.transaction() as connection:
            connection.execute(
                """
                INSERT INTO deep_scan_state(
                    scan_id, status, current_round, max_rounds, workers_per_round,
                    worklist_digest, worklist_json, canonical_candidates_json,
                    previous_candidate_count, novelty_count, created_at, updated_at
                ) VALUES (?, 'awaiting_workers', 1, ?, ?, ?, ?, '[]', 0, 0, ?, ?)
                """,
                (scan["id"], MAX_ROUNDS, WORKERS_PER_ROUND, digest, encoded, now, now),
            )
            self._create_round(connection, scan["id"], 1, now)
        self._write_shared_worklists(scan, worklist, digest)
        return self.status(scan["id"])

    def _write_shared_worklists(self, scan: dict[str, Any], worklist: list[dict[str, Any]], digest: str) -> None:
        discovery = Path(scan["artifact_dir"]) / "02_discovery"
        discovery.mkdir(parents=True, exist_ok=True)
        for name in ("rank_input.jsonl", "deep_review_input.jsonl"):
            path = discovery / name
            path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in worklist), encoding="utf-8")
        guidance = Path(scan["artifact_dir"]) / "context" / "security_guidance.md"
        guidance.parent.mkdir(parents=True, exist_ok=True)
        guidance.write_text(
            "# Security guidance\n\n"
            "Review the resolved scope without editing repository files. Preserve independently reachable instances, "
            "concrete root-control/source/sink evidence, authorization boundaries, exploitability, and remediation closure.\n\n"
            f"Authoritative worklist SHA-256: `{digest}`\n",
            encoding="utf-8",
        )

    @staticmethod
    def _create_round(connection: Any, scan_id: str, round_number: int, now: str) -> None:
        for worker_index in range(1, WORKERS_PER_ROUND + 1):
            connection.execute(
                """
                INSERT INTO deep_workers(
                    id, scan_id, round_number, worker_index, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', ?, ?)
                """,
                (stable_id("deep-worker", scan_id, str(round_number), str(worker_index)), scan_id, round_number, worker_index, now, now),
            )
        connection.execute(
            """
            INSERT INTO deep_merge_records(id, scan_id, round_number, status, created_at, updated_at)
            VALUES (?, ?, ?, 'pending', ?, ?)
            """,
            (stable_id("deep-merge", scan_id, str(round_number)), scan_id, round_number, now, now),
        )

    def _state_row(self, scan_id: str) -> dict[str, Any] | None:
        connection = self.workbench._connect()
        try:
            row = connection.execute("SELECT * FROM deep_scan_state WHERE scan_id=?", (scan_id,)).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def _require_deep_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.workbench.get_scan(scan_id)
        if scan["mode"] != "deep":
            raise EngineError("not_deep_scan", "The requested scan is not a Deep Security Scan.")
        if scan["phase"] != "discovery":
            raise EngineError("deep_wrong_phase", f"Deep orchestration is available only during discovery; current phase is {scan['phase']}.")
        if scan["status"] not in ("running", "interrupted"):
            raise EngineError("deep_scan_not_active", f"Deep scan is {scan['status']}.")
        if not self._state_row(scan_id):
            raise EngineError("deep_not_ready", "The Deep worklist has not been initialized yet.")
        return scan

    def status(self, scan_id: str) -> dict[str, Any]:
        scan = self.workbench.get_scan(scan_id)
        state = self._state_row(scan_id)
        if not state:
            return {
                "scanId": scan_id,
                "status": "preparing",
                "round": 0,
                "nextAction": "wait_for_discovery",
                "message": "The engine is preparing the authoritative Deep worklist.",
            }
        connection = self.workbench._connect()
        try:
            rows = connection.execute(
                "SELECT status, COUNT(*) AS count FROM deep_workers WHERE scan_id=? AND round_number=? GROUP BY status",
                (scan_id, state["current_round"]),
            ).fetchall()
            counts = {row["status"]: int(row["count"]) for row in rows}
            merge = connection.execute(
                "SELECT status FROM deep_merge_records WHERE scan_id=? AND round_number=?",
                (scan_id, state["current_round"]),
            ).fetchone()
        finally:
            connection.close()
        status = state["status"]
        if scan["status"] == "interrupted":
            next_action = "resume_scan"
        elif status == "awaiting_workers":
            next_action = "claim_worker" if counts.get("pending", 0) else "submit_claimed_workers"
        elif status == "awaiting_merge":
            next_action = "claim_merge" if merge and merge["status"] == "pending" else "submit_merge"
        elif status in ("saturated", "capped"):
            next_action = "wait_for_central_validation"
        else:
            next_action = "inspect_status"
        return {
            "scanId": scan_id,
            "scanStatus": scan["status"],
            "phase": scan["phase"],
            "status": status,
            "round": int(state["current_round"]),
            "maxRounds": int(state["max_rounds"]),
            "workersPerRound": WORKERS_PER_ROUND,
            "workerCounts": counts,
            "canonicalCandidateCount": len(json.loads(state["canonical_candidates_json"])),
            "noveltyCount": int(state["novelty_count"]),
            "worklistDigest": state["worklist_digest"],
            "nextAction": next_action,
            "message": self._status_message(status, int(state["current_round"]), counts),
        }

    @staticmethod
    def _status_message(status: str, round_number: int, counts: dict[str, int]) -> str:
        if status == "awaiting_workers":
            return f"Deep round {round_number}: {counts.get('completed', 0)}/6 independent discovery workers completed."
        if status == "awaiting_merge":
            return f"Deep round {round_number}: all six worker artifacts are closed; semantic merge is required."
        if status == "saturated":
            return f"Deep discovery saturated after round {round_number}; centralized phases are continuing."
        return f"Deep discovery reached its {MAX_ROUNDS}-round cap; centralized phases are continuing with explicit capped coverage."

    def claim_worker(self, scan_id: str, model_id: str, delegation_id: str, runtime: dict[str, Any] | None = None) -> dict[str, Any]:
        scan = self._require_deep_scan(scan_id)
        state = self._state_row(scan_id)
        assert state is not None
        if scan["status"] != "running" or state["status"] != "awaiting_workers":
            raise EngineError("deep_worker_not_available", "The Deep scan is not accepting worker claims.")
        if not model_id or len(model_id) > 256 or not delegation_id or len(delegation_id) > 256:
            raise EngineError("invalid_worker_identity", "modelId and delegationId are required bounded strings.")
        now = utc_now()
        token = random_id("deep-claim")
        with self.workbench.transaction() as connection:
            row = connection.execute(
                """
                SELECT * FROM deep_workers
                WHERE scan_id=? AND round_number=? AND status='pending'
                ORDER BY worker_index LIMIT 1
                """,
                (scan_id, state["current_round"]),
            ).fetchone()
            if row is None:
                raise EngineError("deep_no_pending_worker", "All six workers for this round have already been claimed.")
            duplicate = connection.execute(
                "SELECT 1 FROM deep_workers WHERE scan_id=? AND round_number=? AND delegation_id=?",
                (scan_id, state["current_round"], delegation_id),
            ).fetchone()
            if duplicate:
                raise EngineError("duplicate_delegation", "Each discovery worker must have a fresh delegationId.")
            connection.execute(
                """
                UPDATE deep_workers SET status='claimed', claim_token=?, delegation_id=?, model_id=?, runtime_json=?,
                    claimed_at=?, updated_at=? WHERE id=? AND status='pending'
                """,
                (token, delegation_id, model_id, json.dumps(runtime or {}, separators=(",", ":")), now, now, row["id"]),
            )
        worklist = json.loads(state["worklist_json"])
        worker_index = int(row["worker_index"])
        output_dir = Path(scan["artifact_dir"]) / "deep_discovery" / f"round-{int(state['current_round']):02d}" / f"worker-{worker_index:02d}"
        output_dir.mkdir(parents=True, exist_ok=True)
        assignment = {
            "scanId": scan_id,
            "round": int(state["current_round"]),
            "workerIndex": worker_index,
            "workerId": row["id"],
            "claimToken": token,
            "delegationId": delegation_id,
            "modelId": model_id,
            "scope": scan["scope"],
            "workspaceRoot": str(self.workbench.workspace),
            "worklistDigest": state["worklist_digest"],
            "worklistPath": str(Path(scan["artifact_dir"]) / "02_discovery" / "deep_review_input.jsonl"),
            "securityGuidancePath": str(Path(scan["artifact_dir"]) / "context" / "security_guidance.md"),
            "outputDirectory": str(output_dir),
            "worklist": worklist,
            "brief": self._worker_brief(scan, int(state["current_round"]), worker_index),
            "submissionContract": {
                "reviewedPaths": "Every path in worklist, exactly once, or provide an explicit closure receipt.",
                "candidates": "Evidence-grounded candidates only; include affectedLocations with label/path/lines and remediation.",
                "forbidden": ["repository edits", "reading prior worker results", "top-level validation", "top-level finalization"],
            },
        }
        write_json(output_dir / "assignment.json", assignment)
        return assignment

    @staticmethod
    def _worker_brief(scan: dict[str, Any], round_number: int, worker_index: int) -> str:
        return (
            "You are an independent Deep Security Scan discovery worker, not the coordinator. "
            f"Review the exact target {scan['scope']!r} for round {round_number}, worker {worker_index}. "
            "Read the security guidance and authoritative exhaustive worklist. Generate your own threat model, inspect every worklist row, "
            "preserve independently reachable instances, and return only technically plausible candidates with concrete source/root-control/sink evidence. "
            "Do not read prior worker or merge outputs, do not edit repository files, and do not run centralized validation or final reporting."
        )

    def submit_worker(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = str(params.get("scanId") or "")
        self._require_deep_scan(scan_id)
        worker_id = str(params.get("workerId") or "")
        token = str(params.get("claimToken") or "")
        reviewed_paths = params.get("reviewedPaths")
        candidates = params.get("candidates")
        threat_model = str(params.get("threatModel") or "")
        summary = str(params.get("summary") or "")
        if not isinstance(reviewed_paths, list) or not all(isinstance(item, str) for item in reviewed_paths):
            raise EngineError("invalid_worker_receipts", "reviewedPaths must be an array of worklist paths.")
        if not isinstance(candidates, list):
            raise EngineError("invalid_worker_candidates", "candidates must be an array.")
        state = self._state_row(scan_id)
        assert state is not None
        expected_paths = [row["path"] for row in json.loads(state["worklist_json"])]
        if len(reviewed_paths) != len(set(reviewed_paths)) or set(reviewed_paths) != set(expected_paths):
            missing = sorted(set(expected_paths) - set(reviewed_paths))[:20]
            extra = sorted(set(reviewed_paths) - set(expected_paths))[:20]
            raise EngineError(
                "incomplete_worker_coverage",
                "A Deep discovery worker must close every authoritative worklist row exactly once.",
                {"missing": missing, "extra": extra, "expectedCount": len(expected_paths), "receivedCount": len(reviewed_paths)},
            )
        connection = self.workbench._connect()
        try:
            row = connection.execute("SELECT * FROM deep_workers WHERE id=? AND scan_id=?", (worker_id, scan_id)).fetchone()
        finally:
            connection.close()
        if row is None or row["status"] != "claimed" or row["claim_token"] != token:
            raise EngineError("invalid_worker_claim", "Worker claim is missing, stale, or already completed.")
        normalized = []
        for index, candidate in enumerate(candidates):
            normalized_candidate = self._normalize_candidate(candidate, set(expected_paths))
            normalized_candidate["sourceRef"] = f"r{row['round_number']}-w{row['worker_index']}-c{index + 1}"
            normalized.append(normalized_candidate)
        payload = {
            "threatModel": threat_model[:200000],
            "summary": summary[:20000],
            "reviewedPaths": reviewed_paths,
            "candidates": normalized,
            "worklistDigest": state["worklist_digest"],
        }
        now = utc_now()
        with self.workbench.transaction() as tx:
            tx.execute(
                """
                UPDATE deep_workers SET status='completed', result_json=?, completed_at=?, updated_at=?
                WHERE id=? AND status='claimed' AND claim_token=?
                """,
                (json.dumps(payload, separators=(",", ":"), ensure_ascii=False), now, now, worker_id, token),
            )
            completed = int(tx.execute(
                "SELECT COUNT(*) FROM deep_workers WHERE scan_id=? AND round_number=? AND status='completed'",
                (scan_id, row["round_number"]),
            ).fetchone()[0])
            if completed == WORKERS_PER_ROUND:
                tx.execute("UPDATE deep_scan_state SET status='awaiting_merge', updated_at=? WHERE scan_id=?", (now, scan_id))
        output_dir = Path(self.workbench.get_scan(scan_id)["artifact_dir"]) / "deep_discovery" / f"round-{int(row['round_number']):02d}" / f"worker-{int(row['worker_index']):02d}"
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "worker-result.json", payload)
        return self.status(scan_id)

    def claim_merge(self, scan_id: str) -> dict[str, Any]:
        scan = self._require_deep_scan(scan_id)
        state = self._state_row(scan_id)
        assert state is not None
        if scan["status"] != "running" or state["status"] != "awaiting_merge":
            raise EngineError("deep_merge_not_available", "All six workers must complete before semantic merge can be claimed.")
        now = utc_now()
        token = random_id("deep-merge-claim")
        with self.workbench.transaction() as connection:
            merge = connection.execute(
                "SELECT * FROM deep_merge_records WHERE scan_id=? AND round_number=?",
                (scan_id, state["current_round"]),
            ).fetchone()
            if merge is None or merge["status"] not in ("pending", "claimed"):
                raise EngineError("deep_merge_already_completed", "This round has already been merged.")
            if merge["status"] == "pending":
                connection.execute(
                    "UPDATE deep_merge_records SET status='claimed', claim_token=?, claimed_at=?, updated_at=? WHERE id=?",
                    (token, now, now, merge["id"]),
                )
            else:
                token = str(merge["claim_token"])
            workers = connection.execute(
                "SELECT worker_index, result_json FROM deep_workers WHERE scan_id=? AND round_number=? ORDER BY worker_index",
                (scan_id, state["current_round"]),
            ).fetchall()
        if len(workers) != WORKERS_PER_ROUND or any(row["result_json"] is None for row in workers):
            raise EngineError("incomplete_deep_round", "A merge requires exactly six completed worker artifact sets.")
        worker_candidates = []
        for worker in workers:
            result = json.loads(worker["result_json"])
            worker_candidates.extend(result.get("candidates") or [])
        return {
            "scanId": scan_id,
            "round": int(state["current_round"]),
            "claimToken": token,
            "worklistDigest": state["worklist_digest"],
            "workerCandidateCount": len(worker_candidates),
            "workerCandidates": worker_candidates,
            "priorCanonicalCandidates": json.loads(state["canonical_candidates_json"]),
            "mergeContract": {
                "consumeEveryCurrentSourceRefExactlyOnce": True,
                "preserveEveryPriorCanonicalCandidate": True,
                "mergeOnlyWhenOneRemediationClosesEveryUpstreamCandidate": True,
                "keepIndependentlyReachableSiblingInstancesSeparate": True,
                "stopOnlyAfterAFullRoundAddsZeroNewCanonicalCandidates": True,
            },
        }

    def submit_merge(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = str(params.get("scanId") or "")
        self._require_deep_scan(scan_id)
        token = str(params.get("claimToken") or "")
        raw_candidates = params.get("canonicalCandidates")
        if not isinstance(raw_candidates, list):
            raise EngineError("invalid_merge_candidates", "canonicalCandidates must be an array.")
        state = self._state_row(scan_id)
        assert state is not None
        connection = self.workbench._connect()
        try:
            merge = connection.execute(
                "SELECT * FROM deep_merge_records WHERE scan_id=? AND round_number=?",
                (scan_id, state["current_round"]),
            ).fetchone()
            worker_rows = connection.execute(
                "SELECT result_json FROM deep_workers WHERE scan_id=? AND round_number=? AND status='completed' ORDER BY worker_index",
                (scan_id, state["current_round"]),
            ).fetchall()
        finally:
            connection.close()
        if merge is None or merge["status"] != "claimed" or merge["claim_token"] != token:
            raise EngineError("invalid_merge_claim", "Merge claim is missing, stale, or already completed.")
        if len(worker_rows) != WORKERS_PER_ROUND:
            raise EngineError("incomplete_deep_round", "Exactly six completed workers are required before merge.")
        current_candidates = []
        for row in worker_rows:
            current_candidates.extend(json.loads(row["result_json"]).get("candidates") or [])
        expected_refs = [item["sourceRef"] for item in current_candidates]
        previous = json.loads(state["canonical_candidates_json"])
        previous_ids = {item["canonicalId"] for item in previous}
        worklist_paths = {row["path"] for row in json.loads(state["worklist_json"])}
        normalized = []
        consumed: list[str] = []
        for raw in raw_candidates:
            if not isinstance(raw, dict):
                raise EngineError("invalid_merge_candidate", "Every canonical candidate must be an object.")
            refs = raw.get("sourceRefs") or []
            if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
                raise EngineError("invalid_source_refs", "sourceRefs must be an array of current worker source references.")
            consumed.extend(refs)
            item = self._normalize_candidate(raw, worklist_paths)
            canonical_id = str(raw.get("canonicalId") or stable_id("deep-candidate", item["fingerprint"]))
            item["canonicalId"] = canonical_id
            item["sourceRefs"] = refs
            normalized.append(item)
        if len(consumed) != len(set(consumed)) or set(consumed) != set(expected_refs):
            missing = sorted(set(expected_refs) - set(consumed))[:20]
            extra = sorted(set(consumed) - set(expected_refs))[:20]
            raise EngineError(
                "incomplete_semantic_merge",
                "Semantic merge must consume every current worker sourceRef exactly once.",
                {"missing": missing, "extra": extra},
            )
        output_ids = {item["canonicalId"] for item in normalized}
        missing_previous = sorted(previous_ids - output_ids)
        if missing_previous:
            raise EngineError(
                "canonical_candidate_disappeared",
                "Prior canonical candidates must remain until centralized validation rejects them.",
                {"missingCanonicalIds": missing_previous[:20]},
            )
        if len(output_ids) != len(normalized):
            raise EngineError("duplicate_canonical_id", "Each canonical candidate must have a unique canonicalId.")
        novelty = len(output_ids - previous_ids)
        round_number = int(state["current_round"])
        if novelty == 0:
            terminal = "saturated"
        elif round_number >= int(state["max_rounds"]):
            terminal = "capped"
        else:
            terminal = "awaiting_workers"
        now = utc_now()
        encoded = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False)
        with self.workbench.transaction() as tx:
            tx.execute(
                """
                UPDATE deep_merge_records SET status='completed', consumed_source_refs_json=?,
                    canonical_candidates_json=?, novelty_count=?, completed_at=?, updated_at=?
                WHERE id=? AND status='claimed'
                """,
                (json.dumps(consumed), encoded, novelty, now, now, merge["id"]),
            )
            if terminal == "awaiting_workers":
                next_round = round_number + 1
                tx.execute(
                    """
                    UPDATE deep_scan_state SET status='awaiting_workers', current_round=?,
                        canonical_candidates_json=?, previous_candidate_count=?, novelty_count=?, updated_at=?
                    WHERE scan_id=?
                    """,
                    (next_round, encoded, len(previous), novelty, now, scan_id),
                )
                self._create_round(tx, scan_id, next_round, now)
            else:
                tx.execute(
                    """
                    UPDATE deep_scan_state SET status=?, canonical_candidates_json=?,
                        previous_candidate_count=?, novelty_count=?, updated_at=? WHERE scan_id=?
                    """,
                    (terminal, encoded, len(previous), novelty, now, scan_id),
                )
        scan = self.workbench.get_scan(scan_id)
        merge_dir = Path(scan["artifact_dir"]) / "deep_discovery" / f"round-{round_number:02d}"
        merge_dir.mkdir(parents=True, exist_ok=True)
        write_json(
            merge_dir / "merge.json",
            {"round": round_number, "noveltyCount": novelty, "status": terminal, "canonicalCandidates": normalized},
        )
        write_json(Path(scan["artifact_dir"]) / "02_discovery" / "canonical-candidates.json", normalized)
        return self.status(scan_id)

    def canonical_candidates(self, scan_id: str) -> list[dict[str, Any]] | None:
        state = self._state_row(scan_id)
        if not state or state["status"] not in ("saturated", "capped"):
            return None
        return json.loads(state["canonical_candidates_json"])

    def retry_worker(self, scan_id: str, worker_index: int, reason: str) -> dict[str, Any]:
        self._require_deep_scan(scan_id)
        state = self._state_row(scan_id)
        assert state is not None
        if state["status"] != "awaiting_workers" or worker_index < 1 or worker_index > WORKERS_PER_ROUND:
            raise EngineError("invalid_worker_retry", "Only a claimed or failed worker in the active round can be retried.")
        now = utc_now()
        with self.workbench.transaction() as tx:
            row = tx.execute(
                "SELECT status FROM deep_workers WHERE scan_id=? AND round_number=? AND worker_index=?",
                (scan_id, state["current_round"], worker_index),
            ).fetchone()
            if row is None or row["status"] == "completed":
                raise EngineError("completed_worker_immutable", "Completed Deep worker artifacts are immutable and cannot be retried.")
            tx.execute(
                """
                UPDATE deep_workers SET status='pending', claim_token=NULL, delegation_id=NULL, model_id=NULL,
                    runtime_json=NULL, result_json=NULL, failure_message=?, claimed_at=NULL, completed_at=NULL, updated_at=?
                WHERE scan_id=? AND round_number=? AND worker_index=?
                """,
                (reason[:4000], now, scan_id, state["current_round"], worker_index),
            )
        return self.status(scan_id)

    def _normalize_candidate(self, raw: Any, worklist_paths: set[str]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise EngineError("invalid_candidate", "Candidate must be an object.")
        title = self._bounded(raw.get("title"), "title", 500)
        summary = self._bounded(raw.get("summary"), "summary", 8000)
        rule_id = self._bounded(raw.get("ruleId") or raw.get("rule_id") or "model-discovered.security", "ruleId", 200)
        remediation = self._bounded(raw.get("remediation"), "remediation", 12000)
        locations_raw = raw.get("affectedLocations") or raw.get("affected_locations") or raw.get("locations")
        if not isinstance(locations_raw, list) or not locations_raw:
            raise EngineError("candidate_missing_locations", "Every candidate requires at least one concrete affected location.")
        locations = []
        for item in locations_raw:
            if not isinstance(item, dict):
                raise EngineError("invalid_candidate_location", "Affected locations must be objects.")
            path = self._bounded(item.get("path"), "location.path", 4096)
            if path not in worklist_paths:
                raise EngineError("candidate_path_outside_worklist", f"Candidate evidence path is not in the authoritative worklist: {path}")
            start, end = self._parse_lines(item.get("lines"), item.get("startLine"), item.get("endLine"))
            locations.append({"path": path, "startLine": start, "endLine": end, "role": str(item.get("label") or item.get("role") or "evidence")[:100]})
        severity_raw = raw.get("severity")
        if isinstance(severity_raw, dict):
            severity_level = str(severity_raw.get("level") or "medium").lower()
            score = severity_raw.get("score")
            rationale = str(severity_raw.get("rationale") or "Model-assisted Deep discovery severity; centralized validation may revise it.")
        else:
            severity_level = str(severity_raw or "medium").lower()
            score = raw.get("severityScore")
            rationale = str(raw.get("severityRationale") or "Model-assisted Deep discovery severity; centralized validation may revise it.")
        if severity_level not in _ALLOWED_SEVERITIES:
            raise EngineError("invalid_candidate_severity", f"Unsupported severity: {severity_level}")
        confidence_raw = raw.get("confidence")
        if isinstance(confidence_raw, dict):
            confidence_level = str(confidence_raw.get("level") or "medium").lower()
            confidence_rationale = str(confidence_raw.get("rationale") or "Evidence was supplied by an independent Deep discovery worker.")
        else:
            confidence_level = str(confidence_raw or "medium").lower()
            confidence_rationale = str(raw.get("confidenceRationale") or "Evidence was supplied by an independent Deep discovery worker.")
        if confidence_level not in _ALLOWED_CONFIDENCE:
            raise EngineError("invalid_candidate_confidence", f"Unsupported confidence: {confidence_level}")
        taxonomy = raw.get("taxonomy") if isinstance(raw.get("taxonomy"), dict) else {}
        category = str(taxonomy.get("category") or raw.get("category") or "security")[:200]
        cwe = taxonomy.get("cwe") or raw.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        if not isinstance(cwe, list):
            cwe = []
        identity_raw = raw.get("identity") if isinstance(raw.get("identity"), dict) else {}
        anchor = str(identity_raw.get("anchor") or raw.get("anchor") or rule_id)[:500]
        instance = str(identity_raw.get("instance") or f"{locations[0]['path']}:{locations[0]['startLine']}")[:1000]
        fingerprint_base = json.dumps(
            {"ruleId": rule_id, "anchor": anchor, "instance": instance, "locations": locations},
            sort_keys=True,
            separators=(",", ":"),
        )
        fingerprint = str(raw.get("fingerprint") or f"kiro-security/deep-v1:sha256:{hashlib.sha256(fingerprint_base.encode()).hexdigest()}")
        evidence = []
        supplied_evidence = raw.get("codeEvidence") or raw.get("evidence") or []
        if isinstance(supplied_evidence, list):
            for item in supplied_evidence:
                if not isinstance(item, dict):
                    continue
                path = str(item.get("path") or "")
                if path not in worklist_paths:
                    continue
                start, end = self._parse_lines(item.get("lines"), item.get("startLine"), item.get("endLine"))
                evidence.append(
                    {
                        "kind": str(item.get("kind") or "code")[:100],
                        "label": str(item.get("label") or "Deep discovery evidence")[:500],
                        "path": path,
                        "startLine": start,
                        "endLine": end,
                        "language": item.get("language"),
                        "role": str(item.get("role") or item.get("label") or "evidence")[:100],
                        "code": str(item.get("code") or item.get("snippet") or "")[:12000],
                        "explanation": str(item.get("explanation") or item.get("detail") or summary)[:4000],
                    }
                )
        if not evidence:
            for location in locations:
                evidence.append(
                    {
                        "kind": "code",
                        "label": f"Deep discovery {location['role']}",
                        "path": location["path"],
                        "startLine": location["startLine"],
                        "endLine": location["endLine"],
                        "role": location["role"],
                        "code": self._read_snippet(location["path"], location["startLine"], location["endLine"]),
                        "explanation": summary[:4000],
                    }
                )
        return {
            "fingerprint": fingerprint,
            "ruleId": rule_id,
            "identity": {"anchor": anchor, "instance": instance},
            "title": title,
            "summary": summary,
            "severity": {"level": severity_level, "score": float(score) if isinstance(score, (int, float)) else None, "rationale": rationale[:4000]},
            "confidence": {"level": confidence_level, "rationale": confidence_rationale[:4000]},
            "taxonomy": {"category": category, "cwe": [str(item)[:50] for item in cwe[:20]]},
            "locations": locations,
            "remediation": remediation,
            "codeEvidence": evidence,
            "details": {
                "discoveryEngine": "kiro-agent-deep-orchestration",
                "exploitability": raw.get("exploitability"),
                "impact": raw.get("impact"),
                "sourceToSink": raw.get("sourceToSink"),
                "rootCause": raw.get("rootCause"),
            },
        }

    def _read_snippet(self, relative_path: str, start: int, end: int) -> str:
        try:
            path = (self.workbench.workspace / relative_path).resolve(strict=True)
            if self.workbench.workspace != path and self.workbench.workspace not in path.parents:
                return ""
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(lines[max(0, start - 2):min(len(lines), end + 1)])[:12000]
        except (OSError, UnicodeError):
            return ""

    @staticmethod
    def _parse_lines(lines: Any, start_line: Any, end_line: Any) -> tuple[int, int]:
        if isinstance(lines, str):
            match = re.fullmatch(r"\s*(\d+)\s*(?:[-:]\s*(\d+)\s*)?", lines)
            if not match:
                raise EngineError("invalid_location_lines", f"Invalid affected location lines: {lines}")
            start = int(match.group(1))
            end = int(match.group(2) or start)
        else:
            try:
                start = int(start_line)
                end = int(end_line if end_line is not None else start)
            except (TypeError, ValueError) as exc:
                raise EngineError("invalid_location_lines", "Affected location requires lines or startLine/endLine.") from exc
        if start < 1 or end < start:
            raise EngineError("invalid_location_lines", "Affected location lines must be positive and ordered.")
        return start, end

    @staticmethod
    def _bounded(value: Any, field: str, max_length: int) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > max_length or "\x00" in value:
            raise EngineError("invalid_candidate_field", f"{field} must be a non-empty bounded string.")
        return value.strip()
