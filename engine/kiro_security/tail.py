from __future__ import annotations

import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from .constants import ARTIFACT_KINDS, is_model_scan
from .db import Workbench
from .deep import _PROFILE_FIELDS, DeepCoordinator
from .errors import EngineError
from .hardening import register_model_hardening, render_model_hardening
from .security import atomic_write, random_id, sha256_bytes, stable_id, utc_now, write_json

TAIL_KINDS = ("threat_model", "validation", "attack_path", "writeup", "hardening")
_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
_CONFIDENCES = {"high", "medium", "low"}
_VALIDATION_STATUSES = {"validated", "rejected", "needs_review"}
_MAX_RESULT_BYTES = 1_000_000


class DeepTailCoordinator:
    """One durable assignment workflow shared by every model-based Deep tail stage."""

    def __init__(self, workbench: Workbench, deep: DeepCoordinator) -> None:
        self.workbench = workbench
        self.deep = deep

    @staticmethod
    def _text(value: Any, field: str, maximum: int = 12000) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > maximum or "\x00" in value:
            raise EngineError("invalid_tail_result", f"{field} must be a bounded non-empty string.", {"field": field})
        return value.strip()

    @classmethod
    def _strings(cls, value: Any, field: str, *, required: bool = False, maximum: int = 100) -> list[str]:
        if not isinstance(value, list) or len(value) > maximum:
            raise EngineError("invalid_tail_result", f"{field} must be a bounded array.", {"field": field})
        items = [cls._text(item, f"{field}[]", 8000) for item in value]
        if required and not items:
            raise EngineError("invalid_tail_result", f"{field} must not be empty.", {"field": field})
        return items

    @classmethod
    def _objects(cls, value: Any, field: str, *, required: bool = False, maximum: int = 200) -> list[dict[str, Any]]:
        if not isinstance(value, list) or len(value) > maximum or any(not isinstance(item, dict) for item in value):
            raise EngineError("invalid_tail_result", f"{field} must be a bounded array of objects.", {"field": field})
        if required and not value:
            raise EngineError("invalid_tail_result", f"{field} must not be empty.", {"field": field})
        return value

    @staticmethod
    def _encoded(value: Any) -> str:
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise EngineError("invalid_tail_result", "Tail result must be finite JSON.") from exc
        if len(encoded.encode("utf-8")) > _MAX_RESULT_BYTES:
            raise EngineError("tail_result_too_large", f"Tail result exceeds {_MAX_RESULT_BYTES} bytes.")
        return encoded

    def _require_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.workbench.get_scan(scan_id)
        if not is_model_scan(scan):
            raise EngineError("not_model_scan", "Model tail assignments require an Agent model scan.")
        if scan["status"] != "running" or scan.get("cancellation_requested"):
            raise EngineError("deep_tail_scan_inactive", f"Deep tail submission is unavailable while the scan is {scan['status']}.")
        return scan

    @staticmethod
    def _row(row: Any, *, include_payload: bool = False) -> dict[str, Any]:
        result = {
            "assignmentId": row["id"], "scanId": row["scan_id"], "kind": row["kind"],
            "subjectId": row["subject_id"], "status": row["status"], "attempt": int(row["attempt"]),
            "previousAssignmentId": row["previous_assignment_id"],
            "previousReceiptDigest": row["previous_receipt_digest"], "modelId": row["model_id"],
            "receiptDigest": row["receipt_digest"], "claimedAt": row["claimed_at"],
            "completedAt": row["completed_at"],
        }
        if include_payload:
            result["payload"] = json.loads(row["payload_json"])
        return result

    def status(self, scan_id: str) -> dict[str, Any]:
        connection = self.workbench._connect()
        try:
            rows = connection.execute(
                """
                SELECT current.kind, current.status, COUNT(*) AS count
                FROM deep_tail_assignments current
                WHERE current.scan_id=? AND NOT EXISTS (
                    SELECT 1 FROM deep_tail_assignments newer
                    WHERE newer.scan_id=current.scan_id AND newer.kind=current.kind
                      AND newer.subject_id=current.subject_id AND newer.attempt>current.attempt
                )
                GROUP BY current.kind, current.status
                """,
                (scan_id,),
            ).fetchall()
        finally:
            connection.close()
        counts = {kind: {status: 0 for status in ("pending", "claimed", "completed", "failed")} for kind in TAIL_KINDS}
        for row in rows:
            counts[str(row["kind"])][str(row["status"])] = int(row["count"])
        active_kind = next(
            (kind for kind in TAIL_KINDS if counts[kind]["pending"] or counts[kind]["claimed"] or counts[kind]["failed"]),
            None,
        )
        if active_kind is None:
            if counts["hardening"]["completed"]:
                next_action = "tail_complete"
            elif any(counts[kind]["completed"] for kind in TAIL_KINDS):
                next_action = "await_tail_materialization"
            else:
                next_action = "await_discovery_completion"
        elif counts[active_kind]["pending"]:
            next_action = "claim_tail_assignment"
        elif counts[active_kind]["failed"]:
            next_action = "retry_writeup"
        else:
            next_action = "submit_tail_result"
        return {"activeKind": active_kind, "nextAction": next_action, "counts": counts}

    def _snapshot(self, scan: dict[str, Any]) -> dict[str, Any]:
        state = self.workbench.get_deep_scan_state(scan["id"])
        if state is None:
            raise EngineError("deep_tail_not_ready", "Deep discovery has not prepared its canonical worklist.")
        return {
            "revision": scan.get("target_revision"),
            "snapshotDigest": scan.get("snapshot_digest"),
            "worklistDigest": state["worklist_digest"],
            "securityContextDigest": state["worklist"][0].get("securityContextDigest") if state["worklist"] else None,
            "diffContextDigest": state["worklist"][0].get("diffContextDigest") if state["worklist"] else None,
        }

    def _assert_snapshot(self, scan: dict[str, Any], payload: dict[str, Any]) -> None:
        expected = payload.get("snapshot") or {}
        actual = self._snapshot(scan)
        if expected != actual:
            raise EngineError("deep_tail_snapshot_drift", "The immutable Deep snapshot changed after assignment creation.", {"expected": expected, "actual": actual})
        state = self.workbench.get_deep_scan_state(scan["id"])
        assert state is not None
        self.deep._validate_security_context(scan, state["worklist"])

    def _ensure_assignment(self, scan_id: str, kind: str, subject_id: str, payload: dict[str, Any]) -> None:
        now = utc_now()
        with self.workbench.transaction() as tx:
            existing = tx.execute(
                "SELECT id FROM deep_tail_assignments WHERE scan_id=? AND kind=? AND subject_id=? ORDER BY attempt DESC LIMIT 1",
                (scan_id, kind, subject_id),
            ).fetchone()
            if existing is not None:
                return
            tx.execute(
                """
                INSERT INTO deep_tail_assignments(
                    id, scan_id, kind, subject_id, status, attempt, payload_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'pending', 1, ?, ?, ?)
                """,
                (random_id("tail"), scan_id, kind, subject_id, self._encoded(payload), now, now),
            )

    def _completed(self, scan_id: str, kind: str, subject_id: str | None = None) -> list[Any]:
        connection = self.workbench._connect()
        try:
            if subject_id is None:
                return connection.execute(
                    "SELECT * FROM deep_tail_assignments WHERE scan_id=? AND kind=? AND status='completed' ORDER BY subject_id",
                    (scan_id, kind),
                ).fetchall()
            row = connection.execute(
                "SELECT * FROM deep_tail_assignments WHERE scan_id=? AND kind=? AND subject_id=? AND status='completed' ORDER BY attempt DESC LIMIT 1",
                (scan_id, kind, subject_id),
            ).fetchone()
            return [] if row is None else [row]
        finally:
            connection.close()

    def _threat_payload(self, scan: dict[str, Any]) -> dict[str, Any]:
        state = self.workbench.get_deep_scan_state(scan["id"])
        assert state is not None
        context = self.deep._validate_security_context(scan, state["worklist"])
        connection = self.workbench._connect()
        try:
            workers = connection.execute(
                "SELECT round_number, worker_index FROM deep_workers WHERE scan_id=? AND status='completed' ORDER BY round_number, worker_index",
                (scan["id"],),
            ).fetchall()
        finally:
            connection.close()
        candidates = [
            {
                "canonicalId": item.get("canonicalId"), "ruleId": item.get("ruleId"), "identity": item.get("identity"),
                "title": item.get("title"), "locations": item.get("locations"), "sourceRefs": item.get("sourceRefs"),
            }
            for item in state["canonicalCandidates"]
        ]
        receipts = self.workbench.list_coverage_rows(scan["id"])
        provenance = []
        evidence_paths = {row["path"] for row in state["worklist"]}
        for row in state["worklist"]:
            evidence_paths.update(str(path) for path in row.get("diffSupportingPaths") or [])
        for source in [
            *context.get("repositoryEvidenceSources", []),
            *context.get("policySources", []),
            *context.get("guidanceSources", []),
        ]:
            path = str(source.get("path") or "")
            if not path:
                continue
            if (
                source.get("status") == "ok"
                and source.get("digestScope") == "full_content"
                and str(source.get("contentDigest") or "").startswith("sha256:")
            ):
                evidence_paths.add(path)
            provenance.append({
                "path": path,
                "kind": source.get("kind"),
                "status": source.get("status"),
                "contentDigest": source.get("contentDigest"),
                "appliesTo": source.get("appliesTo"),
            })
        return {
            "scanId": scan["id"], "subjectId": scan["id"], "snapshot": self._snapshot(scan),
            "workerThreatModels": [
                {"round": int(row["round_number"]), "workerIndex": int(row["worker_index"]),
                 "path": f"deep_discovery/round-{int(row['round_number']):02d}/worker-{int(row['worker_index']):02d}/threat-model.md"}
                for row in workers
            ],
            "canonicalCandidates": candidates,
            "coverage": {
                "rowCount": len(receipts),
                "deferred": [{"rowId": row["rowId"], "path": row["path"], "reason": row["reason"]} for row in receipts if row["disposition"] == "deferred"],
            },
            "repositoryContext": {
                "status": "compiled",
                "path": state["worklist"][0]["securityContextPath"],
                "contextDigest": context["contextDigest"],
                "guidanceDigest": context["guidanceProjectionDigest"],
                "sourceProvenance": provenance,
                "unknowns": context.get("unknowns") or [],
                "applicablePolicyPaths": [item["path"] for item in context.get("policySources", [])],
                "applicableGuidancePaths": [item["path"] for item in context.get("guidanceSources", [])],
            },
            "evidencePaths": sorted(evidence_paths),
            "proofContract": {
                "required": ["protectedAssets", "actors", "trustBoundaries", "entrypoints", "privilegedOperations", "securityControls", "highImpactAttackSurfaces", "candidateThreatAssumptions", "evidenceReferences", "unknowns"],
                "repositorySpecific": True,
            },
        }

    def prepare_validation(self, scan_id: str) -> bool:
        scan = self._require_scan(scan_id)
        state = self.workbench.get_deep_scan_state(scan_id)
        if state is None or state["status"] not in ("saturated", "capped"):
            raise EngineError("deep_tail_not_ready", "Tail assignments cannot start before canonical discovery merge completes.")
        self._ensure_assignment(scan_id, "threat_model", scan_id, self._threat_payload(scan))
        threat = self._completed(scan_id, "threat_model", scan_id)
        if not threat:
            return False
        threat_result = json.loads(threat[0]["result_json"])
        findings = [self.workbench.get_finding(item["occurrenceId"]) for item in self.workbench.list_findings(scan_id)]
        for finding in findings:
            self._ensure_assignment(scan_id, "validation", finding["occurrenceId"], {
                "scanId": scan_id, "subjectId": finding["occurrenceId"], "findingId": finding["findingId"],
                "snapshot": self._snapshot(scan),
                "finding": {
                    key: finding[key] for key in ("findingId", "occurrenceId", "ruleId", "fingerprint", "identity", "title", "summary", "severity", "confidence", "taxonomy", "locations", "codeEvidence", "remediation", "details")
                },
                "threatModel": threat_result,
                "reviewPaths": sorted({item["path"] for item in finding["locations"] + finding["codeEvidence"]}),
                "proofContract": {
                    "statuses": sorted(_VALIDATION_STATUSES), "dynamicPreferred": True,
                    "staticFallbackRequiresDynamicUnavailableReason": True,
                },
            })
        return len(self._completed(scan_id, "validation")) == len(findings)

    def prepare_attack_paths_and_writeups(self, scan_id: str) -> bool:
        scan = self._require_scan(scan_id)
        findings = [self.workbench.get_finding(item["occurrenceId"]) for item in self.workbench.list_findings(scan_id)]
        if len(self._completed(scan_id, "validation")) != len(findings):
            raise EngineError("deep_tail_stage_blocked", "Every validation assignment must complete before attack-path assignment creation.")
        eligible = [finding for finding in findings if finding["validationStatus"] in ("validated", "needs_review")]
        for finding in eligible:
            validation = json.loads(self._completed(scan_id, "validation", finding["occurrenceId"])[0]["result_json"])
            self._ensure_assignment(scan_id, "attack_path", finding["occurrenceId"], {
                "scanId": scan_id, "subjectId": finding["occurrenceId"], "findingId": finding["findingId"],
                "snapshot": self._snapshot(scan), "finding": finding, "validation": validation,
                "reviewPaths": sorted({
                    str(path)
                    for row in self.workbench.get_deep_scan_state(scan_id)["worklist"]
                    for path in [row["path"], *(row.get("diffSupportingPaths") or [])]
                }),
                "proofContract": {"evidenceBacked": True, "severityReassessmentRequired": True},
            })
        if len(self._completed(scan_id, "attack_path")) != len(eligible):
            return False
        for finding in eligible:
            attack = json.loads(self._completed(scan_id, "attack_path", finding["occurrenceId"])[0]["result_json"])
            validation = json.loads(self._completed(scan_id, "validation", finding["occurrenceId"])[0]["result_json"])
            self._ensure_assignment(scan_id, "writeup", finding["occurrenceId"], {
                "scanId": scan_id, "subjectId": finding["occurrenceId"], "findingId": finding["findingId"],
                "slug": self._slug(finding["findingId"]), "snapshot": self._snapshot(scan),
                "finding": finding, "validation": validation, "attackPath": attack,
                "proofContract": {"structuredSectionsRequired": True, "engineOwnsPaths": True},
            })
        return len(self._completed(scan_id, "writeup")) == len(eligible)

    def prepare_hardening(self, scan_id: str) -> bool:
        scan = self._require_scan(scan_id)
        findings = [self.workbench.get_finding(item["occurrenceId"]) for item in self.workbench.list_findings(scan_id)]
        eligible = [finding for finding in findings if finding["validationStatus"] in ("validated", "needs_review")]
        if len(self._completed(scan_id, "writeup")) != len(eligible):
            raise EngineError("deep_tail_stage_blocked", "Every required writeup must complete before hardening assignment creation.")
        threat = self._completed(scan_id, "threat_model", scan_id)
        if not threat:
            raise EngineError("deep_tail_stage_blocked", "Canonical threat-model synthesis must complete before hardening.")
        subjects = []
        for finding in eligible:
            subjects.append({
                "finding": finding,
                "validation": json.loads(self._completed(scan_id, "validation", finding["occurrenceId"])[0]["result_json"]),
                "attackPath": json.loads(self._completed(scan_id, "attack_path", finding["occurrenceId"])[0]["result_json"]),
            })
        self._ensure_assignment(scan_id, "hardening", scan_id, {
            "scanId": scan_id, "subjectId": scan_id, "snapshot": self._snapshot(scan),
            "threatModel": json.loads(threat[0]["result_json"]), "findings": subjects,
            "proofContract": {"multipleOptions": True, "tradeoffs": True, "jsonSourceMarkdownProjection": True},
        })
        completed = self._completed(scan_id, "hardening", scan_id)
        if completed:
            register_model_hardening(scan_id, json.loads(completed[0]["result_json"]))
        return bool(completed)

    def claim(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = self._text(params.get("scanId"), "scanId", 256)
        scan = self._require_scan(scan_id)
        state = self.workbench.get_deep_scan_state(scan_id)
        if state is None or state["status"] not in ("saturated", "capped"):
            raise EngineError("deep_tail_not_ready", "No tail assignment is claimable before canonical discovery completes.")
        model_id = self._text(params.get("modelId"), "modelId", 256)
        delegation_id = self._text(params.get("delegationId"), "delegationId", 256)
        runtime = self.deep._normalize_runtime_attestation(params.get("runtime"))
        candidate_profile = self.deep._worker_profile(model_id, runtime)
        preflight = (scan.get("capabilities") or {}).get("deepHost") or {}
        expected_profile = self.deep._worker_profile(str(preflight.get("modelId") or ""), preflight.get("runtime") or {})
        for field in _PROFILE_FIELDS:
            if candidate_profile.get(field) != expected_profile.get(field):
                raise EngineError("deep_worker_profile_mismatch", "Tail assignment profile must match Deep preflight.", {"field": field, "expected": expected_profile.get(field), "actual": candidate_profile.get(field)})
        now = utc_now()
        token = random_id("tail-claim")
        with self.workbench.transaction() as tx:
            row = tx.execute(
                """
                SELECT * FROM deep_tail_assignments WHERE scan_id=? AND status='pending'
                ORDER BY CASE kind WHEN 'threat_model' THEN 0 WHEN 'validation' THEN 1 WHEN 'attack_path' THEN 2 WHEN 'writeup' THEN 3 ELSE 4 END,
                         created_at, subject_id LIMIT 1
                """,
                (scan_id,),
            ).fetchone()
            if row is None:
                raise EngineError("deep_tail_not_available", "No eligible pending Deep tail assignment is available.")
            self._assert_snapshot(scan, json.loads(row["payload_json"]))
            try:
                tx.execute(
                    """
                    UPDATE deep_tail_assignments SET status='claimed', claim_token=?, delegation_id=?, model_id=?, runtime_json=?,
                        claimed_at=?, updated_at=? WHERE id=? AND status='pending'
                    """,
                    (token, delegation_id, model_id, self._encoded(runtime), now, now, row["id"]),
                )
            except Exception as exc:
                if "UNIQUE" in str(exc):
                    raise EngineError("duplicate_delegation", "Each Deep tail assignment requires a fresh delegationId.") from exc
                raise
            claimed = tx.execute("SELECT * FROM deep_tail_assignments WHERE id=?", (row["id"],)).fetchone()
        result = self._row(claimed, include_payload=True)
        result["claimToken"] = token
        result["modelProfile"] = candidate_profile
        result["submissionContract"] = {
            "completionAttestation": {"freshContext": True, "coordinatorHistoryInherited": False, "workerState": "completed_idle"},
            "sameModelRuntimeAndDelegationAsClaim": True,
        }
        return result

    def submit(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = self._text(params.get("scanId"), "scanId", 256)
        assignment_id = self._text(params.get("assignmentId"), "assignmentId", 256)
        token = self._text(params.get("claimToken"), "claimToken", 256)
        model_id = self._text(params.get("modelId"), "modelId", 256)
        delegation_id = self._text(params.get("delegationId"), "delegationId", 256)
        scan = self._require_scan(scan_id)
        runtime = self.deep._normalize_runtime_attestation(params.get("runtime"))
        completion = self.deep._normalize_completion_attestation(params.get("completionAttestation"))
        connection = self.workbench._connect()
        try:
            row = connection.execute("SELECT * FROM deep_tail_assignments WHERE id=? AND scan_id=?", (assignment_id, scan_id)).fetchone()
        finally:
            connection.close()
        if row is None or row["status"] != "claimed" or row["claim_token"] != token:
            raise EngineError("invalid_tail_claim", "Tail assignment claim is missing, stale, or already completed.")
        if row["model_id"] != model_id or row["delegation_id"] != delegation_id or json.loads(row["runtime_json"] or "{}") != runtime:
            raise EngineError("deep_tail_profile_mismatch", "Tail completion profile must exactly match its claim profile.")
        payload = json.loads(row["payload_json"])
        self._assert_snapshot(scan, payload)
        normalized = self._normalize_result(str(row["kind"]), str(row["subject_id"]), params.get("result"), payload)
        receipt_digest = "sha256:" + sha256_bytes(self._encoded({
            "assignmentId": assignment_id, "kind": row["kind"], "subjectId": row["subject_id"],
            "attempt": int(row["attempt"]), "modelProfile": self.deep._worker_profile(model_id, runtime),
            "completionAttestation": completion, "result": normalized,
        }).encode("utf-8"))
        now = utc_now()
        with self.workbench.transaction() as tx:
            current = tx.execute("SELECT * FROM deep_tail_assignments WHERE id=?", (assignment_id,)).fetchone()
            if current is None or current["status"] != "claimed" or current["claim_token"] != token:
                raise EngineError("invalid_tail_claim", "Tail assignment became stale before completion.")
            self._materialize(tx, scan, current, normalized, receipt_digest)
            cursor = tx.execute(
                """
                UPDATE deep_tail_assignments SET status='completed', result_json=?, completion_json=?, receipt_digest=?, completed_at=?, updated_at=?
                WHERE id=? AND status='claimed' AND claim_token=?
                """,
                (self._encoded(normalized), self._encoded(completion), receipt_digest, now, now, assignment_id, token),
            )
            if cursor.rowcount != 1:
                raise EngineError("invalid_tail_claim", "Tail assignment became stale before completion commit.")
        return {"assignmentId": assignment_id, "kind": row["kind"], "status": "completed", "receiptDigest": receipt_digest, "completionAttestation": completion}

    def retry_writeup(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = self._text(params.get("scanId"), "scanId", 256)
        assignment_id = self._text(params.get("assignmentId"), "assignmentId", 256)
        reason = self._text(params.get("reason") or "Incomplete writeup retry requested.", "reason", 4000)
        scan = self._require_scan(scan_id)
        now = utc_now()
        with self.workbench.transaction() as tx:
            row = tx.execute("SELECT * FROM deep_tail_assignments WHERE id=? AND scan_id=?", (assignment_id, scan_id)).fetchone()
            if row is None or row["kind"] != "writeup":
                raise EngineError("tail_assignment_not_found", "Writeup assignment was not found.")
            latest = tx.execute(
                "SELECT * FROM deep_tail_assignments WHERE scan_id=? AND kind='writeup' AND subject_id=? ORDER BY attempt DESC LIMIT 1",
                (scan_id, row["subject_id"]),
            ).fetchone()
            if latest["id"] != assignment_id:
                raise EngineError("stale_tail_assignment", "Only the latest writeup attempt can be retried.")
            if row["status"] == "completed":
                raise EngineError("completed_tail_assignment_immutable", "Completed Deep writeup artifacts are immutable.")
            self._clean_writeup(scan, str(row["subject_id"]))
            tx.execute("UPDATE deep_tail_assignments SET status='failed', failure_message=?, updated_at=? WHERE id=?", (reason, now, assignment_id))
            new_id = random_id("tail")
            tx.execute(
                """
                INSERT INTO deep_tail_assignments(
                    id, scan_id, kind, subject_id, status, attempt, previous_assignment_id,
                    previous_receipt_digest, payload_json, created_at, updated_at
                ) VALUES (?, ?, 'writeup', ?, 'pending', ?, ?, ?, ?, ?, ?)
                """,
                (new_id, scan_id, row["subject_id"], int(row["attempt"]) + 1, assignment_id, row["receipt_digest"], row["payload_json"], now, now),
            )
        return {"assignmentId": new_id, "kind": "writeup", "status": "pending", "attempt": int(row["attempt"]) + 1, "previousAssignmentId": assignment_id, "previousReceiptDigest": row["receipt_digest"]}

    def threat_model(self, scan_id: str) -> dict[str, Any]:
        rows = self._completed(scan_id, "threat_model", scan_id)
        if not rows:
            raise EngineError("deep_tail_stage_blocked", "Canonical threat model is incomplete.")
        return json.loads(rows[0]["result_json"])

    def writeup_paths(self, scan_id: str) -> dict[str, str]:
        paths: dict[str, str] = {}
        for row in self._completed(scan_id, "writeup"):
            payload = json.loads(row["payload_json"])
            finding_id = str(payload["findingId"])
            slug = self._slug(finding_id)
            paths[finding_id] = (Path("findings") / slug / f"{slug}.md").as_posix()
        return paths

    def completed_results(self, scan_id: str) -> dict[str, dict[str, dict[str, Any]]]:
        results: dict[str, dict[str, dict[str, Any]]] = {kind: {} for kind in TAIL_KINDS}
        connection = self.workbench._connect()
        try:
            rows = connection.execute(
                "SELECT kind, subject_id, result_json FROM deep_tail_assignments WHERE scan_id=? AND status='completed'",
                (scan_id,),
            ).fetchall()
        finally:
            connection.close()
        for row in rows:
            results[str(row["kind"])][str(row["subject_id"])] = json.loads(row["result_json"])
        return results

    def _normalize_result(self, kind: str, subject_id: str, raw: Any, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise EngineError("invalid_tail_result", "Tail result must be an object.")
        normalizers = {
            "threat_model": self._normalize_threat_model,
            "validation": self._normalize_validation,
            "attack_path": self._normalize_attack_path,
            "writeup": self._normalize_writeup,
            "hardening": self._normalize_hardening,
        }
        result = normalizers[kind](raw, payload)
        expected_identity = payload["scanId"] if kind in ("threat_model", "hardening") else payload["findingId"]
        actual_identity = result["scanId"] if kind in ("threat_model", "hardening") else result["findingId"]
        if actual_identity != expected_identity or payload["subjectId"] != subject_id:
            raise EngineError("tail_subject_mismatch", "Tail result identity does not match its durable assignment subject.")
        self._encoded(result)
        return result

    def _normalize_threat_model(self, raw: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        valid_paths = set(payload["evidencePaths"])
        evidence = self._objects(raw.get("evidenceReferences"), "evidenceReferences", required=True)
        normalized_evidence = []
        for item in evidence:
            path = self._text(item.get("path"), "evidenceReferences[].path", 4096)
            if path not in valid_paths:
                raise EngineError("tail_evidence_outside_snapshot", f"Threat-model evidence path is outside the worklist: {path}")
            normalized_evidence.append({"path": path, "reason": self._text(item.get("reason"), "evidenceReferences[].reason", 4000)})
        assumptions = self._objects(raw.get("candidateThreatAssumptions"), "candidateThreatAssumptions")
        expected_ids = {item.get("canonicalId") for item in payload["canonicalCandidates"]}
        submitted_ids = [item.get("canonicalId") for item in assumptions]
        if len(submitted_ids) != len(set(submitted_ids)) or set(submitted_ids) != expected_ids:
            raise EngineError("tail_candidate_identity_mismatch", "Threat assumptions must cover every canonical candidate exactly once.")
        normalized_assumptions = [{"canonicalId": item["canonicalId"], "assumption": self._text(item.get("assumption"), "candidateThreatAssumptions[].assumption", 8000)} for item in assumptions]
        return {
            "scanId": self._text(raw.get("scanId"), "scanId", 256),
            "summary": self._text(raw.get("summary"), "summary", 12000),
            "protectedAssets": self._strings(raw.get("protectedAssets"), "protectedAssets", required=True),
            "actors": self._strings(raw.get("actors"), "actors", required=True),
            "trustBoundaries": self._strings(raw.get("trustBoundaries"), "trustBoundaries", required=True),
            "entrypoints": self._strings(raw.get("entrypoints"), "entrypoints", required=True),
            "privilegedOperations": self._strings(raw.get("privilegedOperations"), "privilegedOperations", required=True),
            "securityControls": self._strings(raw.get("securityControls"), "securityControls", required=True),
            "highImpactAttackSurfaces": self._strings(raw.get("highImpactAttackSurfaces"), "highImpactAttackSurfaces", required=True),
            "candidateThreatAssumptions": normalized_assumptions,
            "evidenceReferences": normalized_evidence,
            "unknowns": self._strings(raw.get("unknowns"), "unknowns"),
        }

    def _normalize_validation(self, raw: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        status = self._text(raw.get("status"), "status", 32)
        if status not in _VALIDATION_STATUSES:
            raise EngineError("invalid_tail_result", "validation.status must be validated, rejected, or needs_review.")
        method = self._text(raw.get("method"), "method", 200)
        dynamic_reason = raw.get("dynamicValidationUnavailableReason")
        if "static" in method.lower() and (not isinstance(dynamic_reason, str) or not dynamic_reason.strip()):
            raise EngineError("static_fallback_reason_required", "Static validation fallback requires a concrete dynamicValidationUnavailableReason.")
        evidence = self._objects(raw.get("evidence"), "evidence", required=True)
        review_paths = set(payload["reviewPaths"])
        if any(item.get("path") not in review_paths for item in evidence):
            raise EngineError("tail_evidence_outside_snapshot", "Validation evidence must reference an assigned review path.")
        tests = self._objects(raw.get("tests"), "tests")
        return {
            "findingId": self._text(raw.get("findingId"), "findingId", 256), "status": status, "method": method,
            "rationale": self._text(raw.get("rationale"), "rationale", 12000),
            "evidence": [{"path": self._text(item.get("path"), "evidence[].path", 4096), "result": self._text(item.get("result"), "evidence[].result", 8000)} for item in evidence],
            "counterevidence": self._strings(raw.get("counterevidence"), "counterevidence"),
            "crossFileTrace": self._strings(raw.get("crossFileTrace"), "crossFileTrace"),
            "frameworkControls": self._strings(raw.get("frameworkControls"), "frameworkControls", required=True),
            "proofGaps": self._strings(raw.get("proofGaps"), "proofGaps"),
            "tests": [{"name": self._text(item.get("name"), "tests[].name", 500), "result": self._text(item.get("result"), "tests[].result", 12000)} for item in tests],
            "dynamicValidationUnavailableReason": None if dynamic_reason in (None, "") else self._text(dynamic_reason, "dynamicValidationUnavailableReason", 8000),
        }

    def _normalize_attack_path(self, raw: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        severity = raw.get("severity")
        if not isinstance(severity, dict):
            raise EngineError("attack_path_severity_required", "Attack-path result requires severity reassessment.")
        level = self._text(severity.get("level"), "severity.level", 32)
        if level not in _SEVERITIES:
            raise EngineError("invalid_tail_result", "Unsupported attack-path severity level.")
        rationale = self._text(severity.get("rationale"), "severity.rationale", 8000)
        path = self._objects(raw.get("crossFilePath"), "crossFilePath", required=True)
        review_paths = set(payload["reviewPaths"])
        if any(item.get("path") not in review_paths for item in path):
            raise EngineError("tail_evidence_outside_snapshot", "Attack-path evidence must reference the immutable Deep worklist.")
        normalized_path = [{"path": self._text(item.get("path"), "crossFilePath[].path", 4096), "step": self._text(item.get("step"), "crossFilePath[].step", 8000)} for item in path]
        confidence = raw.get("confidence")
        if not isinstance(confidence, dict):
            raise EngineError("invalid_tail_result", "Attack-path confidence requires level and rationale.")
        confidence_level = self._text(confidence.get("level"), "confidence.level", 32)
        if confidence_level not in _CONFIDENCES:
            raise EngineError("invalid_tail_result", "Unsupported attack-path confidence.")
        return {
            "findingId": self._text(raw.get("findingId"), "findingId", 256),
            "narrative": self._text(raw.get("narrative"), "narrative", 16000),
            "actor": self._text(raw.get("actor"), "actor", 4000),
            "attackerPrerequisite": self._text(raw.get("attackerPrerequisite"), "attackerPrerequisite", 4000),
            "entrypoint": self._text(raw.get("entrypoint"), "entrypoint", 4000),
            "attackerControlledSource": self._text(raw.get("attackerControlledSource"), "attackerControlledSource", 4000),
            "rootControl": self._text(raw.get("rootControl"), "rootControl", 4000),
            "controlBypass": self._text(raw.get("controlBypass"), "controlBypass", 8000),
            "crossFilePath": normalized_path,
            "privilegedSink": self._text(raw.get("privilegedSink"), "privilegedSink", 4000),
            "impact": self._text(raw.get("impact"), "impact", 8000),
            "exploitPreconditions": self._strings(raw.get("exploitPreconditions"), "exploitPreconditions", required=True),
            "counterevidence": self._strings(raw.get("counterevidence"), "counterevidence"),
            "residualUncertainty": self._text(raw.get("residualUncertainty"), "residualUncertainty", 8000),
            "severity": {"level": level, "rationale": rationale},
            "exploitability": self._text(raw.get("exploitability"), "exploitability", 4000),
            "confidence": {"level": confidence_level, "rationale": self._text(confidence.get("rationale"), "confidence.rationale", 8000)},
        }

    def _normalize_writeup(self, raw: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        sections = raw.get("sections")
        if not isinstance(sections, dict):
            raise EngineError("writeup_sections_required", "Writeup result requires structured sections.")
        names = (
            "title", "severity", "executiveSummary", "affectedComponent", "threatContext", "rootCause",
            "evidence", "validationProof", "counterevidence", "attackPath", "impact", "remediation",
            "verificationGuidance", "proofGaps",
        )
        normalized_sections = {name: self._text(sections.get(name), f"sections.{name}", 30000) for name in names}
        pocs = self._objects(raw.get("poc", []), "poc", maximum=20)
        normalized_pocs = []
        for item in pocs:
            relative = self._safe_poc_path(item.get("relativePath"))
            normalized_pocs.append({"relativePath": relative, "content": self._text(item.get("content"), "poc[].content", 100000)})
        return {"findingId": self._text(raw.get("findingId"), "findingId", 256), "sections": normalized_sections, "poc": normalized_pocs}

    def _normalize_hardening(self, raw: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        options = self._objects(raw.get("options"), "options", required=True, maximum=20)
        if len(options) < 2:
            raise EngineError("hardening_options_incomplete", "Hardening requires at least two viable options with tradeoffs.")
        normalized_options = [{
            "id": self._text(item.get("id"), "options[].id", 100), "title": self._text(item.get("title"), "options[].title", 500),
            "description": self._text(item.get("description"), "options[].description", 12000),
            "advantages": self._strings(item.get("advantages"), "options[].advantages", required=True),
            "disadvantages": self._strings(item.get("disadvantages"), "options[].disadvantages", required=True),
            "tradeoffs": self._text(item.get("tradeoffs"), "options[].tradeoffs", 8000),
            "evidenceRefs": self._strings(item.get("evidenceRefs"), "options[].evidenceRefs", required=True),
        } for item in options]
        option_ids = {item["id"] for item in normalized_options}
        recommended = self._text(raw.get("recommendedOptionId"), "recommendedOptionId", 100)
        if recommended not in option_ids:
            raise EngineError("invalid_tail_result", "recommendedOptionId must identify a submitted hardening option.")
        packages = self._objects(raw.get("workPackages"), "workPackages", required=True)
        normalized_packages = [{
            "id": self._text(item.get("id"), "workPackages[].id", 100), "title": self._text(item.get("title"), "workPackages[].title", 500),
            "dependencies": self._strings(item.get("dependencies"), "workPackages[].dependencies"),
            "deliverables": self._strings(item.get("deliverables"), "workPackages[].deliverables", required=True),
        } for item in packages]
        return {
            "scanId": self._text(raw.get("scanId"), "scanId", 256),
            "title": self._text(raw.get("title"), "title", 500),
            "summary": self._text(raw.get("summary"), "summary", 12000),
            "architectureBoundaries": self._strings(raw.get("architectureBoundaries"), "architectureBoundaries", required=True),
            "options": normalized_options, "recommendedOptionId": recommended,
            "recommendationRationale": self._text(raw.get("recommendationRationale"), "recommendationRationale", 12000),
            "migrationSteps": self._strings(raw.get("migrationSteps"), "migrationSteps", required=True),
            "rolloutPlan": self._strings(raw.get("rolloutPlan"), "rolloutPlan", required=True),
            "rollbackPlan": self._strings(raw.get("rollbackPlan"), "rollbackPlan", required=True),
            "successMetrics": self._strings(raw.get("successMetrics"), "successMetrics", required=True),
            "workPackages": normalized_packages,
            "diagram": self._text(raw.get("diagram"), "diagram", 20000),
            "evidenceReferences": self._strings(raw.get("evidenceReferences"), "evidenceReferences", required=True),
        }

    def _materialize(self, tx: Any, scan: dict[str, Any], row: Any, result: dict[str, Any], receipt_digest: str) -> None:
        kind = str(row["kind"])
        subject_id = str(row["subject_id"])
        if kind == "threat_model":
            write_json(self._safe_artifact_path(scan, Path("deep_tail") / "threat-model.json"), result)
            atomic_write(self._safe_artifact_path(scan, ARTIFACT_KINDS["threatModel"]), self._render_threat_model(result))
        elif kind == "validation":
            tx.execute(
                "INSERT INTO validation_records(id, occurrence_id, status, method, rationale, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (random_id("val"), subject_id, result["status"], result["method"], result["rationale"], self._encoded(result["evidence"]), utc_now()),
            )
            tx.execute("UPDATE finding_occurrences SET validation_status=?, updated_at=? WHERE id=?", (result["status"], utc_now(), subject_id))
            self._save_provenance(tx, subject_id, row, receipt_digest)
        elif kind == "attack_path":
            tx.execute(
                """
                INSERT INTO attack_paths(id, occurrence_id, narrative, path_json, exploitability, impact, severity_rationale, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(occurrence_id) DO UPDATE SET narrative=excluded.narrative, path_json=excluded.path_json,
                    exploitability=excluded.exploitability, impact=excluded.impact,
                    severity_rationale=excluded.severity_rationale, updated_at=excluded.updated_at
                """,
                (stable_id("path", subject_id), subject_id, result["narrative"], self._encoded(result["crossFilePath"]), result["exploitability"], result["impact"], result["severity"]["rationale"], utc_now(), utc_now()),
            )
            tx.execute(
                "UPDATE finding_occurrences SET severity=?, severity_rationale=?, confidence=?, confidence_rationale=?, updated_at=? WHERE id=?",
                (result["severity"]["level"], result["severity"]["rationale"], result["confidence"]["level"], result["confidence"]["rationale"], utc_now(), subject_id),
            )
            self._save_provenance(tx, subject_id, row, receipt_digest)
        elif kind == "writeup":
            self._materialize_writeup(scan, row, result)
            self._save_provenance(tx, subject_id, row, receipt_digest)
        elif kind == "hardening":
            json_path = self._safe_artifact_path(scan, Path("hardening") / "hardening.json")
            markdown_path = self._safe_artifact_path(scan, ARTIFACT_KINDS["hardening"])
            write_json(json_path, result)
            rendered = render_model_hardening(result)
            atomic_write(markdown_path, rendered["content"])
            tx.execute(
                """
                INSERT INTO hardening_proposals(id, scan_id, title, summary, artifact_path, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET title=excluded.title, summary=excluded.summary, artifact_path=excluded.artifact_path, updated_at=excluded.updated_at
                """,
                (stable_id("hard", scan["id"]), scan["id"], result["title"], result["summary"], str(markdown_path), utc_now(), utc_now()),
            )
            register_model_hardening(scan["id"], result)

    def _save_provenance(self, tx: Any, occurrence_id: str, row: Any, receipt_digest: str) -> None:
        finding = tx.execute("SELECT details_json FROM finding_occurrences WHERE id=?", (occurrence_id,)).fetchone()
        if finding is None:
            raise EngineError("finding_not_found", f"Finding occurrence not found: {occurrence_id}")
        details = json.loads(finding["details_json"] or "{}")
        runtime = json.loads(row["runtime_json"] or "{}")
        profile = {field: (row["model_id"] if field == "modelId" else runtime.get(field)) for field in _PROFILE_FIELDS}
        provenance = details.setdefault("deepTailProvenance", {})
        provenance[str(row["kind"])] = {
            "assignmentId": row["id"], "kind": row["kind"], "attempt": int(row["attempt"]),
            "modelProfile": profile, "receiptDigest": receipt_digest,
        }
        tx.execute("UPDATE finding_occurrences SET details_json=?, updated_at=? WHERE id=?", (self._encoded(details), utc_now(), occurrence_id))

    @staticmethod
    def _render_threat_model(result: dict[str, Any]) -> str:
        sections = [
            ("Protected assets", result["protectedAssets"]), ("Actors", result["actors"]),
            ("Trust boundaries", result["trustBoundaries"]), ("Entrypoints", result["entrypoints"]),
            ("Privileged operations", result["privilegedOperations"]), ("Security controls", result["securityControls"]),
            ("High-impact attack surfaces", result["highImpactAttackSurfaces"]), ("Unknowns and proof gaps", result["unknowns"]),
        ]
        lines = ["# Canonical model threat model", "", result["summary"], ""]
        for title, items in sections:
            lines.extend([f"## {title}", "", *[f"- {item}" for item in items], ""])
        lines.extend(["## Candidate threat assumptions", ""])
        lines.extend(f"- `{item['canonicalId']}`: {item['assumption']}" for item in result["candidateThreatAssumptions"])
        lines.extend(["", "## Evidence references", ""])
        lines.extend(f"- `{item['path']}`: {item['reason']}" for item in result["evidenceReferences"])
        return "\n".join(lines) + "\n"

    @staticmethod
    def _slug(finding_id: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", finding_id):
            raise EngineError("unsafe_writeup_slug", "Finding identity cannot be converted to a safe writeup slug.")
        return finding_id.lower()

    @staticmethod
    def _safe_artifact_path(scan: dict[str, Any], relative: str | Path) -> Path:
        root = Path(scan["artifact_dir"])
        candidate_relative = Path(relative)
        if candidate_relative.is_absolute() or any(part in ("", ".", "..") for part in candidate_relative.parts):
            raise EngineError("unsafe_artifact_path", f"Artifact path must stay relative to the scan directory: {relative}")
        try:
            resolved_root = root.resolve(strict=True)
        except OSError as exc:
            raise EngineError("unsafe_artifact_path", f"Unable to resolve scan artifact directory: {root}") from exc
        if root.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to use symlink scan artifact directory: {root}")
        current = root
        for part in candidate_relative.parts:
            current = current / part
            if current.is_symlink():
                raise EngineError("unsafe_artifact_path", f"Refusing to use symlink artifact path: {current}")
        try:
            resolved = (root / candidate_relative).resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise EngineError("unsafe_artifact_path", f"Unable to resolve artifact path: {relative}") from exc
        if resolved != resolved_root and resolved_root not in resolved.parents:
            raise EngineError("unsafe_artifact_path", f"Artifact path escapes the scan directory: {relative}")
        return root / candidate_relative

    @classmethod
    def _safe_poc_path(cls, value: Any) -> str:
        text = cls._text(value, "poc[].relativePath", 512)
        path = PurePosixPath(text)
        if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
            raise EngineError("unsafe_writeup_path", "PoC paths must be safe relative paths below the finding poc directory.")
        return path.as_posix()

    def _writeup_root(self, scan: dict[str, Any], occurrence_id: str) -> tuple[Path, str]:
        finding = self.workbench.get_finding(occurrence_id)
        slug = self._slug(finding["findingId"])
        root = self._safe_artifact_path(scan, Path("findings") / slug)
        return root, slug

    def _materialize_writeup(self, scan: dict[str, Any], row: Any, result: dict[str, Any]) -> None:
        root, slug = self._writeup_root(scan, str(row["subject_id"]))
        if root.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to write through symlink: {root}")
        root.mkdir(parents=True, exist_ok=True)
        markdown = root / f"{slug}.md"
        if markdown.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to replace symlink: {markdown}")
        sections = result["sections"]
        order = (
            ("Executive summary", "executiveSummary"), ("Affected component", "affectedComponent"),
            ("Threat context", "threatContext"), ("Root cause", "rootCause"), ("Evidence", "evidence"),
            ("Validation proof", "validationProof"), ("Counterevidence", "counterevidence"),
            ("Attack path", "attackPath"), ("Concrete impact", "impact"), ("Remediation", "remediation"),
            ("Verification guidance", "verificationGuidance"), ("Remaining proof gaps", "proofGaps"),
        )
        lines = [f"# {sections['title']}", "", f"Severity: **{sections['severity']}**", ""]
        for title, key in order:
            lines.extend([f"## {title}", "", sections[key], ""])
        atomic_write(markdown, "\n".join(lines))
        poc_root = root / "poc"
        if poc_root.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to write through symlink: {poc_root}")
        if poc_root.exists():
            shutil.rmtree(poc_root)
        for item in result["poc"]:
            destination = self._safe_artifact_path(
                scan, Path("findings") / slug / "poc" / PurePosixPath(item["relativePath"])
            )
            atomic_write(destination, item["content"])

    def _clean_writeup(self, scan: dict[str, Any], occurrence_id: str) -> None:
        root, slug = self._writeup_root(scan, occurrence_id)
        if root.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to clean symlink: {root}")
        markdown = root / f"{slug}.md"
        if markdown.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to clean symlink: {markdown}")
        try:
            markdown.unlink()
        except FileNotFoundError:
            pass
        poc_root = root / "poc"
        if poc_root.is_symlink():
            raise EngineError("unsafe_artifact_path", f"Refusing to clean symlink: {poc_root}")
        if poc_root.exists():
            shutil.rmtree(poc_root)

    def clean_resume_writeups(self, scan_id: str, assignments: list[dict[str, Any]]) -> None:
        scan = self.workbench.get_scan(scan_id)
        if scan["status"] not in ("interrupted", "failed"):
            raise EngineError("deep_tail_scan_active", "Orphaned tail claims can be recovered only during scan resume.")
        for assignment in assignments:
            if assignment.get("kind") == "writeup":
                self._clean_writeup(scan, str(assignment["subject_id"]))
