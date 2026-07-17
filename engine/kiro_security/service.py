from __future__ import annotations

import json
import os
import shutil
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .constants import ARTIFACT_KINDS, EXPORT_FORMATS, MODES, PHASES, PROTOCOL_VERSION, TRIAGE_DECISIONS, is_model_scan
from .db import Workbench
from .errors import EngineError
from .exports import export_report
from .hardening import create_hardening_proposal
from .remediation import (
    create_remediation_artifact, current_git_revision, load_patch_artifact, normalize_verification_receipt,
    prepare_patch_artifact, reconcile_patch_application, touched_file_digests, verify_patch_inputs,
)
from .runner import ScanRunner
from .scanner import build_inventory
from .security import (
    atomic_write, canonical_workspace, random_id, redact, resolve_within, run_process,
    sha256_bytes, sha256_file, write_json,
)
from .threat_model import build_threat_model
from .tracking import (
    TRACKING_PROVIDERS, create_tracking_handoff, normalize_tracking_readback,
    normalize_triage_intake, normalize_triage_result,
)
from .validator import validate_finding
from .attack_path import build_attack_path

EventEmitter = Callable[[str, dict[str, Any]], None]


class SecurityService:
    def __init__(self, workspace_root: str, client_kind: str, emit: EventEmitter) -> None:
        self.workspace = canonical_workspace(workspace_root)
        self.client_kind = client_kind
        self.emit = emit
        self.workbench = Workbench(self.workspace)
        self.session_id = random_id("session")
        self.workbench.register_session(self.session_id, os.getpid(), client_kind, PROTOCOL_VERSION)
        self.recovered_scans = self.workbench.recover_stale_sessions()
        # Stale running scans are already downgraded to interrupted above, so
        # this reconciliation never races an actively finalizing session.
        self.integrity_issues = self.workbench.reconcile_finalization_integrity()
        for issue in self.integrity_issues:
            emit("engine.log", {
                "level": "warning",
                "code": issue.get("code"),
                "message": issue.get("message"),
                "scanId": issue.get("scanId"),
            })
        self.workspace_record = self.workbench.register_workspace(self.workspace)
        self._reconcile_verifying_remediations()
        self.runner = ScanRunner(self.workbench, self.session_id, emit)
        self._closing = threading.Event()
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, name="kiro-security-heartbeat", daemon=True)
        self._heartbeat.start()

    @staticmethod
    def _write_immutable_json(path: Path, value: dict[str, Any]) -> tuple[str, bool]:
        payload = (json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        digest = sha256_bytes(payload)
        if path.exists():
            if path.is_symlink() or not path.is_file() or sha256_file(path) != digest:
                raise EngineError("immutable_artifact_changed", "An immutable workflow artifact path already has different content.")
            return digest, False
        atomic_write(path, payload)
        return digest, True

    @staticmethod
    def _cleanup_new_artifact(path: Path, created: bool) -> None:
        if created:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            try:
                path.parent.rmdir()
            except OSError:
                pass

    def _require_sealed_reportable_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        scan = self.workbench.get_scan(finding["scanId"])
        artifact_dir = Path(scan["artifact_dir"])
        findings_path = resolve_within(artifact_dir, ARTIFACT_KINDS["findings"], must_exist=True)
        try:
            manifest = self.workbench.require_intact_sealed_bundle(scan["id"])
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
            artifact = next(item for item in manifest["scan"]["artifacts"] if item["path"] == ARTIFACT_KINDS["findings"])
        except (EngineError, OSError, KeyError, StopIteration, TypeError, json.JSONDecodeError) as exc:
            raise EngineError("remediation_source_unsealed", "The sealed canonical finding source is invalid.") from exc
        if artifact.get("sha256") != sha256_file(findings_path) or not any(
            item.get("findingId") == finding["findingId"] and item.get("occurrenceId") == finding["occurrenceId"]
            for item in findings.get("findings", [])
        ):
            raise EngineError("remediation_finding_not_reportable", "The occurrence is not reportable in the sealed findings document.")
        return scan

    def _reconcile_remediation_record(self, record: dict[str, Any], *, force: bool = False) -> dict[str, Any]:
        if record["state"] != "verifying":
            return record
        try:
            owner_session_id = json.loads(record.get("verification_summary") or "{}").get("ownerSessionId")
        except (TypeError, json.JSONDecodeError):
            owner_session_id = None
        if not force and owner_session_id and self.workbench.session_is_live(owner_session_id):
            raise EngineError(
                "remediation_busy", "The remediation is being applied by a live engine session.",
                {"remediationId": record["id"]},
            )
        try:
            scan = self.workbench.get_scan(record["scan_id"])
            metadata, path = load_patch_artifact(Path(scan["artifact_dir"]), record)
            state, current = reconcile_patch_application(self.workspace, path, metadata)
        except Exception as exc:
            journal = {
                "phase": "reconciliation_failed", "patchDigest": record.get("patch_digest"),
                "reason": redact(str(exc))[:2000],
            }
            return self.workbench.transition_remediation(
                record["id"], record["version"], "verifying", "failed",
                verification_summary=json.dumps(journal, separators=(",", ":")),
            )
        if state == "not_applied":
            journal = {"phase": "reconciled_not_applied", "patchDigest": record["patch_digest"], "preApplyDigests": current}
            return self.workbench.transition_remediation(
                record["id"], record["version"], "verifying", "generated",
                verification_summary=json.dumps(journal, separators=(",", ":")),
            )
        if state == "applied":
            journal = {
                "phase": "applied", "patchDigest": record["patch_digest"],
                "preApplyDigests": metadata.get("touchedFiles") or [], "postApplyDigests": current,
                "reconciled": True,
            }
            return self.workbench.transition_remediation(
                record["id"], record["version"], "verifying", "applied",
                verification_summary=json.dumps(journal, separators=(",", ":")),
            )
        journal = {
            "phase": "reconciliation_failed", "patchDigest": record["patch_digest"],
            "preApplyDigests": metadata.get("touchedFiles") or [], "observedDigests": current,
        }
        return self.workbench.transition_remediation(
            record["id"], record["version"], "verifying", "failed",
            verification_summary=json.dumps(journal, separators=(",", ":")),
        )

    def _reconcile_verifying_remediations(self) -> None:
        for record in self.workbench.list_verifying_remediations():
            try:
                self._reconcile_remediation_record(record)
            except EngineError as exc:
                if exc.code != "remediation_busy":
                    self.emit("engine.log", {
                        "level": "warning", "code": "remediation_reconciliation_failed",
                        "message": redact(str(exc))[:2000], "scanId": record.get("scan_id"),
                    })
            except Exception as exc:
                self.emit("engine.log", {
                    "level": "warning", "code": "remediation_reconciliation_failed",
                    "message": redact(str(exc))[:2000], "scanId": record.get("scan_id"),
                })

    def _heartbeat_loop(self) -> None:
        while not self._closing.wait(3.0):
            try:
                self.workbench.heartbeat_session(self.session_id)
            except Exception as exc:
                self.emit("engine.log", {"level": "warning", "code": "heartbeat_failed", "message": str(exc), "scanId": None})

    def capabilities(self) -> dict[str, Any]:
        return {
            "product": "Kiro Security Power",
            "engineVersion": __version__,
            "protocolVersion": PROTOCOL_VERSION,
            "modes": list(MODES),
            "phases": list(PHASES),
            "exports": list(EXPORT_FORMATS),
            "triageDecisions": list(TRIAGE_DECISIONS),
            "supports": {
                "resume": True,
                "cancellation": True,
                "durableRecovery": True,
                "mcpSharedState": True,
                "threatModel": True,
                "validation": True,
                "attackPath": True,
                "remediation": True,
                "hardening": True,
                "trackingHandoffs": True,
                "trackingAdapters": False,
                "scanCleanup": True,
                "deepAgentOrchestration": True,
                "deepIndependentWorkers": 6,
                "deepMaxRounds": 10,
                "deepModelTailAssignments": True,
            },
            "workspaceRoot": str(self.workspace),
            "stateDirectory": str(self.workbench.state_dir),
            "database": self.workbench.database_info(),
            "dependencies": {
                "python": {"available": True, "version": sys.version.split()[0], "executable": sys.executable},
                "sqlite": {"available": True, "version": sqlite3.sqlite_version},
                "git": {"available": shutil.which("git") is not None, "executable": shutil.which("git")},
            },
        }

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "serverInfo": {"name": "kiro-security-engine", "version": __version__},
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": self.capabilities(),
            "workspace": self.workspace_record,
            "recoveredScanIds": self.recovered_scans,
            "integrityIssues": self.integrity_issues,
        }

    def register_workspace(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("workspaceRoot")
        if requested:
            canonical = canonical_workspace(requested)
            if canonical != self.workspace:
                raise EngineError("workspace_mismatch", "This engine process is bound to a different workspace root.")
        default_scope = params.get("defaultScope") or self.workspace_record.get("default_scope") or "."
        default_mode = params.get("defaultMode") or self.workspace_record.get("default_mode") or "standard"
        if default_mode not in MODES:
            raise EngineError("invalid_mode", f"Unsupported default mode: {default_mode}")
        resolve_within(self.workspace, default_scope, must_exist=True)
        self.workspace_record = self.workbench.register_workspace(
            self.workspace, default_scope=default_scope, default_mode=default_mode
        )
        return self.workspace_record

    def start_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params["mode"]
        analysis_profile = "model" if mode == "deep" else str(params.get("analysisProfile") or "fast")
        if analysis_profile not in ("fast", "model") or (mode == "deep" and analysis_profile != "model"):
            raise EngineError("invalid_analysis_profile", "Deep requires model analysis; Standard/Diff accept fast or model.")
        scope = params.get("scope") or "."
        resolve_within(self.workspace, scope, must_exist=True)
        deep_host = (
            self.runner.deep.preflight_host(params.get("modelId"), params.get("runtime"))
            if analysis_profile == "model"
            else None
        )
        max_files = int(params.get("maxFiles") or 10_000)
        max_file_bytes = int(params.get("maxFileBytes") or 1_048_576)
        scan = self.workbench.create_scan(
            workspace_id=self.workspace_record["id"],
            mode=mode,
            scope=scope,
            artifact_dir=None,
            session_id=self.session_id,
            diff_target_kind=params.get("diffTargetKind") if mode == "diff" else None,
            diff_base_revision=params.get("diffBaseRevision") if mode == "diff" else None,
            diff_head_revision=params.get("diffHeadRevision") if mode == "diff" else None,
        )
        Path(scan["artifact_dir"]).mkdir(parents=True, exist_ok=True)
        capabilities = {
            "analysisProfile": analysis_profile,
            "maxFiles": max_files,
            "maxFileBytes": max_file_bytes,
        }
        if deep_host is not None:
            capabilities["deepHost"] = deep_host
        self.workbench.set_capabilities(scan["id"], capabilities)
        self.runner.start(scan["id"])
        return self.workbench.get_scan(scan["id"])

    def resume_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = params["scanId"]
        scan = self.workbench.resume_scan(
            scan_id,
            self.session_id,
            recover_tail_artifacts=lambda assignments: self.runner.tail.clean_resume_writeups(scan_id, assignments),
        )
        self.runner.start(scan["id"], resuming=True)
        return scan

    def cancel_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        scan_id = params["scanId"]
        requested = self.workbench.request_cancel(scan_id)
        # Agent-orchestrated model handoffs intentionally have no local runner
        # while they await worker, merge, or tail receipts, so cancel them here.
        if (
            is_model_scan(requested)
            and requested.get("status") == "running"
            and scan_id not in self.runner.active_scan_ids()
        ):
            return self.workbench.cancel_scan(scan_id)
        return requested

    def deep_get_status(self, params: dict[str, Any]) -> dict[str, Any]:
        status = self.runner.deep.status(params["scanId"])
        if status.get("status") in ("saturated", "capped"):
            tail = self.runner.tail.status(params["scanId"])
            status["tail"] = tail
            if tail["nextAction"] != "await_discovery_completion":
                status["nextAction"] = tail["nextAction"]
        return status

    def deep_claim_worker(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.deep.claim_worker(
            params["scanId"], params["modelId"], params["delegationId"], params.get("runtime")
        )

    def deep_submit_worker(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.deep.submit_worker(params)

    def deep_retry_worker(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.deep.retry_worker(
            params["scanId"], int(params["workerIndex"]), str(params.get("reason") or "Worker replacement requested")
        )

    def deep_claim_merge(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.deep.claim_merge(params["scanId"])

    def deep_submit_merge(self, params: dict[str, Any]) -> dict[str, Any]:
        status = self.runner.deep.submit_merge(params)
        if status.get("status") in ("saturated", "capped"):
            scan_id = params["scanId"]
            scan = self.workbench.get_scan(scan_id)
            if scan["status"] == "running":
                self.runner.resume_when_idle(scan_id)
        return status

    def deep_get_tail_assignment(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.tail.claim(params)

    def deep_submit_tail_result(self, params: dict[str, Any]) -> dict[str, Any]:
        result = self.runner.tail.submit(params)
        scan_id = params["scanId"]
        scan = self.workbench.get_scan(scan_id)
        if scan["status"] == "running":
            self.runner.resume_when_idle(scan_id)
        return result

    def deep_retry_writeup(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.runner.tail.retry_writeup(params)

    def get_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.get_scan(params["scanId"])

    def list_scans(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.workbench.list_scans(int(params.get("limit") or 50))

    def get_progress(self, params: dict[str, Any]) -> dict[str, Any] | None:
        return self.workbench.get_scan(params["scanId"])["progress"]

    def list_findings(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.workbench.list_findings(
            params["scanId"], search=params.get("search"), limit=int(params.get("limit") or 500)
        )

    @staticmethod
    def _finding_key(params: dict[str, Any]) -> str:
        return params.get("occurrenceId") or params.get("findingId")

    def get_finding(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.get_finding(self._finding_key(params))

    def validate_finding(self, params: dict[str, Any]) -> dict[str, Any]:
        finding = self.workbench.get_finding(self._finding_key(params))
        if is_model_scan(self.workbench.get_scan(finding["scanId"])):
            raise EngineError(
                "model_tail_result_immutable",
                "Model validation and attack-path results are managed by immutable tail assignments.",
            )
        result = validate_finding(self.workspace, finding)
        updated = self.workbench.save_validation(finding["occurrenceId"], result)
        if result["status"] in ("validated", "needs_review"):
            updated = self.workbench.save_attack_path(updated["occurrenceId"], build_attack_path(updated))
        self.emit("finding.updated", {"scanId": updated["scanId"], "finding": updated, "change": "validation"})
        return updated

    def triage_finding(self, params: dict[str, Any]) -> dict[str, Any]:
        updated = self.workbench.triage_finding(params["occurrenceId"], params["decision"], params.get("note"))
        self.emit("finding.updated", {"scanId": updated["scanId"], "finding": updated, "change": "triage"})
        return updated

    def create_remediation(self, params: dict[str, Any]) -> dict[str, Any]:
        finding = self.workbench.get_finding(self._finding_key(params))
        scan = self.workbench.get_scan(finding["scanId"])
        summary, path = create_remediation_artifact(finding, Path(scan["artifact_dir"]))
        updated = self.workbench.save_remediation(finding["occurrenceId"], summary, str(path))
        artifact = self.workbench.add_artifact(finding["scanId"], f"remediation:{finding['findingId']}", path, "text/markdown")
        self.emit("artifact.created", {"scanId": finding["scanId"], "artifact": artifact})
        self.emit("finding.updated", {"scanId": finding["scanId"], "finding": updated, "change": "remediation"})
        return updated

    def prepare_remediation_patch(self, params: dict[str, Any]) -> dict[str, Any]:
        finding = self.workbench.get_finding(params["occurrenceId"])
        scan = self._require_sealed_reportable_finding(finding)
        self.workbench.require_patch_remediation_available(finding["occurrenceId"])
        record_id = random_id("rem")
        metadata, path, digest = prepare_patch_artifact(
            self.workspace, Path(scan["artifact_dir"]), finding, scan,
            patch=params["patch"], plan=params["plan"], verification_plan=params["verificationPlan"],
            record_id=record_id,
        )
        try:
            record = self.workbench.create_patch_remediation(
                record_id, finding["occurrenceId"],
                json.dumps(metadata, separators=(",", ":"), ensure_ascii=False), str(path), digest,
            )
        except Exception:
            self._cleanup_new_artifact(path, True)
            raise
        artifact = self.workbench.add_artifact(
            finding["scanId"], f"remediation-patch:{record['id']}", path, "text/x-diff"
        )
        self.emit("artifact.created", {"scanId": finding["scanId"], "artifact": artifact})
        return {**record, "artifact": artifact, "plan": metadata}

    def apply_remediation_patch(self, params: dict[str, Any]) -> dict[str, Any]:
        record = self.workbench.get_remediation_record(params["remediationId"])
        if record["version"] != params["expectedVersion"]:
            raise EngineError("remediation_state_conflict", "The remediation version changed before apply.")
        if record["state"] == "verifying":
            record = self._reconcile_remediation_record(record)
            if record["state"] == "applied":
                return record
        if record["state"] != "generated":
            raise EngineError("remediation_state_conflict", "Only the expected generated remediation can be applied.")
        scan = self.workbench.get_scan(record["scan_id"])
        metadata, path = verify_patch_inputs(self.workspace, Path(scan["artifact_dir"]), record)
        run_process("git", ["apply", "--check", "--whitespace=nowarn", str(path)], cwd=self.workspace)
        applying = json.dumps({
            "phase": "applying", "patchDigest": record["patch_digest"],
            "preApplyDigests": metadata.get("touchedFiles") or [],
            "ownerSessionId": self.session_id,
        }, separators=(",", ":"))
        self.workbench.transition_remediation(
            record["id"], params["expectedVersion"], "generated", "verifying", verification_summary=applying
        )
        try:
            run_process("git", ["apply", "--whitespace=nowarn", str(path)], cwd=self.workspace)
            applied = json.dumps({
                "phase": "applied", "patchDigest": record["patch_digest"],
                "preApplyDigests": metadata.get("touchedFiles") or [],
                "postApplyDigests": touched_file_digests(self.workspace, metadata),
            }, separators=(",", ":"))
            result = self.workbench.transition_remediation(
                record["id"], params["expectedVersion"], "verifying", "applied", verification_summary=applied
            )
        except Exception as exc:
            current = self.workbench.get_remediation_record(record["id"])
            if current["state"] == "verifying":
                self._reconcile_remediation_record(current, force=True)
            raise
        self.emit("finding.updated", {
            "scanId": record["scan_id"], "finding": self.workbench.get_finding(record["occurrence_id"]),
            "change": "remediation_applied",
        })
        return result

    def verify_remediation_patch(self, params: dict[str, Any]) -> dict[str, Any]:
        record = self.workbench.get_remediation_record(params["remediationId"])
        if record["state"] != "applied" or record["version"] != params["expectedVersion"]:
            raise EngineError("remediation_state_conflict", "Only the expected applied remediation can be verified.")
        try:
            application = json.loads(record["verification_summary"])
            metadata = json.loads(record["summary"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise EngineError("remediation_record_invalid", "Remediation application metadata is invalid.") from exc
        if application.get("postApplyDigests") != touched_file_digests(self.workspace, metadata):
            raise EngineError("remediation_code_drift", "Touched files changed after the remediation was applied.")
        receipt = normalize_verification_receipt(params["verification"])
        receipt.update({
            "remediationId": record["id"], "findingId": record["finding_id"],
            "occurrenceId": record["occurrence_id"], "patchDigest": record["patch_digest"],
            "postApplyDigests": application["postApplyDigests"],
        })
        scan = self.workbench.get_scan(record["scan_id"])
        receipt_digest = sha256_bytes(
            (json.dumps(receipt, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        )
        receipt_path = resolve_within(
            Path(scan["artifact_dir"]), f"remediations/{record['id']}/verification-{receipt_digest}.json"
        )
        actual_digest, created = self._write_immutable_json(receipt_path, receipt)
        if actual_digest != receipt_digest:
            self._cleanup_new_artifact(receipt_path, created)
            raise EngineError("immutable_artifact_changed", "The remediation verification digest changed during materialization.")
        final_state = "verified" if receipt["outcome"] == "verified" else "failed"
        updated = self.workbench.transition_remediation(
            record["id"], params["expectedVersion"], "applied", final_state,
            verification_summary=json.dumps(receipt, separators=(",", ":"), ensure_ascii=False),
            artifact=(
                record["scan_id"], f"remediation-verification:{record['id']}",
                receipt_path, "application/json",
            ),
        )
        artifact = updated.pop("_artifact")
        self.emit("artifact.created", {"scanId": record["scan_id"], "artifact": artifact})
        return {**updated, "verificationArtifact": artifact}

    def create_triage_intake(self, params: dict[str, Any]) -> dict[str, Any]:
        intake = normalize_triage_intake(params["sourceType"], params["inputId"], params["input"])
        assessment_id = random_id("triage")
        intake_digest = sha256_bytes(
            (json.dumps(intake, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        )
        path = resolve_within(self.workbench.state_dir, f"triage/{assessment_id}/intake-{intake_digest}.json")
        self._write_immutable_json(path, intake)
        return self.workbench.create_triage_assessment(
            assessment_id, intake, params.get("occurrenceId"), str(path)
        )

    def submit_triage_assessment(self, params: dict[str, Any]) -> dict[str, Any]:
        assessment = self.workbench.get_triage_assessment(params["assessmentId"])
        result = normalize_triage_result(params["result"], assessment["intake"])
        location_bindings = []
        for location in result["affectedLocations"]:
            path = resolve_within(self.workspace, location["path"], must_exist=True)
            current = self.workspace
            for part in Path(location["path"]).parts:
                current = current / part
                if current.is_symlink():
                    raise EngineError("invalid_triage_result", "Affected locations may not use symlinks.")
            if not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
                raise EngineError("invalid_triage_result", "Affected locations must be bounded regular files.")
            try:
                line_count = max(1, len(path.read_text(encoding="utf-8").splitlines()))
            except (OSError, UnicodeDecodeError) as exc:
                raise EngineError("invalid_triage_result", "Affected locations must be readable UTF-8 files.") from exc
            if location["endLine"] > line_count:
                raise EngineError("invalid_triage_result", "Affected location lines exceed the current file.")
            location_bindings.append({**location, "contentDigest": sha256_file(path)})
        finding = None
        scan = None
        if assessment["occurrenceId"]:
            finding = self.workbench.get_finding(assessment["occurrenceId"])
            scan = self.workbench.get_scan(finding["scanId"])
        revision = current_git_revision(self.workspace)
        if scan and scan.get("target_revision") and revision != scan["target_revision"]:
            raise EngineError("triage_repository_drift", "The repository revision changed from the bound finding scan.")
        result["repositoryBinding"] = {
            "assessmentId": assessment["id"],
            "occurrenceId": None if finding is None else finding["occurrenceId"],
            "findingId": None if finding is None else finding["findingId"],
            "scanId": None if finding is None else finding["scanId"],
            "revision": revision,
            "scanRevision": None if scan is None else scan.get("target_revision"),
            "snapshotDigest": None if scan is None else scan.get("snapshot_digest"),
            "locations": location_bindings,
        }
        result_bytes = json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        result_digest = sha256_bytes(result_bytes.encode("utf-8"))
        path = resolve_within(
            self.workbench.state_dir, f"triage/{assessment['id']}/result-{result_digest}.json"
        )
        actual_digest, _ = self._write_immutable_json(path, result)
        completed = self.workbench.complete_triage_assessment(
            assessment["id"], result, actual_digest, str(path),
            artifact=None if scan is None else (
                scan["id"], f"triage-result:{assessment['id']}", path, "application/json",
            ),
        )
        artifact = completed.pop("_artifact", None)
        if artifact is not None:
            self.emit("artifact.created", {"scanId": scan["id"], "artifact": artifact})
        return completed

    def create_hardening_proposal(self, params: dict[str, Any]) -> dict[str, Any]:
        scan = self.workbench.get_scan(params["scanId"])
        if is_model_scan(scan):
            raise EngineError(
                "model_tail_result_immutable",
                "Model hardening results are managed by immutable tail assignments.",
            )
        findings = [self.workbench.get_finding(item["occurrenceId"]) for item in self.workbench.list_findings(scan["id"])]
        path = Path(scan["artifact_dir"]) / "hardening" / "hardening.md"
        proposal = create_hardening_proposal(scan["id"], findings, path)
        saved = self.workbench.save_hardening(scan["id"], proposal["title"], proposal["summary"], path)
        artifact = self.workbench.add_artifact(scan["id"], "hardening", path, "text/markdown")
        self.emit("artifact.created", {"scanId": scan["id"], "artifact": artifact})
        return saved

    def export_report(self, params: dict[str, Any]) -> dict[str, Any]:
        record = export_report(
            self.workbench,
            params["scanId"],
            params["format"],
            destination=params.get("destination"),
            allowed_root=params.get("allowedRoot"),
            occurrence_id=params.get("occurrenceId"),
        )
        self.emit("artifact.created", {"scanId": params["scanId"], "artifact": {**record, "kind": f"export:{params['format']}"}})
        return record

    def create_tracking_handoff(self, params: dict[str, Any]) -> dict[str, Any]:
        finding = self.workbench.get_finding(self._finding_key(params))
        provider = params.get("provider") or "manual"
        if provider not in TRACKING_PROVIDERS:
            raise EngineError("invalid_tracking_provider", f"Unsupported tracking provider: {provider}")
        destination = params.get("destination") or "manual-review"
        scan = self._require_sealed_reportable_finding(finding)
        record_id = random_id("track")
        payload = create_tracking_handoff(
            finding, provider=provider, destination=destination, output_path=None,
            record_id=record_id, tracking_proof=params.get("trackingProof"),
            stable_link=params.get("stableLink"),
            source_seal={
                "status": "sealed", "manifestDigest": scan["sealed_manifest_digest"],
                "snapshotDigest": scan.get("snapshot_digest"), "revision": scan.get("target_revision"),
            },
        )
        destination = payload["destination"]
        payload_digest = sha256_bytes(
            (json.dumps(payload, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        )
        path = resolve_within(
            Path(scan["artifact_dir"]), f"tracking/{record_id}/handoff-{payload_digest}.json"
        )
        actual_digest, _ = self._write_immutable_json(path, payload)
        record = self.workbench.save_tracking_handoff(
            record_id, finding["occurrenceId"], provider, destination, path
        )
        if record["payloadSha256"] != actual_digest:
            raise EngineError("tracking_payload_changed", "The durable tracking payload digest changed.")
        artifact = self.workbench.add_artifact(
            finding["scanId"], f"tracking:{finding['findingId']}:{provider}", path, "application/json"
        )
        self.emit("artifact.created", {"scanId": finding["scanId"], "artifact": artifact})
        self.emit("finding.updated", {
            "scanId": finding["scanId"], "finding": self.workbench.get_finding(finding["occurrenceId"]),
            "change": "tracking_handoff",
        })
        return {**record, "artifact": artifact}

    def record_tracking_result(self, params: dict[str, Any]) -> dict[str, Any]:
        record = self.workbench.get_tracking_record(params["recordId"])
        scan = self.workbench.get_scan(record["scan_id"])
        raw_handoff_path = record.get("payload_artifact_path")
        if not raw_handoff_path:
            raise EngineError("tracking_payload_changed", "The durable tracking payload path is missing.")
        try:
            relative = Path(raw_handoff_path).resolve(strict=True).relative_to(Path(scan["artifact_dir"]).resolve(strict=True))
        except (OSError, ValueError, RuntimeError) as exc:
            raise EngineError("tracking_payload_changed", "The durable tracking payload path escaped its scan.") from exc
        handoff_path = resolve_within(Path(scan["artifact_dir"]), relative, must_exist=True)
        if sha256_file(handoff_path) != record["payload_sha256"] or params["payloadSha256"] != record["payload_sha256"]:
            raise EngineError("tracking_payload_changed", "The approved tracking handoff is missing or changed.")
        try:
            handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EngineError("tracking_payload_changed", "The approved tracking handoff is unreadable.") from exc
        readback = normalize_tracking_readback({**params, "recordId": record["id"]}, handoff)
        readback_bytes = json.dumps(readback, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
        readback_digest = sha256_bytes(readback_bytes.encode("utf-8"))
        readback_path = resolve_within(
            Path(scan["artifact_dir"]), f"tracking/{record['id']}/readback-{readback_digest}.json"
        )
        actual_digest, _ = self._write_immutable_json(readback_path, readback)
        updated = self.workbench.record_tracking_result(
            record["id"], record["payload_sha256"], readback["outcome"],
            readback["externalId"], readback["externalUrl"], actual_digest, str(readback_path),
            artifact=(
                record["scan_id"], f"tracking-readback:{record['id']}",
                readback_path, "application/json",
            ),
        )
        artifact = updated.pop("_artifact")
        return {**updated, "readbackDigest": actual_digest, "artifact": artifact}

    def cleanup_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        result = self.workbench.cleanup_scan(params["scanId"])
        self.emit("engine.log", {
            "level": "info", "code": "scan_cleaned", "message": f"Cleaned scan {params['scanId']}",
            "scanId": params["scanId"],
        })
        return result

    def refresh_threat_model(self, params: dict[str, Any]) -> dict[str, Any]:
        scope = params.get("scope") or "."
        inventory = build_inventory(
            self.workspace,
            mode="standard",
            scope=scope,
            diff_target_kind=None,
            diff_base_revision=None,
            diff_head_revision=None,
            max_files=10_000,
            max_file_bytes=1_048_576,
        )
        path = self.workbench.state_dir / "threat-model.md"
        model = build_threat_model(self.workspace, inventory, path)
        return {"path": str(path), "model": model}

    def get_dashboard(self, params: dict[str, Any]) -> dict[str, Any]:
        scans = self.workbench.list_scans(int(params.get("limit") or 25))
        active = next((scan for scan in scans if scan["status"] in ("queued", "running")), None)
        selected = active or next((scan for scan in scans if scan["status"] == "completed"), scans[0] if scans else None)
        findings = self.workbench.list_findings(selected["id"]) if selected else []
        return {
            "workspace": self.workspace_record,
            "engine": self.capabilities(),
            "activeScan": active,
            "selectedScan": selected,
            "scans": scans,
            "findings": findings,
            "latestResumableScan": self.workbench.latest_resumable_scan(),
        }

    def poll_events(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.workbench.events_since(int(params.get("afterSequence") or 0), int(params.get("limit") or 200))

    def database_info(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.database_info()

    def shutdown(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._closing.is_set():
            return {"interruptedScanIds": []}
        self._closing.set()
        interrupted = self.runner.shutdown(timeout=5.0)
        self.workbench.close_session(self.session_id)
        return {"interruptedScanIds": interrupted}

    def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        handlers = {
            "initialize": self.initialize,
            "get_capabilities": lambda _: self.capabilities(),
            "register_workspace": self.register_workspace,
            "start_scan": self.start_scan,
            "resume_scan": self.resume_scan,
            "cancel_scan": self.cancel_scan,
            "get_scan": self.get_scan,
            "list_scans": self.list_scans,
            "get_progress": self.get_progress,
            "deep_get_status": self.deep_get_status,
            "deep_claim_worker": self.deep_claim_worker,
            "deep_submit_worker": self.deep_submit_worker,
            "deep_retry_worker": self.deep_retry_worker,
            "deep_claim_merge": self.deep_claim_merge,
            "deep_submit_merge": self.deep_submit_merge,
            "deep_get_tail_assignment": self.deep_get_tail_assignment,
            "deep_submit_tail_result": self.deep_submit_tail_result,
            "deep_retry_writeup": self.deep_retry_writeup,
            "list_findings": self.list_findings,
            "get_finding": self.get_finding,
            "validate_finding": self.validate_finding,
            "triage_finding": self.triage_finding,
            "create_remediation": self.create_remediation,
            "prepare_remediation_patch": self.prepare_remediation_patch,
            "apply_remediation_patch": self.apply_remediation_patch,
            "verify_remediation_patch": self.verify_remediation_patch,
            "create_triage_intake": self.create_triage_intake,
            "submit_triage_assessment": self.submit_triage_assessment,
            "create_hardening_proposal": self.create_hardening_proposal,
            "export_report": self.export_report,
            "create_tracking_handoff": self.create_tracking_handoff,
            "record_tracking_result": self.record_tracking_result,
            "cleanup_scan": self.cleanup_scan,
            "refresh_threat_model": self.refresh_threat_model,
            "get_dashboard": self.get_dashboard,
            "poll_events": self.poll_events,
            "database_info": self.database_info,
            "shutdown": self.shutdown,
        }
        try:
            handler = handlers[method]
        except KeyError as exc:
            raise EngineError("method_not_found", f"Unknown RPC method: {method}") from exc
        return handler(params)
