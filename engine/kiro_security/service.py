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
from .constants import ARTIFACT_KINDS, MODES, PROTOCOL_VERSION
from .db import Workbench
from .errors import EngineError
from .exports import export_report
from .remediation import (
    MAX_PATCH_BYTES, create_remediation_artifact, current_git_revision, load_patch_artifact,
    expected_post_apply_digests, normalize_verification_receipt, parse_remediation_patch, prepare_patch_artifact,
    reconcile_patch_application, touched_file_digests, verify_patch_inputs, verify_unmodified_files,
)
from .model import (
    complete_model_scan, get_model_context, resolve_diff_target_configuration,
    revalidate_model_target, setup_model_scan,
)
from .git_safety import git_filter_overrides
from .security import (
    atomic_write, canonical_workspace, random_id, redact, resolve_within, run_process,
    sha256_bytes, sha256_file, write_json,
)
from .tracking import (
    TRACKING_PROVIDERS, create_tracking_handoff, normalize_tracking_readback,
    normalize_triage_intake, normalize_triage_result,
)

EventEmitter = Callable[[str, dict[str, Any]], None]


class SecurityService:
    def __init__(self, workspace_root: str, client_kind: str, emit: EventEmitter) -> None:
        self.workspace = canonical_workspace(workspace_root)
        self.client_kind = client_kind
        self.emit = emit
        self.workbench = Workbench(self.workspace)
        self.session_id = random_id("session")
        self.workbench.register_session(self.session_id, os.getpid(), client_kind, PROTOCOL_VERSION)
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

    def _require_scan(self, scan_id: str) -> dict[str, Any]:
        return self.workbench.get_scan(scan_id)

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
            parsed_journal = json.loads(record.get("verification_summary") or "{}")
            applying_journal = parsed_journal if isinstance(parsed_journal, dict) else {}
            owner_session_id = applying_journal.get("ownerSessionId")
        except (TypeError, json.JSONDecodeError):
            applying_journal = {}
            owner_session_id = None
        if not force and owner_session_id and self.workbench.session_is_live(owner_session_id):
            raise EngineError(
                "remediation_busy", "The remediation is being applied by a live engine session.",
                {"remediationId": record["id"]},
            )
        try:
            scan = self.workbench.get_scan(record["scan_id"])
            metadata, path = load_patch_artifact(Path(scan["artifact_dir"]), record)
            state, current = reconcile_patch_application(
                self.workspace, path, metadata, record["patch_digest"]
            )
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
            "engine": {"available": True, "version": __version__, "protocolVersion": PROTOCOL_VERSION},
            "python": {"available": True, "version": sys.version.split()[0]},
            "sqlite": {"available": True, "version": sqlite3.sqlite_version},
            "git": {"available": shutil.which("git") is not None},
            "workspace": {"root": str(self.workspace), "stateDirectory": str(self.workbench.state_dir)},
            "supportedModes": list(MODES),
            "canonicalFinalizer": True,
        }

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "serverInfo": {"name": "kiro-security-engine", "version": __version__},
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": self.capabilities(),
            "workspace": self.workspace_record,
            "integrityIssues": self.integrity_issues,
        }

    def register_workspace(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = params.get("workspaceRoot")
        if requested:
            canonical = canonical_workspace(requested)
            if canonical != self.workspace:
                raise EngineError("workspace_mismatch", "This engine process is bound to a different workspace root.")
        workspace_id = params.get("workspaceId")
        task_id = params.get("taskId")
        self.workspace_record = (
            self.workbench.get_workspace(workspace_id, thread_id=task_id)
            if workspace_id
            else self.workbench.register_workspace(self.workspace, thread_id=task_id)
        )
        return self.workspace_record

    def start_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        mode = params["mode"]
        requested_scope = params.get("scope") or "."
        scope_path = resolve_within(self.workspace, requested_scope, must_exist=True)
        scope = "." if scope_path == self.workspace else scope_path.relative_to(self.workspace).as_posix()
        diff_target_kind = None
        diff_base_revision = None
        diff_head_revision = None
        diff_content_digest = None
        if mode == "diff":
            resolved = resolve_diff_target_configuration(
                self.workbench,
                scope=scope,
                kind=params.get("diffTargetKind") or "working_tree",
                base_revision=params.get("diffBaseRevision"),
                head_revision=params.get("diffHeadRevision"),
            )
            diff_target_kind = resolved["kind"]
            diff_base_revision = resolved["baseRevision"]
            diff_head_revision = resolved["headRevision"]
            diff_content_digest = resolved.get("contentDigest")
        workspace_id = params.get("workspaceId")
        task_id = params.get("taskId")
        workspace = (
            self.workbench.get_workspace(workspace_id, thread_id=task_id)
            if workspace_id
            else self.workbench.create_workspace(self.workspace, thread_id=task_id)
        )
        requested = (
            mode, scope, params.get("userContext"), diff_target_kind,
            diff_base_revision, diff_head_revision, diff_content_digest,
        )
        if workspace["active_scan_id"] is None:
            workspace = self.workbench.save_workspace(
                workspace["id"], mode=mode, scope=scope,
                user_context=params.get("userContext"),
                diff_target_kind=diff_target_kind,
                diff_base_revision=diff_base_revision,
                diff_head_revision=diff_head_revision,
                diff_content_digest=diff_content_digest,
            )
        elif self.workbench.workspace_configuration(workspace) != requested:
            raise EngineError(
                "workspace_setup_locked",
                "This workspace already has a scan. Open a new workspace to use different setup.",
                {"workspaceId": workspace["id"], "activeScanId": workspace["active_scan_id"]},
            )
        scan, _created = self.workbench.create_scan(
            workspace_id=workspace["id"],
            artifact_dir=None,
            session_id=self.session_id,
            setup_scan=lambda draft: setup_model_scan(self.workbench, draft),
        )
        self.workspace_record = self.workbench.get_workspace(workspace["id"])
        return scan

    def acquire_scan_coordinator(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.acquire_coordinator_lease(params["scanId"], self.session_id)

    def renew_scan_coordinator(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.renew_coordinator_lease(
            params["scanId"], params["coordinatorToken"],
            params["coordinatorGeneration"], self.session_id,
        )

    def release_scan_coordinator(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.release_coordinator_lease(
            params["scanId"], params["coordinatorToken"], params["coordinatorGeneration"]
        )

    def cancel_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.cancel_scan(
            params["scanId"], params["coordinatorToken"], params["coordinatorGeneration"]
        )

    def get_scan_context(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_scan(params["scanId"])
        revalidate_model_target(self.workbench, params["scanId"])
        return get_model_context(self.workbench, params["scanId"])

    def update_scan_progress(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.update_scan_progress(
            params["scanId"],
            token=params["coordinatorToken"],
            generation=params["coordinatorGeneration"],
            phase=params.get("phase"),
            phase_percent=params.get("phasePercent"),
            review_items_total=params.get("itemsTotal"),
            review_items_completed=params.get("itemsCompleted"),
            reportable_findings_count=params.get("reportableFindingsCount"),
            message=params.get("message"),
        )

    def complete_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_scan(params["scanId"])
        return complete_model_scan(
            self.workbench, params["scanId"],
            params["coordinatorToken"], params["coordinatorGeneration"],
        )

    def fail_scan(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_scan(params["scanId"])
        return self.workbench.fail_scan(
            params["scanId"], "scan_failed", params["reason"],
            params["coordinatorToken"], params["coordinatorGeneration"],
        )

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
        try:
            with path.open("rb") as handle:
                patch_bytes = handle.read(MAX_PATCH_BYTES + 1)
        except OSError as exc:
            raise EngineError("remediation_patch_changed", "The prepared remediation patch is unreadable.") from exc
        if len(patch_bytes) > MAX_PATCH_BYTES or sha256_bytes(patch_bytes) != record["patch_digest"]:
            raise EngineError("remediation_patch_changed", "The prepared remediation patch is missing or changed.")
        try:
            parse_remediation_patch(patch_bytes.decode("utf-8"))
        except UnicodeDecodeError as exc:
            raise EngineError("remediation_patch_changed", "The prepared remediation patch is not UTF-8 text.") from exc
        run_process(
            "git", [*git_filter_overrides(self.workspace), "apply",
                    *(["--no-index"] if metadata.get("baseRevision") is None else []),
                    "--check", "--whitespace=nowarn", "-"],
            cwd=self.workspace, input_bytes=patch_bytes,
        )
        verify_unmodified_files(self.workspace, Path(scan["artifact_dir"]), metadata)
        if touched_file_digests(self.workspace, metadata) != (metadata.get("touchedFiles") or []):
            raise EngineError("remediation_code_drift", "A touched file changed after patch validation.")
        expected_post_apply = expected_post_apply_digests(self.workspace, metadata, patch_bytes)
        applying = json.dumps({
            "phase": "applying", "patchDigest": record["patch_digest"],
            "preApplyDigests": metadata.get("touchedFiles") or [],
            "expectedPostApplyDigests": expected_post_apply,
            "ownerSessionId": self.session_id,
        }, separators=(",", ":"))
        self.workbench.transition_remediation(
            record["id"], params["expectedVersion"], "generated", "verifying", verification_summary=applying
        )
        try:
            verify_unmodified_files(self.workspace, Path(scan["artifact_dir"]), metadata)
            if touched_file_digests(self.workspace, metadata) != (metadata.get("touchedFiles") or []):
                raise EngineError("remediation_code_drift", "A touched file changed before patch application.")
            run_process(
                "git", [*git_filter_overrides(self.workspace), "apply",
                        *(["--no-index"] if metadata.get("baseRevision") is None else []),
                        "--whitespace=nowarn", "-"],
                cwd=self.workspace, input_bytes=patch_bytes,
            )
            observed_post_apply = touched_file_digests(self.workspace, metadata)
            try:
                verify_unmodified_files(self.workspace, Path(scan["artifact_dir"]), metadata)
            except EngineError:
                drift = json.dumps({
                    "phase": "apply_content_drift", "patchDigest": record["patch_digest"],
                    "expectedPostApplyDigests": expected_post_apply,
                    "observedPostApplyDigests": observed_post_apply,
                }, separators=(",", ":"))
                self.workbench.transition_remediation(
                    record["id"], params["expectedVersion"], "verifying", "failed",
                    verification_summary=drift,
                )
                raise
            if observed_post_apply != expected_post_apply:
                drift = json.dumps({
                    "phase": "apply_content_drift", "patchDigest": record["patch_digest"],
                    "expectedPostApplyDigests": expected_post_apply,
                    "observedPostApplyDigests": observed_post_apply,
                }, separators=(",", ":"))
                self.workbench.transition_remediation(
                    record["id"], params["expectedVersion"], "verifying", "failed",
                    verification_summary=drift,
                )
                raise EngineError("remediation_code_drift", "A touched file changed during patch application.")
            applied = json.dumps({
                "phase": "applied", "patchDigest": record["patch_digest"],
                "preApplyDigests": metadata.get("touchedFiles") or [],
                "postApplyDigests": observed_post_apply,
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
        scan = self.workbench.get_scan(record["scan_id"])
        metadata, _ = load_patch_artifact(Path(scan["artifact_dir"]), record)
        try:
            application = json.loads(record["verification_summary"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise EngineError("remediation_record_invalid", "Remediation application metadata is invalid.") from exc
        verify_unmodified_files(self.workspace, Path(scan["artifact_dir"]), metadata)
        if application.get("postApplyDigests") != touched_file_digests(self.workspace, metadata):
            raise EngineError("remediation_code_drift", "Touched files changed after the remediation was applied.")
        receipt = normalize_verification_receipt(params["verification"])
        receipt.update({
            "remediationId": record["id"], "findingId": record["finding_id"],
            "occurrenceId": record["occurrence_id"], "patchDigest": record["patch_digest"],
            "postApplyDigests": application["postApplyDigests"],
        })
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

    def get_dashboard(self, params: dict[str, Any]) -> dict[str, Any]:
        scans = self.workbench.list_scans(int(params.get("limit") or 25))
        active = next((scan for scan in scans if scan["status"] == "running"), None)
        selected_id = params.get("selectedScanId")
        selected = self.workbench.get_scan(selected_id) if selected_id else None
        if selected is not None:
            selected_workspace = self.workbench.get_workspace(selected["workspace_id"])
            if selected_workspace["root_path"] != str(self.workspace):
                raise EngineError("scan_not_found", "The selected scan is outside this workbench.")
        selected = selected or active or next(
            (scan for scan in scans if scan["status"] == "completed"),
            scans[0] if scans else None,
        )
        findings = self.workbench.list_findings(selected["id"], limit=500) if selected else []
        workspace = self.workbench.get_workspace(
            selected["workspace_id"] if selected else params.get("workspaceId")
        )
        self.workspace_record = workspace
        return {
            "workspace": workspace,
            "engine": self.capabilities(),
            "activeScan": active,
            "selectedScan": selected,
            "scans": scans,
            "findings": findings,
        }

    def poll_events(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        return self.workbench.events_since(int(params.get("afterSequence") or 0), int(params.get("limit") or 200))

    def database_info(self, params: dict[str, Any]) -> dict[str, Any]:
        return self.workbench.database_info()

    def shutdown(self, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._closing.is_set():
            return {"releasedCoordinatorLeaseScanIds": []}
        self._closing.set()
        released = set(self.workbench.release_session_leases(self.session_id))
        self.workbench.close_session(self.session_id)
        return {"releasedCoordinatorLeaseScanIds": sorted(released)}

    def dispatch(self, method: str, params: dict[str, Any]) -> Any:
        handlers = {
            "initialize": self.initialize,
            "get_capabilities": lambda _: self.capabilities(),
            "register_workspace": self.register_workspace,
            "start_scan": self.start_scan,
            "acquire_scan_coordinator": self.acquire_scan_coordinator,
            "renew_scan_coordinator": self.renew_scan_coordinator,
            "release_scan_coordinator": self.release_scan_coordinator,
            "cancel_scan": self.cancel_scan,
            "get_scan": self.get_scan,
            "list_scans": self.list_scans,
            "get_progress": self.get_progress,
            "get_scan_context": self.get_scan_context,
            "update_scan_progress": self.update_scan_progress,
            "complete_scan": self.complete_scan,
            "fail_scan": self.fail_scan,
            "list_findings": self.list_findings,
            "get_finding": self.get_finding,
            "triage_finding": self.triage_finding,
            "create_remediation": self.create_remediation,
            "prepare_remediation_patch": self.prepare_remediation_patch,
            "apply_remediation_patch": self.apply_remediation_patch,
            "verify_remediation_patch": self.verify_remediation_patch,
            "create_triage_intake": self.create_triage_intake,
            "submit_triage_assessment": self.submit_triage_assessment,
            "export_report": self.export_report,
            "create_tracking_handoff": self.create_tracking_handoff,
            "record_tracking_result": self.record_tracking_result,
            "cleanup_scan": self.cleanup_scan,
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
