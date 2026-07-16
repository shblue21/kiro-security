from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import threading
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .constants import EXPORT_FORMATS, MODES, PHASES, PROTOCOL_VERSION, TRIAGE_DECISIONS
from .db import Workbench
from .errors import EngineError
from .exports import export_report
from .hardening import create_hardening_proposal
from .remediation import create_remediation_artifact
from .runner import ScanRunner
from .scanner import build_inventory
from .security import canonical_workspace, random_id, resolve_within
from .threat_model import build_threat_model
from .tracking import TRACKING_PROVIDERS, create_tracking_handoff
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
        self.runner = ScanRunner(self.workbench, self.session_id, emit)
        self._closing = threading.Event()
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, name="kiro-security-heartbeat", daemon=True)
        self._heartbeat.start()

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
        scope = params.get("scope") or "."
        resolve_within(self.workspace, scope, must_exist=True)
        deep_host = (
            self.runner.deep.preflight_host(params.get("modelId"), params.get("runtime"))
            if mode == "deep"
            else None
        )
        max_files = int(params.get("maxFiles") or 10_000)
        max_file_bytes = int(params.get("maxFileBytes") or 1_048_576)
        self.runner.max_files = max_files
        self.runner.max_file_bytes = max_file_bytes
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
        if deep_host is not None:
            self.workbench.set_capabilities(scan["id"], {"deepHost": deep_host})
        self.runner.start(scan["id"])
        return scan

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
        # Agent-orchestrated Deep discovery intentionally has no local runner
        # while it waits for worker/merge receipts, so complete cancellation here.
        if (
            requested.get("mode") == "deep"
            and requested.get("status") == "running"
            and requested.get("phase") == "discovery"
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

    def create_hardening_proposal(self, params: dict[str, Any]) -> dict[str, Any]:
        scan = self.workbench.get_scan(params["scanId"])
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
        scan = self.workbench.get_scan(finding["scanId"])
        path = Path(scan["artifact_dir"]) / "tracking" / f"{finding['findingId']}-{provider}.json"
        create_tracking_handoff(
            finding, provider=provider, destination=destination, output_path=path,
            stable_link=params.get("stableLink"),
        )
        record = self.workbench.save_tracking_handoff(
            finding["occurrenceId"], provider, destination, path
        )
        artifact = self.workbench.add_artifact(
            finding["scanId"], f"tracking:{finding['findingId']}:{provider}", path, "application/json"
        )
        self.emit("artifact.created", {"scanId": finding["scanId"], "artifact": artifact})
        self.emit("finding.updated", {
            "scanId": finding["scanId"], "finding": self.workbench.get_finding(finding["occurrenceId"]),
            "change": "tracking_handoff",
        })
        return {**record, "artifact": artifact}

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
            "create_hardening_proposal": self.create_hardening_proposal,
            "export_report": self.export_report,
            "create_tracking_handoff": self.create_tracking_handoff,
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
