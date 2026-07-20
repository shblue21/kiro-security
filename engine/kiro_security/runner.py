from __future__ import annotations

import json
import threading
import traceback
from pathlib import Path
from typing import Any, Callable

from .attack_path import build_attack_path
from .constants import ARTIFACT_KINDS, PHASES, is_model_scan
from .coverage import coverage_row_id
from .db import Workbench
from .deep import DeepCoordinator
from .errors import CancelledScan, EngineError, InterruptedScan
from .finalizer import finalize_scan, prepare_finalization
from .reporting import write_canonical_documents
from .scanner import Inventory, build_inventory, scan_inventory
from .security import redact, utc_now, write_json
from .security_context import write_security_context
from .tail import DeepTailCoordinator
from .threat_model import build_threat_model
from .validator import validate_finding

EventEmitter = Callable[[str, dict[str, Any]], None]


class ScanRunner:
    def __init__(
        self,
        workbench: Workbench,
        session_id: str,
        emit: EventEmitter,
        *,
        max_files: int = 10_000,
        max_file_bytes: int = 1_048_576,
    ) -> None:
        self.workbench = workbench
        self.session_id = session_id
        self.emit = emit
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.deep = DeepCoordinator(workbench)
        self.tail = DeepTailCoordinator(workbench, self.deep)
        self._shutdown = threading.Event()
        self._threads: dict[str, threading.Thread] = {}
        self._resume_requested: set[str] = set()
        self._lock = threading.RLock()

    def start(self, scan_id: str, *, resuming: bool = False) -> None:
        with self._lock:
            existing = self._threads.get(scan_id)
            if existing and existing.is_alive():
                raise EngineError("scan_already_running", f"Scan {scan_id} already has a local runner.")
            thread = threading.Thread(
                target=self._run,
                name=f"kiro-security-{scan_id[-8:]}",
                args=(scan_id, resuming),
                daemon=True,
            )
            self._threads[scan_id] = thread
            thread.start()

    def resume_when_idle(self, scan_id: str) -> None:
        with self._lock:
            existing = self._threads.get(scan_id)
            if existing and existing.is_alive():
                self._resume_requested.add(scan_id)
                return
        self.start(scan_id, resuming=True)

    def _emit(self, event: str, payload: dict[str, Any]) -> None:
        scan_id = payload.get("scanId")
        try:
            sequence = self.workbench.add_event(event, payload, scan_id)
            payload = {**payload, "sequence": sequence}
        except Exception:
            pass
        self.emit(event, payload)

    def _log(self, level: str, message: str, *, scan_id: str | None = None, code: str | None = None) -> None:
        self._emit(
            "engine.log",
            {"scanId": scan_id, "level": level, "code": code, "message": redact(message), "timestamp": utc_now()},
        )

    def _cancelled(self, scan_id: str) -> bool:
        return self.workbench.cancellation_requested(scan_id)

    def _interrupted(self) -> bool:
        return self._shutdown.is_set()

    def _check(self, scan_id: str) -> None:
        if self._cancelled(scan_id):
            raise CancelledScan()
        if self._interrupted():
            raise InterruptedScan()

    def _inventory_path(self, scan: dict[str, Any]) -> Path:
        return Path(scan["artifact_dir"]) / "inventory.json"

    def _scan_limits(self, scan: dict[str, Any]) -> tuple[int, int]:
        capabilities = scan.get("capabilities") or {}
        return (
            int(capabilities.get("maxFiles") or self.max_files),
            int(capabilities.get("maxFileBytes") or self.max_file_bytes),
        )

    def _build_inventory(self, scan: dict[str, Any], *, require_same_snapshot: bool = False) -> Inventory:
        max_files, max_file_bytes = self._scan_limits(scan)
        inventory = build_inventory(
            self.workbench.workspace,
            mode=scan["mode"],
            scope=scan["scope"],
            diff_target_kind=scan.get("diff_target_kind"),
            diff_base_revision=scan.get("diff_base_revision"),
            diff_head_revision=scan.get("diff_head_revision"),
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            include_security_surfaces=is_model_scan(scan),
        )
        if require_same_snapshot and scan.get("snapshot_digest") and inventory.snapshot_digest != scan["snapshot_digest"]:
            raise EngineError(
                "target_changed",
                "The workspace snapshot changed after the scan was interrupted. Start a new scan instead of resuming.",
                {"expected": scan["snapshot_digest"], "actual": inventory.snapshot_digest},
            )
        if require_same_snapshot and scan.get("target_revision") and inventory.revision != scan["target_revision"]:
            raise EngineError(
                "target_changed",
                "The workspace Git revision changed after preflight. Start a new scan instead of resuming.",
                {"expected": scan["target_revision"], "actual": inventory.revision},
            )
        return inventory

    @staticmethod
    def _inventory_data(inventory: Inventory, *, include_diff_context_row: bool = False) -> dict[str, Any]:
        files = []
        for source in inventory.files:
            surface = source.surface or f"source_review:{source.language}"
            product_area = source.relative_path.split("/", 1)[0] if "/" in source.relative_path else "."
            files.append({
                "rowId": coverage_row_id(source.relative_path, surface),
                "path": source.relative_path,
                "language": source.language,
                "surface": surface,
                "size": source.size,
                "runtimeRelevance": source.runtime_relevance or "Supported source selected for runtime security review.",
                "productArea": product_area,
                "deploymentSignificance": source.deployment_significance,
                "entrypoint": None,
                "privilegedBoundary": None,
                "rootControl": None,
                "seedAdvisoryAnchor": None,
                "highImpactFamily": None,
                "workShard": "all-workers",
                "rankingReason": source.ranking_reason or f"Included in the canonical supported inventory as {source.language} source ({surface}).",
                "deferredReason": None,
                "excludedReason": None,
            })
        if include_diff_context_row and inventory.diff_context is not None:
            path = "context/diff-context.json"
            surface = "diff_review:bounded_patch"
            files.append({
                "rowId": coverage_row_id(path, surface),
                "path": path,
                "language": "diff",
                "surface": surface,
                "size": len(str(inventory.diff_context.get("patch") or "").encode("utf-8", "surrogatepass")),
                "runtimeRelevance": "Bounded immutable Git patch selected for model Diff review.",
                "productArea": ".",
                "deploymentSignificance": None,
                "entrypoint": None,
                "privilegedBoundary": None,
                "rootControl": None,
                "seedAdvisoryAnchor": None,
                "highImpactFamily": None,
                "workShard": "all-workers",
                "rankingReason": "The Diff workflow requires an explicit receipt for its immutable changed/deleted-line context.",
                "deferredReason": None,
                "excludedReason": None,
            })
        deferred = []
        for item in inventory.deferred:
            normalized = dict(item)
            path = str(normalized.get("path") or normalized.get("id") or ".")
            surface = str(normalized.get("surface") or normalized.get("kind") or "inventory_deferred")
            normalized["path"] = path
            normalized["surface"] = surface
            normalized["rowId"] = str(normalized.get("rowId") or coverage_row_id(path, surface))
            deferred.append(normalized)
        data = {
            "includePaths": inventory.include_paths,
            "excludePaths": inventory.exclude_paths,
            "deferred": deferred,
            "revision": inventory.revision,
            "snapshotDigest": inventory.snapshot_digest,
            "gitAvailable": inventory.git_available,
            "diffSummary": inventory.diff_summary,
            "warnings": inventory.warnings,
            "supportedFileCount": len(files),
            "files": files,
        }
        if inventory.diff_context is not None:
            data["diffContext"] = {
                "path": "context/diff-context.json",
                "contextDigest": inventory.diff_context["contextDigest"],
                "supportingPaths": [item["path"] for item in inventory.diff_context["supportingPaths"]],
            }
        return data

    def _progress(self, scan_id: str, completed: int, total: int, current: str, *, deep_pass: int | None = None) -> None:
        percent = 100.0 if total == 0 else (completed / total) * 100.0
        scan = self.workbench.get_scan(scan_id)
        if scan["phase"] in ("preflight", "discovery"):
            self.workbench.set_file_counts(scan_id, total, completed)
        progress = self.workbench.update_progress(
            scan_id,
            phase_percent=percent,
            review_items_total=total,
            review_items_completed=completed,
            reportable_findings_count=self.workbench.scan_counts(scan_id)["total"],
            deep_review_pass=deep_pass,
            message=f"Reviewing {current}" if current else "Review complete",
        )
        self._emit("scan.progress", {"scanId": scan_id, "progress": progress})

    def _run(self, scan_id: str, resuming: bool) -> None:
        prepared_finalization: dict[str, Any] | None = None
        try:
            scan = self.workbench.get_scan(scan_id)
            self._emit("scan.started", {"scanId": scan_id, "scan": scan, "resumed": resuming})
            start_index = int(scan["phase_index"])
            for phase_index in range(start_index, len(PHASES)):
                self._check(scan_id)
                phase = PHASES[phase_index]
                scan = self.workbench.set_phase(scan_id, phase, resuming=resuming and phase_index == start_index)
                self._emit("scan.phaseChanged", {"scanId": scan_id, "phase": phase, "scan": scan})
                phase_complete = True
                if phase == "preflight":
                    self._phase_preflight(scan_id, require_same_snapshot=resuming)
                elif phase == "threat_model":
                    # Deep workers independently generate discovery threat models. A shared
                    # canonical threat model is retained for centralized validation/reporting.
                    self._phase_threat_model(scan_id)
                elif phase == "discovery":
                    phase_complete = self._phase_discovery(scan_id)
                elif phase == "validation":
                    phase_complete = self._phase_validation(scan_id)
                elif phase == "attack_path":
                    phase_complete = self._phase_attack_path(scan_id)
                elif phase == "reporting":
                    prepared_finalization = self._phase_reporting(scan_id)
                    phase_complete = prepared_finalization is not None
                if not phase_complete:
                    return
                self.workbench.update_progress(scan_id, phase_percent=100, message=f"Completed {phase.replace('_', ' ')}")
                resuming = False
            if prepared_finalization is None:
                raise EngineError("finalizer_not_prepared", "Reporting completed without a validated canonical finalization bundle.")
            records = finalize_scan(self.workbench, prepared_finalization)
            for record in records:
                self._emit("artifact.created", {"scanId": scan_id, "artifact": record})
            completed = self.workbench.get_scan(scan_id)
            self._emit("scan.completed", {"scanId": scan_id, "scan": completed})
        except CancelledScan:
            try:
                cancelled = self.workbench.cancel_scan(scan_id)
                self._emit("scan.cancelled", {"scanId": scan_id, "scan": cancelled})
            except EngineError as exc:
                self._log("warning", str(exc), scan_id=scan_id, code=exc.code)
        except InterruptedScan:
            try:
                interrupted = self.workbench.interrupt_scan(scan_id)
                self._log("info", "Scan handed off as interrupted for durable resume.", scan_id=scan_id, code="scan_interrupted")
                self._emit("scan.progress", {"scanId": scan_id, "progress": interrupted.get("progress")})
            except EngineError:
                pass
        except EngineError as exc:
            try:
                current = self.workbench.get_scan(scan_id)
                if current["status"] == "completed" and not current.get("sealed_manifest_digest"):
                    failed = self.workbench.fail_unsealed_completion(scan_id, exc.code, exc.message)
                else:
                    failed = self.workbench.fail_scan(scan_id, exc.code, exc.message)
            except EngineError:
                failed = self.workbench.get_scan(scan_id)
            self._emit("scan.failed", {"scanId": scan_id, "scan": failed, "error": {"code": exc.code, "message": exc.message, "data": exc.data}})
        except Exception as exc:  # defensive boundary: convert to structured failure
            message = redact(f"{type(exc).__name__}: {exc}")
            try:
                current = self.workbench.get_scan(scan_id)
                if current["status"] == "completed" and not current.get("sealed_manifest_digest"):
                    failed = self.workbench.fail_unsealed_completion(scan_id, "internal_error", message)
                else:
                    failed = self.workbench.fail_scan(scan_id, "internal_error", message)
            except EngineError:
                failed = self.workbench.get_scan(scan_id)
            self._emit("scan.failed", {"scanId": scan_id, "scan": failed, "error": {"code": "internal_error", "message": message}})
            self._log("error", "Internal runner exception:\n" + traceback.format_exc(limit=20), scan_id=scan_id, code="internal_error")
        finally:
            resume = False
            with self._lock:
                self._threads.pop(scan_id, None)
                if scan_id in self._resume_requested:
                    self._resume_requested.remove(scan_id)
                    resume = not self._shutdown.is_set()
            if resume:
                try:
                    if self.workbench.get_scan(scan_id)["status"] == "running":
                        self.start(scan_id, resuming=True)
                except EngineError as exc:
                    self._log("warning", str(exc), scan_id=scan_id, code=exc.code)

    def _phase_preflight(self, scan_id: str, *, require_same_snapshot: bool) -> None:
        scan = self.workbench.get_scan(scan_id)
        max_files, max_file_bytes = self._scan_limits(scan)
        inventory = self._build_inventory(scan, require_same_snapshot=require_same_snapshot)
        self._check(scan_id)
        capabilities = {
            "engine": "ready",
            "python": True,
            "git": inventory.git_available,
            "mode": scan["mode"],
            "diffReady": scan["mode"] != "diff" or inventory.git_available,
            "supportedFiles": len(inventory.files),
            "maxFiles": max_files,
            "maxFileBytes": max_file_bytes,
            "workspaceTrustedByHost": None,
        }
        if is_model_scan(scan):
            requested = (scan.get("capabilities") or {}).get("deepHost") or {}
            capabilities["deepHost"] = self.deep.preflight_host(requested.get("modelId"), requested.get("runtime"))
            capabilities["analysisProfile"] = "model"
        else:
            capabilities["analysisProfile"] = "fast"
        self.workbench.set_capabilities(scan_id, capabilities)
        diff_target = (inventory.diff_context or {}).get("target") or {}
        self.workbench.set_scan_target(
            scan_id, revision=inventory.revision, snapshot_digest=inventory.snapshot_digest,
            diff_base_revision=diff_target.get("resolvedBaseRevision"),
            diff_head_revision=diff_target.get("resolvedHeadRevision"),
        )
        inventory_path = self._inventory_path(scan)
        inventory_data = self._inventory_data(inventory, include_diff_context_row=is_model_scan(scan))
        if inventory.diff_context is not None:
            diff_path = Path(scan["artifact_dir"]) / "context" / "diff-context.json"
            write_json(diff_path, inventory.diff_context)
            diff_artifact = self.workbench.add_artifact(scan_id, "diffContext", diff_path, "application/json")
            self._emit("artifact.created", {"scanId": scan_id, "artifact": diff_artifact})
        write_json(inventory_path, inventory_data)
        artifact = self.workbench.add_artifact(scan_id, "inventory", inventory_path, "application/json")
        self._emit("artifact.created", {"scanId": scan_id, "artifact": artifact})
        self._progress(scan_id, len(inventory.files), len(inventory.files), "preflight inventory")
        for warning in inventory.warnings:
            self._log("warning", warning, scan_id=scan_id, code="coverage_warning")

    def _phase_threat_model(self, scan_id: str) -> None:
        scan = self.workbench.get_scan(scan_id)
        inventory = self._build_inventory(scan, require_same_snapshot=True)
        if is_model_scan(scan):
            context = write_security_context(self.workbench.workspace, scan, inventory)
            inventory_path = self._inventory_path(scan)
            inventory_data = (
                json.loads(inventory_path.read_text(encoding="utf-8"))
                if inventory_path.exists()
                else self._inventory_data(inventory, include_diff_context_row=is_model_scan(scan))
            )
            row_policy_refs = context.pop("rowPolicyRefs")
            inventory_data["securityContext"] = context
            for row in inventory_data.get("files") or []:
                refs = row_policy_refs.get(str(row.get("path") or ""), {})
                row.update({
                    "securityContextPath": context["path"],
                    "securityContextDigest": context["contextDigest"],
                    "securityContextArtifactDigest": context["artifactDigest"],
                    "securityGuidancePath": context["guidancePath"],
                    "securityGuidanceDigest": context["guidanceDigest"],
                    "policyRefs": refs.get("securityPolicies") or [],
                    "guidanceRefs": refs.get("securityGuidance") or [],
                })
                diff_context = inventory_data.get("diffContext") or {}
                if diff_context:
                    row.update({
                        "diffContextPath": diff_context.get("path"),
                        "diffContextDigest": diff_context.get("contextDigest"),
                        "diffSupportingPaths": diff_context.get("supportingPaths") or [],
                    })
            write_json(inventory_path, inventory_data)
            artifacts = (
                ("inventory", inventory_path, "application/json"),
                ("securityContext", Path(scan["artifact_dir"]) / context["path"], "application/json"),
                ("securityGuidance", Path(scan["artifact_dir"]) / context["guidancePath"], "text/markdown"),
                ("deepDiscoveryContext", Path(scan["artifact_dir"]) / "context" / "pre-discovery-threat-model.md", "text/markdown"),
            )
            for kind, path, media_type in artifacts:
                artifact = self.workbench.add_artifact(scan_id, kind, path, media_type)
                self._emit("artifact.created", {"scanId": scan_id, "artifact": artifact})
            self._progress(scan_id, len(inventory.files), len(inventory.files), "repository security context")
            return
        output = Path(scan["artifact_dir"]) / ARTIFACT_KINDS["threatModel"]
        build_threat_model(self.workbench.workspace, inventory, output)
        artifact = self.workbench.add_artifact(scan_id, "threatModel", output, "text/markdown")
        self._emit("artifact.created", {"scanId": scan_id, "artifact": artifact})
        self._progress(scan_id, len(inventory.files), len(inventory.files), "threat model")

    def _phase_discovery(self, scan_id: str) -> bool:
        scan = self.workbench.get_scan(scan_id)
        inventory = self._build_inventory(scan, require_same_snapshot=True)
        if is_model_scan(scan):
            inventory_path = self._inventory_path(scan)
            inventory_data = (
                json.loads(inventory_path.read_text(encoding="utf-8"))
                if inventory_path.exists()
                else self._inventory_data(inventory, include_diff_context_row=is_model_scan(scan))
            )
            status = self.deep.ensure(scan, inventory_data)
            canonical = self.deep.canonical_candidates(scan_id)
            if canonical is None:
                completed = int(status.get("workerCounts", {}).get("completed", 0))
                total = int(status.get("workersPerRound", 6))
                self.workbench.update_progress(
                    scan_id,
                    phase_percent=min(95.0, (completed / max(1, total)) * 80.0),
                    review_items_total=total,
                    review_items_completed=completed,
                    reportable_findings_count=int(status.get("canonicalCandidateCount", 0)),
                    deep_review_pass=int(status.get("round", 1)),
                    message=status.get("message") or "Awaiting Kiro Agent Deep discovery workers",
                )
                self._log(
                    "info",
                    "Model discovery is awaiting Agent-orchestrated independent workers; no deterministic Fast fallback was run.",
                    scan_id=scan_id,
                    code="model_agent_handoff",
                )
                return False
            for candidate in canonical:
                self._check(scan_id)
                finding = self.workbench.upsert_finding(scan_id, candidate, durable_deep_candidate=True)
                self._emit("finding.discovered", {"scanId": scan_id, "finding": finding})
            terminal_status = status.get("status", "saturated")
            self.workbench.update_progress(
                scan_id,
                phase_percent=100,
                review_items_total=len(inventory.files),
                review_items_completed=len(inventory.files),
                reportable_findings_count=len(canonical),
                deep_review_pass=int(status.get("round", 1)),
                message=f"Model discovery {terminal_status} with {len(canonical)} canonical candidate(s)",
            )
            return True

        candidates = scan_inventory(
            inventory,
            pass_name="all",
            progress=lambda completed, total, current: self._progress(scan_id, completed, total, current),
            cancelled=lambda: self._cancelled(scan_id),
            interrupted=self._interrupted,
        )
        for candidate in candidates:
            self._check(scan_id)
            finding = self.workbench.upsert_finding(scan_id, candidate)
            self._emit("finding.discovered", {"scanId": scan_id, "finding": finding})
        self.workbench.update_progress(
            scan_id,
            phase_percent=100,
            review_items_total=len(inventory.files),
            review_items_completed=len(inventory.files),
            reportable_findings_count=len(candidates),
            message=f"Discovered {len(candidates)} candidate finding(s)",
        )
        return True

    def _phase_validation(self, scan_id: str) -> bool:
        scan = self.workbench.get_scan(scan_id)
        if is_model_scan(scan):
            complete = self.tail.prepare_validation(scan_id)
            tail = self.tail.status(scan_id)
            self.workbench.update_progress(
                scan_id, phase_percent=95 if complete else 10,
                message="Model validation complete" if complete else f"Awaiting model tail {tail['activeKind']} assignment",
            )
            return complete
        summaries = self.workbench.list_findings(scan_id)
        total = len(summaries)
        for index, summary in enumerate(summaries, start=1):
            self._check(scan_id)
            finding = self.workbench.get_finding(summary["occurrenceId"])
            result = validate_finding(self.workbench.workspace, finding)
            updated = self.workbench.save_validation(finding["occurrenceId"], result)
            self._emit("finding.updated", {"scanId": scan_id, "finding": updated, "change": "validation"})
            self._progress(scan_id, index, total, finding["title"])
        counts = self.workbench.scan_counts(scan_id)
        self.workbench.update_progress(scan_id, phase_percent=100, reportable_findings_count=counts["validated"] + counts["needs_review"], message="Validation complete")
        return True

    def _phase_attack_path(self, scan_id: str) -> bool:
        scan = self.workbench.get_scan(scan_id)
        if is_model_scan(scan):
            complete = self.tail.prepare_attack_paths_and_writeups(scan_id)
            tail = self.tail.status(scan_id)
            self.workbench.update_progress(
                scan_id, phase_percent=95 if complete else 10,
                message="Model attack paths and writeups complete" if complete else f"Awaiting model tail {tail['activeKind']} assignment",
            )
            return complete
        summaries = self.workbench.list_findings(scan_id)
        eligible = [item for item in summaries if item.get("validationStatus") in ("validated", "needs_review")]
        total = len(eligible)
        for index, summary in enumerate(eligible, start=1):
            self._check(scan_id)
            finding = self.workbench.get_finding(summary["occurrenceId"])
            result = build_attack_path(finding)
            updated = self.workbench.save_attack_path(finding["occurrenceId"], result)
            self._emit("finding.updated", {"scanId": scan_id, "finding": updated, "change": "attack_path"})
            self._progress(scan_id, index, total, finding["title"])
        if total == 0:
            self._progress(scan_id, 0, 0, "no reportable attack paths")
        return True

    def _phase_reporting(self, scan_id: str) -> dict[str, Any] | None:
        scan = self.workbench.get_scan(scan_id)
        inventory_path = self._inventory_path(scan)
        if not inventory_path.exists():
            inventory = self._build_inventory(scan, require_same_snapshot=True)
            inventory_data = self._inventory_data(inventory, include_diff_context_row=is_model_scan(scan))
            write_json(inventory_path, inventory_data)
        else:
            inventory_data = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory = self._build_inventory(scan, require_same_snapshot=True)
        if is_model_scan(scan):
            state = self.workbench.get_deep_scan_state(scan_id)
            if state is not None:
                self.deep._validate_security_context(scan, state["worklist"])
            if not self.tail.prepare_hardening(scan_id):
                tail = self.tail.status(scan_id)
                self.workbench.update_progress(scan_id, phase_percent=10, message=f"Awaiting model tail {tail['activeKind']} assignment")
                return None
            threat_model = self.tail.threat_model(scan_id)
            writeup_paths = self.tail.writeup_paths(scan_id)
            tail_results = self.tail.completed_results(scan_id)
        else:
            threat_path = Path(scan["artifact_dir"]) / ARTIFACT_KINDS["threatModel"]
            threat_model = build_threat_model(self.workbench.workspace, inventory, threat_path)
            writeup_paths = None
            tail_results = None
        bundle = write_canonical_documents(
            self.workbench, scan_id, inventory_data, threat_model,
            writeup_paths=writeup_paths, tail_results=tail_results,
        )
        prepared = prepare_finalization(self.workbench, bundle)
        canonical_count = len(bundle["paths"])
        self._progress(scan_id, canonical_count, canonical_count, "validated canonical reporting documents")
        return prepared

    def shutdown(self, timeout: float = 5.0) -> list[str]:
        with self._lock:
            active_ids = [scan_id for scan_id, thread in self._threads.items() if thread.is_alive()]
            threads = list(self._threads.values())
        self._shutdown.set()
        for thread in threads:
            thread.join(timeout=max(0.0, timeout / max(1, len(threads))))
        interrupted = set(self.workbench.interrupt_owned_scans(self.session_id))
        for scan_id in active_ids:
            try:
                if self.workbench.get_scan(scan_id)["status"] == "interrupted":
                    interrupted.add(scan_id)
            except EngineError:
                pass
        return sorted(interrupted)

    def active_scan_ids(self) -> list[str]:
        with self._lock:
            return [scan_id for scan_id, thread in self._threads.items() if thread.is_alive()]
