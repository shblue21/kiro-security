from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import jsonschema
import pytest

from kiro_security.service import SecurityService

from .conftest import PROJECT_ROOT, run_git, wait_for_scan

pytestmark = pytest.mark.integration


def service_for(workspace: Path, events: list[dict] | None = None) -> SecurityService:
    sink = events if events is not None else []
    return SecurityService(str(workspace), "test", lambda event, payload: sink.append({"event": event, "payload": payload}))


def assert_schema(path: Path, schema_name: str) -> None:
    schema = json.loads((PROJECT_ROOT / "engine" / "schemas" / schema_name).read_text(encoding="utf-8"))
    document = json.loads(path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(document)


DEEP_WORKER_RUNTIME = {
    "contractVersion": "deep-worker/v2",
    "agentType": "delegated-worker",
    "reasoningEffort": "high",
    "hostVersion": "integration-test-host/1.0",
    "delegationMode": "fresh",
    "capabilities": {
        "delegatedAgentAvailable": True,
        "freshContextMode": True,
        "usableWorkerSlots": 6,
        "goalSupport": True,
    },
}
DEEP_COMPLETION_ATTESTATION = {
    "freshContext": True,
    "coordinatorHistoryInherited": False,
    "workerState": "completed_idle",
}


def deep_scan_params(**overrides: object) -> dict:
    return {"mode": "deep", "scope": ".", "modelId": "integration-model", "runtime": DEEP_WORKER_RUNTIME, **overrides}


def complete_empty_deep_round(service: SecurityService, scan_id: str, timeout: float = 30.0) -> None:
    """Drive one honest six-worker zero-candidate round for integration tests."""

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = service.deep_get_status({"scanId": scan_id})
        if status.get("nextAction") in ("claim_worker", "submit_claimed_workers"):
            break
        scan = service.get_scan({"scanId": scan_id})
        if scan["status"] not in ("queued", "running"):
            raise AssertionError(f"deep scan stopped before worker handoff: {scan}")
        time.sleep(0.03)
    else:
        raise AssertionError("Deep worklist was not prepared")

    # All six workers must be claimed before the first result is submitted.
    assignments = [
        service.deep_claim_worker({
            "scanId": scan_id,
            "modelId": "integration-model",
            "delegationId": f"integration-delegation-{worker_index}",
            "runtime": DEEP_WORKER_RUNTIME,
        })
        for worker_index in range(1, 7)
    ]
    for assignment in assignments:
        row_receipts = [
            {
                "rowId": row["rowId"],
                "disposition": "not_applicable",
                "reason": "The independent integration worker reviewed this row and submitted no candidate.",
                "evidenceRefs": [],
                "candidateIds": [],
            }
            for row in assignment["worklist"]
        ]
        service.deep_submit_worker({
            "scanId": scan_id,
            "workerId": assignment["workerId"],
            "claimToken": assignment["claimToken"],
            "rowReceipts": row_receipts,
            "threatModel": "Independent integration-test threat model.",
            "summary": "No candidate was submitted by this deterministic integration worker.",
            "candidates": [],
            "completionAttestation": DEEP_COMPLETION_ATTESTATION,
        })
    merge = service.deep_claim_merge({"scanId": scan_id})
    service.deep_submit_merge({
        "scanId": scan_id,
        "claimToken": merge["claimToken"],
        "canonicalCandidates": [],
    })


def test_standard_scan_artifacts_validation_exports_and_events(workspace: Path, tmp_path: Path) -> None:
    events: list[dict] = []
    service = service_for(workspace, events)
    try:
        scan = service.start_scan({"mode": "standard", "scope": "."})
        completed = wait_for_scan(service, scan["id"])
        assert completed["status"] == "completed", completed["failure_message"]
        assert completed["phase"] == "reporting"
        assert completed["progress"]["overall_percent"] == 100
        findings = service.list_findings({"scanId": scan["id"], "limit": 2000})
        assert len(findings) >= 5
        assert all(item["validationStatus"] in ("validated", "needs_review", "rejected") for item in findings)
        assert any(item["validationStatus"] == "validated" for item in findings)
        detail = service.get_finding({"occurrenceId": findings[0]["occurrenceId"]})
        assert detail["codeEvidence"]
        if detail["validationStatus"] in ("validated", "needs_review"):
            assert detail["attackPath"]

        artifacts = {item["kind"]: Path(item["path"]) for item in completed["artifacts"]}
        for kind in ("manifest", "coverage", "findings", "markdownReport", "threatModel", "discovery", "validation", "attackPath", "hardening"):
            assert artifacts[kind].is_file(), kind
        assert_schema(artifacts["findings"], "findings.schema.json")
        assert_schema(artifacts["coverage"], "coverage.schema.json")
        assert_schema(artifacts["manifest"], "scan-manifest.schema.json")

        for format_name, suffix in (("json", ".json"), ("csv", ".csv"), ("sarif", ".sarif"), ("markdown", ".md")):
            destination = tmp_path / f"report-{format_name}{suffix}"
            exported = service.export_report({"scanId": scan["id"], "format": format_name, "destination": str(destination), "allowedRoot": str(tmp_path)})
            assert Path(exported["path"]).is_file()
            assert exported["sha256"]
        event_names = {item["event"] for item in events}
        assert {"scan.started", "scan.phaseChanged", "scan.progress", "finding.discovered", "finding.updated", "artifact.created", "scan.completed"} <= event_names
    finally:
        service.shutdown({})


def test_deep_and_diff_modes_use_real_repository_state(workspace: Path) -> None:
    service = service_for(workspace)
    try:
        deep = service.start_scan(deep_scan_params())
        complete_empty_deep_round(service, deep["id"])
        completed = wait_for_scan(service, deep["id"])
        assert completed["status"] == "completed", completed["failure_message"]
        assert completed["mode"] == "deep"
        assert service.list_findings({"scanId": deep["id"]}) == []
        assert completed["coverage"]["completeness"] == "partial"
        assert completed["coverage"]["deepStatus"] == "saturated"
        assert completed["coverage"]["deferred"], "unsupported in-scope files remain explicit"

        changed = workspace / "src" / "safe.py"
        changed.write_text(changed.read_text(encoding="utf-8") + "\nuser = input()\nsubprocess.run(user, shell=True)\n", encoding="utf-8")
        diff = service.start_scan({"mode": "diff", "scope": ".", "diffTargetKind": "working_tree"})
        diff_completed = wait_for_scan(service, diff["id"])
        assert diff_completed["status"] == "completed", diff_completed["failure_message"]
        assert diff_completed["files_total"] == 1
        diff_findings = service.list_findings({"scanId": diff["id"]})
        assert diff_findings
        assert all(item["locations"][0]["path"] == "src/safe.py" for item in diff_findings)
    finally:
        service.shutdown({})


def test_cancellation_is_cooperative_and_terminal(workspace: Path) -> None:
    for index in range(500):
        (workspace / "src" / f"generated_{index}.py").write_text(f"value_{index} = input()\n", encoding="utf-8")
    service = service_for(workspace)
    try:
        scan = service.start_scan(deep_scan_params(maxFiles=2000))
        service.cancel_scan({"scanId": scan["id"]})
        terminal = wait_for_scan(service, scan["id"])
        assert terminal["status"] == "cancelled"
        assert terminal["cancellation_requested"]
    finally:
        service.shutdown({})


def test_shutdown_handoff_and_resume_after_restart(workspace: Path) -> None:
    first = service_for(workspace)
    scan = first.start_scan(deep_scan_params())
    first.runner._shutdown.set()  # deterministic interruption at the next cooperative boundary
    interrupted = wait_for_scan(first, scan["id"])
    assert interrupted["status"] == "interrupted"
    assert interrupted["handoff_state"] == "available"
    first.shutdown({})

    second = service_for(workspace)
    try:
        resumed = second.resume_scan({"scanId": scan["id"]})
        assert resumed["status"] == "running"
        complete_empty_deep_round(second, scan["id"], timeout=45)
        completed = wait_for_scan(second, scan["id"], timeout=45)
        assert completed["status"] == "completed", completed["failure_message"]
        assert completed["resume_count"] >= 1
    finally:
        second.shutdown({})


def test_source_locations_are_workspace_relative_and_existing(workspace: Path) -> None:
    service = service_for(workspace)
    try:
        scan = service.start_scan({"mode": "standard", "scope": "."})
        completed = wait_for_scan(service, scan["id"])
        assert completed["status"] == "completed"
        for finding in service.list_findings({"scanId": scan["id"]}):
            for location in finding["locations"]:
                assert not Path(location["path"]).is_absolute()
                source = (workspace / location["path"]).resolve()
                assert workspace == source or workspace in source.parents
                assert source.is_file()
                assert location["startLine"] >= 1
    finally:
        service.shutdown({})


def test_tracking_handoff_related_artifacts_and_cleanup(workspace: Path, tmp_path: Path) -> None:
    from kiro_security.errors import EngineError

    service = service_for(workspace)
    try:
        scan = service.start_scan({"mode": "standard", "scope": "."})
        completed = wait_for_scan(service, scan["id"])
        assert completed["status"] == "completed"
        findings = service.list_findings({"scanId": scan["id"]})
        assert findings
        occurrence_id = findings[0]["occurrenceId"]
        handoff = service.create_tracking_handoff({
            "occurrenceId": occurrence_id,
            "provider": "github",
            "destination": "owner/repository",
            "stableLink": "vscode://test/finding/example",
        })
        payload_path = Path(handoff["artifact"]["path"])
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        assert payload["externalWritePerformed"] is False
        assert payload["approvalRequired"] is True
        assert payload["finding"]["stableLink"] == "vscode://test/finding/example"
        detail = service.get_finding({"occurrenceId": occurrence_id})
        assert detail["trackingRecords"][0]["status"] == "prepared"
        single_export = tmp_path / "one-finding.json"
        service.export_report({
            "scanId": scan["id"], "occurrenceId": occurrence_id, "format": "json",
            "destination": str(single_export), "allowedRoot": str(tmp_path),
        })
        exported_document = json.loads(single_export.read_text(encoding="utf-8"))
        assert len(exported_document["findings"]) == 1
        assert exported_document["findings"][0]["occurrenceId"] == occurrence_id
        assert any(item["kind"].startswith("tracking:") for item in detail["artifactLinks"])
        assert isinstance(detail["relatedFindings"], list)

        external_export = tmp_path / "retained.json"
        service.export_report({
            "scanId": scan["id"], "format": "json", "destination": str(external_export),
            "allowedRoot": str(tmp_path),
        })
        artifact_dir = Path(completed["artifact_dir"])
        cleanup = service.cleanup_scan({"scanId": scan["id"]})
        assert cleanup["scanId"] == scan["id"]
        assert not artifact_dir.exists()
        assert external_export.exists(), "explicit external exports are retained during cleanup"
        with pytest.raises(EngineError) as error:
            service.get_scan({"scanId": scan["id"]})
        assert error.value.code == "scan_not_found"
    finally:
        service.shutdown({})
