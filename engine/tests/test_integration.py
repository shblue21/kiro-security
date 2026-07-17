from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

import jsonschema
import pytest

from kiro_security.errors import EngineError
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


def zero_finding_tail_result(assignment: dict, scan_id: str) -> dict:
    if assignment["kind"] == "threat_model":
        evidence_path = assignment["payload"]["evidencePaths"][0]
        return {
            "scanId": scan_id,
            "summary": f"The zero-finding integration fixture contains the reviewed source {evidence_path}.",
            "protectedAssets": ["Repository source integrity"],
            "actors": ["Repository user"],
            "trustBoundaries": ["Workspace input entering application code"],
            "entrypoints": [evidence_path],
            "privilegedOperations": ["Repository-defined runtime behavior"],
            "securityControls": ["Canonical supported-source inventory"],
            "highImpactAttackSurfaces": ["Repository-defined application entrypoints"],
            "candidateThreatAssumptions": [],
            "evidenceReferences": [{"path": evidence_path, "reason": "The path is in the immutable Deep worklist."}],
            "unknowns": ["No reportable canonical candidate was produced."],
        }
    assert assignment["kind"] == "hardening", assignment["kind"]
    return {
        "scanId": scan_id,
        "title": "Zero-finding integration hardening portfolio",
        "summary": "Preserve the reviewed security boundaries and continue repository-native regression coverage.",
        "architectureBoundaries": ["Workspace inputs cross into repository-defined application code."],
        "options": [
            {"id": "tests", "title": "Boundary regression tests", "description": "Add negative tests at reviewed boundaries.", "advantages": ["Executable evidence"], "disadvantages": ["Maintenance cost"], "tradeoffs": "Higher test maintenance for stronger regression detection.", "evidenceRefs": [scan_id]},
            {"id": "review", "title": "Focused security review", "description": "Repeat focused review when boundaries change.", "advantages": ["Low implementation impact"], "disadvantages": ["Manual effort"], "tradeoffs": "Lower code cost with recurring review effort.", "evidenceRefs": [scan_id]},
        ],
        "recommendedOptionId": "tests",
        "recommendationRationale": "Repository-native negative tests provide repeatable evidence.",
        "migrationSteps": ["Identify reviewed boundaries", "Add negative regression tests"],
        "rolloutPlan": ["Land tests with boundary owners"],
        "rollbackPlan": ["Revert only unstable tests while retaining documented boundaries"],
        "successMetrics": ["Boundary regression tests pass"],
        "workPackages": [{"id": "tests", "title": "Boundary tests", "dependencies": [], "deliverables": ["Negative regression tests"]}],
        "diagram": "Before: input -> repository boundary\nAfter: input -> tested repository boundary",
        "evidenceReferences": [scan_id],
    }


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
    tail_index = 0
    while time.monotonic() < deadline:
        scan = service.get_scan({"scanId": scan_id})
        if scan["status"] == "completed":
            return
        assert scan["status"] == "running", scan
        status = service.deep_get_status({"scanId": scan_id})
        if status.get("nextAction") != "claim_tail_assignment":
            time.sleep(0.03)
            continue
        tail_index += 1
        delegation_id = f"integration-tail-{tail_index}"
        assignment = service.deep_get_tail_assignment({
            "scanId": scan_id,
            "modelId": "integration-model",
            "delegationId": delegation_id,
            "runtime": DEEP_WORKER_RUNTIME,
        })
        assert assignment["kind"] in ("threat_model", "hardening"), assignment["kind"]
        service.deep_submit_tail_result({
            "scanId": scan_id,
            "assignmentId": assignment["assignmentId"],
            "claimToken": assignment["claimToken"],
            "modelId": "integration-model",
            "delegationId": delegation_id,
            "runtime": DEEP_WORKER_RUNTIME,
            "completionAttestation": DEEP_COMPLETION_ATTESTATION,
            "result": zero_finding_tail_result(assignment, scan_id),
        })
    raise AssertionError("Deep zero-finding tail did not complete")


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


def prepare_tail_test_scan(service: SecurityService) -> dict:
    scan = service.start_scan(deep_scan_params())
    deadline = time.monotonic() + 10
    while service.workbench.get_deep_scan_state(scan["id"]) is None:
        assert time.monotonic() < deadline
        time.sleep(0.02)
    while scan["id"] in service.runner.active_scan_ids():
        assert time.monotonic() < deadline
        time.sleep(0.02)
    with service.workbench.transaction() as connection:
        connection.execute("UPDATE deep_scan_state SET status='saturated' WHERE scan_id=?", (scan["id"],))
    return service.workbench.get_scan(scan["id"])


def tail_test_finding(service: SecurityService, scan_id: str) -> dict:
    path = service.workbench.get_deep_scan_state(scan_id)["worklist"][0]["path"]
    return service.workbench.upsert_finding(scan_id, {
        "fingerprint": f"kiro-security/deep-v1:sha256:{scan_id}", "ruleId": "integration.tail-proof",
        "identity": {"anchor": "integration-tail", "instance": f"{path}:1"},
        "title": "Integration tail proof", "summary": "Focused Deep tail regression finding.",
        "severity": {"level": "high", "score": None, "rationale": "Focused fixture severity."},
        "confidence": {"level": "high", "rationale": "Focused fixture confidence."},
        "taxonomy": {"category": "security", "cwe": []},
        "locations": [{"path": path, "startLine": 1, "endLine": 1, "role": "source"}],
        "remediation": "Preserve the focused regression contract.",
        "codeEvidence": [{"path": path, "startLine": 1, "endLine": 1, "role": "source", "code": "fixture", "explanation": "Focused fixture evidence."}],
        "details": {},
    })


def test_threat_completion_is_not_tail_complete(workspace: Path) -> None:
    service = service_for(workspace)
    try:
        scan = prepare_tail_test_scan(service)
        assert service.runner.tail.prepare_validation(scan["id"]) is False
        with service.workbench.transaction() as connection:
            connection.execute("UPDATE deep_tail_assignments SET status='completed', result_json='{}', receipt_digest='sha256:test' WHERE scan_id=? AND kind='threat_model'", (scan["id"],))
        status = service.runner.tail.status(scan["id"])
        assert status["counts"]["hardening"]["completed"] == 0
        assert status["nextAction"] == "await_tail_materialization"
    finally:
        service.shutdown({})


def test_writeup_rejects_symlinked_findings_ancestor(workspace: Path, tmp_path: Path) -> None:
    service = service_for(workspace)
    try:
        scan = prepare_tail_test_scan(service)
        finding = tail_test_finding(service, scan["id"])
        outside = tmp_path / "outside"
        outside.mkdir()
        (Path(scan["artifact_dir"]) / "findings").symlink_to(outside, target_is_directory=True)
        sections = {key: key for key in (
            "title", "severity", "executiveSummary", "affectedComponent", "threatContext", "rootCause",
            "evidence", "validationProof", "counterevidence", "attackPath", "impact", "remediation",
            "verificationGuidance", "proofGaps",
        )}
        with pytest.raises(EngineError) as error:
            service.runner.tail._materialize_writeup(scan, {"subject_id": finding["occurrenceId"]}, {"findingId": finding["findingId"], "sections": sections, "poc": []})
        assert error.value.code == "unsafe_artifact_path"
        assert not any(outside.iterdir())
    finally:
        service.shutdown({})


def test_deep_get_finding_overlays_completed_tail_proof(workspace: Path) -> None:
    service = service_for(workspace)
    try:
        scan = prepare_tail_test_scan(service)
        finding = tail_test_finding(service, scan["id"])
        validation = {"findingId": finding["findingId"], "status": "validated", "method": "focused test", "rationale": "Confirmed.", "evidence": [], "counterevidence": ["none"], "crossFileTrace": ["trace"], "frameworkControls": ["none"], "proofGaps": [], "tests": [{"name": "focused", "result": "PASS"}], "dynamicValidationUnavailableReason": None}
        attack = {"findingId": finding["findingId"], "actor": "remote user", "crossFilePath": [{"path": finding["locations"][0]["path"], "step": "flow"}], "severity": {"level": "high", "rationale": "proof"}, "confidence": {"level": "high", "rationale": "proof"}}
        now = "2026-01-01T00:00:00.000Z"
        with service.workbench.transaction() as connection:
            for kind, result in (("validation", validation), ("attack_path", attack)):
                connection.execute("INSERT INTO deep_tail_assignments(id,scan_id,kind,subject_id,status,attempt,payload_json,result_json,receipt_digest,created_at,updated_at,completed_at) VALUES (?,?,?,?, 'completed',1,'{}',?,'sha256:test',?,?,?)", (f"tail-{kind}", scan["id"], kind, finding["occurrenceId"], json.dumps(result), now, now, now))
        detail = service.get_finding({"occurrenceId": finding["occurrenceId"]})
        assert detail["validation"]["tests"][0]["result"] == "PASS"
        assert detail["attackPath"]["actor"] == "remote user"
    finally:
        service.shutdown({})


def test_resume_recovers_orphaned_claimed_tail_attempt(workspace: Path) -> None:
    service = service_for(workspace)
    resumed: SecurityService | None = None
    try:
        scan = prepare_tail_test_scan(service)
        assert service.runner.tail.prepare_validation(scan["id"]) is False
        claimed = service.deep_get_tail_assignment({"scanId": scan["id"], "modelId": "integration-model", "delegationId": "orphaned-tail-1", "runtime": DEEP_WORKER_RUNTIME})
        service.shutdown({})
        resumed = service_for(workspace)
        resumed.resume_scan({"scanId": scan["id"]})
        connection = resumed.workbench._connect()
        try:
            attempts = connection.execute("SELECT status,attempt,previous_assignment_id FROM deep_tail_assignments WHERE scan_id=? AND kind='threat_model' ORDER BY attempt", (scan["id"],)).fetchall()
        finally:
            connection.close()
        assert [(row["status"], row["attempt"]) for row in attempts] == [("failed", 1), ("pending", 2)]
        assert attempts[1]["previous_assignment_id"] == claimed["assignmentId"]
        replacement = resumed.deep_get_tail_assignment({"scanId": scan["id"], "modelId": "integration-model", "delegationId": "orphaned-tail-2", "runtime": DEEP_WORKER_RUNTIME})
        assert replacement["attempt"] == 2
    finally:
        if resumed is not None:
            resumed.shutdown({})
        else:
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


def test_deep_security_context_policy_binding_and_tamper(tmp_path: Path) -> None:
    workspace = tmp_path / "context-workspace"
    for relative, content in {
        "SECURITY.md": "Root repository security policy.\n",
        "AGENTS.md": "Use the repository formatter.\n",
        "README.md": "Repository service AAAA.\n",
        "src/SECURITY.md": "Nested source security policy.\n",
        "src/AGENTS.md": "Security scan guidance: inspect authentication boundaries.\n",
        "src/service.py": "def route(request):\n    return request.token\n",
        "lib/helper.py": "def helper(config):\n    return config\n",
    }.items():
        path = workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    (workspace / "Dockerfile").write_bytes(b"FROM invalid\xff\n")
    service = service_for(workspace)
    try:
        scan = service.start_scan(deep_scan_params())
        deadline = time.monotonic() + 10
        while service.deep_get_status({"scanId": scan["id"]}).get("nextAction") != "claim_worker":
            assert time.monotonic() < deadline
            time.sleep(0.02)
        state = service.workbench.get_deep_scan_state(scan["id"])
        context_path = Path(scan["artifact_dir"]) / "context" / "security-context.json"
        context = json.loads(context_path.read_text(encoding="utf-8"))
        assert [(item["path"], item["appliesTo"]) for item in context["policySources"]] == [
            ("SECURITY.md", "."), ("src/SECURITY.md", "src")
        ]
        assert [item["path"] for item in context["guidanceSources"]] == ["src/AGENTS.md"]
        considered = {item["path"]: item["includedAsSecurityGuidance"] for item in context["consideredGuidanceSources"]}
        assert considered == {"AGENTS.md": False, "src/AGENTS.md": True}
        rows = {item["path"]: item for item in state["worklist"]}
        assert len(rows["src/service.py"]["policyRefs"]) == 2
        assert len(rows["lib/helper.py"]["policyRefs"]) == 1
        assert rows["src/service.py"]["guidanceRefs"] and not rows["lib/helper.py"]["guidanceRefs"]
        encoded = json.dumps(state["worklist"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert hashlib.sha256(encoded.encode("utf-8", "surrogatepass")).hexdigest() == state["worklist_digest"]
        payload = service.runner.tail._threat_payload(service.workbench.get_scan(scan["id"]))
        provenance = {item["path"]: item for item in payload["repositoryContext"]["sourceProvenance"]}
        assert "src/service.py" not in provenance and "lib/helper.py" not in provenance
        assert provenance["Dockerfile"]["status"] == "invalid_utf8"
        assert "Dockerfile" not in payload["evidencePaths"]
        assert {"README.md", "SECURITY.md"} <= set(payload["evidencePaths"])
        readme = workspace / "README.md"
        original = readme.read_text(encoding="utf-8")
        changed = original.replace("AAAA", "BBBB")
        assert len(original) == len(changed)
        readme.write_text(changed, encoding="utf-8")
        with pytest.raises(EngineError) as error:
            service.deep_claim_worker({
                "scanId": scan["id"], "modelId": "integration-model",
                "delegationId": "changed-readme", "runtime": DEEP_WORKER_RUNTIME,
            })
        assert error.value.code == "security_context_changed"
        readme.write_text(original, encoding="utf-8")
        assignments = [service.deep_claim_worker({
            "scanId": scan["id"], "modelId": "integration-model",
            "delegationId": f"context-worker-{index}", "runtime": DEEP_WORKER_RUNTIME,
        }) for index in range(6)]
        assert len({(item["securityContextPath"], item["securityContextDigest"], item["securityGuidanceDigest"]) for item in assignments}) == 1
        context_path.write_text(context_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
        with pytest.raises(EngineError) as error:
            service.deep_submit_worker({
                "scanId": scan["id"], "workerId": assignments[0]["workerId"],
                "claimToken": assignments[0]["claimToken"], "rowReceipts": [], "candidates": [],
                "completionAttestation": DEEP_COMPLETION_ATTESTATION,
            })
        assert error.value.code == "security_context_changed"
    finally:
        service.shutdown({})


def test_deep_security_context_rejects_undigestible_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "oversized-policy-workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("value = input()\n", encoding="utf-8")
    (workspace / "SECURITY.md").write_bytes(b"A" * (1024 * 1024 + 1))
    service = service_for(workspace)
    try:
        scan = service.start_scan(deep_scan_params())
        failed = wait_for_scan(service, scan["id"])
        assert failed["status"] == "failed"
        assert failed["failure_code"] == "security_context_invalid"
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
