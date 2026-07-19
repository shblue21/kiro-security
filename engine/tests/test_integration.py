from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path

import jsonschema
import pytest
import kiro_security.remediation as remediation_module
import kiro_security.service as service_module

from kiro_security.errors import EngineError
from kiro_security.remediation import parse_remediation_patch
from kiro_security.security import redact
from kiro_security.service import SecurityService
from kiro_security.tracking import normalize_tracking_readback

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


def tracking_proof(provider: str = "github", host: str = "github.com") -> dict:
    return {
        "connector": {"provider": provider, "host": host, "identity": "integration-connector"},
        "duplicateSearch": {"status": "none", "query": "finding-id and fingerprint", "candidateIds": []},
        "visibility": "private",
        "audience": ["security-team"],
    }


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


def test_deep_two_round_discovery_enforces_worker_merge_and_receipt_contracts(workspace: Path) -> None:
    service = service_for(workspace)

    def receipts(assignment: dict, candidate_id: str | None = None, candidate_path: str | None = None) -> list[dict]:
        return [
            {
                "rowId": row["rowId"],
                "disposition": "reportable" if candidate_id and row["path"] == candidate_path else "not_applicable",
                "reason": "The independent worker reviewed this complete worklist row.",
                "evidenceRefs": [],
                "candidateIds": [candidate_id] if candidate_id and row["path"] == candidate_path else [],
            }
            for row in assignment["worklist"]
        ]

    def submit(assignment: dict, *, candidates: list[dict] | None = None, completion: dict | None = None) -> dict:
        submitted = candidates or []
        candidate_id = submitted[0]["candidateId"] if submitted else None
        candidate_path = submitted[0]["affectedLocations"][0]["path"] if submitted else None
        return service.deep_submit_worker({
            "scanId": scan["id"],
            "workerId": assignment["workerId"],
            "claimToken": assignment["claimToken"],
            "rowReceipts": receipts(assignment, candidate_id, candidate_path),
            "threatModel": f"Independent round {assignment['round']} worker {assignment['workerIndex']} threat model.",
            "summary": "Focused multi-round discovery regression.",
            "seedResearch": "Repository-native seed review." if submitted else None,
            "dedupeReport": "No prior canonical candidate subsumed this candidate." if submitted else None,
            "candidates": submitted,
            "completionAttestation": completion or DEEP_COMPLETION_ATTESTATION,
        })

    try:
        scan = service.start_scan(deep_scan_params())
        deadline = time.monotonic() + 10
        while service.deep_get_status({"scanId": scan["id"]}).get("nextAction") != "claim_worker":
            assert time.monotonic() < deadline
            time.sleep(0.02)

        first = service.deep_claim_worker({
            "scanId": scan["id"], "modelId": "integration-model",
            "delegationId": "round-1-interrupted", "runtime": DEEP_WORKER_RUNTIME,
        })
        with pytest.raises(EngineError) as error:
            submit(first)
        assert error.value.code == "deep_round_not_fully_claimed"

        service.deep_retry_worker({
            "scanId": scan["id"], "workerIndex": first["workerIndex"],
            "reason": "Simulated interrupted delegated worker replacement.",
        })
        replacement = service.deep_claim_worker({
            "scanId": scan["id"], "modelId": "integration-model",
            "delegationId": "round-1-replacement", "runtime": DEEP_WORKER_RUNTIME,
        })
        with pytest.raises(EngineError) as error:
            submit(first)
        assert error.value.code == "invalid_worker_claim"

        mismatched_runtime = {**DEEP_WORKER_RUNTIME, "reasoningEffort": "medium"}
        with pytest.raises(EngineError) as error:
            service.deep_claim_worker({
                "scanId": scan["id"], "modelId": "integration-model",
                "delegationId": "round-1-profile-drift", "runtime": mismatched_runtime,
            })
        assert error.value.code == "deep_worker_profile_mismatch"

        round_one = [replacement] + [
            service.deep_claim_worker({
                "scanId": scan["id"], "modelId": "integration-model",
                "delegationId": f"round-1-worker-{index}", "runtime": DEEP_WORKER_RUNTIME,
            })
            for index in range(2, 7)
        ]
        assert len(round_one) == 6
        assert {item["workerIndex"] for item in round_one} == set(range(1, 7))
        with pytest.raises(EngineError) as error:
            service.deep_claim_worker({
                "scanId": scan["id"], "modelId": "integration-model",
                "delegationId": "round-1-worker-7", "runtime": DEEP_WORKER_RUNTIME,
            })
        assert error.value.code == "deep_no_pending_worker"
        assert len({(
            item["worklistDigest"], item["securityContextPath"], item["securityContextDigest"],
            item["securityGuidanceDigest"],
        ) for item in round_one}) == 1

        with pytest.raises(EngineError) as error:
            submit(replacement, completion={
                "freshContext": False,
                "coordinatorHistoryInherited": False,
                "workerState": "completed_idle",
            })
        assert error.value.code == "invalid_worker_completion_attestation"

        candidate_path = next(row["path"] for row in replacement["worklist"] if row["language"] == "python")
        source_lines = (workspace / candidate_path).read_text(encoding="utf-8").splitlines()
        source_line = next(index for index, line in enumerate(source_lines, start=1) if "request.args.get('command')" in line)
        sink_line = next(index for index, line in enumerate(source_lines, start=1) if "os.system(command)" in line)
        candidate = {
            "candidateId": "round-1-command-injection",
            "ruleId": "integration.command-injection",
            "identity": {"anchor": "command-execution-boundary", "instance": "request-command-to-os-system"},
            "title": "Request input reaches command execution",
            "summary": "An independently reviewed request value reaches a command execution boundary.",
            "severity": {"level": "high", "rationale": "The sink executes attacker-controlled command text."},
            "confidence": {"level": "high", "rationale": "The submitted source and sink evidence show the flow."},
            "taxonomy": {"category": "command-injection", "cwe": ["CWE-78"]},
            "affectedLocations": [
                {"path": candidate_path, "startLine": source_line, "endLine": source_line, "role": "source"},
                {"path": candidate_path, "startLine": sink_line, "endLine": sink_line, "role": "sink"},
            ],
            "impact": "An attacker may execute commands with the application process privileges.",
            "rootCause": "Attacker-controlled command text crosses into a shell execution sink without an allowlist.",
            "remediation": "Replace shell execution with a fixed executable and validated argument array.",
            "codeEvidence": [
                {"path": candidate_path, "startLine": source_line, "endLine": source_line, "role": "source", "code": source_lines[source_line - 1].strip(), "explanation": "The request supplies command text."},
                {"path": candidate_path, "startLine": sink_line, "endLine": sink_line, "role": "sink", "code": source_lines[sink_line - 1].strip(), "explanation": "The value reaches a shell execution sink."},
            ],
        }
        submit(replacement, candidates=[candidate])
        for assignment in round_one[1:]:
            submit(assignment)

        receipt_rows = service.workbench.list_deep_worker_coverage_receipts(scan["id"], 1)
        assert len(receipt_rows) == 6 * len(replacement["worklist"])
        assert {item["workerId"] for item in receipt_rows} == {item["workerId"] for item in round_one}
        worker_dir = Path(scan["artifact_dir"]) / "deep_discovery" / "round-01" / "worker-01"
        for relative in (
            "worker-result.json", "threat-model.md", "finding-discovery-report.md", "seed-research.md",
            "dedupe-report.md", "work-ledger.jsonl", "raw-candidates.jsonl", "deduped-candidates.jsonl",
            "repository-coverage-ledger.md", "candidate-ledger/r1-w1-c1.json",
        ):
            assert (worker_dir / relative).is_file(), relative

        merge = service.deep_claim_merge({"scanId": scan["id"]})
        connection = service.workbench._connect()
        try:
            result = connection.execute("SELECT result_json FROM deep_workers WHERE id=?", (replacement["workerId"],)).fetchone()
        finally:
            connection.close()
        source = json.loads(result["result_json"])["candidates"][0]
        canonical = {
            **source,
            "sourceRefs": [source["sourceRef"]],
            "mergeRationale": "The single evidence chain is retained without deduplication.",
            "identityRationale": "The canonical semantic identity matches the submitted source identity.",
            "remediationSubsumption": "The canonical remediation preserves the submitted remediation.",
        }
        with pytest.raises(EngineError) as error:
            service.deep_submit_merge({
                "scanId": scan["id"], "claimToken": merge["claimToken"],
                "canonicalCandidates": [{**canonical, "sourceRefs": ["r1-w1-c999"]}],
            })
        assert error.value.code == "incomplete_semantic_merge"
        with pytest.raises(EngineError) as error:
            service.deep_submit_merge({
                "scanId": scan["id"], "claimToken": merge["claimToken"],
                "canonicalCandidates": [{**canonical, "identity": {**canonical["identity"], "instance": "manipulated"}}],
            })
        assert error.value.code == "canonical_source_identity_mismatch"
        first_merge = service.deep_submit_merge({
            "scanId": scan["id"], "claimToken": merge["claimToken"], "canonicalCandidates": [canonical],
        })
        assert first_merge["status"] == "awaiting_workers"
        assert first_merge["round"] == 2 and first_merge["noveltyCount"] == 1

        round_two = [
            service.deep_claim_worker({
                "scanId": scan["id"], "modelId": "integration-model",
                "delegationId": f"round-2-worker-{index}", "runtime": DEEP_WORKER_RUNTIME,
            })
            for index in range(1, 7)
        ]
        for assignment in round_two:
            submit(assignment)
        retained = service.workbench.get_deep_scan_state(scan["id"])["canonicalCandidates"][0]
        retained_identity = (retained["canonicalId"], retained["fingerprint"], retained["identity"])
        second_merge = service.deep_claim_merge({"scanId": scan["id"]})
        saturated = service.deep_submit_merge({
            "scanId": scan["id"],
            "claimToken": second_merge["claimToken"],
            "canonicalCandidates": [{
                **retained,
                "sourceRefs": [],
                "mergeRationale": "No new source candidate changed the retained canonical finding.",
                "identityRationale": "The prior canonical identity and fingerprint are unchanged.",
                "remediationSubsumption": "The prior canonical remediation is retained unchanged.",
            }],
        })
        assert saturated["status"] == "saturated"
        assert saturated["round"] == 2 and saturated["noveltyCount"] == 0
        assert saturated["maxRounds"] == 10 and saturated["canonicalCandidateCount"] == 1
        final_candidate = service.workbench.get_deep_scan_state(scan["id"])["canonicalCandidates"][0]
        assert (final_candidate["canonicalId"], final_candidate["fingerprint"], final_candidate["identity"]) == retained_identity
        assert len(service.workbench.list_deep_worker_coverage_receipts(scan["id"], 2)) == 6 * len(round_two[0]["worklist"])
    finally:
        service.shutdown({})


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
        with pytest.raises(EngineError) as immutable_validation:
            service.validate_finding({"occurrenceId": finding["occurrenceId"]})
        assert immutable_validation.value.code == "model_tail_result_immutable"
        with pytest.raises(EngineError) as immutable_hardening:
            service.create_hardening_proposal({"scanId": scan["id"]})
        assert immutable_hardening.value.code == "model_tail_result_immutable"
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

        model_diff = service.start_scan({
            "mode": "diff", "analysisProfile": "model", "scope": ".",
            "diffTargetKind": "working_tree", "modelId": "integration-model", "runtime": DEEP_WORKER_RUNTIME,
        })
        deadline = time.monotonic() + 10
        while service.deep_get_status({"scanId": model_diff["id"]}).get("nextAction") != "claim_worker":
            assert time.monotonic() < deadline
            time.sleep(0.02)
        changed.write_text(changed.read_text(encoding="utf-8") + "\n# changed after Diff preflight\n", encoding="utf-8")
        with pytest.raises(EngineError) as drift:
            service.deep_claim_worker({
                "scanId": model_diff["id"], "modelId": "integration-model",
                "delegationId": "diff-drift", "runtime": DEEP_WORKER_RUNTIME,
            })
        assert drift.value.code == "diff_context_changed"
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
        handoff = service.workbench.create_scan(
            workspace_id=service.workspace_record["id"], mode="standard", scope=".",
            artifact_dir=None, session_id=service.session_id,
        )
        service.workbench.set_capabilities(handoff["id"], {"analysisProfile": "model"})
        for phase in ("threat_model", "discovery", "validation"):
            service.workbench.set_phase(handoff["id"], phase)
        cancelled = service.cancel_scan({"scanId": handoff["id"]})
        assert cancelled["status"] == "cancelled"
        assert cancelled["phase"] == "validation"
    finally:
        service.shutdown({})


def test_shutdown_handoff_and_resume_after_restart(workspace: Path) -> None:
    first = service_for(workspace)
    scan = first.start_scan(deep_scan_params(maxFiles=321, maxFileBytes=4096))
    first.runner._shutdown.set()  # deterministic interruption at the next cooperative boundary
    interrupted = wait_for_scan(first, scan["id"])
    assert interrupted["status"] == "interrupted"
    assert interrupted["handoff_state"] == "available"
    first.shutdown({})

    second = service_for(workspace)
    try:
        resumed = second.resume_scan({"scanId": scan["id"]})
        assert resumed["status"] == "running"
        assert resumed["capabilities"]["maxFiles"] == 321
        assert resumed["capabilities"]["maxFileBytes"] == 4096
        complete_empty_deep_round(second, scan["id"], timeout=45)
        completed = wait_for_scan(second, scan["id"], timeout=45)
        assert completed["status"] == "completed", completed["failure_message"]
        assert completed["resume_count"] >= 1
    finally:
        second.shutdown({})


def test_range_diff_resume_uses_resolved_revisions(workspace: Path) -> None:
    base = run_git(workspace, "rev-parse", "HEAD")
    run_git(workspace, "tag", "resume-base", base)
    source = workspace / "src" / "safe.py"
    source.write_text(source.read_text(encoding="utf-8") + "\nprint('range head')\n", encoding="utf-8")
    run_git(workspace, "add", "src/safe.py")
    run_git(workspace, "commit", "-m", "range head")
    head = run_git(workspace, "rev-parse", "HEAD")

    first = service_for(workspace)
    scan = first.start_scan({
        "mode": "diff", "analysisProfile": "model", "scope": ".", "diffTargetKind": "range",
        "diffBaseRevision": "resume-base", "diffHeadRevision": head,
        "modelId": "integration-model", "runtime": DEEP_WORKER_RUNTIME,
    })
    deadline = time.monotonic() + 10
    while first.deep_get_status({"scanId": scan["id"]}).get("nextAction") != "claim_worker":
        assert time.monotonic() < deadline
        time.sleep(0.02)
    sealed = first.get_scan({"scanId": scan["id"]})
    assert sealed["diff_base_revision"] == base
    assert sealed["diff_head_revision"] == head
    first.shutdown({})
    run_git(workspace, "tag", "-d", "resume-base")

    second = service_for(workspace)
    try:
        second.resume_scan({"scanId": scan["id"]})
        deadline = time.monotonic() + 10
        while (
            scan["id"] in second.runner.active_scan_ids()
            or second.deep_get_status({"scanId": scan["id"]}).get("nextAction") != "claim_worker"
        ):
            assert time.monotonic() < deadline
            assert second.get_scan({"scanId": scan["id"]})["status"] == "running"
            time.sleep(0.02)
        assert second.get_scan({"scanId": scan["id"]})["status"] == "running"
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
            "trackingProof": tracking_proof(),
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


def test_unversioned_standard_remediation_uses_directory_snapshot(tmp_path: Path) -> None:
    workspace = tmp_path / "unversioned"
    (workspace / "src").mkdir(parents=True)
    (workspace / "config").mkdir()
    source = workspace / "src" / "app.py"
    unrelated = workspace / "config" / "security.py"
    source.write_text("import os\nuser = input()\nos.system(user)\n", encoding="utf-8")
    unrelated.write_text("POLICY = 'AAAA'\n", encoding="utf-8")
    service = service_for(workspace)
    try:
        scan = wait_for_scan(service, service.start_scan({"mode": "standard", "scope": "src"})["id"])
        assert scan["status"] == "completed" and scan["target_revision"] is None
        finding = next(
            item for item in service.list_findings({"scanId": scan["id"]})
            if item["ruleId"] == "command-injection.shell-execution"
        )
        patch = (
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -1,3 +1,3 @@\n import os\n user = input()\n"
            "-os.system(user)\n+os.system('echo safe')\n"
        )
        prepared = service.prepare_remediation_patch({
            "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Use a fixed value.",
            "verificationPlan": ["Run the focused source check."],
        })
        metadata = json.loads(service.workbench.get_remediation_record(prepared["id"])["summary"])
        assert metadata["scope"] == "src" and metadata["snapshotScope"] == "."
        unrelated.write_text("POLICY = 'BBBB'\n", encoding="utf-8")
        with pytest.raises(EngineError) as outside_scope_drift:
            service.apply_remediation_patch({
                "remediationId": prepared["id"], "expectedVersion": prepared["version"],
            })
        assert outside_scope_drift.value.code == "remediation_code_drift"
        unrelated.write_text("POLICY = 'AAAA'\n", encoding="utf-8")
        applied = service.apply_remediation_patch({
            "remediationId": prepared["id"], "expectedVersion": prepared["version"],
        })
        verified = service.verify_remediation_patch({
            "remediationId": applied["id"], "expectedVersion": applied["version"],
            "verification": {
                "outcome": "verified", "originalIssueNoLongerReproduces": True, "preservedBehavior": True,
                "securityValidation": {
                    "status": "passed", "method": "focused source review",
                    "rationale": "Attacker input no longer reaches the sink.", "evidence": ["The sink uses a fixed value."],
                },
                "tests": [{"command": "python focused smoke", "status": "passed", "summary": "passed"}],
                "proofGaps": [],
            },
        })
        assert verified["state"] == "verified" and "echo safe" in source.read_text(encoding="utf-8")
    finally:
        service.shutdown({})


def test_remediation_snapshot_rejects_nested_submodule_drift(tmp_path: Path) -> None:
    def initialize(repository: Path) -> None:
        repository.mkdir()
        run_git(repository, "init")
        run_git(repository, "config", "user.email", "security-test@example.invalid")
        run_git(repository, "config", "user.name", "Kiro Security Test")

    leaf = tmp_path / "leaf"
    initialize(leaf)
    (leaf / "value.txt").write_text("one\n", encoding="utf-8")
    run_git(leaf, "add", ".")
    run_git(leaf, "commit", "-m", "leaf one")
    leaf_one = run_git(leaf, "rev-parse", "HEAD")
    (leaf / "value.txt").write_text("two\n", encoding="utf-8")
    run_git(leaf, "commit", "-am", "leaf two")
    leaf_two = run_git(leaf, "rev-parse", "HEAD")
    run_git(leaf, "checkout", leaf_one)

    middle = tmp_path / "middle"
    initialize(middle)
    run_git(middle, "-c", "protocol.file.allow=always", "submodule", "add", str(leaf), "leaf")
    run_git(middle, "config", "-f", ".gitmodules", "submodule.leaf.ignore", "all")
    run_git(middle, "add", ".")
    run_git(middle, "commit", "-m", "nested leaf")

    workspace = tmp_path / "workspace-with-submodule"
    initialize(workspace)
    run_git(workspace, "-c", "protocol.file.allow=always", "submodule", "add", str(middle), "vendor/middle")
    run_git(workspace, "commit", "-am", "middle submodule")
    run_git(workspace, "-c", "protocol.file.allow=always", "submodule", "update", "--init", "--recursive")
    remediation_module.worktree_content_digest(workspace, ".")
    run_git(workspace / "vendor" / "middle" / "leaf", "checkout", leaf_two)
    with pytest.raises(EngineError) as nested_drift:
        remediation_module.worktree_content_digest(workspace, ".")
    assert nested_drift.value.code == "remediation_code_drift"


def test_h_workflow_artifacts_state_and_proof_are_immutable(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    service = service_for(workspace)
    try:
        scan = service.start_scan({"mode": "standard", "scope": "."})
        completed = wait_for_scan(service, scan["id"])
        assert completed["status"] == "completed"
        finding = next(
            item for item in service.list_findings({"scanId": scan["id"]})
            if item["locations"][0]["path"] == "src/app.py" and item["taxonomy"]["category"] == "command-injection"
        )
        with pytest.raises(EngineError) as reserved:
            parse_remediation_patch("--- a/.kiro/state\n+++ b/.kiro/state\n@@ -1 +1 @@\n-old\n+new\n")
        assert reserved.value.code == "unsafe_remediation_patch"
        patch = (
            "--- a/src/app.py\n+++ b/src/app.py\n@@ -8,7 +8,7 @@\n @app.get('/run')\n"
            " def run_command():\n     command = request.args.get('command')\n-    os.system(command)\n"
            "+    os.system('echo safe')\n     return 'ok'\n \n @app.get('/users')\n"
        )
        prepared_one = service.prepare_remediation_patch({
            "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Replace the unsafe sink.",
            "verificationPlan": ["Run the focused command route test."],
        })
        prepared_two = service.prepare_remediation_patch({
            "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Replace the unsafe sink.",
            "verificationPlan": ["Run the focused command route test."],
        })
        assert service.workbench.get_remediation_record(prepared_one["id"])["state"] == "superseded"
        service.workbench.transition_remediation(
            prepared_two["id"], prepared_two["version"], "generated", "verifying",
            verification_summary=json.dumps({
                "phase": "applying", "patchDigest": prepared_two["patch_digest"],
                "ownerSessionId": service.session_id,
            }),
        )
        peer = service_for(workspace)
        try:
            with pytest.raises(EngineError) as live_owner:
                peer._reconcile_remediation_record(peer.workbench.get_remediation_record(prepared_two["id"]))
            assert live_owner.value.code == "remediation_busy"
            service.workbench.close_session(service.session_id)
            assert peer._reconcile_remediation_record(
                peer.workbench.get_remediation_record(prepared_two["id"])
            )["state"] == "generated"
        finally:
            peer.shutdown({})
        original_run_process = service_module.run_process
        original_source = (workspace / "src" / "app.py").read_text(encoding="utf-8")

        record = service.workbench.get_remediation_record(prepared_two["id"])
        metadata, patch_path = remediation_module.load_patch_artifact(Path(completed["artifact_dir"]), record)
        legacy_metadata = {key: value for key, value in metadata.items() if key != "unmodifiedContentDigest"}
        with pytest.raises(EngineError) as legacy_snapshot:
            remediation_module.verify_unmodified_files(service.workspace, Path(completed["artifact_dir"]), legacy_metadata)
        assert legacy_snapshot.value.code == "remediation_record_invalid"
        approved_patch = patch_path.read_bytes()
        swapped_patch = approved_patch.replace(b"+    os.system('echo safe')", b"+    os.system('echo swapped')")
        assert swapped_patch != approved_patch
        try:
            patch_path.write_bytes(swapped_patch)
            (workspace / "src" / "app.py").write_text(
                original_source.replace("os.system(command)", "os.system('echo swapped')"), encoding="utf-8",
            )
            reconciled, _ = remediation_module.reconcile_patch_application(
                service.workspace, patch_path, metadata, record["patch_digest"],
            )
            assert reconciled == "ambiguous"
        finally:
            patch_path.write_bytes(approved_patch)
            (workspace / "src" / "app.py").write_text(original_source, encoding="utf-8")

        def replace_source_after_check(executable: str, args: list[str], **kwargs: object):
            result = original_run_process(executable, args, **kwargs)
            if executable == "git" and args[:2] == ["apply", "--check"]:
                (workspace / "src" / "app.py").write_text("# changed after check\n", encoding="utf-8")
            return result

        monkeypatch.setattr(service_module, "run_process", replace_source_after_check)
        with pytest.raises(EngineError) as changed_after_check:
            service.apply_remediation_patch({
                "remediationId": prepared_two["id"], "expectedVersion": prepared_two["version"],
            })
        assert changed_after_check.value.code == "remediation_code_drift"
        assert service.workbench.get_remediation_record(prepared_two["id"])["state"] == "generated"
        (workspace / "src" / "app.py").write_text(original_source, encoding="utf-8")

        race_prepared = service.prepare_remediation_patch({
            "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Reject concurrent source drift.",
            "verificationPlan": ["Run the focused command route test."],
        })
        original_copy2 = remediation_module.shutil.copy2
        changed_during_copy = False

        def change_before_copy(source: str, destination: str, *args: object, **kwargs: object):
            nonlocal changed_during_copy
            if Path(source).resolve() == (workspace / "src" / "app.py").resolve() and not changed_during_copy:
                with Path(source).open("a", encoding="utf-8") as handle:
                    handle.write("\n# raced expected preimage\n")
                changed_during_copy = True
            return original_copy2(source, destination, *args, **kwargs)

        monkeypatch.setattr(remediation_module.shutil, "copy2", change_before_copy)
        with pytest.raises(EngineError) as raced_preimage:
            service.apply_remediation_patch({
                "remediationId": race_prepared["id"], "expectedVersion": race_prepared["version"],
            })
        assert raced_preimage.value.code == "remediation_code_drift"
        assert service.workbench.get_remediation_record(race_prepared["id"])["state"] == "generated"
        monkeypatch.setattr(remediation_module.shutil, "copy2", original_copy2)
        (workspace / "src" / "app.py").write_text(original_source, encoding="utf-8")

        changed_during_apply = False

        def change_during_apply(executable: str, args: list[str], **kwargs: object):
            nonlocal changed_during_apply
            result = original_run_process(executable, args, **kwargs)
            if executable == "git" and args[:2] == ["apply", "--whitespace=nowarn"] and not changed_during_apply:
                with (workspace / "src" / "app.py").open("a", encoding="utf-8") as handle:
                    handle.write("\n# concurrent writer\n")
                changed_during_apply = True
            return result

        monkeypatch.setattr(service_module, "run_process", change_during_apply)
        with pytest.raises(EngineError) as concurrent_drift:
            service.apply_remediation_patch({
                "remediationId": race_prepared["id"], "expectedVersion": race_prepared["version"],
            })
        assert concurrent_drift.value.code == "remediation_code_drift"
        failed_race = service.workbench.get_remediation_record(race_prepared["id"])
        assert failed_race["state"] == "failed"
        assert json.loads(failed_race["verification_summary"])["phase"] == "apply_content_drift"
        (workspace / "src" / "app.py").write_text(original_source, encoding="utf-8")

        final_prepared = service.prepare_remediation_patch({
            "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Apply the captured approved patch.",
            "verificationPlan": ["Run the focused command route test."],
        })

        alternate_patch = (
            "--- a/src/safe.py\n+++ b/src/safe.py\n@@ -1 +1 @@\n"
            "-from pathlib import Path\n+raise RuntimeError('unapproved replacement')\n"
        )
        replaced = False

        def replace_patch_after_check(executable: str, args: list[str], **kwargs: object):
            nonlocal replaced
            result = original_run_process(executable, args, **kwargs)
            if executable == "git" and args[:2] == ["apply", "--check"] and not replaced:
                Path(final_prepared["artifact_path"]).write_text(alternate_patch, encoding="utf-8")
                replaced = True
            return result

        monkeypatch.setattr(service_module, "run_process", replace_patch_after_check)
        applied = service.apply_remediation_patch({
            "remediationId": final_prepared["id"], "expectedVersion": final_prepared["version"],
        })
        monkeypatch.setattr(service_module, "run_process", original_run_process)
        assert applied["state"] == "applied"
        assert replaced
        assert "os.system('echo safe')" in (workspace / "src" / "app.py").read_text(encoding="utf-8")
        assert (workspace / "src" / "safe.py").read_text(encoding="utf-8").startswith("from pathlib import Path")
        with pytest.raises(EngineError) as busy:
            service.prepare_remediation_patch({
                "occurrenceId": finding["occurrenceId"], "patch": patch, "plan": "Do not supersede applied work.",
                "verificationPlan": ["No-op"],
            })
        assert busy.value.code == "remediation_busy"
        verification = {
            "outcome": "verified", "originalIssueNoLongerReproduces": True, "preservedBehavior": True,
            "securityValidation": {"status": "passed", "method": "focused", "rationale": "token=secret-value-hidden", "evidence": ["route rejects attacker control"]},
            "tests": [{"command": "TOKEN=secret-value-hidden pytest focused", "status": "passed", "summary": "passed"}],
            "proofGaps": [],
        }
        with pytest.raises(EngineError) as changed_artifact:
            service.verify_remediation_patch({
                "remediationId": applied["id"], "expectedVersion": applied["version"],
                "verification": verification,
            })
        assert changed_artifact.value.code == "remediation_patch_changed"
        Path(final_prepared["artifact_path"]).write_text(patch, encoding="utf-8")

        source = workspace / "src" / "app.py"
        original_mode = source.stat().st_mode
        source.chmod(original_mode ^ 0o100)
        try:
            with pytest.raises(EngineError) as mode_drift:
                service.verify_remediation_patch({
                    "remediationId": applied["id"], "expectedVersion": applied["version"],
                    "verification": verification,
                })
            assert mode_drift.value.code == "remediation_code_drift"
        finally:
            source.chmod(original_mode)
        unrelated = workspace / "src" / "safe.py"
        unrelated_source = unrelated.read_text(encoding="utf-8")
        unrelated.write_text(unrelated_source + "\n# unrelated drift\n", encoding="utf-8")
        try:
            with pytest.raises(EngineError) as unrelated_drift:
                service.verify_remediation_patch({
                    "remediationId": applied["id"], "expectedVersion": applied["version"],
                    "verification": verification,
                })
            assert unrelated_drift.value.code == "remediation_code_drift"
        finally:
            unrelated.write_text(unrelated_source, encoding="utf-8")
        verified = service.verify_remediation_patch({
            "remediationId": applied["id"], "expectedVersion": applied["version"],
            "verification": verification,
        })
        verification_path = Path(verified["verificationArtifact"]["path"])
        assert verified["state"] == "verified" and final_prepared["id"] in str(verification_path)
        assert "secret-value-hidden" not in verification_path.read_text(encoding="utf-8")
        assert all(part not in (".git", ".kiro") for part in Path(final_prepared["artifact_path"]).parts[-3:])
        service.workbench.transition_remediation(
            final_prepared["id"], final_prepared["version"], "verified", "verifying",
            verification_summary=json.dumps({"phase": "applying", "patchDigest": final_prepared["patch_digest"]}),
        )
        Path(final_prepared["artifact_path"]).unlink()
        orphaned = service._reconcile_remediation_record(
            service.workbench.get_remediation_record(final_prepared["id"])
        )
        assert orphaned["state"] == "failed" and "reconciliation_failed" in orphaned["verification_summary"]

        assert redact("Authorization: Bearer secret-value-hidden") == "Authorization: <redacted>"
        assert redact("Authorization=Basic dXNlcjpwYXNz") == "Authorization=<redacted>"
        assert redact("Authorization: Custom first second third") == "Authorization: <redacted>"
        assert redact('Authorization: "first\r\nsecond"') == 'Authorization: "<redacted>"'
        assert redact('Authorization: "first\r\nsecond') == 'Authorization: "<redacted>'
        assert redact('Authorization: "first\r\nsecond\\') == 'Authorization: "<redacted>'
        assert redact("Authorization: Custom\r\n LEAKME123\r\nrequestId=keep") == "Authorization: <redacted>\r\nrequestId=keep"
        assert "secret-value-hidden" not in redact('{"Authorization": "Bearer secret-value-hidden"}')
        aws = redact(
            "Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260718/us-east-1/service/aws4_request, "
            "SignedHeaders=host;x-amz-date, Signature=deadbeef requestId=keep-me"
        )
        assert "AKIAEXAMPLE" not in aws and "deadbeef" not in aws and "requestId=keep-me" in aws
        digest = redact(
            'Authorization: Digest username="alice", realm="private", nonce="secret-nonce", '
            'uri="/admin", response="secret-response" requestId=keep-me'
        )
        assert "alice" not in digest and "secret-response" not in digest and "requestId=keep-me" in digest
        intake = service.create_triage_intake({
            "occurrenceId": finding["occurrenceId"], "sourceType": "scanner_ticket", "inputId": "external-1",
            "input": {"summary": "authorization: Bearer secret-value-hidden"},
        })
        assert "secret-value-hidden" not in Path(intake["intakeArtifactPath"]).read_text(encoding="utf-8")
        with pytest.raises(EngineError) as empty_proof:
            service.submit_triage_assessment({
                "assessmentId": intake["id"],
                "result": {
                    "inputId": "external-1", "verdict": "confirmed", "confidence": "high",
                    "rationale": "Missing proof.", "source": "unknown", "control": "unknown", "sink": "unknown",
                    "affectedLocations": [], "reachablePath": [], "evidence": [], "counterevidence": [], "proofGaps": [],
                    "boundaryAssessment": {"productSurface": "unknown", "sourceTrust": "unknown", "boundaryCrossed": None, "policyBasis": "unknown"},
                    "exploitabilityStackRank": {"rankQueue": "confirmed", "rank": 1, "rationale": "unknown", "drivers": []},
                    "recommendedNextStep": "Review.",
                },
            })
        assert empty_proof.value.code == "invalid_triage_result"
        triage = service.submit_triage_assessment({
            "assessmentId": intake["id"],
            "result": {
                "inputId": "external-1", "verdict": "confirmed", "confidence": "high",
                "rationale": "Repository proof confirms reachability.", "source": "request argument",
                "control": "missing validation", "sink": "command execution",
                "affectedLocations": [{"path": "src/app.py", "startLine": 11, "endLine": 11, "role": "sink", "detail": "patched sink"}],
                "reachablePath": ["request -> command -> sink"],
                "boundaryAssessment": {"productSurface": "route", "sourceTrust": "untrusted", "boundaryCrossed": True, "policyBasis": "request boundary"},
                "exploitabilityStackRank": {"rankQueue": "confirmed", "rank": 1, "rationale": "direct", "drivers": ["reachable"]},
                "evidence": ["current source"], "counterevidence": [], "proofGaps": [],
                "recommendedNextStep": "Retain the patch.",
            },
        })
        assert triage["result"]["repositoryBinding"]["findingId"] == finding["findingId"]
        assert len(triage["result"]["repositoryBinding"]["locations"][0]["contentDigest"]) == 64
        result_path = Path(triage["resultArtifactPath"])
        conflicting_result = {**triage["result"], "rationale": "A conflicting immutable retry."}
        with pytest.raises(EngineError) as immutable_triage:
            service.submit_triage_assessment({"assessmentId": intake["id"], "result": conflicting_result})
        assert immutable_triage.value.code in ("triage_subject_mismatch", "triage_assessment_immutable")
        assert result_path.exists()

        contradictory_proof = tracking_proof()
        contradictory_proof["duplicateSearch"]["candidateIds"] = ["issue-existing"]
        with pytest.raises(EngineError) as contradictory_duplicate:
            service.create_tracking_handoff({
                "occurrenceId": finding["occurrenceId"], "provider": "github",
                "destination": "https://github.com/owner/repository", "trackingProof": contradictory_proof,
            })
        assert contradictory_duplicate.value.code == "invalid_tracking_proof"
        with pytest.raises(EngineError) as unsafe_destination:
            service.create_tracking_handoff({
                "occurrenceId": finding["occurrenceId"], "provider": "github",
                "destination": "https://github.com/owner/repository?token=secret", "trackingProof": tracking_proof(),
            })
        assert unsafe_destination.value.code == "invalid_tracking_proof"
        findings_path = Path(completed["artifact_dir"]) / "findings.json"
        sealed_findings = findings_path.read_bytes()
        findings_path.write_text("{}\n", encoding="utf-8")
        with pytest.raises(EngineError) as changed_findings:
            service.create_tracking_handoff({
                "occurrenceId": finding["occurrenceId"], "provider": "github",
                "destination": "https://github.com/owner/repository", "trackingProof": tracking_proof(),
            })
        assert changed_findings.value.code == "remediation_source_unsealed"
        findings_path.write_bytes(sealed_findings)
        handoff = service.create_tracking_handoff({
            "occurrenceId": finding["occurrenceId"], "provider": "github",
            "destination": "https://github.com/owner/repository", "trackingProof": tracking_proof(),
        })
        payload_path = Path(handoff["artifact"]["path"])
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
        record = service.workbench.get_tracking_record(handoff["id"])
        assert record["payload_artifact_path"] == str(payload_path)
        readback_proof = {
            "bindingFindingId": payload["finding"]["findingId"],
            "bindingFingerprint": payload["finding"]["fingerprint"],
            "externalId": "issue-1",
            "externalUrl": "https://github.com/owner/repository/issues/1",
            "titleDigest": payload["writePreview"]["titleDigest"], "bodyDigest": payload["writePreview"]["bodyDigest"],
            "previewDigest": payload["writePreview"]["previewDigest"],
            "connectorHost": "github.com",
            "duplicateQueryDigest": payload["routingProof"]["duplicateSearch"]["queryDigest"],
            "destinationDigest": payload["routingProof"]["destination"]["digest"],
            "visibility": "private", "audienceDigest": payload["routingProof"]["audienceDigest"],
        }
        approval = {
            "approved": True, "approvedPreviewDigest": payload["writePreview"]["previewDigest"],
            "approvedPayloadSha256": handoff["payloadSha256"],
            "approvedBy": "integration-reviewer", "approvedAt": "2026-01-01T00:00:00Z",
            "scope": "exact sealed preview",
        }
        readback_proof["approvalDigest"] = hashlib.sha256(json.dumps(
            approval, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")).hexdigest()
        with pytest.raises(EngineError) as uncertain_mutation:
            service.record_tracking_result({
                "recordId": handoff["id"], "payloadSha256": handoff["payloadSha256"], "outcome": "uncertain",
                "externalMutationPerformed": True,
            })
        assert uncertain_mutation.value.code == "invalid_tracking_result"
        tracking_result = {
            "recordId": handoff["id"], "payloadSha256": handoff["payloadSha256"], "outcome": "created",
            "externalMutationPerformed": True, "externalId": "issue-1",
            "externalUrl": "https://github.com/owner/repository/issues/1", "approval": approval,
            "readback": readback_proof,
        }
        duplicate_handoff = json.loads(json.dumps(payload))
        duplicate_handoff["routingProof"]["duplicateSearch"].update({
            "status": "existing", "candidateIds": ["issue-existing"],
        })
        with pytest.raises(EngineError) as duplicate_mismatch:
            normalize_tracking_readback(tracking_result, duplicate_handoff)
        assert duplicate_mismatch.value.code == "tracking_readback_mismatch"
        with pytest.raises(EngineError) as missing_duplicate:
            normalize_tracking_readback(
                {**tracking_result, "outcome": "reused", "externalMutationPerformed": False}, payload,
            )
        assert missing_duplicate.value.code == "tracking_readback_mismatch"
        with pytest.raises(EngineError) as mismatched_external_item:
            normalize_tracking_readback({
                **tracking_result,
                "readback": {**readback_proof, "externalUrl": "https://github.com/owner/repository/issues/2"},
            }, payload)
        assert mismatched_external_item.value.code == "tracking_readback_mismatch"
        register_artifact = service.workbench._register_artifact
        monkeypatch.setattr(service.workbench, "_register_artifact", lambda *_args: (_ for _ in ()).throw(OSError("injected registry failure")))
        with pytest.raises(OSError):
            service.record_tracking_result(tracking_result)
        assert service.workbench.get_tracking_record(handoff["id"])["status"] == "prepared"
        monkeypatch.setattr(service.workbench, "_register_artifact", register_artifact)
        tracked = service.record_tracking_result(tracking_result)
        readback_path = Path(tracked["artifact"]["path"])
        with pytest.raises(EngineError) as same_tracking:
            service.record_tracking_result(tracking_result)
        assert same_tracking.value.code == "tracking_record_immutable" and readback_path.exists()
        with pytest.raises(EngineError) as immutable_tracking:
            service.record_tracking_result({
                "recordId": handoff["id"], "payloadSha256": handoff["payloadSha256"], "outcome": "failed",
                "externalMutationPerformed": False,
            })
        assert immutable_tracking.value.code == "tracking_record_immutable"
        assert readback_path.exists()
    finally:
        service.shutdown({})
