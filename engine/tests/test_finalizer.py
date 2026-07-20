from __future__ import annotations

from copy import deepcopy
import json
import threading
from pathlib import Path

import pytest

from kiro_security.constants import ARTIFACT_KINDS, PHASES, PROTOCOL_VERSION
from kiro_security.coverage import coverage_row_id
from kiro_security.db import Workbench
from kiro_security.errors import EngineError
from kiro_security.finalizer import (
    _project_report, _validate_auxiliary_documents, _validate_finding_semantics, _validate_writeup_artifacts,
    finalize_scan, prepare_finalization,
)
from kiro_security.reporting import _write_writeups, build_findings_document, write_canonical_documents
from kiro_security.schema_validation import validate_against_schema
from kiro_security.security import sha256_file, stable_id, utc_now


def _create_reporting_scan(workbench: Workbench) -> dict:
    session_id = "finalizer-test"
    workbench.register_session(session_id, 1001, "test", PROTOCOL_VERSION)
    registered = workbench.register_workspace(workbench.workspace)
    scan = workbench.create_scan(
        workspace_id=registered["id"],
        mode="standard",
        scope=".",
        artifact_dir=None,
        session_id=session_id,
    )
    for phase in PHASES[1:]:
        scan = workbench.set_phase(scan["id"], phase)
    return scan


def _inventory() -> dict:
    surface = "source_review:python"
    return {
        "includePaths": ["."],
        "excludePaths": [],
        "files": [
            {
                "rowId": coverage_row_id("src/app.py", surface),
                "path": "src/app.py",
                "surface": surface,
                "language": "python",
                "size": 42,
            }
        ],
        "deferred": [],
        "warnings": [],
        "supportedFileCount": 1,
    }


def _prepare_bundle(workbench: Workbench, scan: dict) -> dict:
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    threat_model = {
        "summary": "A bounded deterministic threat model used for finalizer tests.",
        "assets": [],
        "trustBoundaries": [],
        "entrypoints": [],
        "securityObjectives": [],
    }
    (artifact_dir / ARTIFACT_KINDS["threatModel"]).write_text("# Threat model\n", encoding="utf-8")
    bundle = write_canonical_documents(workbench, scan["id"], _inventory(), threat_model)
    return prepare_finalization(workbench, bundle)


def test_valid_canonical_bundle_is_sealed_then_projected(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    artifact_dir = Path(scan["artifact_dir"])

    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["markdownReport"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["hardening"]).exists()

    records = finalize_scan(workbench, prepared)
    sealed = workbench.get_scan(scan["id"])
    manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
    report_path = artifact_dir / ARTIFACT_KINDS["markdownReport"]
    hardening_path = artifact_dir / ARTIFACT_KINDS["hardening"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert sealed["status"] == "completed"
    assert sealed["sealed_manifest_digest"] == sha256_file(manifest_path)
    assert manifest["scan"]["status"] == sealed["status"]
    assert manifest["scan"]["completedAt"] == sealed["completed_at"]
    assert manifest["scan"]["sealedAt"] >= manifest["scan"]["completedAt"]
    assert report_path.is_file()
    assert hardening_path.is_file()
    assert "projection of the sealed canonical JSON" in report_path.read_text(encoding="utf-8")

    sealed_paths = {item["path"] for item in manifest["scan"]["artifacts"]}
    derived_paths = {item["path"] for item in manifest["scan"]["derivedArtifacts"]}
    assert ARTIFACT_KINDS["coverage"] in sealed_paths
    assert ARTIFACT_KINDS["findings"] in sealed_paths
    assert "inventory.json" in sealed_paths
    assert ARTIFACT_KINDS["markdownReport"] not in sealed_paths
    assert ARTIFACT_KINDS["hardening"] not in sealed_paths
    assert ARTIFACT_KINDS["markdownReport"] in derived_paths
    assert ARTIFACT_KINDS["hardening"] in derived_paths
    assert {item["kind"] for item in records} >= {"manifest", "coverage", "findings", "inventory", "markdownReport", "hardening"}

    # The manifest entry, the actual file bytes, and the durable artifact
    # registry must all carry the same immutable snapshot digest.
    manifest_hashes = {item["path"]: item["sha256"] for item in manifest["scan"]["artifacts"]}
    registry_hashes = {item["kind"]: item["sha256"] for item in sealed["artifacts"]}
    for kind, relative in (("coverage", "coverage.json"), ("findings", "findings.json"), ("inventory", "inventory.json")):
        disk_hash = sha256_file(artifact_dir / relative)
        assert manifest_hashes[relative] == disk_hash
        assert registry_hashes[kind] == disk_hash



def test_completed_state_is_not_visible_before_manifest_publication_commits(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    artifact_dir = Path(scan["artifact_dir"])
    entered = threading.Event()
    release = threading.Event()
    failure: list[BaseException] = []

    from kiro_security import finalizer as finalizer_module

    real_atomic_write = finalizer_module.atomic_write

    def blocking_atomic_write(path: Path, data: str | bytes) -> None:
        if path.name == ARTIFACT_KINDS["manifest"]:
            entered.set()
            assert release.wait(timeout=10), "test did not release manifest publication"
        real_atomic_write(path, data)

    monkeypatch.setattr(finalizer_module, "atomic_write", blocking_atomic_write)

    def run() -> None:
        try:
            finalize_scan(workbench, prepared)
        except BaseException as exc:  # captured for the main test thread
            failure.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert entered.wait(timeout=10), "finalizer did not reach manifest publication"

    visible = workbench.get_scan(scan["id"])
    assert visible["status"] == "running"
    assert visible["sealed_manifest_digest"] is None
    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()

    release.set()
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert failure == []
    completed = workbench.get_scan(scan["id"])
    assert completed["status"] == "completed"
    assert completed["sealed_manifest_digest"] == sha256_file(artifact_dir / ARTIFACT_KINDS["manifest"])

def test_shrunken_coverage_frontier_is_rejected(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    bundle = _prepare_bundle(workbench, scan)
    coverage_path = Path(bundle["paths"]["coverage"])
    document = json.loads(coverage_path.read_text(encoding="utf-8"))
    # A reduced-frontier document: the durable ledger still holds one row,
    # but the projection claims zero in-scope rows were fully reviewed.
    document.update({
        "completeness": "complete",
        "supportedFileCount": 1,
        "inScopeRowCount": 0,
        "closedRowCount": 0,
        "surfaces": [],
        "unclosedRows": [],
        "deferred": [],
    })
    coverage_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(EngineError) as error:
        prepare_finalization(workbench, bundle)

    assert error.value.code == "coverage_frontier_mismatch"
    assert workbench.list_coverage_rows(scan["id"]), "the durable ledger row must survive"
    current = workbench.get_scan(scan["id"])
    assert current["status"] == "running"
    assert current["sealed_manifest_digest"] is None


def test_canonical_mutation_between_prepare_and_commit_is_rejected(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    artifact_dir = Path(scan["artifact_dir"])
    coverage_path = Path(prepared["paths"]["coverage"])

    from kiro_security import finalizer as finalizer_module

    real_render = finalizer_module.render_hardening_proposal

    def mutate_then_render(scan_id: str, findings: list) -> dict:
        # Simulate a concurrent writer between snapshot capture and commit.
        document = json.loads(coverage_path.read_text(encoding="utf-8"))
        document["openQuestions"] = [{"question": "mutated after snapshot"}]
        coverage_path.write_text(json.dumps(document), encoding="utf-8")
        return real_render(scan_id, findings)

    monkeypatch.setattr(finalizer_module, "render_hardening_proposal", mutate_then_render)

    with pytest.raises(EngineError) as error:
        finalize_scan(workbench, prepared)

    assert error.value.code == "canonical_artifact_changed"
    current = workbench.get_scan(scan["id"])
    assert current["status"] == "running"
    assert current["sealed_manifest_digest"] is None
    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()


def test_canonical_mutation_during_publication_is_rejected(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    artifact_dir = Path(scan["artifact_dir"])
    coverage_path = Path(prepared["paths"]["coverage"])

    from kiro_security import finalizer as finalizer_module

    real_atomic_write = finalizer_module.atomic_write

    def mutate_during_manifest_write(path: Path, data: str | bytes) -> None:
        # The first snapshot verification has already passed at this point;
        # mutate a canonical file while the manifest itself is being published.
        if path.name == ARTIFACT_KINDS["manifest"]:
            document = json.loads(coverage_path.read_text(encoding="utf-8"))
            document["openQuestions"] = [{"question": "mutated during publication"}]
            coverage_path.write_text(json.dumps(document), encoding="utf-8")
        real_atomic_write(path, data)

    monkeypatch.setattr(finalizer_module, "atomic_write", mutate_during_manifest_write)

    with pytest.raises(EngineError) as error:
        finalize_scan(workbench, prepared)

    assert error.value.code == "canonical_artifact_changed"
    assert error.value.data.get("expected")
    current = workbench.get_scan(scan["id"])
    assert current["status"] == "running"
    assert current["sealed_manifest_digest"] is None
    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["markdownReport"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["hardening"]).exists()
    assert coverage_path.exists(), "canonical inputs must remain for diagnosis"


def test_reconciliation_quarantines_orphan_manifest(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
    manifest_path.write_text("{\"documentType\": \"kiro-security-power.scan-manifest\"}\n", encoding="utf-8")
    workbench.interrupt_scan(scan["id"])

    issues = workbench.reconcile_finalization_integrity()

    codes = {item["code"] for item in issues}
    assert "orphan_manifest_quarantined" in codes
    assert not manifest_path.exists()
    quarantined = list(artifact_dir.glob("quarantine/*/scan-manifest.json"))
    assert quarantined, "the orphan manifest must be preserved in quarantine"


def test_reconciliation_quarantines_tampered_completed_manifest(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    finalize_scan(workbench, prepared)
    artifact_dir = Path(scan["artifact_dir"])
    manifest_path = artifact_dir / ARTIFACT_KINDS["manifest"]
    manifest_path.write_text(manifest_path.read_text(encoding="utf-8") + "\n// tampered\n", encoding="utf-8")

    issues = workbench.reconcile_finalization_integrity()

    mismatch = [item for item in issues if item["code"] == "sealed_manifest_digest_mismatch"]
    assert mismatch and mismatch[0]["scanId"] == scan["id"]
    assert mismatch[0]["expected"] and mismatch[0]["actual"]
    assert any("scan-manifest.json" in path for path in mismatch[0]["quarantinedPaths"])
    # The tampered publication must leave the official path but stay auditable.
    assert not manifest_path.exists()
    assert not (artifact_dir / ARTIFACT_KINDS["markdownReport"]).exists()
    assert list(artifact_dir.glob("quarantine/*/scan-manifest.json"))
    events = workbench.events_since(0, limit=1000)
    assert any(
        item["event"] == "scan.integrityIssue"
        and item["scanId"] == scan["id"]
        and item["payload"]["code"] == "sealed_manifest_digest_mismatch"
        for item in events
    ), "the integrity issue must be durably recorded as an event"
    # The scan stays completed, but its seal is no longer presented as valid.
    assert workbench.get_scan(scan["id"])["status"] == "completed"


def test_reconciliation_quarantines_manifest_when_sealed_artifact_changed(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    finalize_scan(workbench, _prepare_bundle(workbench, scan))
    artifact_dir = Path(scan["artifact_dir"])
    coverage_path = artifact_dir / ARTIFACT_KINDS["coverage"]
    coverage_path.write_text(coverage_path.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    issues = workbench.reconcile_finalization_integrity()

    mismatch = [item for item in issues if item["code"] == "sealed_artifact_digest_mismatch"]
    assert mismatch and mismatch[0]["path"] == ARTIFACT_KINDS["coverage"]
    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()


def test_reconciliation_quarantines_projections_when_sealed_manifest_missing(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    finalize_scan(workbench, prepared)
    artifact_dir = Path(scan["artifact_dir"])
    (artifact_dir / ARTIFACT_KINDS["manifest"]).unlink()

    issues = workbench.reconcile_finalization_integrity()

    missing = [item for item in issues if item["code"] == "sealed_manifest_missing"]
    assert missing and missing[0]["scanId"] == scan["id"]
    assert missing[0]["actual"] is None
    assert any("report.md" in path for path in missing[0]["quarantinedPaths"])
    assert not (artifact_dir / ARTIFACT_KINDS["markdownReport"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["hardening"]).exists()


def test_invalid_findings_document_blocks_seal_and_preserves_partial_state(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    artifact_dir = Path(scan["artifact_dir"])
    threat_model = {"summary": "Finalizer validation failure test."}
    (artifact_dir / ARTIFACT_KINDS["threatModel"]).parent.mkdir(parents=True, exist_ok=True)
    (artifact_dir / ARTIFACT_KINDS["threatModel"]).write_text("# Threat model\n", encoding="utf-8")
    bundle = write_canonical_documents(workbench, scan["id"], _inventory(), threat_model)
    findings_path = Path(bundle["paths"]["findings"])
    invalid = json.loads(findings_path.read_text(encoding="utf-8"))
    invalid.pop("findings")
    findings_path.write_text(json.dumps(invalid), encoding="utf-8")

    with pytest.raises(EngineError) as error:
        prepare_finalization(workbench, bundle)

    assert error.value.code == "schema_validation_failed"
    current = workbench.get_scan(scan["id"])
    assert current["status"] == "running"
    assert current["sealed_manifest_digest"] is None
    assert findings_path.exists()
    assert not (artifact_dir / ARTIFACT_KINDS["manifest"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["markdownReport"]).exists()
    assert not (artifact_dir / ARTIFACT_KINDS["hardening"]).exists()


def test_canonical_documents_include_more_than_the_public_finding_page(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    for index in range(501):
        workbench.upsert_finding(scan["id"], {
            "fingerprint": f"kiro-security/v1:sha256:{index:064x}",
            "ruleId": "test.rule", "identity": {"anchor": "test", "instance": f"sink-{index}"},
            "title": f"Test finding {index:03d}", "summary": "Test summary.",
            "severity": {"level": "medium", "score": None, "rationale": "Evidence-backed."},
            "confidence": {"level": "high", "rationale": "Direct evidence."},
            "taxonomy": {"category": "security", "cwe": []},
            "locations": [{"path": "src/app.py", "startLine": 1, "endLine": 1, "role": "sink"}],
            "codeEvidence": [{"path": "src/app.py", "startLine": 1, "endLine": 1, "role": "sink",
                              "code": "sink(value)", "explanation": "Sink evidence."}],
            "remediation": "Validate input.", "details": {},
        })
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / ARTIFACT_KINDS["threatModel"]).write_text("# Threat model\n", encoding="utf-8")
    bundle = write_canonical_documents(
        workbench, scan["id"], _inventory(), {"summary": "Threat model."}, writeup_paths={},
    )

    assert len(workbench.list_findings(scan["id"], limit=500)) == 500
    assert len(workbench.list_findings(scan["id"])) == 501
    assert len(bundle["documents"]["findings"]["findings"]) == 501
    prepare_finalization(workbench, bundle)


def test_model_proof_must_match_durable_tail_result(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    workbench.set_capabilities(scan["id"], {"analysisProfile": "model"})
    scan = workbench.get_scan(scan["id"])
    fingerprint = "kiro-security/deep-v1:sha256:" + "a" * 64
    finding_id = stable_id("kspf", fingerprint)
    occurrence_id = stable_id("occ", scan["id"], finding_id)
    receipt = "sha256:" + "b" * 64
    profile = {
        "modelId": "model", "agentType": "agent", "reasoningEffort": "high",
        "hostVersion": "host", "delegationMode": "fresh", "contractVersion": "deep-worker/v2",
    }
    finding = workbench.upsert_finding(scan["id"], {
        "fingerprint": fingerprint, "ruleId": "test.rule", "identity": {"anchor": "test", "instance": "sink"},
        "title": "Test finding", "summary": "Test summary.",
        "severity": {"level": "high", "score": None, "rationale": "Evidence-backed."},
        "confidence": {"level": "high", "rationale": "Direct evidence."},
        "taxonomy": {"category": "security", "cwe": []},
        "locations": [{"path": "src/app.py", "startLine": 1, "endLine": 1, "role": "sink"}],
        "codeEvidence": [{
            "kind": "code", "label": "Sink", "path": "src/app.py", "startLine": 1, "endLine": 1,
            "language": "python", "role": "sink", "code": "sink(value)", "explanation": "Sink evidence.",
        }],
        "remediation": "Validate input.",
        "details": {"deepTailProvenance": {"validation": {
            "assignmentId": "tail-validation", "kind": "validation", "attempt": 1,
            "modelProfile": profile, "receiptDigest": receipt,
        }}},
    })
    result = {
        "findingId": finding_id, "status": "rejected", "method": "repository_test",
        "rationale": "Durable proof.", "evidence": [{"path": "src/app.py", "result": "PASS"}],
        "counterevidence": [], "crossFileTrace": [], "frameworkControls": ["Control blocks reachability."],
        "proofGaps": [], "tests": [], "dynamicValidationUnavailableReason": None,
    }
    now = utc_now()
    with workbench.transaction() as connection:
        connection.execute("UPDATE finding_occurrences SET validation_status='rejected' WHERE id=?", (occurrence_id,))
        connection.execute(
            """
            INSERT INTO deep_tail_assignments(
                id, scan_id, kind, subject_id, status, attempt, model_id, payload_json,
                result_json, receipt_digest, created_at, updated_at
            ) VALUES ('tail-validation', ?, 'validation', ?, 'completed', 1, 'model', '{}', ?, ?, ?, ?)
            """,
            (scan["id"], occurrence_id, json.dumps(result, separators=(",", ":")), receipt, now, now),
        )
    artifact_dir = Path(scan["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / ARTIFACT_KINDS["threatModel"]).write_text("# Threat model\n", encoding="utf-8")
    bundle = write_canonical_documents(
        workbench, scan["id"], _inventory(), {"summary": "Threat model."},
        tail_results={"validation": {occurrence_id: result}, "attack_path": {}},
    )
    prepare_finalization(workbench, bundle)
    findings_path = Path(bundle["paths"]["findings"])
    document = json.loads(findings_path.read_text(encoding="utf-8"))
    document["findings"][0]["validation"]["rationale"] = "Tampered proof."
    findings_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(EngineError) as error:
        prepare_finalization(workbench, bundle)
    assert error.value.code == "canonical_tail_result_mismatch"


def test_canonical_schema_contract_rejects_malformed_mutations(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_reporting_scan(workbench)
    prepared = _prepare_bundle(workbench, scan)
    schema_dir = Path(__file__).parents[1] / "schemas"

    def valid(document: dict, schema_name: str) -> None:
        validate_against_schema(document, schema_dir / schema_name, schema_name)

    def rejected(document: dict, schema_name: str) -> None:
        with pytest.raises(EngineError) as error:
            valid(document, schema_name)
        assert error.value.code == "schema_validation_failed"

    finding_id = "kspf_" + "a" * 24
    occurrence_id = "occ_" + "b" * 24
    item = {
        "findingId": finding_id, "occurrenceId": occurrence_id, "ruleId": "test.rule",
        "identity": {"anchor": "test", "instance": "sink"},
        "fingerprint": "kiro-security/v1:sha256:" + "c" * 64,
        "title": "Test finding", "summary": "Test summary.",
        "severity": {"level": "high", "score": 8.0, "rationale": "Evidence-backed."},
        "confidence": {"level": "high", "rationale": "Direct evidence."},
        "taxonomy": {"category": "security", "cwe": ["CWE-78"]},
        "locations": [{"path": "src/app.py", "startLine": 1, "endLine": 1, "role": "sink"}],
        "codeEvidence": [{
            "id": "evidence-1", "kind": "code", "label": "Sink", "path": "src/app.py",
            "startLine": 1, "endLine": 1, "language": "python", "role": "sink",
            "code": "sink(value)", "explanation": "Sink evidence.",
        }],
        "remediation": "Validate input.", "validationStatus": "validated", "triageStatus": "open", "details": {},
        "validation": {"id": "val_" + "d" * 24, "createdAt": "2026-01-01T00:00:00Z", "status": "validated", "method": "static_trace", "rationale": "Still present.", "evidence": []},
        "attackPath": {"id": "path_" + "e" * 24, "narrative": "Source reaches sink.", "path": [], "exploitability": "high", "impact": "Impact.", "severityRationale": "High impact."},
    }
    standard = build_findings_document(scan["id"], [item], {finding_id: f"writeups/{finding_id}.md"})
    assert isinstance(standard["findings"][0]["rootCause"], dict)
    assert standard["findings"][0]["rootCause"]["summary"] == item["summary"]
    valid(standard, "findings.schema.json")
    valid(prepared["documents"]["findings"], "findings.schema.json")

    deep_validation = {
        "findingId": finding_id, "status": "validated", "method": "repository_test", "rationale": "Proved.",
        "evidence": [{"path": "src/app.py", "result": "PASS"}], "counterevidence": [],
        "crossFileTrace": ["source to sink"], "frameworkControls": ["No mitigating middleware."],
        "proofGaps": [], "tests": [{"name": "focused", "result": "PASS"}],
        "dynamicValidationUnavailableReason": None,
    }
    deep_attack = {
        "findingId": finding_id, "narrative": "Source reaches sink.", "actor": "remote user",
        "attackerPrerequisite": "Network access.", "entrypoint": "Route", "attackerControlledSource": "Body",
        "rootControl": "Authentication", "controlBypass": "Missing validation",
        "crossFilePath": [{"path": "src/app.py", "step": "Input reaches sink."}], "privilegedSink": "Shell",
        "impact": "Code execution.", "exploitPreconditions": ["Reachable route"], "counterevidence": [],
        "residualUncertainty": "None observed.", "severity": {"level": "high", "rationale": "Code execution."},
        "exploitability": "high", "confidence": {"level": "high", "rationale": "Focused test passed."},
    }
    explicit_root_cause = "The reviewed request value reaches the shell sink without command validation."
    deep_item = {
        **item,
        "fingerprint": "kiro-security/deep-v1:sha256:" + "d" * 64,
        "details": {
            "discoveryEngine": "kiro-agent-deep-orchestration", "rootCause": explicit_root_cause,
            "deepTailProvenance": {"validation": {
                "assignmentId": "tail-validation", "kind": "validation", "attempt": 1,
                "modelProfile": {
                    "modelId": "model", "agentType": "agent", "reasoningEffort": "high",
                    "hostVersion": "host", "delegationMode": "fresh", "contractVersion": "deep-worker/v2",
                },
                "receiptDigest": "sha256:" + "f" * 64,
            }},
        },
    }
    deep = build_findings_document(
        scan["id"], [deep_item], {finding_id: f"findings/{finding_id}/{finding_id}.md"},
        {"validation": {occurrence_id: deep_validation}, "attack_path": {occurrence_id: deep_attack}},
    )
    assert deep["findings"][0]["rootCause"] == explicit_root_cause
    valid(deep, "findings.schema.json")
    _validate_finding_semantics({"mode": "deep"}, deep, _inventory())
    for model_scan, proof_name in (
        ({"mode": "standard", "capabilities": {"analysisProfile": "model"}}, "validation"),
        ({"mode": "diff", "capabilities": {"analysisProfile": "model"}}, "attackPath"),
    ):
        downgraded = deepcopy(deep)
        downgraded["findings"][0][proof_name] = item[proof_name]
        with pytest.raises(EngineError) as proof_error:
            _validate_finding_semantics(model_scan, downgraded, _inventory())
        assert proof_error.value.code == "canonical_deep_proof_incomplete"
    status_mismatch = deepcopy(deep)
    status_mismatch["findings"][0]["validation"]["status"] = "rejected"
    status_mismatch["findings"][0]["attackPath"] = None
    rejected_with_attack = deepcopy(deep)
    rejected_with_attack["findings"][0]["validation"]["status"] = "rejected"
    rejected_with_attack["findings"][0]["extensions"]["validationStatus"] = "rejected"
    for mutation in (status_mismatch, rejected_with_attack):
        with pytest.raises(EngineError) as status_error:
            _validate_finding_semantics({"mode": "deep"}, mutation, _inventory())
        assert status_error.value.code == "canonical_deep_proof_incomplete"
    for proof_name, field in (("validation", "evidence"), ("attackPath", "crossFilePath")):
        outside = deepcopy(deep)
        outside["findings"][0][proof_name][field][0]["path"] = "outside.py"
        with pytest.raises(EngineError) as path_error:
            _validate_finding_semantics({"mode": "deep"}, outside, _inventory())
        assert path_error.value.code == "canonical_proof_path_invalid"
    structured_root_cause = {"summary": explicit_root_cause, "evidenceRefs": ["evidence-1"]}
    structured = build_findings_document(
        scan["id"], [{**deep_item, "details": {"discoveryEngine": "kiro-agent-deep-orchestration", "rootCause": structured_root_cause}}]
    )
    assert structured["findings"][0]["rootCause"] == structured_root_cause
    valid(structured, "findings.schema.json")
    _validate_finding_semantics({"mode": "standard"}, structured)
    invalid_references = []
    for refs in (["missing-evidence"], [""]):
        mutation = deepcopy(structured)
        mutation["findings"][0]["rootCause"]["evidenceRefs"] = refs
        invalid_references.append(mutation)
    duplicate_evidence = deepcopy(structured)
    duplicate_evidence["findings"][0]["codeEvidence"].append(
        deepcopy(duplicate_evidence["findings"][0]["codeEvidence"][0])
    )
    invalid_references.append(duplicate_evidence)
    for mutation in invalid_references:
        with pytest.raises(EngineError) as reference_error:
            _validate_finding_semantics({"mode": "standard"}, mutation)
        assert reference_error.value.code == "canonical_evidence_reference_invalid"
    mapping_root = workspace / "evidence-mapping"
    mapping_root.mkdir()
    mapping_workbench = Workbench(mapping_root)
    mapping_scan = _create_reporting_scan(mapping_workbench)
    mapped_item = deepcopy(deep_item)
    mapped_item["details"] = {"rootCause": structured_root_cause}
    mapped_item["codeEvidence"][0]["id"] = "evidence-1"
    mapped_finding = mapping_workbench.upsert_finding(mapping_scan["id"], mapped_item)
    mapped_document = build_findings_document(mapping_scan["id"], [mapped_finding])
    assert mapped_document["findings"][0]["rootCause"]["evidenceRefs"] == [
        mapped_document["findings"][0]["codeEvidence"][0]["id"]
    ]
    prior_item = deepcopy(deep_item)
    prior_item["fingerprint"] = "kiro-security/deep-v1:sha256:" + "e" * 64
    prior_item["identity"] = {"anchor": "test", "instance": "prior-sink"}
    prior_item["canonicalId"] = "deep-candidate_prior"
    prior_item["sourceRefs"] = []
    prior_item["details"] = {
        "discoveryEngine": "kiro-agent-deep-orchestration", "rootCause": structured_root_cause,
    }
    prior_item["codeEvidence"][0].pop("id", None)
    prior_finding = mapping_workbench.upsert_finding(mapping_scan["id"], prior_item)
    assert prior_finding["details"]["rootCause"] == {"summary": explicit_root_cause}
    assert prior_finding["details"]["rootCauseEvidenceStatus"] == "prior_unresolved"
    terminal_item = deepcopy(prior_item)
    terminal_item["fingerprint"] = "kiro-security/deep-v1:sha256:" + "d" * 64
    terminal_item["identity"] = {"anchor": "test", "instance": "terminal-prior-sink"}
    terminal_item["sourceRefs"] = ["r1-w1-c1"]
    with pytest.raises(EngineError) as untrusted_terminal:
        mapping_workbench.upsert_finding(mapping_scan["id"], terminal_item)
    assert untrusted_terminal.value.code == "candidate_evidence_reference_invalid"
    terminal_finding = mapping_workbench.upsert_finding(
        mapping_scan["id"], terminal_item, durable_deep_candidate=True,
    )
    assert terminal_finding["details"]["rootCauseEvidenceStatus"] == "prior_unresolved"
    for missing_root_cause in (None, {}):
        source_to_sink_only = build_findings_document(scan["id"], [{
            **deep_item,
            "details": {
                "discoveryEngine": "kiro-agent-deep-orchestration",
                "rootCause": missing_root_cause,
                "sourceToSink": "The submitted source reaches the sink without an intervening control.",
            },
        }])
        assert "rootCause" not in source_to_sink_only["findings"][0]
        valid(source_to_sink_only, "findings.schema.json")
    report = _project_report(
        {**scan, "mode": "deep"}, deep, prepared["documents"]["coverage"],
        {"summary": "Canonical threat-model marker."},
    )
    assert f"](findings/{finding_id}/{finding_id}.md)" in report
    assert "Canonical threat-model marker." in report
    assert "hardening/hardening.md" in report
    inline_deep = deepcopy(deep)
    inline_deep["findings"][0].pop("writeup")
    inline_report = _project_report({**scan, "mode": "deep"}, inline_deep, prepared["documents"]["coverage"])
    assert explicit_root_cause in inline_report
    assert deep_attack["narrative"] in inline_report
    for proof in (
        deep_validation["rationale"], deep_validation["crossFileTrace"][0],
        deep_validation["frameworkControls"][0], deep_attack["impact"],
        deep_attack["residualUncertainty"], deep_attack["severity"]["rationale"],
    ):
        assert proof in inline_report
    injected = deepcopy(inline_deep)
    injected["findings"][0]["summary"] = "# injected\n[link](javascript:alert(1))"
    injected_report = _project_report({**scan, "mode": "deep"}, injected, prepared["documents"]["coverage"])
    assert "\n# injected" not in injected_report
    assert r"\[link\]" in injected_report
    injected_scope = _project_report(
        {**scan, "scope": "`\n# injected"}, {"findings": []}, prepared["documents"]["coverage"]
    )
    assert "\n# injected" not in injected_scope
    unsafe_writeup_item = deepcopy(item)
    unsafe_writeup_item["locations"][0]["path"] = "src/x` ![probe](https://example.invalid/collect)"
    unsafe_writeups = _write_writeups(Path(prepared["artifactDir"]), [unsafe_writeup_item])
    assert "![probe](https://example.invalid/collect)" not in (
        Path(prepared["artifactDir"]) / unsafe_writeups[finding_id]
    ).read_text(encoding="utf-8")
    contradictory = deepcopy(prepared["documents"])
    contradictory["validation"]["records"] = [{"findingId": "ghost"}]
    with pytest.raises(EngineError) as projection_error:
        _validate_auxiliary_documents(contradictory, scan["id"], contradictory["findings"])
    assert projection_error.value.code == "canonical_projection_mismatch"
    findings_path = Path(prepared["paths"]["findings"])
    original_findings = findings_path.read_bytes()
    identity_mismatch = deepcopy(deep)
    identity_mismatch["findings"][0]["validation"]["findingId"] = "kspf_" + "f" * 24
    findings_path.write_text(json.dumps(identity_mismatch), encoding="utf-8")
    with pytest.raises(EngineError) as identity_error:
        prepare_finalization(workbench, prepared)
    assert identity_error.value.code == "canonical_finding_identity_mismatch"
    findings_path.write_bytes(original_findings)
    for forbidden in ("claimToken", "runtime", "capabilities", "rawResult"):
        mutation = deepcopy(deep)
        mutation["findings"][0]["provenance"][forbidden] = "secret"
        rejected(mutation, "findings.schema.json")
    mutation = deepcopy(deep)
    mutation["findings"][0]["extensions"]["claimToken"] = "secret"
    rejected(mutation, "findings.schema.json")
    legacy_item = {**deep_item, "details": {"legacyContract": True}, "validation": None, "attackPath": None}
    legacy = build_findings_document(scan["id"], [legacy_item])
    assert "rootCause" not in legacy["findings"][0]
    valid(legacy, "findings.schema.json")

    writeup_relative = f"findings/{finding_id}/{finding_id}.md"
    writeup_path = Path(prepared["artifactDir"]) / writeup_relative
    writeup_path.parent.mkdir(parents=True, exist_ok=True)
    writeup_path.write_text("# Dedicated writeup\n", encoding="utf-8")
    duplicate_writeup = deepcopy(deep)
    duplicate_finding = deepcopy(duplicate_writeup["findings"][0])
    duplicate_finding["findingId"] = "kspf_" + "f" * 24
    duplicate_writeup["findings"].append(duplicate_finding)
    with pytest.raises(EngineError) as duplicate_writeup_error:
        _validate_writeup_artifacts(
            {"artifactDir": prepared["artifactDir"], "writeupPaths": {finding_id: writeup_relative}},
            duplicate_writeup,
        )
    assert duplicate_writeup_error.value.code == "canonical_writeup_reference_invalid"
    mapped_finding = mapping_workbench.save_validation(mapped_finding["occurrenceId"], {
        "status": "validated", "method": "static_trace", "rationale": "Still present.", "evidence": [],
    })
    mapped_relative = f"findings/{mapped_finding['findingId']}/{mapped_finding['findingId']}.md"
    mapped_writeup = Path(mapping_scan["artifact_dir"]) / mapped_relative
    mapped_writeup.parent.mkdir(parents=True, exist_ok=True)
    mapped_writeup.write_text("# Dedicated writeup\n", encoding="utf-8")
    (Path(mapping_scan["artifact_dir"]) / ARTIFACT_KINDS["threatModel"]).write_text("# Threat model\n", encoding="utf-8")
    mapped_bundle = write_canonical_documents(
        mapping_workbench, mapping_scan["id"], _inventory(), {"summary": "Threat model."},
        writeup_paths={mapped_finding["findingId"]: mapped_relative},
    )
    mapped_findings_path = Path(mapped_bundle["paths"]["findings"])
    mapped_findings_document = json.loads(mapped_findings_path.read_text(encoding="utf-8"))
    identity_drift = deepcopy(mapped_findings_document)
    identity_drift["findings"][0]["findingId"] = "kspf_" + "0" * 24
    mapped_findings_path.write_text(json.dumps(identity_drift), encoding="utf-8")
    with pytest.raises(EngineError) as durable_identity_error:
        prepare_finalization(mapping_workbench, mapped_bundle)
    assert durable_identity_error.value.code == "canonical_finding_identity_mismatch"
    mapped_findings_path.write_text(json.dumps(mapped_findings_document), encoding="utf-8")
    prepared_with_writeup = prepare_finalization(mapping_workbench, mapped_bundle)
    mapped_writeup.unlink()
    with pytest.raises(EngineError) as missing_writeup:
        finalize_scan(mapping_workbench, prepared_with_writeup)
    assert missing_writeup.value.code == "artifact_missing"

    for name, value in (("findingId", "bad"), ("occurrenceId", "bad")):
        mutation = deepcopy(standard)
        mutation["findings"][0][name] = value
        rejected(mutation, "findings.schema.json")
    mutation = deepcopy(standard)
    mutation["findings"][0]["fingerprints"]["algorithm"] = "kiro-security/deep-v1"
    rejected(mutation, "findings.schema.json")
    for report_path in ("/tmp/report.md", "writeups/../report.md"):
        mutation = deepcopy(standard)
        mutation["findings"][0]["writeup"]["reportPath"] = report_path
        rejected(mutation, "findings.schema.json")
    for field in ("locations", "codeEvidence"):
        for unsafe_path in ("../src/app.py", "C:src/app.py"):
            mutation = deepcopy(standard)
            mutation["findings"][0][field][0]["path"] = unsafe_path
            rejected(mutation, "findings.schema.json")
    for field in ("validation", "attackPath"):
        mutation = deepcopy(standard)
        mutation["findings"][0][field].pop("rationale" if field == "validation" else "impact")
        rejected(mutation, "findings.schema.json")

    coverage = prepared["documents"]["coverage"]
    valid(coverage, "coverage.schema.json")
    surface = coverage["surfaces"][0]
    false_complete = [
        {**deepcopy(coverage), "deferred": [{key: surface[key] for key in ("id", "rowId", "path", "reason", "receiptDigest")}]},
        {**deepcopy(coverage), "unclosedRows": [{"rowId": surface["rowId"], "path": surface["path"], "surface": surface["surface"], "reason": "Unclosed."}]},
        {**deepcopy(coverage), "deepStatus": "capped"},
    ]
    for mutation in false_complete:
        rejected(mutation, "coverage.schema.json")

    finalize_scan(workbench, prepared)
    manifest_path = Path(scan["artifact_dir"]) / ARTIFACT_KINDS["manifest"]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    valid(manifest, "scan-manifest.schema.json")
    model_manifest = deepcopy(manifest)
    model_manifest["scan"]["scope"]["validationMode"] = "agent-assisted-discovery+model-validation"
    valid(model_manifest, "scan-manifest.schema.json")
    for path in ("coverage.json", "findings.json"):
        mutation = deepcopy(manifest)
        mutation["scan"]["artifacts"] = [item for item in mutation["scan"]["artifacts"] if item["path"] != path]
        rejected(mutation, "scan-manifest.schema.json")
        mutation = deepcopy(manifest)
        mutation["scan"]["artifacts"].append(next(item for item in mutation["scan"]["artifacts"] if item["path"] == path))
        rejected(mutation, "scan-manifest.schema.json")
    mutation = deepcopy(manifest)
    next(item for item in mutation["scan"]["artifacts"] if item["path"] not in ("coverage.json", "findings.json"))["path"] = "../artifact.json"
    rejected(mutation, "scan-manifest.schema.json")
