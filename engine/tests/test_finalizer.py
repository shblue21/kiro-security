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
from kiro_security.finalizer import finalize_scan, prepare_finalization
from kiro_security.reporting import build_findings_document, write_canonical_documents
from kiro_security.schema_validation import validate_against_schema
from kiro_security.security import sha256_file


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
    deep_item = {**item, "fingerprint": "kiro-security/deep-v1:sha256:" + "d" * 64}
    deep = build_findings_document(
        scan["id"], [deep_item], {finding_id: f"findings/{finding_id}/{finding_id}.md"},
        {"validation": {occurrence_id: deep_validation}, "attack_path": {occurrence_id: deep_attack}},
    )
    valid(deep, "findings.schema.json")
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
