from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from kiro_security.constants import ARTIFACT_KINDS, PHASES, PROTOCOL_VERSION
from kiro_security.coverage import coverage_row_id
from kiro_security.db import Workbench
from kiro_security.errors import EngineError
from kiro_security.finalizer import finalize_scan, prepare_finalization
from kiro_security.reporting import write_canonical_documents
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
