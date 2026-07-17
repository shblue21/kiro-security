from __future__ import annotations

from pathlib import Path

import pytest

from kiro_security.constants import PROTOCOL_VERSION
from kiro_security.coverage import coverage_receipt_digest, coverage_row_id, make_coverage_row
from kiro_security.db import Workbench
from kiro_security.deep import DeepCoordinator
from kiro_security.errors import EngineError
from kiro_security.reporting import build_coverage_document, synchronize_coverage_ledger
from kiro_security.runner import ScanRunner
from kiro_security.scanner import build_inventory


def _create_scan(workbench: Workbench, mode: str) -> dict:
    session_id = f"coverage-{mode}"
    workbench.register_session(session_id, 1000, "test", PROTOCOL_VERSION)
    registered = workbench.register_workspace(workbench.workspace)
    return workbench.create_scan(
        workspace_id=registered["id"],
        mode=mode,
        scope=".",
        artifact_dir=None,
        session_id=session_id,
        diff_target_kind="working_tree" if mode == "diff" else None,
    )


def _source(path: str, language: str = "python") -> dict:
    surface = f"source_review:{language}"
    return {
        "rowId": coverage_row_id(path, surface),
        "path": path,
        "surface": surface,
        "language": language,
        "size": 42,
    }


def _inventory(*, files: list[dict] | None = None, deferred: list[dict] | None = None) -> dict:
    return {
        "includePaths": ["."],
        "excludePaths": [],
        "files": files or [],
        "deferred": deferred or [],
        "warnings": [],
        "supportedFileCount": len(files or []),
    }


@pytest.mark.parametrize("mode", ["standard", "diff"])
def test_zero_supported_files_never_claim_complete(workspace: Path, mode: str) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, mode)
    inventory = _inventory()

    synchronize_coverage_ledger(workbench, scan, inventory, [])
    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["completeness"] == "unknown"
    assert coverage["supportedFileCount"] == 0
    assert coverage["inScopeRowCount"] == 0
    assert coverage["surfaces"] == []
    assert any("No supported source files" in item["question"] for item in coverage["openQuestions"])


def test_deep_zero_supported_files_remains_blocked(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "deep")

    with pytest.raises(EngineError) as error:
        DeepCoordinator(workbench).ensure(scan, _inventory())

    assert error.value.code == "deep_no_supported_files"


def test_deep_capped_state_forces_partial_even_with_closed_rows(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "deep")
    source = _source("src/app.py")
    inventory = _inventory(files=[source])
    DeepCoordinator(workbench).ensure(scan, inventory)
    workbench.upsert_coverage_row(
        scan["id"],
        make_coverage_row(
            row_id=source["rowId"],
            path=source["path"],
            surface=source["surface"],
            disposition="not_applicable",
            reason="All six workers closed the row without a canonical reportable candidate.",
        ),
    )
    with workbench.transaction() as connection:
        connection.execute(
            "UPDATE deep_scan_state SET status='capped', current_round=10 WHERE scan_id=?",
            (scan["id"],),
        )

    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["deepStatus"] == "capped"
    assert coverage["completeness"] == "partial"
    assert any("round cap" in item["question"] for item in coverage["openQuestions"])


def test_deferred_inventory_row_forces_partial(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "standard")
    source = _source("src/app.py")
    deferred = {
        "rowId": coverage_row_id("Dockerfile", "unsupported_file"),
        "path": "Dockerfile",
        "surface": "unsupported_file",
        "reason": "The in-scope file type is not supported by the deterministic scanner.",
    }
    inventory = _inventory(files=[source], deferred=[deferred])

    synchronize_coverage_ledger(workbench, scan, inventory, [])
    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["completeness"] == "partial"
    assert len(coverage["deferred"]) == 1
    assert any(item["path"] == "Dockerfile" and item["disposition"] == "deferred" for item in coverage["surfaces"])


def test_all_clean_rows_are_complete_with_real_receipt_digests(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "standard")
    files = [_source("src/app.py"), _source("src/safe.py")]
    inventory = _inventory(files=files)

    synchronize_coverage_ledger(workbench, scan, inventory, [])
    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["completeness"] == "complete"
    assert coverage["supportedFileCount"] == 2
    assert coverage["inScopeRowCount"] == 2
    assert coverage["closedRowCount"] == 2
    assert len(coverage["surfaces"]) == 2
    assert {item["path"] for item in coverage["surfaces"]} == {"src/app.py", "src/safe.py"}
    for surface in coverage["surfaces"]:
        assert surface["disposition"] == "not_applicable"
        assert surface["receiptRefs"] == [surface["receiptDigest"]]
        assert surface["receiptDigest"] == coverage_receipt_digest(
            row_id=surface["rowId"],
            disposition=surface["disposition"],
            reason=surface["reason"],
            evidence_refs=surface["evidenceRefs"],
            candidate_ids=surface["candidateIds"],
        )



def test_deep_deferred_receipt_remains_partial_when_a_finding_is_linked(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "deep")
    source = _source("src/app.py")
    inventory = _inventory(files=[source])
    DeepCoordinator(workbench).ensure(scan, inventory)
    workbench.upsert_coverage_row(
        scan["id"],
        make_coverage_row(
            row_id=source["rowId"],
            path=source["path"],
            surface=source["surface"],
            disposition="deferred",
            reason="One independent worker could not complete this row.",
            candidate_ids=["candidate-before-validation"],
        ),
    )
    finding = {
        "findingId": "finding-current",
        "validationStatus": "validated",
        "triageStatus": "open",
        "locations": [{"path": "src/app.py", "startLine": 1, "endLine": 1, "role": "sink"}],
        "codeEvidence": [{"id": "evidence-current", "path": "src/app.py"}],
    }

    synchronize_coverage_ledger(workbench, scan, inventory, [finding])
    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["disposition"] == "deferred"
    assert coverage["surfaces"][0]["candidateIds"] == ["finding-current"]

def test_unclosed_deep_row_is_partial_and_auditable(workspace: Path) -> None:
    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "deep")
    source = _source("src/app.py")
    inventory = _inventory(files=[source])
    DeepCoordinator(workbench).ensure(scan, inventory)

    coverage = build_coverage_document(workbench, scan, inventory)

    assert coverage["completeness"] == "partial"
    assert coverage["closedRowCount"] == 0
    assert coverage["unclosedRows"] == [
        {
            "rowId": source["rowId"],
            "path": "src/app.py",
            "surface": "source_review:python",
            "reason": "No disposition receipt was recorded for this in-scope row.",
        }
    ]


def test_legacy_reviewed_paths_workers_merge_as_deferred_partial(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json
    from kiro_security import deep as deep_module

    workbench = Workbench(workspace)
    scan = _create_scan(workbench, "deep")
    for phase in ("threat_model", "discovery"):
        workbench.set_phase(scan["id"], phase)
    source = _source("src/app.py")
    inventory = _inventory(files=[source])
    coordinator = DeepCoordinator(workbench)
    monkeypatch.setattr(coordinator, "_validate_security_context", lambda *_args: {})
    coordinator.ensure(scan, inventory)
    with workbench.transaction() as connection:
        connection.execute("UPDATE scans SET status='interrupted' WHERE id=?", (scan["id"],))
    for mutation in (
        lambda: coordinator.submit_worker({"scanId": scan["id"]}),
        lambda: coordinator.submit_merge({"scanId": scan["id"], "canonicalCandidates": []}),
        lambda: coordinator.retry_worker(scan["id"], 1, "retry"),
    ):
        with pytest.raises(EngineError) as error:
            mutation()
        assert error.value.code == "deep_scan_not_active"
    with workbench.transaction() as connection:
        connection.execute("UPDATE scans SET status='running' WHERE id=?", (scan["id"],))
    # Simulate six workers completed before migration 008: an attendance-only
    # reviewedPaths result and no durable row receipts.
    legacy_result = json.dumps({
        "reviewedPaths": ["src/app.py"],
        "candidates": [],
        "threatModel": "legacy",
        "summary": "legacy attendance-only result",
    })
    with workbench.transaction() as connection:
        connection.execute(
            "UPDATE deep_workers SET status='completed', result_json=? WHERE scan_id=?",
            (legacy_result, scan["id"]),
        )
        connection.execute(
            "UPDATE deep_scan_state SET status='awaiting_merge' WHERE scan_id=?",
            (scan["id"],),
        )

    merge = coordinator.claim_merge(scan["id"])
    first_receipts = workbench.list_deep_worker_coverage_receipts(scan["id"], 1)
    assert len(first_receipts) == 6
    assert all(item["disposition"] == "deferred" for item in first_receipts)
    original_write_json = deep_module.write_json
    monkeypatch.setattr(
        deep_module,
        "write_json",
        lambda path, payload: (_ for _ in ()).throw(OSError("injected merge artifact failure"))
        if path.name == "merge.json" else original_write_json(path, payload),
    )
    with pytest.raises(OSError, match="injected merge artifact failure"):
        coordinator.submit_merge({
            "scanId": scan["id"],
            "claimToken": merge["claimToken"],
            "canonicalCandidates": [],
        })
    assert coordinator.status(scan["id"])["status"] == "awaiting_merge"
    assert workbench.list_coverage_rows(scan["id"]) == []
    monkeypatch.setattr(deep_module, "write_json", original_write_json)
    status = coordinator.submit_merge({
        "scanId": scan["id"],
        "claimToken": merge["claimToken"],
        "canonicalCandidates": [],
    })
    assert status["status"] == "saturated"
    # Idempotency: repairing again must reproduce the identical receipts.
    coordinator._backfill_legacy_worker_receipts(scan["id"], 1, [source])
    second_receipts = workbench.list_deep_worker_coverage_receipts(scan["id"], 1)
    assert {item["id"] for item in second_receipts} == {item["id"] for item in first_receipts}
    current_refs = [f"r2-w1-c{index}" for index in range(1, 26)]
    provenance = coordinator._deep_provenance(
        canonical_id="candidate-current", round_number=2, refs=current_refs,
        workers_by_round_index={}, prior=None,
        rationales={
            "mergeRationale": "Current sources agree.",
            "identityRationale": "Semantic identity matches.",
            "remediationSubsumption": "One remediation covers the sources.",
        },
    )
    assert provenance["sourceRefs"] == current_refs

    rows = workbench.list_coverage_rows(scan["id"])
    assert [row["disposition"] for row in rows] == ["deferred"]
    coverage = build_coverage_document(workbench, scan, inventory)
    assert coverage["completeness"] == "partial"
    assert coverage["surfaces"][0]["disposition"] == "deferred"


def test_unsupported_in_scope_file_is_explicit_and_never_complete(tmp_path: Path) -> None:
    root = tmp_path / "unsupported-workspace"
    root.mkdir()
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    workbench = Workbench(root)
    scan = _create_scan(workbench, "standard")
    inventory = ScanRunner._inventory_data(
        build_inventory(
            root,
            mode="standard",
            scope=".",
            diff_target_kind=None,
            diff_base_revision=None,
            diff_head_revision=None,
            max_files=100,
            max_file_bytes=1024 * 1024,
        )
    )

    synchronize_coverage_ledger(workbench, scan, inventory, [])
    coverage = build_coverage_document(workbench, scan, inventory)

    assert inventory["supportedFileCount"] == 0
    assert any(
        item["path"] == "Dockerfile"
        and item["kind"] == "security_surface_unreviewed"
        and item["surface"] == "deployment_review:container"
        for item in inventory["deferred"]
    )
    assert coverage["completeness"] == "unknown"
    assert any(item["path"] == "Dockerfile" and item["disposition"] == "deferred" for item in coverage["surfaces"])
