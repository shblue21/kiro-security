from __future__ import annotations

import os
from pathlib import Path

import pytest

from kiro_security.scanner import build_inventory, scan_inventory

from .conftest import run_git


def inventory(workspace: Path, mode: str = "standard", **kwargs):
    return build_inventory(
        workspace,
        mode=mode,
        scope=kwargs.pop("scope", "."),
        diff_target_kind=kwargs.pop("diff_target_kind", None),
        diff_base_revision=kwargs.pop("diff_base_revision", None),
        diff_head_revision=kwargs.pop("diff_head_revision", None),
        max_files=kwargs.pop("max_files", 10_000),
        max_file_bytes=kwargs.pop("max_file_bytes", 1_048_576),
    )


def test_standard_inventory_and_finding_normalization(workspace: Path) -> None:
    result = inventory(workspace)
    assert result.git_available
    assert {item.relative_path for item in result.files} >= {"src/app.py", "src/server.js", "src/safe.py"}
    findings = scan_inventory(
        result,
        pass_name="all",
        progress=lambda *_: None,
        cancelled=lambda: False,
        interrupted=lambda: False,
    )
    rule_ids = {finding["ruleId"] for finding in findings}
    assert "command-injection.shell-execution" in rule_ids
    assert "sql-injection.dynamic-query" in rule_ids
    assert "path-traversal.uncontained-path" in rule_ids
    assert "authorization.missing-route-guard" in rule_ids
    fingerprints = [finding["fingerprint"] for finding in findings]
    assert len(fingerprints) == len(set(fingerprints))
    assert all("safe.py" not in location["path"] for finding in findings for location in finding["locations"])


def test_deep_passes_merge_distinct_fingerprints(workspace: Path) -> None:
    result = inventory(workspace, mode="deep")
    merged = {}
    for pass_name in ("dataflow", "dangerous_api", "authorization"):
        for finding in scan_inventory(result, pass_name=pass_name, progress=lambda *_: None, cancelled=lambda: False, interrupted=lambda: False):
            merged[finding["fingerprint"]] = finding
    assert len(merged) >= 5
    assert {finding["taxonomy"]["category"] for finding in merged.values()} >= {"command-injection", "sql-injection", "authorization"}


def test_diff_inventory_only_reads_changed_source(workspace: Path) -> None:
    safe = workspace / "src" / "safe.py"
    safe.write_text(safe.read_text(encoding="utf-8") + "\nuser = input()\nsubprocess.run(user, shell=True)\n", encoding="utf-8")
    result = inventory(workspace, mode="diff", diff_target_kind="working_tree")
    assert [item.relative_path for item in result.files] == ["src/safe.py"]
    findings = scan_inventory(result, pass_name="all", progress=lambda *_: None, cancelled=lambda: False, interrupted=lambda: False)
    assert any(item["ruleId"] == "command-injection.shell-execution" for item in findings)


def test_diff_deleted_path_stays_on_coverage_frontier(workspace: Path) -> None:
    kept = workspace / "src" / "safe.py"
    kept.write_text(kept.read_text(encoding="utf-8") + "\n# touched by diff test\n", encoding="utf-8")
    deleted = workspace / "src" / "app.py"
    deleted.unlink()
    result = inventory(workspace, mode="diff", diff_target_kind="working_tree")
    assert [item.relative_path for item in result.files] == ["src/safe.py"]
    deleted_rows = [item for item in result.deferred if item["kind"] == "deleted_file"]
    assert [item["path"] for item in deleted_rows] == ["src/app.py"]
    assert deleted_rows[0]["surface"] == "deleted_file"
    assert "deleted" in deleted_rows[0]["reason"]


def test_diff_commit_deletion_is_reported(workspace: Path) -> None:
    (workspace / "src" / "app.py").unlink()
    run_git(workspace, "add", "-A")
    run_git(workspace, "commit", "-m", "delete app.py")
    head = run_git(workspace, "rev-parse", "HEAD")
    result = inventory(workspace, mode="diff", diff_target_kind="commit", diff_head_revision=head)
    assert any(item["kind"] == "deleted_file" and item["path"] == "src/app.py" for item in result.deferred)


def test_symlink_outside_workspace_is_excluded(workspace: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside.py"
    outside.write_text("password = 'abcdefghijklmnopqrstuvwxyz123456'\n", encoding="utf-8")
    link = workspace / "src" / "outside-link.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    result = inventory(workspace)
    assert "src/outside-link.py" not in {item.relative_path for item in result.files}
    assert "src/outside-link.py" in result.exclude_paths


def test_file_and_size_limits_are_reported(workspace: Path) -> None:
    result = inventory(workspace, max_files=1)
    assert len(result.files) == 1
    assert any(item["id"] == "file-limit" for item in result.deferred)
    huge = workspace / "src" / "huge.py"
    huge.write_text("x = 1\n" * 1000, encoding="utf-8")
    result = inventory(workspace, max_file_bytes=1024)
    assert any(item["id"] == "src/huge.py" for item in result.deferred)
