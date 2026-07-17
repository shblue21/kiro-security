from __future__ import annotations

import os
from pathlib import Path

import pytest

from kiro_security.errors import EngineError
from kiro_security.scanner import Inventory, SourceFile, build_inventory, scan_inventory, scan_source_file
from kiro_security.runner import ScanRunner
from kiro_security.security import stable_id

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


def test_security_surface_inventory_is_relevance_based(tmp_path: Path) -> None:
    root = tmp_path / "security-surfaces"
    samples = {
        "Dockerfile": "FROM scratch\n",
        "compose.yaml": "services: {}\n",
        "infra/main.tf": "resource \"example\" \"main\" {}\n",
        "k8s/deployment.yaml": "apiVersion: v1\nkind: Pod\n",
        ".github/workflows/ci.yml": "jobs: {}\n",
        "package-lock.json": "{}\n",
        "requirements-prod.txt": "example==1.0\n",
        "db/migrations/001.sql": "CREATE TABLE example(id INT);\n",
        "nginx/nginx.conf": "server {}\n",
        "iam/role-policy.json": "{}\n",
        ".env.example": "TOKEN=placeholder\n",
        "api/service.proto": "syntax = \"proto3\";\n",
        "api/openapi.yaml": "openapi: 3.0.0\n",
        "config/runtime.xml": "<configuration/>\n",
        "data.json": "{}\n",
        "src/app.py": "print('ok')\n",
        "tests/test_app.py": "def test_ok(): pass\n",
    }
    for relative, content in samples.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    invalid = root / "deploy" / "invalid.yaml"
    invalid.parent.mkdir(parents=True, exist_ok=True)
    invalid.write_bytes(b"setting: \xff\n")

    deep = inventory(root, mode="deep")
    surfaces = ScanRunner._inventory_data(deep)
    rows = {item["path"]: item for item in surfaces["files"]}
    assert rows["Dockerfile"]["surface"] == "deployment_review:container"
    assert rows["infra/main.tf"]["surface"] == "deployment_review:infrastructure_as_code"
    assert rows["k8s/deployment.yaml"]["surface"] == "deployment_review:orchestration"
    assert rows[".github/workflows/ci.yml"]["surface"] == "workflow_review:ci"
    assert rows["package-lock.json"]["surface"] == "dependency_review:lockfile"
    assert rows["db/migrations/001.sql"]["surface"] == "data_review:migration"
    assert rows["iam/role-policy.json"]["surface"] == "authorization_review:iam_policy"
    assert rows["api/openapi.yaml"]["surface"] == "interface_review:openapi"
    assert rows["config/runtime.xml"]["surface"] == "configuration_review:runtime"
    assert rows["Dockerfile"]["runtimeRelevance"] and rows["Dockerfile"]["rankingReason"]
    assert rows["Dockerfile"]["entrypoint"] is None and rows["Dockerfile"]["privilegedBoundary"] is None
    assert "data.json" not in rows and "deploy/invalid.yaml" not in rows
    assert any(item["path"] == "data.json" and item["surface"] == "unsupported_file" for item in surfaces["deferred"])
    assert any(item["path"] == "deploy/invalid.yaml" and item["kind"] == "invalid_security_surface_text" for item in surfaces["deferred"])

    standard = ScanRunner._inventory_data(inventory(root, mode="standard"))
    assert {item["path"] for item in standard["files"]} == {"src/app.py", "tests/test_app.py"}
    assert any(
        item["path"] == "Dockerfile"
        and item["kind"] == "security_surface_unreviewed"
        and item["surface"] == "deployment_review:container"
        for item in standard["deferred"]
    )

    capped = inventory(root, mode="deep", max_files=1)
    assert len(capped.files) == 1 and capped.files[0].surface is not None
    assert capped.files[0].relative_path not in {"src/app.py", "tests/test_app.py"}
    assert any(item["surface"] == "inventory_limit" for item in capped.deferred)
    exact = root / "exact"
    exact.mkdir()
    (exact / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    exact_limit = inventory(root, mode="deep", scope="exact", max_files=1)
    assert len(exact_limit.files) == 1
    assert not any(item["surface"] == "inventory_limit" for item in exact_limit.deferred)


def test_finding_identity_survives_line_shift_and_rename_without_merging_siblings() -> None:
    source = "import os\nimport subprocess\nuser = input()\nos.system(user)\nsubprocess.run(user, shell=True)\n"

    def scan(path: str, text: str) -> dict[str, dict]:
        item = SourceFile(Path(path), path, text, "python", len(text.encode("utf-8")))
        return {finding["details"]["sink"]: finding for finding in scan_source_file(item)}

    original = scan("src/commands.py", source)
    shifted = scan("src/commands.py", "\n\n" + source)
    renamed = scan("services/renamed.py", source)
    for sink in ("os.system", "subprocess shell=True"):
        fingerprints = {original[sink]["fingerprint"], shifted[sink]["fingerprint"], renamed[sink]["fingerprint"]}
        assert len(fingerprints) == 1
        assert len({stable_id("kspf", fingerprint) for fingerprint in fingerprints}) == 1
    assert original["os.system"]["fingerprint"] != original["subprocess shell=True"]["fingerprint"]
    shifted_sink = next(item for item in shifted["os.system"]["locations"] if item["role"] == "sink")
    renamed_sink = next(item for item in renamed["os.system"]["locations"] if item["role"] == "sink")
    assert (shifted_sink["path"], shifted_sink["startLine"]) == ("src/commands.py", 6)
    assert (renamed_sink["path"], renamed_sink["startLine"]) == ("services/renamed.py", 4)

    clone = "import os\nuser = input()\nos.system(user)\n"
    clone_files = [SourceFile(Path(path), path, clone, "python", len(clone)) for path in ("jobs/admin.py", "services/admin.py")]
    clone_findings = scan_inventory(Inventory(clone_files, ["."], [], [], None, "clone-snapshot", False))
    assert len(clone_findings) == 2
    assert {item["locations"][-1]["path"] for item in clone_findings} == {"jobs/admin.py", "services/admin.py"}
    assert len({item["fingerprint"] for item in clone_findings}) == 2
    clone_fingerprints = {item["locations"][-1]["path"]: item["fingerprint"] for item in clone_findings}
    reversed_findings = scan_inventory(Inventory(list(reversed(clone_files)), ["."], [], [], None, "clone-snapshot", False))
    assert {item["locations"][-1]["path"]: item["fingerprint"] for item in reversed_findings} == clone_fingerprints
    shifted_clone = "\n\n" + clone
    shifted_files = [
        SourceFile(Path("jobs/admin.py"), "jobs/admin.py", shifted_clone, "python", len(shifted_clone)),
        clone_files[1],
    ]
    shifted_findings = scan_inventory(Inventory(shifted_files, ["."], [], [], None, "clone-snapshot", False))
    assert {item["locations"][-1]["path"]: item["fingerprint"] for item in shifted_findings} == clone_fingerprints
    shifted_location = next(item["locations"][-1] for item in shifted_findings if item["locations"][-1]["path"] == "jobs/admin.py")
    assert shifted_location["startLine"] == 5

    same_path_clone = (
        "import os\nif enabled:\n    def target():\n        os.system(input())\n"
        "else:\n    def target():\n        os.system(input())\n"
    )
    same_path_findings = scan_inventory(Inventory([
        SourceFile(Path("conditional.py"), "conditional.py", same_path_clone, "python", len(same_path_clone))
    ], ["."], [], [], None, "same-path-snapshot", False))
    assert len(same_path_findings) == 2
    assert len({item["fingerprint"] for item in same_path_findings}) == 2

    target = "import os\ndef target():\n    user = input()\n    os.system(user)\n"
    with_unrelated = "import os\ndef unrelated():\n    user = input()\n    os.system(user)\n\n" + target.split("\n", 1)[1]
    old_target = scan_source_file(SourceFile(Path("target.py"), "target.py", target, "python", len(target)))[0]
    new_target = scan_source_file(SourceFile(Path("target.py"), "target.py", with_unrelated, "python", len(with_unrelated)))[-1]
    assert old_target["fingerprint"] == new_target["fingerprint"]

    same_scope = target.rstrip() + "\n    os.system(user)\n"
    siblings = scan_source_file(SourceFile(Path("target.py"), "target.py", same_scope, "python", len(same_scope)))
    assert len(siblings) == 2 and siblings[0]["fingerprint"] != siblings[1]["fingerprint"]

    arrow = "const first = () => {\n  cp.exec(req.body.cmd);\n};\n\nconst target = () => {\n  cp.exec(req.body.cmd);\n};\n"
    inserted_arrow = arrow.replace("\nconst target", "\nconst inserted = () => {\n  cp.exec(req.body.cmd);\n};\n\nconst target")
    arrow_findings = scan_source_file(SourceFile(Path("commands.js"), "commands.js", arrow, "javascript", len(arrow)))
    inserted_findings = scan_source_file(SourceFile(Path("commands.js"), "commands.js", inserted_arrow, "javascript", len(inserted_arrow)))
    assert len(arrow_findings) == 2 and arrow_findings[0]["fingerprint"] != arrow_findings[1]["fingerprint"]
    assert arrow_findings[-1]["fingerprint"] == inserted_findings[-1]["fingerprint"]
    sibling_arrow = arrow.replace("const target = () => {\n  cp.exec(req.body.cmd);", "const target = () => {\n  cp.exec(req.body.cmd);\n  cp.exec(req.body.cmd);")
    arrow_siblings = scan_source_file(SourceFile(Path("commands.js"), "commands.js", sibling_arrow, "javascript", len(sibling_arrow)))
    assert arrow_siblings[-2]["fingerprint"] != arrow_siblings[-1]["fingerprint"]
    shifted_arrow = scan_source_file(SourceFile(Path("commands.js"), "commands.js", "\n\n" + arrow, "javascript", len(arrow) + 2))
    renamed_arrow = scan_source_file(SourceFile(Path("renamed.js"), "renamed.js", arrow, "javascript", len(arrow)))
    assert arrow_findings[-1]["fingerprint"] == shifted_arrow[-1]["fingerprint"] == renamed_arrow[-1]["fingerprint"]

    secret = 'api_key = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"\n'
    secret_finding = scan_source_file(SourceFile(Path("secret.py"), "secret.py", secret, "python", len(secret)))[0]
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456" not in secret_finding["identity"]["instance"]


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
    model_inventory = ScanRunner._inventory_data(result, include_diff_context_row=True)
    assert [(item["path"], item["surface"]) for item in model_inventory["files"]] == [
        ("context/diff-context.json", "diff_review:bounded_patch")
    ]


def test_diff_commit_rejects_content_from_a_different_checkout(workspace: Path) -> None:
    target = run_git(workspace, "rev-parse", "HEAD")
    (workspace / "src" / "safe.py").write_text('print("new checkout")\n', encoding="utf-8")
    run_git(workspace, "add", "src/safe.py")
    run_git(workspace, "commit", "-m", "advance checkout")

    with pytest.raises(EngineError) as error:
        inventory(workspace, mode="diff", diff_target_kind="commit", diff_head_revision=target)
    assert error.value.code == "diff_target_not_checked_out"

    target = run_git(workspace, "rev-parse", "HEAD")
    (workspace / "src" / "safe.py").write_text('print("dirty worktree")\n', encoding="utf-8")
    with pytest.raises(EngineError) as error:
        inventory(workspace, mode="diff", diff_target_kind="commit", diff_head_revision=target)
    assert error.value.code == "diff_target_worktree_changed"


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
