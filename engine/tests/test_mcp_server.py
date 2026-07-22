from __future__ import annotations

from pathlib import Path

import pytest

from kiro_security import __version__
from kiro_security.mcp_server import McpServer, TOOLS


def test_python_mcp_surface_is_lifecycle_only_for_skill_workflow() -> None:
    names = {tool["name"] for tool in TOOLS}
    lifecycle = {
        "security_get_capabilities", "security_start_scan", "security_get_scan_context",
        "security_update_scan_progress", "security_get_scan", "security_get_progress",
        "security_acquire_scan_coordinator", "security_renew_scan_coordinator",
        "security_release_scan_coordinator", "security_cancel_scan",
        "security_complete_scan", "security_fail_scan",
    }
    assert lifecycle.issubset(names)
    removed = {
        "security_deep_get_status", "security_model_get_plan", "security_model_checkpoint",
        "security_deep_claim_worker", "security_deep_submit_worker_result", "security_deep_retry_worker",
        "security_deep_claim_merge", "security_deep_submit_merge", "security_deep_get_tail_assignment",
        "security_deep_submit_tail_result", "security_deep_retry_writeup",
        "security_list_scans",
    }
    assert removed.isdisjoint(names)
    progress = next(tool for tool in TOOLS if tool["name"] == "security_update_scan_progress")
    assert "results" not in progress["inputSchema"]["properties"]
    assert "receipts" not in progress["inputSchema"]["properties"]
    complete = next(tool for tool in TOOLS if tool["name"] == "security_complete_scan")
    assert complete["inputSchema"]["required"] == [
        "scanId", "coordinatorToken", "coordinatorGeneration",
    ]
    assert "security_resume_scan" not in names


def test_python_mcp_capabilities_are_truthful_and_inputs_are_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    server = McpServer()
    try:
        capabilities = server.call_tool("security_get_capabilities", {"workspaceRoot": str(workspace)})
        assert capabilities["engine"]["version"] == __version__
        assert capabilities["supportedModes"] == ["diff", "standard", "deep"]
        assert capabilities["canonicalFinalizer"] is True
        assert set(capabilities) == {
            "product", "engine", "python", "sqlite", "git", "workspace", "supportedModes", "canonicalFinalizer",
        }
        with pytest.raises(ValueError, match="workspaceRoot"):
            server.call_tool("security_get_capabilities", {"workspaceRoot": ""})
        with pytest.raises(ValueError, match="Unexpected tool argument"):
            server.call_tool("security_complete_scan", {
                "workspaceRoot": str(workspace), "scanId": "scan_x", "findings": [],
            })
    finally:
        server.shutdown()
