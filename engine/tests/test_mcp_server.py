from __future__ import annotations

from pathlib import Path

from kiro_security import __version__
from kiro_security.mcp_server import McpServer, TOOLS


def test_python_mcp_contract_exposes_full_shared_workbench_surface() -> None:
    names = {tool["name"] for tool in TOOLS}
    assert {
        "security_get_capabilities",
        "security_start_scan",
        "security_list_scans",
        "security_resume_scan",
        "security_cancel_scan",
        "security_get_scan",
        "security_get_progress",
        "security_list_findings",
        "security_get_finding",
        "security_validate_finding",
        "security_triage_finding",
        "security_create_remediation",
        "security_prepare_remediation_patch",
        "security_apply_remediation_patch",
        "security_verify_remediation_patch",
        "security_create_triage_intake",
        "security_submit_triage_assessment",
        "security_create_tracking_handoff",
        "security_record_tracking_result",
        "security_create_hardening_proposal",
        "security_create_threat_model",
        "security_export_report",
    }.issubset(names)
    assert len(names) == len(TOOLS)
    for tool in TOOLS:
        assert tool["inputSchema"]["type"] == "object"
        assert tool["name"].startswith("security_")
    tracking = next(tool for tool in TOOLS if tool["name"] == "security_create_tracking_handoff")
    assert "trackingProof" in tracking["inputSchema"]["required"]
    assert tracking["inputSchema"]["properties"]["destination"]["maxLength"] == 512
    tail = next(tool for tool in TOOLS if tool["name"] == "security_deep_submit_tail_result")
    assert tail["inputSchema"]["properties"]["claimToken"]["maxLength"] == 256


def test_python_mcp_capabilities_use_workspace_engine_and_current_version(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    server = McpServer()
    try:
        capabilities = server.call_tool("security_get_capabilities", {"workspaceRoot": str(workspace)})
        assert capabilities["engineVersion"] == __version__
        assert capabilities["modes"] == ["diff", "standard", "deep"]
        assert capabilities["database"]["schemaVersion"] >= 1
        assert Path(capabilities["workspaceRoot"]) == workspace.resolve()
    finally:
        server.shutdown()
