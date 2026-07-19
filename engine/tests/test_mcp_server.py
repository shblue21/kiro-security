from __future__ import annotations

import json
from pathlib import Path

import pytest

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
        workspace = tool["inputSchema"].get("properties", {}).get("workspaceRoot")
        if workspace is not None:
            assert workspace["minLength"] == 1
    tracking = next(tool for tool in TOOLS if tool["name"] == "security_create_tracking_handoff")
    assert "trackingProof" in tracking["inputSchema"]["required"]
    assert tracking["inputSchema"]["properties"]["destination"]["maxLength"] == 512
    tail = next(tool for tool in TOOLS if tool["name"] == "security_deep_submit_tail_result")
    assert tail["inputSchema"]["properties"]["claimToken"]["maxLength"] == 256
    findings = next(tool for tool in TOOLS if tool["name"] == "security_list_findings")
    assert findings["inputSchema"]["properties"]["search"]["minLength"] == 1
    assert findings["inputSchema"]["properties"]["search"]["maxLength"] == 200
    start = next(tool for tool in TOOLS if tool["name"] == "security_start_scan")
    assert start["inputSchema"]["properties"]["scope"]["minLength"] == 1


def test_python_mcp_capabilities_use_workspace_engine_and_current_version(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.chdir(workspace)
    server = McpServer()
    try:
        capabilities = server.call_tool("security_get_capabilities", {"workspaceRoot": str(workspace)})
        assert capabilities["engineVersion"] == __version__
        assert capabilities["modes"] == ["diff", "standard", "deep"]
        assert capabilities["database"]["schemaVersion"] >= 1
        assert Path(capabilities["workspaceRoot"]) == workspace.resolve()
        assert Path(server.call_tool("security_get_capabilities", {})["workspaceRoot"]) == workspace.resolve()
        with pytest.raises(ValueError, match="workspaceRoot"):
            server.call_tool("security_get_capabilities", {"workspaceRoot": ""})
        with pytest.raises(ValueError, match="Unexpected tool argument"):
            server.call_tool("security_get_capabilities", {
                "workspaceRoot": str(workspace), "unexpected": True,
            })
        service = server.service_for({"workspaceRoot": str(workspace)})
        triage_calls: list[dict[str, object]] = []

        def triage(params: dict[str, object]) -> dict[str, object]:
            triage_calls.append(params)
            return params

        monkeypatch.setattr(service, "triage_finding", triage)
        assert server.call_tool("security_triage_finding", {
            "workspaceRoot": str(workspace), "occurrenceId": "occ_test",
            "decision": "open", "note": "",
        })["note"] == ""
        monkeypatch.setattr(service, "start_scan", lambda params: params)
        with pytest.raises(ValueError, match="scope.*non-empty"):
            server.call_tool("security_start_scan", {
                "workspaceRoot": str(workspace), "mode": "standard", "scope": "",
                "analysisProfile": "model", "modelId": "test-model", "runtime": {},
            })
        assert server.call_tool("security_start_scan", {
            "workspaceRoot": str(workspace), "mode": "standard",
            "analysisProfile": "model", "modelId": "test-model", "runtime": {},
        })["scope"] == "."
        with pytest.raises(ValueError, match="search.*200"):
            server.call_tool("security_list_findings", {
                "workspaceRoot": str(workspace), "scanId": "scan_missing", "search": "x" * 201,
            })
        with pytest.raises(ValueError, match="search.*non-empty"):
            server.call_tool("security_list_findings", {
                "workspaceRoot": str(workspace), "scanId": "scan_missing", "search": None,
            })
        server.initialized = True
        server.handle({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "security_get_capabilities", "arguments": False},
        })
        response = json.loads(capsys.readouterr().out)
        assert response["result"]["isError"] is True
        assert "JSON object" in response["result"]["content"][0]["text"]
        baseline = len(triage_calls)
        for invalid_id in (None, False, {"invalid": "id"}):
            server.handle({
                "jsonrpc": "2.0", "id": invalid_id, "method": "tools/call",
                "params": {"name": "security_triage_finding", "arguments": {
                    "workspaceRoot": str(workspace), "occurrenceId": "occ_test", "decision": "open",
                }},
            })
            response = json.loads(capsys.readouterr().out)
            assert response["id"] is None and response["error"]["code"] == -32602
        server.handle({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": "security_triage_finding", "arguments": {
                "workspaceRoot": str(workspace), "occurrenceId": "occ_test", "decision": "open",
            }},
        })
        response = json.loads(capsys.readouterr().out)
        assert response["id"] is None and response["error"]["code"] == -32602
        assert len(triage_calls) == baseline
    finally:
        server.shutdown()
