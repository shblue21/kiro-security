from __future__ import annotations

import math
from pathlib import Path

import pytest

from kiro_security.constants import PROTOCOL_VERSION
from kiro_security.errors import EngineError
from kiro_security.protocol import (
    ENGINE_EVENT_NAMES,
    reject_non_finite,
    validate_method,
    validate_protocol_version,
    validate_request_envelope,
    validate_request_id,
)
from kiro_security.schema_validation import validate_against_schema
from kiro_security.server import RpcServer


def test_initialize_and_start_scan_validation() -> None:
    params = validate_method(
        "initialize",
        {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test", "version": "1"}},
    )
    assert params["protocolVersion"] == PROTOCOL_VERSION
    assert validate_method("start_scan", {"mode": "deep", "scope": "src"})["mode"] == "deep"
    resumed = validate_method(
        "start_scan",
        {"workspaceId": "workspace-session", "taskId": "task-1", "mode": "deep"},
    )
    assert resumed["workspaceId"] == "workspace-session"
    assert resumed["taskId"] == "task-1"
    assert validate_method("start_scan", {"mode": "standard", "scope": "src"})["mode"] == "standard"
    assert validate_method("start_scan", {"mode": "diff"})["mode"] == "diff"
    with pytest.raises(EngineError, match="Unexpected parameter"):
        validate_method("start_scan", {"mode": "deep", "scope": "src", "hostProof": {}})
    with pytest.raises(EngineError, match="mode"):
        validate_method("start_scan", {"mode": "arbitrary"})
    for removed_limit in ("maxFiles", "maxFileBytes"):
        with pytest.raises(EngineError, match=removed_limit):
            validate_method("start_scan", {"mode": "standard", removed_limit: 1024})
    # Removed worker/result and planner methods are unknown.
    for method in (
        "deep_claim_worker", "deep_submit_worker", "deep_retry_worker", "deep_claim_merge",
        "deep_submit_merge", "deep_get_tail_assignment", "deep_submit_tail_result", "deep_retry_writeup",
        "deep_get_status", "model_get_plan", "model_checkpoint",
    ):
        with pytest.raises(EngineError, match="Unknown RPC method"):
            validate_method(method, {"scanId": "scan_x"})
    assert validate_method("get_scan_context", {"scanId": "scan_x"})["scanId"] == "scan_x"
    lease = {"scanId": "scan_x", "coordinatorToken": "a" * 64, "coordinatorGeneration": 1}
    assert validate_method("complete_scan", lease)["scanId"] == "scan_x"
    assert validate_method("fail_scan", {**lease, "reason": "native delegation unavailable"})["scanId"] == "scan_x"
    assert validate_method("update_scan_progress", {**lease, "phase": "discovery", "phasePercent": 25})["phase"] == "discovery"
    with pytest.raises(EngineError, match="coordinatorToken"):
        validate_method("complete_scan", {"scanId": "scan_x"})
    with pytest.raises(EngineError, match="Unknown RPC method"):
        validate_method("resume_scan", {"scanId": "scan_x"})
    with pytest.raises(EngineError, match="Unexpected parameter"):
        validate_method("complete_scan", {**lease, "candidates": []})
    dashboard = validate_method(
        "get_dashboard", {"workspaceId": "workspace-session", "selectedScanId": "scan-1", "limit": 30},
    )
    assert dashboard["selectedScanId"] == "scan-1"
    with pytest.raises(EngineError, match="limit"):
        validate_method("get_dashboard", {"limit": 201})


def test_protocol_mismatch_and_malformed_messages_are_rejected() -> None:
    with pytest.raises(EngineError) as error:
        validate_protocol_version("0.9")
    assert error.value.code == "protocol_version_mismatch"
    with pytest.raises(EngineError):
        validate_method("triage_finding", {"occurrenceId": "occ", "decision": "delete"})
    with pytest.raises(EngineError):
        validate_method("get_finding", {})
    with pytest.raises(ValueError):
        reject_non_finite("NaN")
    assert not math.isfinite(float("inf"))

    schema = Path(__file__).parents[1] / "schemas" / "protocol.schema.json"
    base = {"jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION}
    request = {**base, "id": 1, "method": "get_capabilities", "params": {}}
    assert validate_request_envelope(request) == request
    assert validate_request_id(1) == 1
    validate_against_schema(request, schema, "request")
    with pytest.raises(EngineError) as event_request:
        validate_method("scan.completed", {})
    assert event_request.value.code == "invalid_request"
    for request_id in ("1", True, None, {}, []):
        with pytest.raises(EngineError):
            validate_request_id(request_id)
        with pytest.raises(EngineError):
            validate_against_schema({**request, "id": request_id}, schema, "request")
    validate_against_schema({**base, "id": 1, "result": {}}, schema, "success")
    validate_against_schema({**base, "id": None, "error": {"code": -32700, "message": "parse error"}}, schema, "failure")
    validate_against_schema({**base, "method": "scan.integrityIssue", "params": {}}, schema, "notification")
    assert "scan.integrityIssue" in ENGINE_EVENT_NAMES
    malformed = [
        {**base, "id": 1, "result": {}, "error": {"code": -32000, "message": "failure"}},
        {**base, "method": "scan.completed", "params": {}, "id": 1},
        {**base, "method": "scan.completed", "params": {}, "result": {}},
        {**base, "id": 1, "error": {"code": -32000}},
        {**base, "method": "scan.unknown", "params": {}},
        {**base, "protocolVersion": "0.9", "method": "engine.ready", "params": {}},
        {**base, "id": None, "error": {"code": -32000, "message": "correlated failure"}},
    ]
    for envelope in malformed:
        with pytest.raises(EngineError):
            validate_against_schema(envelope, schema, "protocol envelope")
    with pytest.raises(EngineError):
        validate_request_envelope({**request, "extra": True})
    with pytest.raises(EngineError):
        validate_method("get_capabilities", {"extra": True})


def test_invalid_correlatable_request_preserves_integer_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    server = RpcServer(str(tmp_path), "test")
    responses = []
    monkeypatch.setattr(server, "write", responses.append)
    try:
        server.handle({
            "jsonrpc": "2.0", "protocolVersion": PROTOCOL_VERSION, "id": 7,
            "method": "get_capabilities", "params": {}, "extra": True,
        })
        assert responses[-1]["id"] == 7
        assert responses[-1]["error"]["code"] == -32600
        assert responses[-1]["error"]["data"]["engineCode"] == "invalid_request"
    finally:
        server.service.shutdown({})


def test_export_and_poll_bounds() -> None:
    assert validate_method("export_report", {"scanId": "scan", "format": "sarif"})["format"] == "sarif"
    with pytest.raises(EngineError):
        validate_method("export_report", {"scanId": "scan", "format": "html"})
    with pytest.raises(EngineError):
        validate_method("poll_events", {"limit": 1001})
