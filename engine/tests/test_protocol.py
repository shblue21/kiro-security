from __future__ import annotations

import math

import pytest

from kiro_security.constants import PROTOCOL_VERSION
from kiro_security.errors import EngineError
from kiro_security.protocol import reject_non_finite, validate_method, validate_protocol_version


def test_initialize_and_start_scan_validation() -> None:
    params = validate_method(
        "initialize",
        {"protocolVersion": PROTOCOL_VERSION, "clientInfo": {"name": "test", "version": "1"}},
    )
    assert params["protocolVersion"] == PROTOCOL_VERSION
    assert validate_method("start_scan", {"mode": "deep", "scope": "src", "maxFiles": 100})["mode"] == "deep"
    with pytest.raises(EngineError, match="mode"):
        validate_method("start_scan", {"mode": "arbitrary"})
    with pytest.raises(EngineError, match="maxFiles"):
        validate_method("start_scan", {"mode": "standard", "maxFiles": 0})


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


def test_export_and_poll_bounds() -> None:
    assert validate_method("export_report", {"scanId": "scan", "format": "sarif"})["format"] == "sarif"
    with pytest.raises(EngineError):
        validate_method("export_report", {"scanId": "scan", "format": "html"})
    with pytest.raises(EngineError):
        validate_method("poll_events", {"limit": 1001})
