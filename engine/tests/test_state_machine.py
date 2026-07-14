from __future__ import annotations

import pytest

from kiro_security.errors import EngineError
from kiro_security.state_machine import is_terminal, phase_index, require_phase_transition, require_status_transition


def test_scan_status_transitions() -> None:
    require_status_transition("running", "completed")
    require_status_transition("interrupted", "running")
    require_status_transition("failed", "running")
    with pytest.raises(EngineError, match="Cannot transition"):
        require_status_transition("completed", "running")
    with pytest.raises(EngineError):
        require_status_transition("cancelled", "completed")


def test_phase_transitions_are_strictly_ordered() -> None:
    require_phase_transition("preflight", "threat_model")
    require_phase_transition("validation", "attack_path")
    require_phase_transition("discovery", "discovery", resuming=True)
    with pytest.raises(EngineError, match="Cannot transition"):
        require_phase_transition("preflight", "validation")
    with pytest.raises(EngineError):
        phase_index("invented")


def test_terminal_statuses() -> None:
    assert is_terminal("completed")
    assert is_terminal("cancelled")
    assert is_terminal("failed")
    assert not is_terminal("interrupted")
    assert not is_terminal("running")
