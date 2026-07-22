from __future__ import annotations

from .constants import PHASES, TERMINAL_SCAN_STATUSES
from .errors import EngineError

_ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "running": {"completed", "cancelled", "failed"},
    "completed": set(),
    "cancelled": set(),
    "failed": set(),
}


def require_status_transition(current: str, target: str) -> None:
    if current == target:
        return
    if target not in _ALLOWED_STATUS_TRANSITIONS.get(current, set()):
        raise EngineError(
            "invalid_state_transition",
            f"Cannot transition scan status from {current!r} to {target!r}.",
            {"current": current, "target": target},
        )


def phase_index(phase: str) -> int:
    try:
        return PHASES.index(phase)
    except ValueError as exc:
        raise EngineError("invalid_phase", f"Unknown scan phase: {phase}") from exc


def require_phase_transition(current: str, target: str) -> None:
    current_index = phase_index(current)
    target_index = phase_index(target)
    if target_index == current_index:
        return
    if target_index == current_index + 1:
        return
    raise EngineError(
        "invalid_phase_transition",
        f"Cannot transition scan phase from {current!r} to {target!r}.",
        {"current": current, "target": target},
    )


def is_terminal(status: str) -> bool:
    return status in TERMINAL_SCAN_STATUSES
