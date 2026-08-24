"""Kiro Security workbench value objects."""

from dataclasses import dataclass
from typing import Optional

MODES = ("diff", "standard", "deep")
DIFF_TARGET_KINDS = ("working_tree", "commit", "range")
PHASES = (
    "preflight",
    "threat_model",
    "discovery",
    "validation",
    "attack_path",
    "reporting",
)


@dataclass(frozen=True)
class DiffTarget:
    """An exact Git-backed change selection."""

    kind: str
    base_revision: Optional[str] = None
    head_revision: Optional[str] = None
    content_digest: Optional[str] = None


@dataclass(frozen=True)
class WorkspaceSetup:
    """Mutable workspace setup before the first scan is attached."""

    target_path: Optional[str] = None
    mode: str = "standard"
    scope: str = "."
    user_context: Optional[str] = None
    diff_target: Optional[DiffTarget] = None
