from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EngineError(Exception):
    code: str
    message: str
    data: dict[str, Any] | None = None

    def __str__(self) -> str:
        return self.message


class CancelledScan(Exception):
    pass


class InterruptedScan(Exception):
    pass
