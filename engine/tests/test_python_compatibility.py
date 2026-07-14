from __future__ import annotations

import ast
from pathlib import Path


def test_engine_source_uses_python_39_grammar_and_no_dataclass_slots() -> None:
    engine_root = Path(__file__).resolve().parents[1] / "kiro_security"
    checked = 0
    for source in sorted(engine_root.rglob("*.py")):
        text = source.read_text(encoding="utf-8")
        ast.parse(text, filename=str(source), feature_version=(3, 9))
        assert "@dataclass(slots=True)" not in text
        checked += 1
    assert checked >= 15
