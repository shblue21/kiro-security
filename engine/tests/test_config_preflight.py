"""Stdlib regression tests for Kiro capability evidence gates.

Run directly when pytest is unavailable:

    PYTHONPATH=engine python3 engine/tests/test_config_preflight.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).resolve().parents[1] / "kiro_security" / "codex_contract" / "config_preflight.py"
SKILLS = (
    "attack-path-analysis",
    "finding-discovery",
    "security-scan",
    "threat-model",
    "validation",
)


def _preflight(profile: str, *, nested: bool | None, worker_slots: int | None) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="kiro-preflight-") as temporary:
        empty_config = Path(temporary) / "config.toml"
        empty_config.write_text("", encoding="utf-8")
        command = [
            sys.executable,
            str(SCRIPT),
            "--profile",
            profile,
            "--config",
            str(empty_config),
            "--multi-agent-runtime-owner",
            "native",
            "--multi-agent-runtime-version",
            "v1",
            "--multi-agent-runtime-provenance",
            "tool-surface",
            "--runtime-check",
            "delegation_available=true",
            "--runtime-check",
            "goal_tools_available=true",
        ]
        if nested is not None:
            command.extend([
                "--runtime-check",
                f"nested_delegation_available={'true' if nested else 'false'}",
            ])
        if worker_slots is not None:
            command.extend(["--multi-agent-worker-slots", str(worker_slots)])
        for skill in SKILLS:
            command.extend(["--available-plugin-skill", skill])
        result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=20)
        assert result.returncode in {0, 1, 2}, result.stderr
        return json.loads(result.stdout)


def _result(payload: dict[str, Any], capability: str) -> dict[str, Any]:
    return next(item for item in payload["results"] if item["capability"] == capability)


def test_deep_requires_nested_delegation_and_observed_worker_slots() -> None:
    missing = _preflight("deep_security_scan", nested=False, worker_slots=None)
    assert missing["status"] == "blocked"
    assert _result(missing, "agent_depth_2")["status"] == "fail"
    capacity = _result(missing, "usable_worker_slots_4")
    assert capacity["status"] == "unknown"
    assert capacity["observedSource"] == "documented-default"

    no_capacity = _preflight("deep_security_scan", nested=True, worker_slots=None)
    assert no_capacity["status"] == "incomplete"
    assert _result(no_capacity, "agent_depth_2")["status"] == "pass"
    assert _result(no_capacity, "usable_worker_slots_4")["status"] == "unknown"

    short = _preflight("deep_security_scan", nested=True, worker_slots=3)
    assert short["status"] == "blocked"
    assert _result(short, "usable_worker_slots_4")["status"] == "fail"

    unknown_depth = _preflight("deep_security_scan", nested=None, worker_slots=4)
    assert unknown_depth["status"] == "incomplete"
    assert _result(unknown_depth, "agent_depth_2")["status"] == "unknown"


def test_verified_deep_capacity_is_ready_and_standard_default_is_preserved() -> None:
    ready = _preflight("deep_security_scan", nested=True, worker_slots=4)
    assert ready["status"] == "ready"
    capacity = _result(ready, "usable_worker_slots_4")
    assert capacity["status"] == "pass"
    assert capacity["actual"] == 4
    assert capacity["source"] == "runtime-fact"

    standard = _preflight("security_scan", nested=False, worker_slots=None)
    assert standard["status"] == "ready"
    capacity = _result(standard, "usable_worker_slots_4")
    assert capacity["status"] == "pass"
    assert capacity["source"] == "documented-default"


def main() -> None:
    for test in (
        test_deep_requires_nested_delegation_and_observed_worker_slots,
        test_verified_deep_capacity_is_ready_and_standard_default_is_preserved,
    ):
        test()
        print(f"PASS {test.__name__}")


if __name__ == "__main__":
    main()
