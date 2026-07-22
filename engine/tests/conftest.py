from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = PROJECT_ROOT / "fixtures" / "vulnerable-repo"


def run_git(workspace: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=workspace, text=True, capture_output=True, check=False, timeout=20
    )
    if result.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout.strip()


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    destination = tmp_path / "workspace"
    shutil.copytree(
        FIXTURE_ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", ".kiro", "__pycache__", "*.pyc"),
    )
    run_git(destination, "init")
    run_git(destination, "config", "user.email", "security-test@example.invalid")
    run_git(destination, "config", "user.name", "Kiro Security Test")
    run_git(destination, "add", ".")
    run_git(destination, "commit", "-m", "fixture baseline")
    return destination.resolve()


def wait_for_scan(service: Any, scan_id: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = service.get_scan({"scanId": scan_id})
        if scan["status"] != "running":
            return scan
        time.sleep(0.03)
    raise AssertionError(f"scan {scan_id} did not reach a terminal state")
