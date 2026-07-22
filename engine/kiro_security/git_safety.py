"""Safe Git configuration handling shared by deterministic host operations."""

from __future__ import annotations

from pathlib import Path

from .errors import EngineError
from .security import run_process


def git_filter_overrides(workspace: Path) -> list[str]:
    """Disable repository-local clean/smudge/process filters for Git operations."""
    args = [
        "config", "--includes", "--show-origin", "-z", "--name-only", "--get-regexp",
        r"^filter\..*\.(clean|process|smudge)$",
    ]
    configured = run_process("git", args, cwd=workspace, check=False)
    trusted = run_process("git", ["config", "--global", *args[1:]], cwd=workspace, check=False)

    def records(output: str) -> set[tuple[str, str]]:
        entries = [entry for entry in output.split("\x00") if entry]
        return set(zip(entries[::2], entries[1::2]))

    trusted_records = records(trusted.stdout)
    keys = set()
    for _, key in records(configured.stdout) - trusted_records:
        normalized = key.lower()
        if not normalized.startswith("filter.") or not normalized.endswith((".clean", ".process", ".smudge")):
            continue
        if len(key) > 512:
            raise EngineError("unsafe_git_config", "A repository-local Git filter key exceeds the safety limit.")
        keys.add(key)
    return [part for key in sorted(keys) for part in ("-c", f"{key}=")]
