"""Stable global-storage launcher for the Kiro Security MCP runtime."""

import json
import os
import sys
from pathlib import Path


def _engine_root():
    root = Path(__file__).resolve(strict=True).parent / "engine"
    if not root.is_dir() or root.is_symlink():
        raise RuntimeError("Kiro Security runtime engine is unavailable.")
    return root


def _required_environment(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError("%s is required." % name)
    return value


def main():
    sys.path.insert(0, str(_engine_root()))
    if len(sys.argv) == 2 and sys.argv[1] == "--initialize":
        from kiro_security.workbench import Workbench

        state = Workbench(
            _required_environment("KIRO_SECURITY_STATE_ROOT"),
            _required_environment("KIRO_SECURITY_SCAN_ROOT"),
        ).schema_state()
        print(json.dumps(state, sort_keys=True, separators=(",", ":")))
        return 0
    if len(sys.argv) != 1:
        raise RuntimeError("Unsupported Kiro Security launcher arguments.")
    from kiro_security.mcp_server import main as serve

    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
