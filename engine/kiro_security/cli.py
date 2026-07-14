from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .service import SecurityService


def main() -> int:
    parser = argparse.ArgumentParser(description="Kiro Security Power local engine CLI")
    parser.add_argument("workspace", type=Path)
    parser.add_argument("--mode", choices=("standard", "deep", "diff"), default="standard")
    parser.add_argument("--scope", default=".")
    parser.add_argument("--diff-target-kind", choices=("working_tree", "commit", "range"), default="working_tree")
    parser.add_argument("--diff-base")
    parser.add_argument("--diff-head")
    args = parser.parse_args()
    events: list[dict[str, object]] = []
    service = SecurityService(str(args.workspace), "cli", lambda event, payload: events.append({"event": event, "payload": payload}))
    try:
        scan = service.start_scan(
            {
                "mode": args.mode,
                "scope": args.scope,
                "diffTargetKind": args.diff_target_kind,
                "diffBaseRevision": args.diff_base,
                "diffHeadRevision": args.diff_head,
            }
        )
        while True:
            current = service.get_scan({"scanId": scan["id"]})
            if current["status"] not in ("queued", "running"):
                print(json.dumps(current, indent=2))
                return 0 if current["status"] == "completed" else 1
            time.sleep(0.1)
    finally:
        service.shutdown({})


if __name__ == "__main__":
    raise SystemExit(main())
