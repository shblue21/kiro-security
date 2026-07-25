"""Deterministic Kiro Security workbench CLI."""

import argparse
import json
import sys

from .errors import WorkbenchError
from .models import DiffTarget, WorkspaceSetup
from .workbench import Workbench


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--scan-root")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init")

    create = commands.add_parser("create-workspace")
    _add_setup(create, target_required=False)

    update = commands.add_parser("update-workspace")
    _add_setup(update)
    update.add_argument("--workspace-id", required=True)

    get_workspace = commands.add_parser("get-workspace")
    get_workspace.add_argument("--workspace-id", required=True)

    start = commands.add_parser("start-scan")
    start.add_argument("--workspace-id", required=True)

    context = commands.add_parser("get-scan-context")
    context.add_argument("--scan-id", required=True)

    progress = commands.add_parser("update-progress")
    progress.add_argument("--scan-id", required=True)
    progress.add_argument(
        "--phase",
        choices=(
            "preflight",
            "threat_model",
            "discovery",
            "validation",
            "attack_path",
            "reporting",
        ),
    )
    progress.add_argument("--review-items-total", type=int)
    progress.add_argument("--review-items-completed", type=int)
    progress.add_argument("--reportable-findings-count", type=int)
    progress.add_argument("--deep-review-pass", type=int)

    fail = commands.add_parser("fail-scan")
    fail.add_argument("--scan-id", required=True)
    fail.add_argument("--message")

    cancel = commands.add_parser("cancel-scan")
    cancel.add_argument("--scan-id", required=True)
    return parser


def _add_setup(parser, target_required=True):
    parser.add_argument("--target-path", required=target_required)
    parser.add_argument("--mode", choices=("diff", "standard", "deep"), default="standard")
    parser.add_argument("--scope", default=".")
    parser.add_argument("--user-context")
    parser.add_argument("--diff-kind", choices=("working_tree", "commit", "range"))
    parser.add_argument("--diff-base")
    parser.add_argument("--diff-head")
    parser.add_argument("--diff-content-digest")


def _setup(args):
    diff_target = (
        DiffTarget(
            args.diff_kind,
            args.diff_base,
            args.diff_head,
            args.diff_content_digest,
        )
        if args.diff_kind
        else None
    )
    return WorkspaceSetup(
        target_path=args.target_path,
        mode=args.mode,
        scope=args.scope,
        user_context=args.user_context,
        diff_target=diff_target,
    )


def run(argv=None):
    args = _parser().parse_args(argv)
    try:
        workbench = Workbench(args.state_root, args.scan_root)
        if args.command == "init":
            result = workbench.schema_state()
        elif args.command == "create-workspace":
            result = workbench.create_workspace(_setup(args))
        elif args.command == "update-workspace":
            result = workbench.update_workspace_setup(
                args.workspace_id,
                _setup(args),
            )
        elif args.command == "get-workspace":
            result = workbench.get_workspace(args.workspace_id)
        elif args.command == "start-scan":
            result = workbench.start_scan(args.workspace_id)
        elif args.command == "get-scan-context":
            result = workbench.get_scan_context(args.scan_id)
        elif args.command == "update-progress":
            result = workbench.update_scan_progress(
                args.scan_id,
                args.phase,
                args.review_items_total,
                args.review_items_completed,
                args.reportable_findings_count,
                args.deep_review_pass,
            )
        elif args.command == "fail-scan":
            result = workbench.fail_scan(args.scan_id, args.message)
        elif args.command == "cancel-scan":
            result = workbench.cancel_scan(args.scan_id)
        else:
            raise AssertionError("Unhandled command")
    except WorkbenchError as exc:
        print(
            json.dumps(
                {"error": {"code": exc.code, "message": str(exc)}},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
