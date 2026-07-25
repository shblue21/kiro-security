"""Model-visible MCP tools for the deterministic Kiro Security workbench."""

import os

from .errors import WorkbenchError
from .models import DiffTarget, WorkspaceSetup
from .workbench import Workbench

SERVER_NAME = "kiro-security-power"
SERVER_VERSION = "0.1.0"


def _schema(properties, required=()):
    result = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        result["required"] = list(required)
    return result


def _string(description):
    return {"type": "string", "minLength": 1, "description": description}


def _uuid(description):
    return {
        "type": "string",
        "format": "uuid",
        "description": description,
    }


def _integer(minimum):
    return {"type": "integer", "minimum": minimum}


def _setup_schema(target_required):
    properties = {
        "targetPath": _string("Absolute local target directory."),
        "mode": {"type": "string", "enum": ["diff", "standard", "deep"]},
        "scope": _string("Target-relative POSIX directory scope."),
        "userContext": {"type": "string"},
        "diffTarget": _schema(
            {
                "kind": {
                    "type": "string",
                    "enum": ["working_tree", "commit", "range"],
                },
                "baseRevision": {"type": "string"},
                "headRevision": {"type": "string"},
                "contentDigest": {"type": "string"},
            },
            required=("kind",),
        ),
    }
    return _schema(properties, required=("targetPath",) if target_required else ())


READ_ONLY_TOOLS = (
    "kiro_security_get_capabilities",
    "kiro_security_get_workspace",
    "kiro_security_get_scan_context",
)

TOOL_DEFINITIONS = (
    {
        "name": "kiro_security_get_capabilities",
        "title": "Get Kiro Security capabilities",
        "description": (
            "Read the deterministic workbench version, storage boundary, and "
            "currently implemented execution capabilities."
        ),
        "inputSchema": _schema({}),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_create_workspace",
        "title": "Create a logical security workspace",
        "description": (
            "Create a new opaque logical workspace for this Kiro chat. Setup "
            "may be provisional and must be saved before scan start."
        ),
        "inputSchema": _schema(
            {"setup": _setup_schema(False)},
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": False},
    },
    {
        "name": "kiro_security_get_workspace",
        "title": "Get a logical security workspace",
        "description": "Read one logical workspace by its opaque identifier.",
        "inputSchema": _schema(
            {"sessionId": _uuid("Logical workspace UUID.")},
            required=("sessionId",),
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_save_workspace",
        "title": "Save workspace scan setup",
        "description": (
            "Strictly validate and submit target, mode, scope, context, and exact "
            "Diff identity before the workspace has ever started a scan."
        ),
        "inputSchema": _schema(
            {
                "sessionId": _uuid("Logical workspace UUID."),
                "setup": _setup_schema(True),
            },
            required=("sessionId", "setup"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_start_scan",
        "title": "Start a durable security scan",
        "description": (
            "Capture the submitted target snapshot and create a durable running "
            "scan. Returns scanId; call kiro_security_get_scan_context next."
        ),
        "inputSchema": _schema(
            {"sessionId": _uuid("Logical workspace UUID.")},
            required=("sessionId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_get_scan_context",
        "title": "Get authoritative scan context",
        "description": (
            "Read the immutable snapshot and current lifecycle state for an exact "
            "scanId."
        ),
        "inputSchema": _schema(
            {"scanId": _uuid("Durable scan UUID.")},
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_update_scan_progress",
        "title": "Publish scan progress",
        "description": (
            "Publish monotonic lifecycle telemetry for a running scan. Progress "
            "does not prove that semantic artifacts are complete."
        ),
        "inputSchema": _schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "phase": {
                    "type": "string",
                    "enum": [
                        "preflight",
                        "threat_model",
                        "discovery",
                        "validation",
                        "attack_path",
                        "reporting",
                    ],
                },
                "reviewItemsTotal": _integer(0),
                "reviewItemsCompleted": _integer(0),
                "reportableFindingsCount": _integer(0),
                "deepReviewPass": _integer(1),
            },
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_fail_scan",
        "title": "Mark scan failed",
        "description": (
            "Record an explicit terminal failure for a running scan. This does "
            "not require a coordinator bearer token."
        ),
        "inputSchema": _schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "failureMessage": _string("Concise failure explanation."),
            },
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_cancel_scan",
        "title": "Cancel a running scan",
        "description": (
            "Cancel a running scan by its opaque identifier. The database stores "
            "failed plus canceledAt and projects status canceled."
        ),
        "inputSchema": _schema(
            {"scanId": _uuid("Durable scan UUID.")},
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
)


class WorkbenchTools:
    """Validated MCP-to-workbench adapter with no semantic analysis."""

    def __init__(self, state_root=None, scan_root=None):
        # type: (object, object) -> None
        resolved_state = state_root or os.environ.get("KIRO_SECURITY_STATE_ROOT")
        if not isinstance(resolved_state, str) or not resolved_state.strip():
            raise WorkbenchError(
                "state_root_required",
                "KIRO_SECURITY_STATE_ROOT must identify extension global storage.",
            )
        resolved_scan = scan_root
        if resolved_scan is None:
            resolved_scan = os.environ.get("KIRO_SECURITY_SCAN_ROOT") or None
        self.workbench = Workbench(resolved_state, resolved_scan)

    def call(self, name, arguments):
        # type: (str, object) -> dict
        args = _require_arguments(arguments)
        if name == "kiro_security_get_capabilities":
            _reject_unknown(args, ())
            state = self.workbench.schema_state()
            return {
                "server": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "schemaVersion": state["schemaVersion"],
                "stateRoot": state["stateRoot"],
                "scanRoot": state["scanRoot"],
                "scanStartOwner": "kiro_agent_chat",
                "chatIdentity": "workspace_id_possession_adaptation",
                "semanticAnalysisOwner": "power_skills",
                "semanticWorkflowsAvailable": False,
                "directContinuation": "start_scan_then_get_scan_context",
            }
        if name == "kiro_security_create_workspace":
            _reject_unknown(args, ("setup",))
            setup_value = args.get("setup")
            setup = (
                _workspace_setup(setup_value, target_required=False)
                if setup_value is not None
                else None
            )
            return self.workbench.create_workspace(setup)
        if name == "kiro_security_get_workspace":
            _reject_unknown(args, ("sessionId",))
            return self.workbench.get_workspace(_required_string(args, "sessionId"))
        if name == "kiro_security_save_workspace":
            _reject_unknown(args, ("sessionId", "setup"))
            return self.workbench.update_workspace_setup(
                _required_string(args, "sessionId"),
                _workspace_setup(args.get("setup"), target_required=True),
            )
        if name == "kiro_security_start_scan":
            _reject_unknown(args, ("sessionId",))
            return self.workbench.start_scan(_required_string(args, "sessionId"))
        if name == "kiro_security_get_scan_context":
            _reject_unknown(args, ("scanId",))
            return self.workbench.get_scan_context(_required_string(args, "scanId"))
        if name == "kiro_security_update_scan_progress":
            _reject_unknown(
                args,
                (
                    "scanId",
                    "phase",
                    "reviewItemsTotal",
                    "reviewItemsCompleted",
                    "reportableFindingsCount",
                    "deepReviewPass",
                ),
            )
            return self.workbench.update_scan_progress(
                _required_string(args, "scanId"),
                args.get("phase"),
                args.get("reviewItemsTotal"),
                args.get("reviewItemsCompleted"),
                args.get("reportableFindingsCount"),
                args.get("deepReviewPass"),
            )
        if name == "kiro_security_fail_scan":
            _reject_unknown(args, ("scanId", "failureMessage"))
            return self.workbench.fail_scan(
                _required_string(args, "scanId"),
                _optional_string(args, "failureMessage"),
            )
        if name == "kiro_security_cancel_scan":
            _reject_unknown(args, ("scanId",))
            return self.workbench.cancel_scan(_required_string(args, "scanId"))
        raise WorkbenchError("unknown_tool", "Unknown Kiro Security MCP tool.")


def _require_arguments(value):
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise WorkbenchError("invalid_arguments", "Tool arguments must be an object.")
    return value


def _reject_unknown(arguments, allowed):
    unknown = sorted(set(arguments).difference(allowed))
    if unknown:
        raise WorkbenchError(
            "invalid_arguments",
            "Unexpected tool arguments: %s." % ", ".join(unknown),
        )


def _required_string(arguments, key):
    value = arguments.get(key)
    if not isinstance(value, str) or not value.strip():
        raise WorkbenchError(
            "invalid_arguments",
            "%s must be a non-empty string." % key,
        )
    return value.strip()


def _optional_string(arguments, key):
    value = arguments.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise WorkbenchError("invalid_arguments", "%s must be a string." % key)
    return value


def _workspace_setup(value, target_required):
    if not isinstance(value, dict):
        raise WorkbenchError("invalid_arguments", "setup must be an object.")
    _reject_unknown(
        value,
        ("targetPath", "mode", "scope", "userContext", "diffTarget"),
    )
    target_path = value.get("targetPath")
    if target_required and (not isinstance(target_path, str) or not target_path.strip()):
        raise WorkbenchError(
            "invalid_arguments",
            "setup.targetPath must be a non-empty absolute path.",
        )
    if target_path is not None and not isinstance(target_path, str):
        raise WorkbenchError(
            "invalid_arguments",
            "setup.targetPath must be a string.",
        )
    mode = value.get("mode", "standard")
    scope = value.get("scope", ".")
    user_context = value.get("userContext")
    if not isinstance(mode, str) or not isinstance(scope, str):
        raise WorkbenchError(
            "invalid_arguments",
            "setup mode and scope must be strings.",
        )
    if user_context is not None and not isinstance(user_context, str):
        raise WorkbenchError(
            "invalid_arguments",
            "setup.userContext must be a string.",
        )
    diff_value = value.get("diffTarget")
    diff_target = None
    if diff_value is not None:
        if not isinstance(diff_value, dict):
            raise WorkbenchError(
                "invalid_arguments",
                "setup.diffTarget must be an object.",
            )
        _reject_unknown(
            diff_value,
            ("kind", "baseRevision", "headRevision", "contentDigest"),
        )
        diff_target = DiffTarget(
            _required_string(diff_value, "kind"),
            _optional_string(diff_value, "baseRevision"),
            _optional_string(diff_value, "headRevision"),
            _optional_string(diff_value, "contentDigest"),
        )
    return WorkspaceSetup(
        target_path=target_path,
        mode=mode,
        scope=scope,
        user_context=user_context,
        diff_target=diff_target,
    )
