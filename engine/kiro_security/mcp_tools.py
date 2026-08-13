"""Model-visible MCP tools for the deterministic Kiro Security workbench."""

import json
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


def _sha256(description):
    return {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
        "description": description,
    }


def _attested_schema(properties, required=()):
    attested_properties = {
        "requestNonce": {
            "type": "string",
            "pattern": "^[A-Za-z0-9_-]{16,128}$",
            "description": "Fresh one-time nonce for Kiro Hook attestation.",
        }
    }
    attested_properties.update(properties)
    return _schema(
        attested_properties,
        required=("requestNonce",) + tuple(required),
    )


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


TOOL_DEFINITIONS = (
    {
        "name": "kiro_security_get_capabilities",
        "title": "Get Kiro Security capabilities",
        "description": (
            "Read the deterministic workbench version, storage boundary, and "
            "currently implemented execution capabilities."
        ),
        "inputSchema": _attested_schema({}),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_create_workspace",
        "title": "Create a logical security workspace",
        "description": (
            "Create a new opaque logical workspace for this Kiro chat. Setup "
            "may be provisional and must be saved before scan start."
        ),
        "inputSchema": _attested_schema(
            {"setup": _setup_schema(False)},
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": False},
    },
    {
        "name": "kiro_security_get_workspace",
        "title": "Get a logical security workspace",
        "description": "Read one logical workspace by its opaque identifier.",
        "inputSchema": _attested_schema(
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
        "inputSchema": _attested_schema(
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
            "After the user approves the displayed saved setup, verify its exact "
            "revision, digest, and normalized value; then capture the target and "
            "create a durable running scan. Returns scanId; call "
            "kiro_security_get_scan_context next."
        ),
        "inputSchema": _attested_schema(
            {
                "sessionId": _uuid("Logical workspace UUID."),
                "setupRevision": _integer(1),
                "setupDigest": _sha256(
                    "Digest returned by the authoritative saved workspace."
                ),
                "setup": _setup_schema(True),
            },
            required=("sessionId", "setupRevision", "setupDigest", "setup"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_get_scan_context",
        "title": "Get authoritative scan context",
        "description": (
            "Read the immutable snapshot and current lifecycle state for an exact "
            "scanId, or atomically deliver an explicitly claimed recovery."
        ),
        "inputSchema": _attested_schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "recoveryRequestId": _uuid("Optional recovery request UUID."),
                "recoveryToken": _uuid("Optional token returned by recovery claim."),
                "expectedVersion": _integer(1),
            },
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": False},
    },
    {
        "name": "kiro_security_update_scan_progress",
        "title": "Publish scan progress",
        "description": (
            "Publish monotonic lifecycle telemetry for a running scan. Progress "
            "does not prove that semantic artifacts are complete."
        ),
        "inputSchema": _attested_schema(
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
        "name": "kiro_security_get_artifact_contract",
        "title": "Get authoritative scan artifact contract",
        "description": (
            "Read the current DB-authoritative phase workflow, only that phase's "
            "writable JSON schemas, final closure, and persisted artifacts."
        ),
        "inputSchema": _attested_schema(
            {"scanId": _uuid("Durable scan UUID.")},
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_read_scan_artifact",
        "title": "Read one validated scan artifact",
        "description": (
            "Read one digest-bound semantic artifact owned by this Kiro chat. "
            "The server resolves the allowlisted descriptor inside the scan; "
            "arbitrary filesystem paths are not accepted."
        ),
        "inputSchema": _attested_schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "descriptor": _string("Allowlisted semantic artifact descriptor."),
                "expectedDigest": _sha256(
                    "Exact digest from the current artifact contract."
                ),
            },
            required=("scanId", "descriptor", "expectedDigest"),
        ),
        "annotations": {"readOnlyHint": True, "idempotentHint": True},
    },
    {
        "name": "kiro_security_write_scan_artifact",
        "title": "Write one validated scan artifact",
        "description": (
            "Validate and atomically persist one allowlisted JSON artifact for the "
            "current semantic phase. Pass the exact artifact as contentJson so empty "
            "arrays remain distinguishable from omitted fields."
        ),
        "inputSchema": _attested_schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "descriptor": _string("Allowlisted artifact descriptor."),
                "contentJson": _string(
                    "Exact JSON object text; preserve every explicit empty array."
                ),
                "expectedDigest": _sha256(
                    "Optional digest for idempotent compare-and-swap replacement."
                ),
            },
            required=("scanId", "descriptor", "contentJson"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_complete_scan",
        "title": "Finalize and complete a scan",
        "description": (
            "Validate phase closure and canonical artifacts, deterministically "
            "write report and exports, seal the artifact tree, index findings, "
            "and atomically publish scan completion."
        ),
        "inputSchema": _attested_schema(
            {"scanId": _uuid("Durable scan UUID.")},
            required=("scanId",),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_export_scan",
        "title": "Export a completed scan",
        "description": (
            "Strictly regenerate and return the selected completed-scan export."
        ),
        "inputSchema": _attested_schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "format": {
                    "type": "string",
                    "enum": ["json", "sarif", "csv"],
                },
            },
            required=("scanId", "format"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_claim_scan_recovery",
        "title": "Claim a scan recovery request",
        "description": (
            "Claim an exact VSIX-created running scan recovery request for this "
            "Kiro chat."
        ),
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable recovery request UUID."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_release_scan_recovery",
        "title": "Release a scan recovery claim",
        "description": "Release an undelivered scan recovery claim.",
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable recovery request UUID."),
                "recoveryToken": _uuid("Token returned by recovery claim."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "recoveryToken", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_claim_remediation",
        "title": "Claim an exact remediation action",
        "description": (
            "Claim a VSIX-requested generate, apply, or verify action with "
            "version compare-and-swap."
        ),
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable remediation request UUID."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_get_remediation",
        "title": "Get claimed remediation context",
        "description": (
            "Deliver authoritative scan, finding, patch, and action context to "
            "the chat holding the exact claim."
        ),
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable remediation request UUID."),
                "actionToken": _uuid("Token returned by remediation claim."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "actionToken", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": False},
    },
    {
        "name": "kiro_security_set_remediation",
        "title": "Publish a remediation action result",
        "description": (
            "Publish one exact generated, applied, verified, or failed result "
            "using occurrence, request, token, and expected version."
        ),
        "inputSchema": _attested_schema(
            {
                "occurrenceId": _string("Canonical occurrence identifier."),
                "requestId": _uuid("Durable remediation request UUID."),
                "actionToken": _uuid("Delivered remediation action token."),
                "expectedVersion": _integer(1),
                "state": {
                    "type": "string",
                    "enum": ["generated", "applied", "verified", "failed"],
                },
                "patchPath": {"type": "string"},
                "patchDigest": _sha256("Exact generated patch digest."),
                "appliedContentDigest": _sha256("Exact checkout digest after apply."),
                "summary": {"type": "string"},
                "verificationSummary": {"type": "string"},
            },
            required=(
                "occurrenceId",
                "requestId",
                "actionToken",
                "expectedVersion",
                "state",
            ),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": False},
    },
    {
        "name": "kiro_security_release_remediation",
        "title": "Release a remediation action claim",
        "description": "Release an undelivered remediation action claim.",
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable remediation request UUID."),
                "actionToken": _uuid("Token returned by remediation claim."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "actionToken", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_claim_tracking",
        "title": "Claim an exact finding tracking handoff",
        "description": (
            "Claim a VSIX-created tracking request for one sealed finding."
        ),
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable tracking request UUID."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "expectedVersion"),
        ),
        "annotations": {"readOnlyHint": False, "idempotentHint": True},
    },
    {
        "name": "kiro_security_get_tracking",
        "title": "Get claimed tracking context",
        "description": (
            "Deliver one seal-verified finding and scan context to the chat "
            "holding the exact tracking claim, and re-verify the same delivered "
            "context immediately before an external write."
        ),
        "inputSchema": _attested_schema(
            {
                "requestId": _uuid("Durable tracking request UUID."),
                "trackingToken": _uuid("Token returned by tracking claim."),
                "expectedVersion": _integer(1),
            },
            required=("requestId", "trackingToken", "expectedVersion"),
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
        "inputSchema": _attested_schema(
            {
                "scanId": _uuid("Durable scan UUID."),
                "failureMessage": _string("Concise failure explanation."),
            },
            required=("scanId",),
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
    },
    {
        "name": "kiro_security_cancel_scan",
        "title": "Cancel a running scan",
        "description": (
            "Cancel a running scan by its opaque identifier. The database stores "
            "failed plus canceledAt and projects status canceled."
        ),
        "inputSchema": _attested_schema(
            {"scanId": _uuid("Durable scan UUID.")},
            required=("scanId",),
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
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
        attested_args = _require_arguments(arguments)
        owner_session_hash = self.workbench.consume_chat_attestation(
            name,
            attested_args,
        )
        args = dict(attested_args)
        args.pop("requestNonce", None)
        if name == "kiro_security_get_capabilities":
            _reject_unknown(args, ())
            state = self.workbench.schema_state()
            return {
                "server": {"name": SERVER_NAME, "version": SERVER_VERSION},
                "schemaVersion": state["schemaVersion"],
                "stateRoot": state["stateRoot"],
                "scanRoot": state["scanRoot"],
                "scanStartOwner": "kiro_agent_chat",
                "chatIdentity": "kiro_hook_one_time_attestation",
                "semanticAnalysisOwner": "kiro_agent_steering",
                "semanticWorkflowsAvailable": True,
                "scanModes": ["standard", "diff", "deep"],
                "finalization": "canonical_v1_seal",
                "recovery": "explicit_kiro_chat_transfer",
                "findingFollowup": ["triage", "remediation", "tracking_workflow"],
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
            return self.workbench.create_workspace(
                setup,
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_get_workspace":
            _reject_unknown(args, ("sessionId",))
            return self.workbench.get_workspace(
                _required_string(args, "sessionId"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_save_workspace":
            _reject_unknown(args, ("sessionId", "setup"))
            return self.workbench.update_workspace_setup(
                _required_string(args, "sessionId"),
                _workspace_setup(args.get("setup"), target_required=True),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_start_scan":
            _reject_unknown(
                args,
                ("sessionId", "setupRevision", "setupDigest", "setup"),
            )
            return self.workbench.start_scan(
                _required_string(args, "sessionId"),
                expected_setup_revision=_required_integer(args, "setupRevision", 1),
                expected_setup_digest=_required_sha256(args, "setupDigest"),
                approved_setup=_workspace_setup(args.get("setup"), target_required=True),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_get_scan_context":
            _reject_unknown(
                args,
                (
                    "scanId",
                    "recoveryRequestId",
                    "recoveryToken",
                    "expectedVersion",
                ),
            )
            return self.workbench.get_scan_context(
                _required_string(args, "scanId"),
                recovery_request_id=_optional_string(args, "recoveryRequestId"),
                recovery_token=_optional_string(args, "recoveryToken"),
                expected_version=args.get("expectedVersion"),
                owner_session_hash=owner_session_hash,
            )
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
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_get_artifact_contract":
            _reject_unknown(args, ("scanId",))
            return self.workbench.get_scan_artifact_contract(
                _required_string(args, "scanId"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_read_scan_artifact":
            _reject_unknown(args, ("scanId", "descriptor", "expectedDigest"))
            return self.workbench.read_scan_artifact(
                _required_string(args, "scanId"),
                _required_string(args, "descriptor"),
                _required_sha256(args, "expectedDigest"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_write_scan_artifact":
            _reject_unknown(
                args,
                ("scanId", "descriptor", "contentJson", "expectedDigest"),
            )
            return self.workbench.write_scan_artifact(
                _required_string(args, "scanId"),
                _required_string(args, "descriptor"),
                _required_json_object(args, "contentJson"),
                _optional_string(args, "expectedDigest"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_complete_scan":
            _reject_unknown(args, ("scanId",))
            return self.workbench.complete_scan(
                _required_string(args, "scanId"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_export_scan":
            _reject_unknown(args, ("scanId", "format"))
            return self.workbench.export_scan(
                _required_string(args, "scanId"),
                _required_string(args, "format"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_claim_scan_recovery":
            _reject_unknown(args, ("requestId", "expectedVersion"))
            return self.workbench.claim_scan_recovery(
                _required_string(args, "requestId"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_release_scan_recovery":
            _reject_unknown(
                args,
                ("requestId", "recoveryToken", "expectedVersion"),
            )
            return self.workbench.release_scan_recovery(
                _required_string(args, "requestId"),
                _required_string(args, "recoveryToken"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_claim_remediation":
            _reject_unknown(args, ("requestId", "expectedVersion"))
            return self.workbench.claim_remediation_action(
                _required_string(args, "requestId"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_get_remediation":
            _reject_unknown(
                args,
                ("requestId", "actionToken", "expectedVersion"),
            )
            return self.workbench.get_remediation_context(
                _required_string(args, "requestId"),
                _required_string(args, "actionToken"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_set_remediation":
            _reject_unknown(
                args,
                (
                    "occurrenceId",
                    "requestId",
                    "actionToken",
                    "expectedVersion",
                    "state",
                    "patchPath",
                    "patchDigest",
                    "appliedContentDigest",
                    "summary",
                    "verificationSummary",
                ),
            )
            return self.workbench.set_finding_remediation(
                _required_string(args, "occurrenceId"),
                _required_string(args, "requestId"),
                _required_integer(args, "expectedVersion", 1),
                _required_string(args, "actionToken"),
                _required_string(args, "state"),
                _optional_string(args, "patchPath"),
                _optional_string(args, "patchDigest"),
                _optional_string(args, "appliedContentDigest"),
                _optional_string(args, "summary"),
                _optional_string(args, "verificationSummary"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_release_remediation":
            _reject_unknown(
                args,
                ("requestId", "actionToken", "expectedVersion"),
            )
            return self.workbench.release_remediation_claim(
                _required_string(args, "requestId"),
                _required_integer(args, "expectedVersion", 1),
                _required_string(args, "actionToken"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_claim_tracking":
            _reject_unknown(args, ("requestId", "expectedVersion"))
            return self.workbench.claim_tracking_request(
                _required_string(args, "requestId"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_get_tracking":
            _reject_unknown(
                args,
                ("requestId", "trackingToken", "expectedVersion"),
            )
            return self.workbench.get_tracking_context(
                _required_string(args, "requestId"),
                _required_string(args, "trackingToken"),
                _required_integer(args, "expectedVersion", 1),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_fail_scan":
            _reject_unknown(args, ("scanId", "failureMessage"))
            return self.workbench.fail_scan(
                _required_string(args, "scanId"),
                _optional_string(args, "failureMessage"),
                owner_session_hash=owner_session_hash,
            )
        if name == "kiro_security_cancel_scan":
            _reject_unknown(args, ("scanId",))
            return self.workbench.cancel_scan(
                _required_string(args, "scanId"),
                owner_session_hash=owner_session_hash,
            )
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


def _required_integer(arguments, key, minimum):
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise WorkbenchError(
            "invalid_arguments",
            "%s must be an integer greater than or equal to %s." % (key, minimum),
        )
    return value


def _required_json_object(arguments, key):
    text = _required_string(arguments, key)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise WorkbenchError(
            "invalid_arguments",
            "%s must encode one JSON object without duplicate keys or "
            "non-finite numbers." % key,
        ) from exc
    if not isinstance(value, dict):
        raise WorkbenchError(
            "invalid_arguments",
            "%s must encode a JSON object." % key,
        )
    return value


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _reject_json_constant(_value):
    raise ValueError("non-finite JSON number")


def _required_sha256(arguments, key):
    value = _required_string(arguments, key)
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise WorkbenchError(
            "invalid_arguments",
            "%s must be a lowercase SHA-256 digest." % key,
        )
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
