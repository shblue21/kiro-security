"""Canonical one-time Kiro chat attestation values."""

import hashlib
import json
import re

from .errors import WorkbenchError


REQUEST_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
SESSION_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def require_request_nonce(value):
    # type: (object) -> str
    if not isinstance(value, str) or REQUEST_NONCE_PATTERN.fullmatch(value) is None:
        raise WorkbenchError(
            "chat_attestation_required",
            "A fresh Kiro Security requestNonce is required.",
        )
    return value


def require_session_hash(value):
    # type: (object) -> str
    if not isinstance(value, str) or SESSION_HASH_PATTERN.fullmatch(value) is None:
        raise WorkbenchError(
            "chat_identity_invalid",
            "Kiro chat identity is invalid.",
        )
    return value


def arguments_hash(arguments):
    # type: (dict) -> str
    bound_arguments = dict(arguments)
    bound_arguments.pop("requestNonce", None)
    try:
        canonical = json.dumps(
            bound_arguments,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkbenchError(
            "invalid_arguments",
            "Tool arguments must be canonical JSON values.",
        ) from exc
    return hashlib.sha256(canonical).hexdigest()
