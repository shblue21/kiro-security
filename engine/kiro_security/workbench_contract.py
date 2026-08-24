"""Shared input and setup contracts for Workbench services."""

import hashlib
import json
import uuid

from .errors import WorkbenchError
from .models import PHASES


def require_uuid(value, label):
    try:
        normalized = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise WorkbenchError(
            "invalid_%s_id" % label,
            "%s ID must be a UUID." % label,
        ) from exc
    return normalized


def optional_text(value, maximum=None):
    if value is None:
        return None
    if not isinstance(value, str):
        raise WorkbenchError("invalid_text", "Text input must be a string.")
    normalized = value.strip()
    if not normalized:
        return None
    if maximum is not None and len(normalized) > maximum:
        raise WorkbenchError(
            "text_too_long",
            "Text input exceeds the supported length.",
        )
    return normalized


def optional_digest(value):
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise WorkbenchError(
            "invalid_digest",
            "Expected digest must be a lowercase SHA-256 value.",
        )
    return value


def optional_phase(value):
    if value is None:
        return None
    if not isinstance(value, str) or value not in PHASES:
        raise WorkbenchError(
            "invalid_phase",
            "Scan phase must be one of the supported lifecycle phases.",
        )
    return value


def optional_nonnegative_int(value, name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkbenchError(
            "invalid_progress",
            "%s must be a non-negative integer." % name,
        )
    return value


def optional_positive_int(value, name):
    result = optional_nonnegative_int(value, name)
    if result == 0:
        raise WorkbenchError(
            "invalid_progress",
            "%s must be a positive integer." % name,
        )
    return result


def setup_projection(setup):
    diff = setup.diff_target
    return {
        "targetPath": setup.target_path,
        "mode": setup.mode,
        "scope": setup.scope,
        "userContext": setup.user_context,
        "diffTarget": (
            {
                "kind": diff.kind,
                "baseRevision": diff.base_revision,
                "headRevision": diff.head_revision,
                "contentDigest": diff.content_digest,
            }
            if diff is not None
            else None
        ),
    }


def setup_digest(setup):
    canonical = json.dumps(
        setup_projection(setup),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
