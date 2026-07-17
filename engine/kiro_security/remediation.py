from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .errors import EngineError
from .security import atomic_write, redact, resolve_within, run_process, sha256_file

MAX_PATCH_BYTES = 512 * 1024
_FORBIDDEN_PATCH_MARKERS = (
    "GIT binary patch", "Binary files ", "literal ", "delta ",
    "old mode ", "new mode ", "new file mode ", "deleted file mode ",
    "similarity index ", "dissimilarity index ", "rename from ", "rename to ",
    "copy from ", "copy to ",
)

_REMEDIATION_EXAMPLES = {
    "command-injection": "Use a fixed executable and argument array. Validate each variable argument against an allowlist; do not enable a shell.",
    "code-injection": "Parse a constrained data format and dispatch through an explicit operation map rather than eval/exec.",
    "sql-injection": "Keep SQL syntax static and bind values through placeholders supported by the database driver.",
    "path-traversal": "Resolve against an approved root, reject absolute/traversal inputs, and verify the canonical result remains inside the root.",
    "authorization": "Add authentication and a deny-by-default action/resource authorization check at the route boundary.",
    "unsafe-deserialization": "Replace the object loader with a schema-validated data-only parser or a strict safe loader/type allowlist.",
    "secret-exposure": "Revoke and rotate the value, remove it from source history, and read the replacement from an approved secret store.",
    "transport-security": "Restore certificate verification and configure an approved trust store instead of disabling verification.",
}


def create_remediation_artifact(finding: dict[str, Any], artifact_dir: Path) -> tuple[str, Path]:
    category = finding["taxonomy"]["category"]
    guidance = _REMEDIATION_EXAMPLES.get(category, finding["remediation"])
    sink = next((item for item in finding.get("locations", []) if item.get("role") == "sink"), None)
    path = artifact_dir / "remediations" / f"{finding['findingId']}.md"
    lines = [
        f"# Remediation: {finding['title']}",
        "",
        f"Finding: `{finding['findingId']}`  ",
        f"Occurrence: `{finding['occurrenceId']}`",
        "",
        "## Required security property",
        "",
        guidance,
        "",
        "## Repository-local implementation steps",
        "",
        "1. Confirm the source and sink evidence against the current revision.",
        "2. Introduce the smallest repository-native control that closes the boundary.",
        "3. Add a negative test proving the original attacker-controlled value cannot reach the sink.",
        "4. Run existing unit, integration, and security checks before marking the remediation verified.",
        "",
        "## Affected location",
        "",
        f"- `{sink['path']}:{sink['startLine']}`" if sink else "- No canonical sink location recorded.",
        "",
        "## Verification gate",
        "",
        "Re-run targeted validation and a repository scan. Mark this remediation verified only when the finding is rejected because the control is present, not merely because the line moved.",
        "",
    ]
    atomic_write(path, "\n".join(lines))
    return guidance, path


def _bounded_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit or "\x00" in value:
        raise EngineError("invalid_remediation_patch", f"{field} must be a non-empty string of at most {limit} characters.")
    return redact(value.strip())


def _patch_path(value: str) -> str:
    if value == "/dev/null" or not value.startswith(("a/", "b/")):
        raise EngineError("unsafe_remediation_patch", "Patch creation, deletion, and non-git paths are not accepted.")
    relative = value[2:]
    if not relative or "\\" in relative or "\x00" in relative or "\t" in relative:
        raise EngineError("unsafe_remediation_patch", "Patch paths must be plain workspace-relative POSIX paths.")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts) or relative.startswith("/"):
        raise EngineError("unsafe_remediation_patch", "Patch paths may not be absolute or contain traversal segments.")
    if parts[0] in (".git", ".kiro"):
        raise EngineError("unsafe_remediation_patch", "Patch paths may not modify reserved .git or .kiro state.")
    return relative


def parse_remediation_patch(patch: str) -> list[str]:
    if not isinstance(patch, str) or not patch or "\x00" in patch or len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise EngineError("invalid_remediation_patch", f"patch must be non-empty UTF-8 text of at most {MAX_PATCH_BYTES} bytes.")
    lines = patch.splitlines()
    for line in lines:
        if line.startswith(_FORBIDDEN_PATCH_MARKERS):
            raise EngineError("unsafe_remediation_patch", "Binary, mode, rename, copy, create, and delete patches are not accepted.")
    old_paths = [_patch_path(line[4:]) for line in lines if line.startswith("--- ")]
    new_paths = [_patch_path(line[4:]) for line in lines if line.startswith("+++ ")]
    if not old_paths or len(old_paths) != len(new_paths) or not any(line.startswith("@@ ") for line in lines):
        raise EngineError("invalid_remediation_patch", "patch must contain matched unified diff paths and at least one hunk.")
    if any(old != new for old, new in zip(old_paths, new_paths)):
        raise EngineError("unsafe_remediation_patch", "Patch path changes and renames are not accepted.")
    paths = sorted(set(old_paths))
    if len(paths) > 100:
        raise EngineError("invalid_remediation_patch", "patch may touch at most 100 files.")
    return paths


def _safe_regular_file(workspace: Path, relative: str) -> Path:
    path = resolve_within(workspace, relative, must_exist=True)
    current = workspace
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise EngineError("unsafe_remediation_patch", f"Patch path uses a symlink: {relative}")
    if not path.is_file():
        raise EngineError("unsafe_remediation_patch", f"Patch path is not a regular file: {relative}")
    return path


def current_git_revision(workspace: Path) -> str | None:
    result = run_process("git", ["rev-parse", "HEAD"], cwd=workspace, check=False)
    return result.stdout.strip() if result.returncode == 0 and re.fullmatch(r"[a-f0-9]{40,64}", result.stdout.strip()) else None


def prepare_patch_artifact(
    workspace: Path,
    artifact_dir: Path,
    finding: dict[str, Any],
    scan: dict[str, Any],
    *,
    patch: str,
    plan: Any,
    verification_plan: Any,
    record_id: str,
) -> tuple[dict[str, Any], Path, str]:
    paths = parse_remediation_patch(patch)
    revision = current_git_revision(workspace)
    scan_revision = scan.get("target_revision")
    if scan_revision and revision != scan_revision:
        raise EngineError("remediation_code_drift", "The checkout revision no longer matches the finding scan revision.")
    touched = []
    for relative in paths:
        path = _safe_regular_file(workspace, relative)
        touched.append({"path": relative, "sha256": sha256_file(path)})
    for evidence in finding.get("codeEvidence") or []:
        relative = evidence.get("path")
        code = evidence.get("code")
        if relative in paths and isinstance(code, str) and code:
            source = _safe_regular_file(workspace, relative).read_text(encoding="utf-8")
            if code not in source:
                raise EngineError("remediation_code_drift", f"Recorded finding evidence changed before patch preparation: {relative}")
    if not isinstance(verification_plan, list) or not verification_plan or len(verification_plan) > 50:
        raise EngineError("invalid_remediation_patch", "verificationPlan must contain 1 to 50 bounded checks.")
    checks = [_bounded_text(item, "verificationPlan item", 2000) for item in verification_plan]
    patch_digest = hashlib.sha256(patch.encode("utf-8")).hexdigest()
    metadata = {
        "documentType": "kiro-security-power.remediation-plan",
        "schemaVersion": "1.0",
        "findingId": finding["findingId"],
        "occurrenceId": finding["occurrenceId"],
        "baseRevision": revision,
        "scanRevision": scan_revision,
        "patchPlan": _bounded_text(plan, "plan", 12000),
        "verificationPlan": checks,
        "touchedFiles": touched,
        "patchDigest": patch_digest,
    }
    path = resolve_within(artifact_dir, f"remediations/{record_id}/patch-{patch_digest}.patch")
    atomic_write(path, patch)
    run_process("git", ["apply", "--check", "--whitespace=nowarn", str(path)], cwd=workspace)
    return metadata, path, patch_digest


def load_patch_artifact(artifact_dir: Path, record: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    try:
        metadata = json.loads(record["summary"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise EngineError("remediation_record_invalid", "The remediation plan metadata is invalid.") from exc
    raw_path = Path(record["artifact_path"])
    try:
        relative = raw_path.resolve(strict=True).relative_to(artifact_dir.resolve(strict=True))
    except (OSError, ValueError, RuntimeError) as exc:
        raise EngineError("remediation_patch_changed", "The prepared remediation patch escaped its scan artifact directory.") from exc
    path = resolve_within(artifact_dir, relative, must_exist=True)
    if not path.is_file() or path.is_symlink() or sha256_file(path) != record["patch_digest"]:
        raise EngineError("remediation_patch_changed", "The prepared remediation patch is missing or changed.")
    parse_remediation_patch(path.read_text(encoding="utf-8"))
    return metadata, path


def verify_patch_inputs(workspace: Path, artifact_dir: Path, record: dict[str, Any]) -> tuple[dict[str, Any], Path]:
    metadata, path = load_patch_artifact(artifact_dir, record)
    if current_git_revision(workspace) != metadata.get("baseRevision"):
        raise EngineError("remediation_code_drift", "The checkout revision changed after patch preparation.")
    for item in metadata.get("touchedFiles") or []:
        source = _safe_regular_file(workspace, item["path"])
        if sha256_file(source) != item["sha256"]:
            raise EngineError("remediation_code_drift", f"A touched file changed after patch preparation: {item['path']}")
    return metadata, path


def touched_file_digests(workspace: Path, metadata: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"path": item["path"], "sha256": sha256_file(_safe_regular_file(workspace, item["path"]))}
        for item in metadata.get("touchedFiles") or []
    ]


def reconcile_patch_application(
    workspace: Path, patch_path: Path, metadata: dict[str, Any]
) -> tuple[str, list[dict[str, str]]]:
    """Classify a journaled apply without trusting process-local completion state."""
    current = touched_file_digests(workspace, metadata)
    before = metadata.get("touchedFiles") or []
    forward = run_process(
        "git", ["apply", "--check", "--whitespace=nowarn", str(patch_path)], cwd=workspace, check=False
    ).returncode == 0
    reverse = run_process(
        "git", ["apply", "--reverse", "--check", "--whitespace=nowarn", str(patch_path)],
        cwd=workspace, check=False,
    ).returncode == 0
    if current == before and forward and not reverse:
        return "not_applied", current
    if reverse and not forward:
        return "applied", current
    return "ambiguous", current


def normalize_verification_receipt(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EngineError("invalid_remediation_verification", "verification must be an object.")
    outcome = raw.get("outcome")
    if outcome not in ("verified", "failed"):
        raise EngineError("invalid_remediation_verification", "verification outcome must be verified or failed.")
    security = raw.get("securityValidation")
    tests = raw.get("tests")
    if not isinstance(security, dict) or not isinstance(tests, list) or not tests or len(tests) > 50:
        raise EngineError("invalid_remediation_verification", "securityValidation and 1 to 50 test results are required.")
    security_status = security.get("status")
    if security_status not in ("passed", "failed"):
        raise EngineError("invalid_remediation_verification", "securityValidation.status must be passed or failed.")
    normalized_tests = []
    for item in tests:
        if not isinstance(item, dict) or item.get("status") not in ("passed", "failed", "not_run"):
            raise EngineError("invalid_remediation_verification", "Each test result requires a valid status.")
        normalized_tests.append({
            "command": _bounded_text(item.get("command"), "test command", 2000),
            "status": item["status"],
            "summary": _bounded_text(item.get("summary"), "test summary", 4000),
        })
    proof_gaps = raw.get("proofGaps") or []
    if not isinstance(proof_gaps, list) or len(proof_gaps) > 50:
        raise EngineError("invalid_remediation_verification", "proofGaps must be a bounded list.")
    receipt = {
        "documentType": "kiro-security-power.remediation-verification",
        "schemaVersion": "1.0",
        "agentSubmitted": True,
        "outcome": outcome,
        "originalIssueNoLongerReproduces": raw.get("originalIssueNoLongerReproduces") is True,
        "preservedBehavior": raw.get("preservedBehavior") is True,
        "securityValidation": {
            "status": security_status,
            "method": _bounded_text(security.get("method"), "security validation method", 2000),
            "rationale": _bounded_text(security.get("rationale"), "security validation rationale", 8000),
            "evidence": [_bounded_text(item, "security evidence", 4000) for item in security.get("evidence") or []],
        },
        "tests": normalized_tests,
        "proofGaps": [_bounded_text(item, "proof gap", 4000) for item in proof_gaps],
    }
    passes = (
        receipt["originalIssueNoLongerReproduces"]
        and receipt["preservedBehavior"]
        and security_status == "passed"
        and all(item["status"] == "passed" for item in normalized_tests)
        and not receipt["proofGaps"]
    )
    if outcome == "verified" and not passes:
        raise EngineError("remediation_verification_incomplete", "A remediation cannot be verified while a proof gate is incomplete.")
    return receipt
