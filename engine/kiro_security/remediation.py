from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from .errors import EngineError
from .scanner import _git_filter_overrides
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


def _file_mode(path: Path) -> str:
    return "100755" if path.stat().st_mode & stat.S_IXUSR else "100644"


def _digest_field(digest: Any, label: bytes, value: bytes) -> None:
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _directory_content_digest(root: Path, scope: str, excluded_relative: list[Path]) -> str:
    target = resolve_within(root, scope, must_exist=True)
    paths = [target] if not target.is_dir() else sorted(target.rglob("*"))
    digest = hashlib.sha256()
    _digest_field(digest, b"format", b"kiro-security-remediation-directory/v1")
    for path in paths:
        relative_path = path.relative_to(root)
        if any(
            relative_path == excluded_path or excluded_path in relative_path.parents
            for excluded_path in excluded_relative
        ):
            continue
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise EngineError("remediation_code_drift", f"Unable to read worktree path: {relative_path}") from exc
        _digest_field(digest, b"path", relative_path.as_posix().encode("utf-8", "surrogatepass"))
        _digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode("ascii"))
        if stat.S_ISLNK(metadata.st_mode):
            _digest_field(digest, b"kind", b"symlink")
            _digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISDIR(metadata.st_mode):
            _digest_field(digest, b"kind", b"directory")
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        size += len(chunk)
            except OSError as exc:
                raise EngineError("remediation_code_drift", f"Unable to read worktree file: {relative_path}") from exc
            _digest_field(digest, b"kind", b"file")
            _digest_field(digest, b"size", str(size).encode("ascii"))
            _digest_field(digest, b"content-sha256", content_digest.digest())
        else:
            raise EngineError("remediation_code_drift", f"Unsupported worktree file type: {relative_path}")
    return f"kiro-security-remediation-snapshot/v1:sha256:{digest.hexdigest()}"


def _gitlink_entries(workspace: Path, scope: str) -> dict[str, str]:
    staged = run_process(
        "git", ["ls-files", "--stage", "-z", "--", scope], cwd=workspace, check=False,
    )
    if staged.returncode != 0:
        raise EngineError("remediation_code_drift", "Unable to inspect Git submodules in the worktree.")
    entries = {}
    for record in (item for item in staged.stdout.split("\x00") if item):
        metadata, separator, relative = record.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise EngineError("remediation_code_drift", "Unable to inspect Git submodules in the worktree.")
        mode, object_id, stage = fields
        if mode != "160000":
            continue
        if stage != "0" or not re.fullmatch(r"[a-f0-9]{40,64}", object_id):
            raise EngineError("remediation_code_drift", "Unable to inspect Git submodules in the worktree.")
        entries[relative] = object_id
    return entries


def _digest_gitlink(digest: Any, path: Path, relative: str, expected_revision: str) -> None:
    _digest_field(digest, b"kind", b"gitlink")
    _digest_field(digest, b"expected-revision", expected_revision.encode("ascii"))
    try:
        (path / ".git").lstat()
    except FileNotFoundError:
        _digest_field(digest, b"state", b"uninitialized")
        return
    root = run_process("git", ["rev-parse", "--show-toplevel"], cwd=path, check=False)
    revision = run_process("git", ["rev-parse", "HEAD"], cwd=path, check=False)
    status = run_process(
        "git", [*_git_filter_overrides(path), "status", "--porcelain=v1", "-z", "--untracked-files=all",
                "--ignore-submodules=none"],
        cwd=path, check=False,
    )
    try:
        initialized = root.returncode == 0 and Path(root.stdout.strip()).resolve() == path.resolve()
    except OSError:
        initialized = False
    if (
        not initialized or revision.returncode != 0 or revision.stdout.strip() != expected_revision
        or status.returncode != 0 or status.stdout
    ):
        raise EngineError(
            "remediation_code_drift",
            f"Git submodule must be clean and match the revision recorded by its parent: {relative}",
        )
    _digest_field(digest, b"state", b"initialized")
    _digest_field(digest, b"revision", expected_revision.encode("ascii"))
    for nested_relative, nested_revision in sorted(_gitlink_entries(path, ".").items()):
        _digest_field(digest, b"nested-path", nested_relative.encode("utf-8", "surrogatepass"))
        _digest_gitlink(digest, path / nested_relative, f"{relative}/{nested_relative}", nested_revision)


def worktree_content_digest(
    workspace: Path, scope: str, *, excluded: tuple[Path, ...] = (),
) -> str:
    """Digest tracked and untracked worktree content without invoking Git filters."""
    root = workspace.resolve(strict=True)
    excluded_relative = []
    for path in excluded:
        try:
            excluded_relative.append(path.resolve().relative_to(root))
        except (OSError, ValueError):
            continue
    if current_git_revision(root) is None:
        return _directory_content_digest(root, scope, excluded_relative)
    listed = run_process(
        "git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--", scope],
        cwd=root,
    )
    gitlinks = _gitlink_entries(root, scope)
    digest = hashlib.sha256()
    _digest_field(digest, b"format", b"kiro-security-remediation-snapshot/v1")
    for relative in sorted(item for item in listed.stdout.split("\x00") if item):
        relative_path = Path(relative)
        if any(
            relative_path == excluded_path or excluded_path in relative_path.parents
            for excluded_path in excluded_relative
        ):
            continue
        path = root / relative_path
        _digest_field(digest, b"path", relative.encode("utf-8", "surrogatepass"))
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            if relative in gitlinks:
                _digest_gitlink(digest, path, relative, gitlinks[relative])
            else:
                _digest_field(digest, b"kind", b"missing")
            continue
        _digest_field(digest, b"mode", str(stat.S_IMODE(metadata.st_mode)).encode("ascii"))
        if stat.S_ISLNK(metadata.st_mode):
            _digest_field(digest, b"kind", b"symlink")
            _digest_field(digest, b"content", os.fsencode(os.readlink(path)))
        elif stat.S_ISREG(metadata.st_mode):
            content_digest = hashlib.sha256()
            size = 0
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        content_digest.update(chunk)
                        size += len(chunk)
            except OSError as exc:
                raise EngineError("remediation_code_drift", f"Unable to read worktree file: {relative}") from exc
            _digest_field(digest, b"kind", b"file")
            _digest_field(digest, b"size", str(size).encode("ascii"))
            _digest_field(digest, b"content-sha256", content_digest.digest())
        elif stat.S_ISDIR(metadata.st_mode):
            expected_revision = gitlinks.get(relative)
            if expected_revision is None:
                revision = run_process("git", ["rev-parse", "HEAD"], cwd=path, check=False)
                status = run_process(
                    "git", [*_git_filter_overrides(path), "status", "--porcelain=v1", "-z",
                            "--untracked-files=all", "--ignore-submodules=none"],
                    cwd=path, check=False,
                )
                if revision.returncode != 0 or status.returncode != 0 or status.stdout:
                    raise EngineError(
                        "remediation_code_drift", f"Worktree directory must be a clean Git checkout: {relative}",
                    )
                _digest_field(digest, b"kind", b"gitlink")
                _digest_field(digest, b"revision", revision.stdout.strip().encode("ascii"))
                _digest_field(digest, b"status", status.stdout.encode("utf-8", "surrogatepass"))
            else:
                _digest_gitlink(digest, path, relative, expected_revision)
        else:
            raise EngineError("remediation_code_drift", f"Unsupported worktree file type: {relative}")
    return f"kiro-security-remediation-snapshot/v1:sha256:{digest.hexdigest()}"


def verify_unmodified_files(workspace: Path, artifact_dir: Path, metadata: dict[str, Any]) -> None:
    expected = metadata.get("unmodifiedContentDigest")
    if not isinstance(expected, str) or not re.fullmatch(
        r"kiro-security-remediation-snapshot/v1:sha256:[a-f0-9]{64}", expected,
    ):
        raise EngineError("remediation_record_invalid", "Regenerate remediation metadata with a worktree snapshot.")
    touched = tuple(workspace / item["path"] for item in metadata.get("touchedFiles") or [])
    actual = worktree_content_digest(
        workspace, metadata.get("snapshotScope") or metadata.get("scope") or ".",
        excluded=(workspace / ".kiro" / "security-power", artifact_dir, *touched),
    )
    if actual != expected:
        raise EngineError("remediation_code_drift", "Files outside the approved remediation changed.")


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
    if revision != scan_revision:
        raise EngineError("remediation_code_drift", "The checkout revision no longer matches the finding scan revision.")
    touched = []
    for relative in paths:
        path = _safe_regular_file(workspace, relative)
        touched.append({"path": relative, "sha256": sha256_file(path), "mode": _file_mode(path)})
    unmodified_digest = worktree_content_digest(
        workspace, ".",
        excluded=(workspace / ".kiro" / "security-power", artifact_dir, *(workspace / item["path"] for item in touched)),
    )
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
        "scope": str(scan.get("scope") or "."),
        "snapshotScope": ".",
        "patchPlan": _bounded_text(plan, "plan", 12000),
        "verificationPlan": checks,
        "touchedFiles": touched,
        "unmodifiedContentDigest": unmodified_digest,
        "patchDigest": patch_digest,
    }
    path = resolve_within(artifact_dir, f"remediations/{record_id}/patch-{patch_digest}.patch")
    atomic_write(path, patch)
    run_process(
        "git", [*_git_filter_overrides(workspace), "apply", *(["--no-index"] if revision is None else []),
                "--check", "--whitespace=nowarn", str(path)],
        cwd=workspace,
    )
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
    verify_unmodified_files(workspace, artifact_dir, metadata)
    for item in metadata.get("touchedFiles") or []:
        source = _safe_regular_file(workspace, item["path"])
        if sha256_file(source) != item["sha256"] or (
            item.get("mode") is not None and _file_mode(source) != item["mode"]
        ):
            raise EngineError("remediation_code_drift", f"A touched file changed after patch preparation: {item['path']}")
    return metadata, path


def touched_file_digests(workspace: Path, metadata: dict[str, Any]) -> list[dict[str, str]]:
    digests = []
    for item in metadata.get("touchedFiles") or []:
        source = _safe_regular_file(workspace, item["path"])
        digest = {"path": item["path"], "sha256": sha256_file(source)}
        if item.get("mode") is not None:
            digest["mode"] = _file_mode(source)
        digests.append(digest)
    return digests


def _materialized_patch_digests(
    workspace: Path, metadata: dict[str, Any], patch_bytes: bytes, *, reverse: bool = False,
) -> list[dict[str, str]]:
    with tempfile.TemporaryDirectory(prefix="kiro-remediation-") as temporary:
        root = Path(temporary).resolve()
        for item in metadata.get("touchedFiles") or []:
            destination = root / item["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(_safe_regular_file(workspace, item["path"]), destination)
        if not reverse and touched_file_digests(root, metadata) != (metadata.get("touchedFiles") or []):
            raise EngineError("remediation_code_drift", "A touched file changed while the approved postimage was prepared.")
        attribute_paths = {Path(".gitattributes")}
        for item in metadata.get("touchedFiles") or []:
            parent = Path(item["path"]).parent
            while parent != Path("."):
                attribute_paths.add(parent / ".gitattributes")
                parent = parent.parent
        for relative in sorted(attribute_paths):
            source = workspace / relative
            if not source.exists() and not source.is_symlink():
                continue
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_safe_regular_file(workspace, relative.as_posix()), destination)
        if metadata.get("baseRevision") is None:
            args = [*_git_filter_overrides(workspace), "apply", "--no-index"]
        else:
            git_dir = run_process("git", ["rev-parse", "--absolute-git-dir"], cwd=workspace).stdout.strip()
            args = [*_git_filter_overrides(workspace), f"--git-dir={git_dir}", f"--work-tree={root}", "apply"]
        if reverse:
            args.append("--reverse")
        run_process("git", [*args, "--whitespace=nowarn", "-"], cwd=root, input_bytes=patch_bytes)
        return touched_file_digests(root, metadata)


def expected_post_apply_digests(
    workspace: Path, metadata: dict[str, Any], patch_bytes: bytes
) -> list[dict[str, str]]:
    """Materialize the approved postimage away from the live workspace."""
    return _materialized_patch_digests(workspace, metadata, patch_bytes)


def reconcile_patch_application(
    workspace: Path, patch_path: Path, metadata: dict[str, Any], expected_patch_digest: str,
) -> tuple[str, list[dict[str, str]]]:
    """Classify a journaled apply without trusting process-local completion state."""
    current = touched_file_digests(workspace, metadata)
    before = metadata.get("touchedFiles") or []
    if current == before:
        return "not_applied", current
    try:
        with patch_path.open("rb") as handle:
            patch_bytes = handle.read(MAX_PATCH_BYTES + 1)
        if len(patch_bytes) > MAX_PATCH_BYTES or hashlib.sha256(patch_bytes).hexdigest() != expected_patch_digest:
            return "ambiguous", current
        recovered = _materialized_patch_digests(workspace, metadata, patch_bytes, reverse=True)
    except (EngineError, OSError):
        return "ambiguous", current
    if recovered == before:
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
