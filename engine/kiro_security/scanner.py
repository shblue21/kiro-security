from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from .constants import DEFAULT_IGNORES, SOURCE_EXTENSIONS
from .errors import CancelledScan, EngineError, InterruptedScan
from .security import require_git_ref, resolve_within, run_process, sha256_bytes


@dataclass
class SourceFile:
    path: Path
    relative_path: str
    text: str
    language: str
    size: int
    changed: bool = True
    surface: str | None = None
    runtime_relevance: str | None = None
    deployment_significance: str | None = None
    ranking_reason: str | None = None

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class Inventory:
    files: list[SourceFile]
    include_paths: list[str]
    exclude_paths: list[str]
    deferred: list[dict[str, Any]]
    revision: str | None
    snapshot_digest: str
    git_available: bool
    diff_summary: str | None = None
    diff_context: dict[str, Any] | None = None
    warnings: list[str] = field(default_factory=list)


_LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescriptreact", ".jsx": "javascriptreact", ".java": "java", ".go": "go",
    ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".sh": "shellscript",
    ".bash": "shellscript", ".zsh": "shellscript", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
}


def language_for(path: Path) -> str:
    return _LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "text")


def _security_surface(relative: str) -> dict[str, Any] | None:
    path = PurePosixPath(relative)
    parts = tuple(part.lower() for part in path.parts)
    name = path.name.lower()
    suffix = path.suffix.lower()
    config_suffixes = {".json", ".yaml", ".yml", ".xml"}

    def surface(
        name: str,
        language: str,
        relevance: str,
        ranking_reason: str,
        *,
        deployment: str | None = None,
        priority: int = 0,
    ) -> dict[str, Any]:
        return {
            "surface": name,
            "language": language,
            "runtimeRelevance": relevance,
            "deploymentSignificance": deployment,
            "rankingReason": ranking_reason,
            "priority": priority,
        }

    if name in {"dockerfile", "containerfile"} or name.startswith(("dockerfile.", "containerfile.")):
        return surface(
            "deployment_review:container", "dockerfile",
            "Recognized container build artifact selected for security review.",
            "Matched a canonical Dockerfile or Containerfile name; content semantics are not assumed.",
            deployment="Defines a container build input.",
        )
    if suffix in {".yaml", ".yml"} and (
        name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
        or name.startswith(("docker-compose.", "compose."))
    ):
        return surface(
            "deployment_review:container", "yaml",
            "Recognized container composition artifact selected for security review.",
            "Matched a canonical container composition filename; content semantics are not assumed.",
            deployment="Defines container composition input.",
        )
    if suffix in {".tf", ".tfvars"} or name.endswith(".tf.json"):
        return surface(
            "deployment_review:infrastructure_as_code", "terraform",
            "Recognized Terraform artifact selected for security review.",
            "Matched a Terraform file extension; resource security properties remain unconfirmed.",
            deployment="Defines infrastructure-as-code input.",
        )
    if suffix in config_suffixes and (
        name.startswith(("cloudformation", "template.", "sam-template", "serverless."))
        or any(part in {"cloudformation", "sam", "serverless"} for part in parts[:-1])
    ):
        return surface(
            "deployment_review:cloud_template", "yaml" if suffix in {".yaml", ".yml"} else suffix[1:],
            "Recognized cloud deployment template selected for security review.",
            "Matched a bounded cloud-template path rule; deployed resources remain unconfirmed.",
            deployment="Defines cloud deployment input.",
        )
    if suffix in {".yaml", ".yml"} and (
        name == "chart.yaml" or any(part in {"k8s", "kubernetes", "helm", "charts", "manifests"} for part in parts[:-1])
    ):
        return surface(
            "deployment_review:orchestration", "yaml",
            "Recognized Kubernetes or Helm path selected for security review.",
            "Matched a Kubernetes, Helm, chart, or manifest path; runtime reachability remains unconfirmed.",
            deployment="Defines an orchestration or packaging input.",
        )
    if (
        suffix in {".yaml", ".yml"}
        and len(parts) >= 3 and parts[0:2] == (".github", "workflows")
    ) or name in {".gitlab-ci.yml", ".gitlab-ci.yaml"}:
        return surface(
            "workflow_review:ci", "yaml",
            "Recognized CI workflow selected for security review.",
            "Matched a GitHub Actions or GitLab CI path; job permissions and execution remain unconfirmed.",
            deployment="Defines continuous-integration workflow input.",
        )
    dependency_manifests = {
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
        "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock", "pom.xml", "build.gradle",
        "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "gradle.properties", "gradle.lockfile",
        "cargo.toml", "cargo.lock", "go.mod", "go.sum",
    }
    if name in dependency_manifests or (name.startswith("requirements") and suffix in {".txt", ".in"}):
        is_lock = name.endswith(".lock") or name in {
            "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
            "pipfile.lock", "gradle.lockfile", "cargo.lock", "go.sum",
        }
        return surface(
            f"dependency_review:{'lockfile' if is_lock else 'manifest'}",
            {
                ".json": "json", ".yaml": "yaml", ".yml": "yaml", ".xml": "xml",
                ".toml": "toml", ".kts": "kotlin", ".gradle": "gradle",
            }.get(suffix, "text"),
            "Recognized dependency manifest or lockfile selected for security review.",
            "Matched a canonical package manifest or lockfile name; dependency risk is not inferred.",
            priority=1,
        )
    if suffix == ".sql" and (
        name == "schema.sql" or any(part in {"migration", "migrations", "migrate"} for part in parts[:-1])
    ):
        return surface(
            "data_review:migration", "sql",
            "Recognized database schema or migration artifact selected for security review.",
            "Matched a schema or migration path; execution and privilege context remain unconfirmed.",
            deployment="Defines a database change input.",
            priority=1,
        )
    if name in {"nginx.conf", "httpd.conf", "apache2.conf", ".htaccess"} or (
        suffix == ".conf" and any(part in {"nginx", "apache", "apache2", "httpd"} for part in parts[:-1])
    ):
        return surface(
            "deployment_review:web_server", "configuration",
            "Recognized web-server configuration selected for security review.",
            "Matched a canonical nginx or Apache configuration path; effective runtime settings remain unconfirmed.",
            deployment="Defines web-server configuration input.",
        )
    if suffix in config_suffixes and (
        any(part == "iam" for part in parts[:-1])
        or any(token in name for token in ("iam-policy", "trust-policy", "assume-role-policy"))
    ):
        return surface(
            "authorization_review:iam_policy", "yaml" if suffix in {".yaml", ".yml"} else suffix[1:],
            "Recognized IAM policy artifact selected for security review.",
            "Matched an IAM-specific path or filename; granted privileges remain unconfirmed.",
            deployment="Defines an authorization policy input.",
        )
    if re.fullmatch(r"\.?env(?:\.[a-z0-9_-]+)*\.(?:example|sample|template)", name):
        return surface(
            "configuration_review:environment_template", "dotenv",
            "Recognized environment configuration template selected for security review.",
            "Matched an environment-template filename; no value is assumed to be a live secret.",
            priority=1,
        )
    if suffix == ".proto":
        return surface(
            "interface_review:protobuf", "protobuf",
            "Recognized Protocol Buffers interface definition selected for security review.",
            "Matched a .proto interface definition; exposure and authorization remain unconfirmed.",
            priority=1,
        )
    if suffix in {".json", ".yaml", ".yml"} and any(token in name for token in ("openapi", "swagger")):
        return surface(
            "interface_review:openapi", "yaml" if suffix in {".yaml", ".yml"} else "json",
            "Recognized OpenAPI or Swagger contract selected for security review.",
            "Matched an OpenAPI or Swagger filename; endpoint deployment remains unconfirmed.",
            priority=1,
        )
    if suffix in config_suffixes and (
        any(part in {"config", "configs", "configuration", "settings", "deploy", "deployment", "infra", "infrastructure"} for part in parts[:-1])
        or name in {"application.yml", "application.yaml", "appsettings.json", "config.yml", "config.yaml", "settings.json", "web.config", "web.xml"}
    ):
        return surface(
            "configuration_review:runtime", "yaml" if suffix in {".yaml", ".yml"} else suffix[1:],
            "Recognized runtime or deployment configuration path selected for security review.",
            "Matched a bounded configuration path rule; effective runtime use remains unconfirmed.",
            priority=1,
        )
    return None


def _inventory_priority(relative: str) -> tuple[int, str]:
    surface = _security_surface(relative)
    if surface:
        return int(surface["priority"]), relative
    path = PurePosixPath(relative)
    if path.suffix.lower() in SOURCE_EXTENSIONS:
        secondary = any(part.lower() in {"test", "tests", "spec", "specs", "fixtures", "examples", "demo", "demos"} for part in path.parts[:-1])
        return (3 if secondary else 2), relative
    return 4, relative


def _is_probably_text(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return False
    return True


def _read_source(path: Path, max_bytes: int) -> tuple[str, int] | None:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if not _is_probably_text(data):
        return None
    try:
        return data.decode("utf-8"), size
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), size


def _read_security_surface(path: Path, max_bytes: int) -> tuple[str | None, int, bytes] | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        if len(data) > max_bytes:
            return None
    except OSError:
        return None
    size = len(data)
    if not _is_probably_text(data):
        return None, size, data
    try:
        return data.decode("utf-8"), size, data
    except UnicodeDecodeError:
        return None, size, data


def _git_revision(workspace: Path) -> tuple[bool, str | None]:
    try:
        result = run_process("git", ["rev-parse", "HEAD"], cwd=workspace, timeout=10)
        return True, result.stdout.strip() or None
    except EngineError:
        return False, None


def _require_checked_out_diff_head(workspace: Path, kind: str, head: str | None, revision: str | None) -> None:
    if kind not in ("commit", "range") or not head:
        return
    target = run_process(
        "git", ["rev-parse", "--verify", f"{require_git_ref(head, 'diffHeadRevision')}^{{commit}}"],
        cwd=workspace, timeout=10,
    ).stdout.strip()
    if not revision or target != revision:
        raise EngineError(
            "diff_target_not_checked_out",
            "Commit and range Diff scans require diffHeadRevision to match the checked-out HEAD.",
            {"checkedOutRevision": revision, "diffHeadRevision": target},
        )


def _require_clean_diff_paths(workspace: Path, scope: str, kind: str, changed: DiffPaths) -> None:
    if kind not in ("commit", "range"):
        return
    dirty = _diff_name_only(workspace, ["diff", "--name-only", "-z", "HEAD", "--", scope])
    dirty |= _diff_name_only(workspace, ["ls-files", "--others", "--exclude-standard", "-z", "--", scope])
    overlap = sorted(dirty & changed.existing)
    if overlap:
        raise EngineError(
            "diff_target_worktree_changed",
            "Commit and range Diff source files must match the checked-out target revision.",
            {"paths": overlap[:20]},
        )


def _parse_nul_paths(output: str) -> list[str]:
    return [entry for entry in output.split("\x00") if entry]


@dataclass
class DiffPaths:
    existing: set[str]
    deleted: set[str]


def _diff_name_only(workspace: Path, args: list[str]) -> set[str]:
    # --no-renames keeps a rename as an explicit add + delete pair so the
    # rename source is never silently dropped from the coverage frontier.
    result = run_process("git", args, cwd=workspace)
    return set(_parse_nul_paths(result.stdout))


def _diff_paths(
    workspace: Path,
    scope: str,
    kind: str,
    base: str | None,
    head: str | None,
) -> tuple[DiffPaths, str]:
    scope_args = ["--", scope]
    if kind == "working_tree":
        existing = _diff_name_only(
            workspace,
            ["diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRTUXB", "HEAD", *scope_args],
        )
        existing |= _diff_name_only(workspace, ["ls-files", "--others", "--exclude-standard", "-z", *scope_args])
        deleted = _diff_name_only(
            workspace,
            ["diff", "--name-only", "-z", "--no-renames", "--diff-filter=D", "HEAD", *scope_args],
        )
        return DiffPaths(existing=existing - deleted, deleted=deleted), "working tree compared with HEAD"
    if kind == "commit":
        if not head:
            raise EngineError("invalid_diff_target", "Commit diff requires diffHeadRevision.")
        head = require_git_ref(head, "diffHeadRevision")
        common = ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--no-renames"]
        existing = _diff_name_only(workspace, [*common, "--diff-filter=ACMRTUXB", head, *scope_args])
        deleted = _diff_name_only(workspace, [*common, "--diff-filter=D", head, *scope_args])
        return DiffPaths(existing=existing - deleted, deleted=deleted), f"commit {head}"
    if kind == "range":
        if not base or not head:
            raise EngineError("invalid_diff_target", "Range diff requires diffBaseRevision and diffHeadRevision.")
        base = require_git_ref(base, "diffBaseRevision")
        head = require_git_ref(head, "diffHeadRevision")
        common = ["diff", "--name-only", "-z", "--no-renames"]
        existing = _diff_name_only(workspace, [*common, "--diff-filter=ACMRTUXB", f"{base}...{head}", *scope_args])
        deleted = _diff_name_only(workspace, [*common, "--diff-filter=D", f"{base}...{head}", *scope_args])
        return DiffPaths(existing=existing - deleted, deleted=deleted), f"range {base}...{head}"
    raise EngineError("invalid_diff_target", f"Unsupported diff target kind: {kind}")


def _diff_patch(workspace: Path, scope: str, kind: str, base: str | None, head: str | None) -> str:
    common = ["--no-ext-diff", "--no-textconv", "--find-renames", "--unified=40"]
    if kind == "working_tree":
        args = ["diff", *common, "HEAD", "--", scope]
    elif kind == "commit":
        if not head:
            raise EngineError("invalid_diff_target", "Commit diff requires diffHeadRevision.")
        args = ["show", "--format=", *common, require_git_ref(head, "diffHeadRevision"), "--", scope]
    elif kind == "range":
        if not base or not head:
            raise EngineError("invalid_diff_target", "Range diff requires diffBaseRevision and diffHeadRevision.")
        target = f"{require_git_ref(base, 'diffBaseRevision')}...{require_git_ref(head, 'diffHeadRevision')}"
        args = ["diff", *common, target, "--", scope]
    else:
        raise EngineError("invalid_diff_target", f"Unsupported diff target kind: {kind}")
    output = run_process("git", args, cwd=workspace).stdout
    data = output.encode("utf-8", "surrogatepass")
    if len(data) > 600_000:
        raise EngineError("diff_context_too_large", "The bounded Git patch exceeds 600000 bytes; narrow the Diff scope.")
    return output


def _diff_context(
    workspace: Path,
    scope: str,
    kind: str,
    base: str | None,
    head: str | None,
    changed: DiffPaths,
    max_file_bytes: int,
) -> dict[str, Any]:
    patch = _diff_patch(workspace, scope, kind, base, head)
    if kind == "working_tree":
        untracked = _diff_name_only(workspace, ["ls-files", "--others", "--exclude-standard", "-z", "--", scope])
        additions = []
        for relative in sorted(untracked):
            loaded = _read_source(workspace / relative, max_file_bytes)
            if loaded is None:
                continue
            text, _ = loaded
            lines = text.splitlines()
            additions.extend([
                f"diff --git a/{relative} b/{relative}", "new file mode 100644", "--- /dev/null",
                f"+++ b/{relative}", f"@@ -0,0 +1,{len(lines)} @@", *[f"+{line}" for line in lines],
            ])
        if additions:
            patch += ("\n" if patch and not patch.endswith("\n") else "") + "\n".join(additions) + "\n"
        if len(patch.encode("utf-8", "surrogatepass")) > 600_000:
            raise EngineError("diff_context_too_large", "The bounded Git patch exceeds 600000 bytes; narrow the Diff scope.")
    siblings = _diff_supporting_paths(
        workspace, changed.existing, changed.deleted, max_file_bytes,
    )
    rename_hints = []
    for line in patch.splitlines():
        if line.startswith("rename from "):
            rename_hints.append({"from": line[len("rename from "):], "to": None})
        elif line.startswith("rename to ") and rename_hints and rename_hints[-1]["to"] is None:
            rename_hints[-1]["to"] = line[len("rename to "):]
    payload = {
        "documentType": "kiro-security-power.diff-context",
        "schemaVersion": "1.0",
        "target": {"kind": kind, "baseRevision": base, "headRevision": head, "scope": scope},
        "changedPaths": sorted(changed.existing),
        "deletedPaths": sorted(changed.deleted),
        "renameHints": rename_hints[:200],
        "supportingPaths": siblings,
        "patch": patch,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    payload["contextDigest"] = "sha256:" + sha256_bytes(encoded.encode("utf-8"))
    return payload


def _diff_supporting_paths(
    workspace: Path,
    changed_paths: Iterable[str],
    deleted_paths: Iterable[str],
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    workspace = workspace.resolve()
    siblings: list[dict[str, Any]] = []
    changed = set(changed_paths)
    seen = changed | set(deleted_paths)
    for relative in sorted(changed):
        parent = (workspace / relative).parent
        try:
            candidates = sorted(parent.iterdir())
        except OSError:
            continue
        for candidate in candidates:
            if len(siblings) >= 200:
                break
            try:
                sibling = candidate.relative_to(workspace).as_posix()
                resolved = candidate.resolve(strict=True)
            except ValueError:
                continue
            except OSError:
                continue
            if (
                sibling in seen or candidate.is_symlink() or workspace.resolve() not in resolved.parents
                or not candidate.is_file() or candidate.suffix.lower() not in SOURCE_EXTENSIONS
            ):
                continue
            loaded = _read_security_surface(candidate, max_file_bytes)
            if loaded is None or loaded[0] is None:
                continue
            _, _, data = loaded
            siblings.append({
                "path": sibling,
                "relationship": "same-directory source sibling; caller relationship is unconfirmed",
                "contentDigest": "sha256:" + sha256_bytes(data),
            })
            seen.add(sibling)
    return siblings


def _default_ignored(relative: str) -> bool:
    return any(part in DEFAULT_IGNORES for part in PurePosixPath(relative).parts)


def build_inventory(
    workspace: Path,
    *,
    mode: str,
    scope: str,
    diff_target_kind: str | None,
    diff_base_revision: str | None,
    diff_head_revision: str | None,
    max_files: int,
    max_file_bytes: int,
    include_security_surfaces: bool | None = None,
) -> Inventory:
    scope_path = resolve_within(workspace, scope, must_exist=True)
    git_available, revision = _git_revision(workspace)
    changed_paths: DiffPaths | None = None
    diff_summary: str | None = None
    if mode == "diff":
        if not git_available:
            raise EngineError("git_required", "Diff scans require a Git worktree with a resolvable HEAD.")
        _require_checked_out_diff_head(
            workspace, diff_target_kind or "working_tree", diff_head_revision, revision
        )
        changed_paths, diff_summary = _diff_paths(
            workspace,
            scope,
            diff_target_kind or "working_tree",
            diff_base_revision,
            diff_head_revision,
        )
        _require_clean_diff_paths(workspace, scope, diff_target_kind or "working_tree", changed_paths)
    include_surfaces = mode == "deep" if include_security_surfaces is None else include_security_surfaces

    candidates: Iterable[Path]
    if scope_path.is_file():
        candidates = [scope_path]
    else:
        candidates = sorted(
            (path for path in scope_path.rglob("*") if path.is_file()),
            key=lambda path: _inventory_priority(path.relative_to(workspace).as_posix()),
        )

    files: list[SourceFile] = []
    excluded: list[str] = []
    deferred: list[dict[str, Any]] = []
    inventoried: set[str] = set()
    truncated = False
    digest = hashlib.sha256()
    for path in candidates:
        try:
            relative = path.relative_to(workspace).as_posix()
        except ValueError:
            excluded.append(str(path))
            continue
        if _default_ignored(relative):
            continue
        if changed_paths is not None and relative not in changed_paths.existing:
            continue
        inventoried.add(relative)
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            deferred.append({
                "id": relative,
                "path": relative,
                "kind": "unreadable_path",
                "surface": "unreadable_file",
                "reason": "The in-scope path could not be resolved and was not reviewed.",
            })
            continue
        if resolved != workspace and workspace not in resolved.parents:
            excluded.append(relative)
            continue
        security_surface = _security_surface(relative)
        if security_surface:
            loaded_surface = _read_security_surface(resolved, max_file_bytes)
            if loaded_surface is None:
                try:
                    stat = resolved.stat()
                    digest.update(relative.encode("utf-8", "surrogatepass"))
                    digest.update(b"\0unreadable-security-surface\0")
                    digest.update(f"{stat.st_size}:{stat.st_mtime_ns}".encode("ascii"))
                except OSError:
                    pass
                deferred.append({
                    "id": relative,
                    "path": relative,
                    "kind": "unreadable_or_oversized_security_surface",
                    "surface": security_surface["surface"],
                    "reason": f"The recognized security surface was unreadable or larger than {max_file_bytes} bytes and was not reviewed.",
                })
                continue
            text, size, data = loaded_surface
            digest.update(relative.encode("utf-8", "surrogatepass"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(data).digest())
            if text is None:
                deferred.append({
                    "id": relative,
                    "path": relative,
                    "kind": "invalid_security_surface_text",
                    "surface": security_surface["surface"],
                    "reason": "The recognized security surface was binary or invalid UTF-8 and was not reviewed.",
                })
                continue
            if not include_surfaces:
                deferred.append({
                    "id": relative,
                    "path": relative,
                    "kind": "security_surface_unreviewed",
                    "surface": security_surface["surface"],
                    "language": security_surface["language"],
                    "runtimeRelevance": security_surface["runtimeRelevance"],
                    "reason": "The security-relevant repository surface is inventoried, but the deterministic scanner has no authoritative review receipt for it.",
                })
                continue
            if len(files) >= max_files:
                truncated = True
                deferred.append({
                    "id": "file-limit",
                    "path": scope,
                    "kind": "file_limit",
                    "surface": "inventory_limit",
                    "reason": f"The maximum supported-file count {max_files} was reached; remaining in-scope files were not reviewed.",
                })
                break
            files.append(SourceFile(
                resolved,
                relative,
                text,
                security_surface["language"],
                size,
                changed_paths is None or relative in changed_paths.existing,
                security_surface["surface"],
                security_surface["runtimeRelevance"],
                security_surface["deploymentSignificance"],
                security_surface["rankingReason"],
            ))
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            try:
                stat = resolved.stat()
                digest.update(relative.encode("utf-8", "surrogatepass"))
                digest.update(b"\0unsupported\0")
                digest.update(f"{stat.st_size}:{stat.st_mtime_ns}".encode("ascii"))
            except OSError:
                pass
            deferred.append({
                "id": relative,
                "path": relative,
                "kind": "unsupported_file",
                "surface": "unsupported_file",
                "reason": f"Unsupported in-scope file type {path.suffix or '<no extension>'}; the file was not reviewed.",
            })
            continue
        loaded = _read_source(resolved, max_file_bytes)
        if loaded is None:
            deferred.append({
                "id": relative,
                "path": relative,
                "kind": "unreadable_or_oversized",
                "surface": "unreadable_or_oversized_source",
                "reason": f"The in-scope source was binary, unreadable, or larger than {max_file_bytes} bytes and was not reviewed.",
            })
            continue
        text, size = loaded
        digest.update(relative.encode("utf-8", "surrogatepass"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(text.encode("utf-8", "surrogatepass")).digest())
        if len(files) >= max_files:
            truncated = True
            deferred.append({
                "id": "file-limit",
                "path": scope,
                "kind": "file_limit",
                "surface": "inventory_limit",
                "reason": f"The maximum supported-file count {max_files} was reached; remaining in-scope files were not reviewed.",
            })
            break
        files.append(SourceFile(resolved, relative, text, language_for(path), size, changed_paths is None or relative in changed_paths.existing))
    if changed_paths is not None:
        # Deleted changed paths never appear in the filesystem walk, but their
        # base-revision contents were part of the change and were not reviewed.
        # They must stay on the coverage frontier as explicit deferred rows.
        for relative in sorted(changed_paths.deleted):
            if _default_ignored(relative):
                continue
            digest.update(relative.encode("utf-8", "surrogatepass"))
            digest.update(b"\0deleted\0")
            deferred.append({
                "id": relative,
                "path": relative,
                "kind": "deleted_file",
                "surface": "deleted_file",
                "reason": "The changed path was deleted and its base-revision contents were not reviewed.",
            })
        if not truncated:
            # Reconciliation: any Git-reported changed path that produced no
            # inventory outcome (deleted between diff and walk, unreadable
            # parents, etc.) must not vanish silently from the frontier.
            missing = {
                relative for relative in changed_paths.existing if not _default_ignored(relative)
            } - inventoried
            for relative in sorted(missing):
                digest.update(relative.encode("utf-8", "surrogatepass"))
                digest.update(b"\0missing\0")
                deferred.append({
                    "id": relative,
                    "path": relative,
                    "kind": "missing_changed_path",
                    "surface": "missing_changed_path",
                    "reason": "The Git-reported changed path was not present in the filesystem inventory and was not reviewed.",
                })
    files.sort(key=lambda item: item.relative_path)
    diff_context = (
        _diff_context(
            workspace, scope, diff_target_kind or "working_tree", diff_base_revision,
            diff_head_revision, changed_paths, max_file_bytes,
        )
        if changed_paths is not None else None
    )
    return Inventory(
        files=files,
        include_paths=[scope],
        exclude_paths=sorted(set(excluded)),
        deferred=deferred,
        revision=revision,
        snapshot_digest=f"kiro-security-snapshot/v1:sha256:{digest.hexdigest()}",
        git_available=git_available,
        diff_summary=diff_summary,
        diff_context=diff_context,
        warnings=[] if files else ["No supported source files were found in the selected scope."],
    )


_SOURCE_ASSIGNMENTS = [
    re.compile(r"\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:request\.(?:args|form|json|values|headers)|input\s*\(|sys\.argv|os\.environ)"),
    re.compile(r"\b(?:const|let|var)\s+(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:req\.(?:params|query|body|headers)|request\.(?:json|formData)\s*\(|process\.argv|new URLSearchParams)"),
    re.compile(r"\$(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)"),
]
_DIRECT_SOURCE = re.compile(
    r"request\.(?:args|form|json|values|headers)|req\.(?:params|query|body|headers)|\$_(?:GET|POST|REQUEST|COOKIE)|input\s*\(|sys\.argv|process\.argv|URLSearchParams",
    re.IGNORECASE,
)
_SECRET_LITERAL = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*['\"](?P<value>[A-Za-z0-9_\-+/=]{16,})['\"]"
)
_IDENTITY_STRING_LITERAL = re.compile(r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)''')
_IDENTITY_NUMBER = re.compile(r"(?<![A-Za-z0-9_])(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)(?![A-Za-z0-9_])")
_IDENTITY_SCOPE = re.compile(
    r"^\s*(?:(?:(?:async\s+)?def|class|function)\s+(?P<named>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"|(?:const|let|var)\s+(?P<assigned>[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*:\s*[^=;\n]+)?\s*=\s*"
    r"(?:async\s+)?(?:function\b|\([^\n)]*\)\s*=>))"
)


def _source_variables(lines: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for index, line in enumerate(lines, start=1):
        for pattern in _SOURCE_ASSIGNMENTS:
            match = pattern.search(line)
            if match:
                result[match.group("var").lstrip("$")] = index
    return result


def _used_tainted_variable(text: str, sources: dict[str, int], sink_line: int) -> tuple[str | None, int | None]:
    if _DIRECT_SOURCE.search(text):
        return "direct_input", sink_line
    for variable, source_line in sources.items():
        if source_line <= sink_line and sink_line - source_line <= 120 and re.search(rf"(?<![A-Za-z0-9_$])\$?{re.escape(variable)}(?![A-Za-z0-9_$])", text):
            return variable, source_line
    return None, None


def _context(lines: list[str], line: int, before: int = 3, after: int = 3) -> tuple[int, int, str]:
    start = max(1, line - before)
    end = min(len(lines), line + after)
    return start, end, "\n".join(lines[start - 1 : end])


def _evidence(source_file: SourceFile, line: int, role: str, explanation: str) -> dict[str, Any]:
    start, end, snippet = _context(source_file.lines, line)
    return {
        "kind": "code",
        "label": f"{role.capitalize()} evidence",
        "path": source_file.relative_path,
        "startLine": start,
        "endLine": end,
        "language": source_file.language,
        "role": role,
        "code": snippet,
        "explanation": explanation,
    }


def _identity_fragment(value: str) -> str:
    redacted = _IDENTITY_STRING_LITERAL.sub("<string>", value)
    redacted = _IDENTITY_NUMBER.sub("<number>", redacted)
    redacted = re.sub(r"\s+(?://|#).*$", "", redacted)
    return " ".join(redacted.split())


def _identity_scopes(lines: list[str]) -> list[tuple[tuple[str, ...], tuple[int, ...]]]:
    stack: list[tuple[int, str, int]] = []
    result = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped and not stripped.startswith(("#", "//", "*")):
            indent = len(line) - len(line.lstrip())
            match = _IDENTITY_SCOPE.match(line)
            while stack and indent <= stack[-1][0]:
                stack.pop()
            if match:
                stack.append((indent, match.group("named") or match.group("assigned"), index))
        result.append((tuple(item[1] for item in stack), tuple(item[2] for item in stack)))
    return result


def _semantic_instance(source_file: SourceFile, sink_line: int, details: dict[str, Any]) -> str:
    statement = _identity_fragment(source_file.lines[sink_line - 1])
    scopes = _identity_scopes(source_file.lines)
    scope_names, scope_starts = scopes[sink_line - 1]
    ordinal = sum(
        1
        for index, line in enumerate(source_file.lines[:sink_line])
        if scopes[index][1] == scope_starts and _identity_fragment(line) == statement
    )
    target = _identity_fragment(str(details.get("sink") or details.get("route") or ""))
    encoded = json.dumps(
        {"language": source_file.language, "scope": scope_names or ("module",), "statement": statement, "target": target, "ordinal": ordinal},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"semantic:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()[:32]}"


def _candidate(
    source_file: SourceFile,
    *,
    rule_id: str,
    anchor: str,
    title: str,
    summary: str,
    category: str,
    cwe: list[str],
    severity: str,
    score: float,
    confidence: str,
    confidence_rationale: str,
    remediation: str,
    sink_line: int,
    source_line: int | None = None,
    source_label: str | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    candidate_details = details or {}
    instance = _semantic_instance(source_file, sink_line, candidate_details)
    primary = f"{rule_id}:{anchor}:{instance}"
    fingerprint_digest = hashlib.sha256(primary.encode("utf-8", "surrogatepass")).hexdigest()
    locations: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    if source_line is not None:
        locations.append({"path": source_file.relative_path, "startLine": source_line, "endLine": source_line, "role": "source"})
        evidence.append(_evidence(source_file, source_line, "source", source_label or "Attacker-controlled or externally controlled input enters the data flow here."))
    locations.append({"path": source_file.relative_path, "startLine": sink_line, "endLine": sink_line, "role": "sink"})
    evidence.append(_evidence(source_file, sink_line, "sink", summary))
    return {
        "fingerprint": f"kiro-security/v1:sha256:{fingerprint_digest}",
        "ruleId": rule_id,
        "identity": {"anchor": anchor, "instance": instance},
        "title": title,
        "summary": summary,
        "severity": {
            "level": severity,
            "score": score,
            "scoringSystem": "KiroSecurity:1.0",
            "rationale": f"Static analysis identified the {category} sink at {source_file.relative_path}:{sink_line}.",
        },
        "confidence": {"level": confidence, "rationale": confidence_rationale},
        "taxonomy": {"category": category, "cwe": cwe},
        "locations": locations,
        "remediation": remediation,
        "codeEvidence": evidence,
        "details": candidate_details,
    }


def scan_source_file(source_file: SourceFile, pass_name: str = "all") -> list[dict[str, Any]]:
    lines = source_file.lines
    sources = _source_variables(lines)
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()

    def add(candidate: dict[str, Any], sink_line: int) -> None:
        key = (candidate["ruleId"], sink_line)
        if key not in seen:
            findings.append(candidate)
            seen.add(key)

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "*")):
            continue
        local_context = "\n".join(lines[max(0, index - 4) : min(len(lines), index + 4)])

        if pass_name in ("all", "dataflow"):
            command_sink = None
            if re.search(r"\bos\.system\s*\(", line):
                command_sink = "os.system"
            elif re.search(r"\bsubprocess\.(?:Popen|run|call|check_call|check_output)\s*\(", line) and re.search(r"shell\s*=\s*True", local_context):
                command_sink = "subprocess shell=True"
            elif re.search(r"\b(?:child_process\.)?(?:exec|execSync)\s*\(", line) or re.search(r"\bexec\s*\(", line) and source_file.language in ("javascript", "typescript", "javascriptreact", "typescriptreact"):
                command_sink = "shell command execution"
            elif source_file.language == "shellscript" and re.search(r"\beval\b", line):
                command_sink = "shell eval"
            if command_sink:
                variable, source_line = _used_tainted_variable(local_context, sources, index)
                literal_only = bool(re.search(r"(?:os\.system|exec|execSync)\s*\(\s*['\"][^'\"]+['\"]\s*\)", line))
                if variable or not literal_only:
                    add(
                        _candidate(
                            source_file,
                            rule_id="command-injection.shell-execution",
                            anchor="attacker-input-to-shell-command",
                            title="Externally controlled data can reach shell command execution",
                            summary=f"Input reaches {command_sink} without a demonstrable argument-array boundary or shell escaping.",
                            category="command-injection",
                            cwe=["CWE-78"],
                            severity="critical" if variable else "high",
                            score=9.1 if variable else 8.0,
                            confidence="high" if variable else "medium",
                            confidence_rationale="A bounded local data-flow trace connects external input to a shell-capable API." if variable else "A shell-capable API receives a non-literal expression that requires review.",
                            remediation="Avoid a shell. Invoke the executable with a fixed argument array and validate each untrusted argument against an allowlist.",
                            sink_line=index,
                            source_line=source_line,
                            source_label=f"The variable {variable!r} is derived from external input." if variable else None,
                            details={"sink": command_sink, "taintedVariable": variable, "sourceToSink": bool(variable)},
                        ),
                        index,
                    )

            sql_sink = re.search(r"\.(?:execute|executemany|query|raw)\s*\(", line, re.IGNORECASE)
            interpolation = bool(re.search(r"(?:execute|query|raw)\s*\(\s*(?:f['\"]|['\"].*\+|`[^`]*\$\{|[^,]+\.format\s*\()", local_context, re.DOTALL))
            if sql_sink and interpolation:
                variable, source_line = _used_tainted_variable(local_context, sources, index)
                add(
                    _candidate(
                        source_file,
                        rule_id="sql-injection.dynamic-query",
                        anchor="dynamic-sql-with-untrusted-data",
                        title="Dynamic SQL construction can allow injection",
                        summary="A database query is constructed through string interpolation or concatenation instead of parameter binding.",
                        category="sql-injection",
                        cwe=["CWE-89"],
                        severity="high",
                        score=8.2,
                        confidence="high" if variable else "medium",
                        confidence_rationale="The query construction is visibly dynamic and includes a nearby external-input data flow." if variable else "Dynamic query construction is present; the exact value origin requires review.",
                        remediation="Use the database driver's parameter binding API. Keep SQL syntax static and pass values separately.",
                        sink_line=index,
                        source_line=source_line,
                        source_label=f"The value {variable!r} originates from request or process input." if variable else None,
                        details={"taintedVariable": variable, "sourceToSink": bool(variable)},
                    ),
                    index,
                )

            code_eval = bool(re.search(r"\beval\s*\(", line)) or (
                source_file.language == "python" and bool(re.search(r"\bexec\s*\(", line))
            )
            if code_eval and not re.search(r"ast\.literal_eval", line):
                variable, source_line = _used_tainted_variable(local_context, sources, index)
                if variable or _DIRECT_SOURCE.search(local_context):
                    add(
                        _candidate(
                            source_file,
                            rule_id="code-injection.dynamic-evaluation",
                            anchor="external-input-to-eval",
                            title="External input can reach dynamic code evaluation",
                            summary="Externally controlled text is evaluated as code.",
                            category="code-injection",
                            cwe=["CWE-95"],
                            severity="critical",
                            score=9.4,
                            confidence="high",
                            confidence_rationale="The local trace directly connects an external source to eval/exec.",
                            remediation="Remove dynamic evaluation. Parse a constrained data format or dispatch through an explicit allowlist.",
                            sink_line=index,
                            source_line=source_line,
                            source_label=f"The value {variable!r} is externally controlled." if variable else "The expression directly reads request input.",
                            details={"taintedVariable": variable, "sourceToSink": True},
                        ),
                        index,
                    )

            path_sink = None
            if re.search(r"\b(?:tar|archive|zipfile|zip)\w*\.(?:extract|extractall)\s*\(", line, re.IGNORECASE):
                path_sink = "archive extraction"
            elif re.search(r"\b(?:open|writeFile|writeFileSync|createWriteStream|unlink|readFile|send_file|sendFile)\s*\(", line):
                variable, _ = _used_tainted_variable(local_context, sources, index)
                if variable:
                    path_sink = "filesystem access"
            if path_sink:
                variable, source_line = _used_tainted_variable(local_context, sources, index)
                mitigation = re.search(r"(?:resolve\(|realpath|relative_to|commonpath|startsWith\s*\(|startswith\s*\(|is_relative_to)", local_context)
                if not mitigation:
                    add(
                        _candidate(
                            source_file,
                            rule_id="path-traversal.uncontained-path",
                            anchor="untrusted-path-without-containment",
                            title="Untrusted path can escape the intended filesystem boundary",
                            summary=f"{path_sink.capitalize()} occurs without a nearby canonical containment check.",
                            category="path-traversal",
                            cwe=["CWE-22"],
                            severity="high" if variable else "medium",
                            score=8.1 if variable else 6.4,
                            confidence="high" if variable else "medium",
                            confidence_rationale="A local source-to-sink trace reaches a filesystem API without containment validation." if variable else "The extraction API can honor entry-controlled paths and no containment guard is visible.",
                            remediation="Resolve the candidate path against an approved root, reject absolute paths and traversal, and verify the canonical result remains within the root before access.",
                            sink_line=index,
                            source_line=source_line,
                            source_label=f"The path component {variable!r} is externally controlled." if variable else None,
                            details={"sink": path_sink, "taintedVariable": variable, "sourceToSink": bool(variable)},
                        ),
                        index,
                    )

        if pass_name in ("all", "dangerous_api"):
            if re.search(r"\bpickle\.(?:loads?|load)\s*\(", line) or re.search(r"\byaml\.load\s*\(", line) and not re.search(r"SafeLoader|safe_load", local_context):
                variable, source_line = _used_tainted_variable(local_context, sources, index)
                add(
                    _candidate(
                        source_file,
                        rule_id="unsafe-deserialization.object-loader",
                        anchor="untrusted-data-to-object-deserializer",
                        title="Unsafe object deserialization may execute attacker-controlled behavior",
                        summary="A general-purpose object deserializer is used without a safe loader or trusted-data boundary.",
                        category="unsafe-deserialization",
                        cwe=["CWE-502"],
                        severity="critical" if variable else "high",
                        score=9.0 if variable else 8.0,
                        confidence="high" if variable else "medium",
                        confidence_rationale="External input is passed to an unsafe deserializer." if variable else "An unsafe deserializer is present; the trust boundary requires review.",
                        remediation="Use a data-only format and safe parser. If object serialization is unavoidable, authenticate the payload and enforce a strict type allowlist.",
                        sink_line=index,
                        source_line=source_line,
                        source_label=f"The payload {variable!r} comes from an external source." if variable else None,
                        details={"taintedVariable": variable, "sourceToSink": bool(variable)},
                    ),
                    index,
                )

            secret_match = _SECRET_LITERAL.search(line)
            if secret_match:
                value = secret_match.group("value")
                if len(set(value)) >= 8 and not re.search(r"example|dummy|placeholder|changeme|test", value, re.IGNORECASE):
                    add(
                        _candidate(
                            source_file,
                            rule_id="secret.hardcoded-credential",
                            anchor="credential-literal-in-source",
                            title="Potential credential is hardcoded in source",
                            summary="A high-entropy value is assigned to a credential-like name in tracked source code.",
                            category="secret-exposure",
                            cwe=["CWE-798"],
                            severity="high",
                            score=7.5,
                            confidence="medium",
                            confidence_rationale="The name and literal shape resemble a credential, but only the owner can confirm whether it is live.",
                            remediation="Revoke the credential if live, remove it from history, and load replacements from an approved secret store.",
                            sink_line=index,
                            details={"redactedLiteralLength": len(value), "sourceToSink": False},
                        ),
                        index,
                    )

            if re.search(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0", line, re.IGNORECASE):
                add(
                    _candidate(
                        source_file,
                        rule_id="transport-security.certificate-validation-disabled",
                        anchor="tls-verification-disabled",
                        title="TLS certificate verification is disabled",
                        summary="The code explicitly disables peer certificate validation.",
                        category="transport-security",
                        cwe=["CWE-295"],
                        severity="high",
                        score=7.4,
                        confidence="high",
                        confidence_rationale="The disabling option is explicit in source.",
                        remediation="Remove the disabling option and configure an approved trust store or pinned certificate where necessary.",
                        sink_line=index,
                        details={"sourceToSink": False},
                    ),
                    index,
                )

        if pass_name in ("all", "authorization"):
            route_match = re.search(r"\b(?:app|router|server)\.(?:delete|put|patch|post)\s*\(\s*['\"](?P<route>[^'\"]+)", line)
            flask_route = re.search(r"@\w+\.route\(.*(?:DELETE|PUT|PATCH|admin|users?|roles?|permissions?)", line, re.IGNORECASE)
            sensitive_route = bool(route_match and re.search(r"admin|delete|users?|roles?|permissions?|billing|secrets?", route_match.group("route"), re.IGNORECASE)) or bool(flask_route)
            if sensitive_route:
                auth_context = "\n".join(lines[max(0, index - 5) : min(len(lines), index + 8)])
                if not re.search(r"auth|authorize|permission|isAdmin|login_required|require_role|Depends\s*\(", auth_context, re.IGNORECASE):
                    add(
                        _candidate(
                            source_file,
                            rule_id="authorization.missing-route-guard",
                            anchor="sensitive-route-without-visible-authorization",
                            title="Sensitive route lacks a visible authorization guard",
                            summary="A state-changing or administrative route is registered without nearby authentication or authorization middleware.",
                            category="authorization",
                            cwe=["CWE-862"],
                            severity="high",
                            score=8.0,
                            confidence="medium",
                            confidence_rationale="No guard is visible in the local route registration or decorator context; global middleware may still require review.",
                            remediation="Require authentication and an explicit resource/action authorization check at the route boundary, then test denied roles and cross-tenant access.",
                            sink_line=index,
                            details={"route": route_match.group("route") if route_match else None, "sourceToSink": False},
                        ),
                        index,
                    )
    return findings


def _semantic_collision_key(candidate: dict[str, Any]) -> str:
    return json.dumps(
        sorted((location["path"], location["role"]) for location in candidate["locations"]),
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _disambiguate_semantic_collision(candidate: dict[str, Any], occurrence: int | None = None) -> dict[str, Any]:
    identity = dict(candidate["identity"])
    location_key = _semantic_collision_key(candidate)
    if occurrence is not None:
        location_key = f"{location_key}:{occurrence}"
    suffix = hashlib.sha256(location_key.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    identity["instance"] = f"{identity['instance']}:collision:{suffix}"
    primary = f"{candidate['ruleId']}:{identity['anchor']}:{identity['instance']}"
    candidate["identity"] = identity
    candidate["fingerprint"] = f"kiro-security/v1:sha256:{hashlib.sha256(primary.encode('utf-8', 'surrogatepass')).hexdigest()}"
    return candidate


def scan_inventory(
    inventory: Inventory,
    *,
    pass_name: str = "all",
    progress: Callable[[int, int, str], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    interrupted: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    total = len(inventory.files)
    for completed, source_file in enumerate(inventory.files, start=1):
        if cancelled and cancelled():
            raise CancelledScan()
        if interrupted and interrupted():
            raise InterruptedScan()
        for candidate in scan_source_file(source_file, pass_name=pass_name):
            groups.setdefault(candidate["fingerprint"], []).append(candidate)
        if progress:
            progress(completed, total, source_file.relative_path)
    result = []
    for group in groups.values():
        if len(group) == 1:
            result.extend(group)
            continue
        keys = [_semantic_collision_key(candidate) for candidate in group]
        occurrences: dict[str, int] = {}
        for candidate, key in zip(group, keys):
            occurrence = occurrences.get(key, 0) + 1
            occurrences[key] = occurrence
            result.append(
                _disambiguate_semantic_collision(candidate, occurrence if keys.count(key) > 1 else None)
            )
    return result
