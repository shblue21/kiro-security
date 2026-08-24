"""Deterministic target validation and snapshot identity."""

import hashlib
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

from .errors import WorkbenchError
from .models import DIFF_TARGET_KINDS, MODES, DiffTarget, WorkspaceSetup
from .workbench_contract import optional_text as _optional_text

EMPTY_GIT_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT_REPOSITORY_ENVIRONMENT = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_DIR",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_INDEX_FILE",
    "GIT_NAMESPACE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_WORK_TREE",
)


@dataclass(frozen=True)
class TargetSnapshot:
    """Immutable target identity captured for one scan row."""

    target_path: str
    target_revision: str
    target_snapshot_digest: Optional[str]
    target_device: int
    target_inode: int
    target_id: str
    setup: WorkspaceSetup


class Git:
    """Read-only Git invocation with repository-owned executables disabled."""

    @staticmethod
    def run(target, args, text):
        environment = os.environ.copy()
        for name in GIT_REPOSITORY_ENVIRONMENT:
            environment.pop(name, None)
        environment["GIT_LITERAL_PATHSPECS"] = "1"
        command = ["git", "-c", "core.fsmonitor=false", "-C", str(target)]
        command.extend(args)
        try:
            return subprocess.run(
                command,
                check=False,
                capture_output=True,
                env=environment,
                text=text,
            )
        except FileNotFoundError:
            empty = "" if text else b""
            return subprocess.CompletedProcess(command, 127, empty, empty)

    @classmethod
    def text(cls, target, *args):
        # type: (Path, str) -> Optional[str]
        completed = cls.run(target, list(args), True)
        output = completed.stdout.strip()
        return output if completed.returncode == 0 and output else None

    @classmethod
    def bytes(cls, target, *args):
        # type: (Path, str) -> Optional[bytes]
        completed = cls.run(target, list(args), False)
        return completed.stdout if completed.returncode == 0 else None


class TargetInspector:
    """Validates setup and produces immutable target snapshots."""

    def inspect_setup(self, setup):
        # type: (WorkspaceSetup) -> WorkspaceSetup
        if setup.mode not in MODES:
            raise WorkbenchError("invalid_mode", "Scan mode must be diff, standard, or deep.")
        target = self.require_target(setup.target_path)
        scope = self.require_scope(target, setup.scope, setup.mode)
        if setup.mode == "diff":
            if scope != ".":
                raise WorkbenchError(
                    "diff_scope",
                    "Diff scans require the whole repository target and scope '.'.",
                )
            if setup.diff_target is None:
                raise WorkbenchError(
                    "missing_diff_target",
                    "Diff scans require an exact Git change target.",
                )
            diff_target = self.resolve_diff_target(target, setup.diff_target)
        else:
            if setup.diff_target is not None:
                raise WorkbenchError(
                    "unexpected_diff_target",
                    "A Git diff target can only be used in diff mode.",
                )
            diff_target = None
        return WorkspaceSetup(
            target_path=str(target),
            mode=setup.mode,
            scope=scope,
            user_context=_optional_text(setup.user_context),
            diff_target=diff_target,
        )

    def capture(self, setup):
        # type: (WorkspaceSetup) -> TargetSnapshot
        inspected = self.inspect_setup(setup)
        target = Path(inspected.target_path)
        metadata = target.stat()
        if inspected.mode == "diff":
            refreshed = self.resolve_diff_target(target, inspected.diff_target)
            inspected = WorkspaceSetup(
                target_path=inspected.target_path,
                mode=inspected.mode,
                scope=inspected.scope,
                user_context=inspected.user_context,
                diff_target=refreshed,
            )
            revision = refreshed.head_revision
            snapshot_digest = refreshed.content_digest
        else:
            revision = self.git_revision(target)
            if revision == "unversioned":
                snapshot_digest = self.directory_digest(target)
            else:
                snapshot_digest = self.worktree_digest(target)
        return TargetSnapshot(
            target_path=str(target),
            target_revision=revision,
            target_snapshot_digest=snapshot_digest,
            target_device=int(metadata.st_dev),
            target_inode=int(metadata.st_ino),
            target_id=self.stable_target_id(target),
            setup=inspected,
        )

    def require_target(self, value):
        # type: (Optional[str]) -> Path
        if not isinstance(value, str) or not value.strip():
            raise WorkbenchError(
                "target_required",
                "Scan target must be an absolute local directory path.",
            )
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise WorkbenchError(
                "target_not_absolute",
                "Scan target must be an absolute local directory path.",
            )
        try:
            target = candidate.resolve(strict=True)
        except OSError as exc:
            raise WorkbenchError("target_missing", "Scan target is not accessible.") from exc
        if not target.is_dir():
            raise WorkbenchError("target_not_directory", "Scan target must be a directory.")
        metadata = self.git_metadata(target)
        if metadata["isGit"] and not metadata["isWorktree"]:
            raise WorkbenchError(
                "bare_repository",
                "Kiro Security requires a checked-out worktree, not a bare repository.",
            )
        return target

    def require_scope(self, target, scope, mode):
        # type: (Path, str, str) -> str
        value = (scope or ".").strip() or "."
        if "\\" in value:
            raise WorkbenchError(
                "invalid_scope",
                "Scope must use repository-relative POSIX paths.",
            )
        parsed = PurePosixPath(value)
        if ".." in parsed.parts:
            raise WorkbenchError("scope_escape", "Scope must stay inside the target.")
        try:
            resolved = (
                Path(parsed.as_posix()).resolve()
                if parsed.is_absolute()
                else (target / parsed.as_posix()).resolve()
            )
            relative = resolved.relative_to(target)
        except (RuntimeError, ValueError) as exc:
            raise WorkbenchError("scope_escape", "Scope must stay inside the target.") from exc
        if not resolved.is_dir():
            raise WorkbenchError("scope_not_directory", "Scope must be an existing directory.")
        normalized = relative.as_posix() or "."
        if mode == "deep" and normalized != ".":
            raise WorkbenchError(
                "deep_scope",
                "Deep scans are repository-wide and require scope '.'.",
            )
        return normalized

    def git_metadata(self, target):
        # type: (Path) -> Dict[str, object]
        is_git = Git.text(target, "rev-parse", "--git-dir") is not None
        is_worktree = Git.text(target, "rev-parse", "--is-inside-work-tree") == "true"
        revision = Git.text(target, "rev-parse", "--verify", "HEAD")
        root = Git.text(target, "rev-parse", "--show-toplevel") if is_worktree else None
        return {
            "hasHead": revision is not None,
            "isGit": is_git,
            "isWorktree": is_worktree,
            "repositoryRoot": str(Path(root).resolve()) if root else None,
            "revision": revision,
        }

    def git_revision(self, target):
        # type: (Path) -> str
        return Git.text(target, "rev-parse", "--verify", "HEAD") or "unversioned"

    def resolve_diff_target(self, target, requested):
        # type: (Path, DiffTarget) -> DiffTarget
        if requested.kind not in DIFF_TARGET_KINDS:
            raise WorkbenchError("invalid_diff_target", "Unsupported Git diff target kind.")
        metadata = self.git_metadata(target)
        if (
            not metadata["isGit"]
            or not metadata["isWorktree"]
            or not metadata["hasHead"]
            or metadata["repositoryRoot"] != str(target)
        ):
            raise WorkbenchError(
                "diff_target_not_repository",
                "Diff scans require the checked-out Git repository root.",
            )
        current_head = str(metadata["revision"])
        if requested.kind == "working_tree":
            base = self.resolve_commit(target, requested.base_revision or "HEAD", "base")
            head = self.resolve_commit(target, requested.head_revision or current_head, "head")
            digest = self.worktree_digest(target)
            if base != current_head or head != current_head:
                raise WorkbenchError(
                    "diff_head_changed",
                    "Repository HEAD changed after the working tree was selected.",
                )
            if requested.content_digest and requested.content_digest != digest:
                raise WorkbenchError(
                    "diff_content_changed",
                    "Working-tree contents changed after they were selected.",
                )
            return DiffTarget("working_tree", current_head, current_head, digest)
        if requested.kind == "commit":
            head = self.resolve_commit(target, requested.head_revision or "", "commit")
            raw_commit = Git.text(target, "cat-file", "-p", head)
            if raw_commit is None:
                raise WorkbenchError("commit_missing", "Selected commit is not available.")
            parent_line = next(
                (line for line in raw_commit.splitlines() if line.startswith("parent ")),
                None,
            )
            parent = (
                EMPTY_GIT_TREE
                if parent_line is None
                else self.resolve_commit(target, parent_line[7:].strip(), "commit parent")
            )
            if requested.base_revision:
                supplied = (
                    EMPTY_GIT_TREE
                    if requested.base_revision == EMPTY_GIT_TREE
                    else self.resolve_commit(target, requested.base_revision, "commit base")
                )
                if supplied != parent:
                    raise WorkbenchError(
                        "commit_parent_mismatch",
                        "Commit base must match the selected commit parent.",
                    )
            digest = self.diff_digest(target, parent, head)
            if requested.content_digest and requested.content_digest != digest:
                raise WorkbenchError(
                    "diff_content_changed",
                    "Commit contents changed after they were selected.",
                )
            return DiffTarget("commit", parent, head, digest)
        base = self.resolve_commit(target, requested.base_revision or "", "base")
        head = self.resolve_commit(target, requested.head_revision or "", "head")
        if base == head:
            raise WorkbenchError(
                "empty_diff_range",
                "Diff base and head must identify different commits.",
            )
        digest = self.diff_digest(target, base, head)
        if requested.content_digest and requested.content_digest != digest:
            raise WorkbenchError(
                "diff_content_changed",
                "Range contents changed after they were selected.",
            )
        return DiffTarget("range", base, head, digest)

    def diff_digest(self, target, base, head):
        # type: (Path, str, str) -> str
        content = Git.bytes(
            target,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            base,
            head,
            "--",
            ".",
        )
        if content is None:
            raise WorkbenchError(
                "snapshot_failed",
                "Could not snapshot the selected Git diff.",
            )
        digest = hashlib.sha256()
        _update_digest(digest, b"format", b"codex-security-snapshot/v1")
        _update_digest(digest, b"git-diff", content)
        return "codex-security-snapshot/v1:sha256:%s" % digest.hexdigest()

    def resolve_commit(self, target, value, label):
        # type: (Path, str, str) -> str
        if not value or len(value) > 512:
            raise WorkbenchError("revision_required", "Git %s revision is required." % label)
        resolved = Git.text(
            target,
            "rev-parse",
            "--verify",
            "--end-of-options",
            "%s^{commit}" % value,
        )
        if resolved is None:
            raise WorkbenchError(
                "revision_missing",
                "Git %s revision is not available locally." % label,
            )
        return resolved

    def worktree_digest(self, target):
        # type: (Path) -> str
        repository, pathspec = self._git_context(target)
        self._require_clean_submodules(target)
        tracked = Git.bytes(
            repository,
            "diff",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            "--ignore-submodules=none",
            "HEAD",
            "--",
            pathspec,
        )
        untracked = Git.bytes(
            repository,
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            pathspec,
        )
        if tracked is None or untracked is None:
            raise WorkbenchError(
                "snapshot_failed",
                "Could not snapshot the selected working-tree contents.",
            )
        digest = hashlib.sha256()
        _update_digest(digest, b"format", b"codex-security-snapshot/v1")
        _update_digest(digest, b"tracked-diff", tracked)
        for raw_path in sorted(item for item in untracked.split(b"\0") if item):
            relative = Path(os.fsdecode(raw_path))
            path = repository / relative
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise WorkbenchError(
                    "snapshot_file_missing",
                    "An untracked file changed while the snapshot was being captured.",
                ) from exc
            _update_digest(digest, b"untracked-path", raw_path)
            _update_digest(
                digest,
                b"untracked-mode",
                str(stat.S_IMODE(metadata.st_mode)).encode("ascii"),
            )
            if stat.S_ISLNK(metadata.st_mode):
                _update_digest(digest, b"untracked-kind", b"symlink")
                _update_digest(
                    digest,
                    b"untracked-content",
                    os.fsencode(os.readlink(path)),
                )
            elif stat.S_ISREG(metadata.st_mode):
                file_digest, size = _file_digest(path)
                _update_digest(digest, b"untracked-kind", b"file")
                _update_digest(digest, b"untracked-size", str(size).encode("ascii"))
                _update_digest(digest, b"untracked-content-sha256", file_digest)
            else:
                raise WorkbenchError(
                    "unsupported_target_file",
                    "Working-tree snapshots do not support special untracked files.",
                )
        return "codex-security-snapshot/v1:sha256:%s" % digest.hexdigest()

    def directory_digest(self, target):
        # type: (Path) -> str
        paths = self._directory_snapshot_paths(target)
        digest = hashlib.sha256()
        _update_digest(digest, b"format", b"codex-security-directory/v1")
        for path in paths:
            relative = path.relative_to(target)
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise WorkbenchError(
                    "snapshot_file_missing",
                    "A target file changed while the snapshot was being captured.",
                ) from exc
            _update_digest(digest, b"path", os.fsencode(relative.as_posix()))
            _update_digest(
                digest,
                b"mode",
                str(stat.S_IMODE(metadata.st_mode)).encode("ascii"),
            )
            if stat.S_ISLNK(metadata.st_mode):
                _update_digest(digest, b"kind", b"symlink")
                _update_digest(digest, b"content", os.fsencode(os.readlink(path)))
            elif stat.S_ISDIR(metadata.st_mode):
                _update_digest(digest, b"kind", b"directory")
            elif stat.S_ISREG(metadata.st_mode):
                file_digest, size = _file_digest(path)
                _update_digest(digest, b"kind", b"file")
                _update_digest(digest, b"size", str(size).encode("ascii"))
                _update_digest(digest, b"content-sha256", file_digest)
            else:
                raise WorkbenchError(
                    "unsupported_target_file",
                    "Directory snapshots do not support special files.",
                )
        return "codex-security-snapshot/v1:sha256:%s" % digest.hexdigest()

    def stable_target_id(self, target):
        # type: (Path) -> str
        digest = hashlib.sha256(("local-workspace\0%s" % target).encode("utf-8")).hexdigest()
        return "target_sha256_%s" % digest

    def _git_context(self, target):
        # type: (Path) -> Tuple[Path, str]
        root = Git.text(target, "rev-parse", "--show-toplevel")
        if root is None:
            raise WorkbenchError("git_inspection_failed", "Could not inspect Git worktree.")
        repository = Path(root).resolve()
        try:
            relative = target.relative_to(repository)
        except ValueError as exc:
            raise WorkbenchError("target_escape", "Target must stay inside its worktree.") from exc
        return repository, relative.as_posix() or "."

    def _require_clean_submodules(self, target):
        # type: (Path) -> None
        repository, pathspec = self._git_context(target)
        staged = Git.bytes(repository, "ls-files", "--stage", "-z", "--", pathspec)
        if staged is None:
            raise WorkbenchError("submodule_inspection_failed", "Could not inspect submodules.")
        for record in (item for item in staged.split(b"\0") if item):
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_id, _stage = metadata.split(b" ", 2)
            except ValueError as exc:
                raise WorkbenchError(
                    "submodule_inspection_failed",
                    "Could not parse Git index metadata.",
                ) from exc
            if mode != b"160000":
                continue
            submodule = repository / os.fsdecode(raw_path)
            if not submodule.exists():
                continue
            try:
                (submodule / ".git").lstat()
            except FileNotFoundError:
                continue
            root = Git.text(submodule, "rev-parse", "--show-toplevel")
            try:
                initialized = root is not None and Path(root).resolve() == submodule.resolve()
            except OSError:
                initialized = False
            if not initialized:
                raise WorkbenchError(
                    "submodule_inspection_failed",
                    "Could not inspect an initialized Git submodule.",
                )
            head = Git.text(submodule, "rev-parse", "HEAD")
            if head != object_id.decode("ascii"):
                raise WorkbenchError(
                    "dirty_submodule",
                    "Initialized submodules must match the parent repository revision.",
                )
            status_output = Git.bytes(
                submodule,
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            )
            if status_output is None or status_output:
                raise WorkbenchError(
                    "dirty_submodule",
                    "Initialized submodules must have clean worktrees.",
                )
            self._require_clean_submodules(submodule)

    def _directory_snapshot_paths(self, target):
        # type: (Path) -> list
        repository_root = Git.text(target, "rev-parse", "--show-toplevel")
        if repository_root is None:
            return sorted(
                target.rglob("*"),
                key=lambda path: path.relative_to(target).as_posix(),
            )
        repository = Path(repository_root).resolve()
        try:
            relative = target.relative_to(repository)
        except ValueError as exc:
            raise WorkbenchError(
                "target_escape",
                "Target must stay inside its Git worktree.",
            ) from exc
        pathspec = relative.as_posix() or "."
        listed = Git.bytes(
            repository,
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            pathspec,
        )
        if listed is None:
            raise WorkbenchError(
                "snapshot_failed",
                "Could not enumerate the selected Git directory snapshot.",
            )
        candidates = (
            repository / os.fsdecode(raw_path)
            for raw_path in listed.split(b"\0")
            if raw_path
        )
        paths = []
        for path in candidates:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            paths.append(path)
            if path.is_dir():
                nested_root = Git.text(path, "rev-parse", "--show-toplevel")
                if nested_root is not None and Path(nested_root).resolve() == path.resolve():
                    paths.extend(self._directory_snapshot_paths(path))
                    continue
                paths.extend(
                    nested
                    for nested in path.rglob("*")
                    if ".git" not in nested.relative_to(path).parts
                )
        return sorted(
            set(paths),
            key=lambda path: path.relative_to(target).as_posix(),
        )

def _update_digest(digest, label, value):
    digest.update(len(label).to_bytes(4, "big"))
    digest.update(label)
    digest.update(len(value).to_bytes(8, "big"))
    digest.update(value)


def _file_digest(path):
    # type: (Path) -> Tuple[bytes, int]
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                size += len(chunk)
    except OSError as exc:
        raise WorkbenchError("snapshot_read_failed", "Could not read target file.") from exc
    return digest.digest(), size


