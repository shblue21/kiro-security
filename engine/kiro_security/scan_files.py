"""Safe scan-local path validation, reads, and atomic writes."""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path, PurePosixPath
from typing import Sequence


class ArtifactContractError(ValueError):
    """A canonical artifact or scan-local file violates its contract."""


def validate_scan_relative_path(
    value: str, context: str, allow_dot: bool = False
) -> str:
    """Return one normalized safe POSIX path relative to a scan directory."""

    if not isinstance(value, str):
        raise ArtifactContractError("%s: expected a string" % context)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ArtifactContractError(
            "%s: expected a safe relative POSIX path" % context
        ) from exc
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if (
        not value
        or (normalized == "." and not allow_dot)
        or "\\" in value
        or "\0" in value
        or path.is_absolute()
        or ".." in path.parts
    ):
        raise ArtifactContractError(
            "%s: expected a safe relative POSIX path" % context
        )
    return normalized


def require_scan_directory(scan_dir: Path) -> Path:
    """Return an existing canonical, non-symlink scan directory."""

    root = Path(scan_dir).absolute()
    try:
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise ArtifactContractError(
            "scan directory: expected an existing non-symlink directory"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode) or resolved != root:
        raise ArtifactContractError(
            "scan directory: expected a canonical non-symlink directory"
        )
    return root


def read_regular_file(root: Path, relative_path: str) -> bytes:
    """Read a regular scan-local file without following symlinks."""

    normalized = validate_scan_relative_path(relative_path, relative_path)
    parts = PurePosixPath(normalized).parts
    root_fd = _open_root(root)
    parent_fd = -1
    file_fd = -1
    try:
        parent_fd = _open_parent(root_fd, parts[:-1], create=False)
        expected = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(expected.st_mode):
            raise ArtifactContractError(
                "%s: missing or unsafe regular file" % normalized
            )
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        file_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (expected.st_dev, expected.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ArtifactContractError("%s: expected a regular file" % normalized)
        chunks = []
        while True:
            chunk = os.read(file_fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    except (OSError, ArtifactContractError) as exc:
        if isinstance(exc, ArtifactContractError) and str(exc).startswith(normalized):
            raise
        raise ArtifactContractError(
            "%s: missing or unsafe regular file" % normalized
        ) from exc
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def atomic_write(root: Path, relative_path: str, content: bytes) -> None:
    """Atomically replace one regular scan-local file without following symlinks."""

    normalized = validate_scan_relative_path(
        relative_path, "scan-local output path"
    )
    parts = PurePosixPath(normalized).parts
    root_fd = _open_root(root)
    parent_fd = -1
    temp_name = ".%s.%s.tmp" % (parts[-1], secrets.token_hex(8))
    try:
        parent_fd = _open_parent(root_fd, parts[:-1], create=True)
        try:
            existing = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ArtifactContractError(
                "%s: expected a regular non-symlink output" % normalized
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(temp_fd, content[offset:])
            os.fsync(temp_fd)
        finally:
            os.close(temp_fd)
        os.replace(temp_name, parts[-1], src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError as exc:
        raise ArtifactContractError(
            "%s: could not write atomically" % normalized
        ) from exc
    finally:
        if parent_fd >= 0:
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            os.close(parent_fd)
        os.close(root_fd)


def _open_root(root: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(root), flags)
    except OSError as exc:
        raise ArtifactContractError("scan directory: could not open safely") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ArtifactContractError("scan directory: expected a directory")
    return descriptor


def _open_parent(root_fd: int, parts: Sequence[str], create: bool) -> int:
    descriptor = os.dup(root_fd)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            expected = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(expected.st_mode):
                raise ArtifactContractError(
                    "scan-local path: expected a regular directory"
                )
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            opened = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or (expected.st_dev, expected.st_ino)
                != (opened.st_dev, opened.st_ino)
            ):
                os.close(next_descriptor)
                raise ArtifactContractError(
                    "scan-local path: expected a regular directory"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except (OSError, ArtifactContractError) as exc:
        os.close(descriptor)
        if isinstance(exc, ArtifactContractError):
            raise
        raise ArtifactContractError(
            "scan-local path: expected non-symlink directories"
        ) from exc


__all__ = [
    "ArtifactContractError",
    "atomic_write",
    "read_regular_file",
    "require_scan_directory",
    "validate_scan_relative_path",
]
