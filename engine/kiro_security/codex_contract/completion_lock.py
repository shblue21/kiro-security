# Direct-port provenance:
# upstream: codex-security 0.1.11
# upstream relative path: scripts/workbench_db.py (file-lock imports and lines 127-190)
# upstream sha256: 15ad4281a6c5ebc612e2b133248529563990a0e02649a4d612b7c87610acacbf
# allowed Kiro changes: workspace-local state root and Kiro scan-id validation.
# prohibited semantic changes: none; preserve the upstream cross-process exclusive completion lock.

from __future__ import annotations

import errno
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

try:
    import fcntl as posix_file_lock
except ModuleNotFoundError:  # pragma: no cover - exercised on Windows.
    posix_file_lock = None

try:
    import msvcrt as windows_file_lock
except ModuleNotFoundError:  # pragma: no cover - msvcrt is only available on Windows.
    windows_file_lock = None


SCAN_ID = re.compile(r"^scan_[A-Za-z0-9_-]{1,200}$")


def _require_scan_id(scan_id: str) -> str:
    if not isinstance(scan_id, str) or not SCAN_ID.fullmatch(scan_id):
        raise ValueError("scan-id is invalid")
    return scan_id


@contextmanager
def scan_completion_lock(state_dir: Path, scan_id: str) -> Any:
    lock_dir = state_dir / "completion-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / f"{_require_scan_id(scan_id)}.lock"
    descriptor = os.open(
        lock_path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0),
        0o600,
    )
    locked = False
    try:
        acquire_completion_file_lock(descriptor)
        locked = True
        yield
    finally:
        try:
            if locked:
                release_completion_file_lock(descriptor)
        finally:
            os.close(descriptor)


def is_file_lock_contention(error: OSError) -> bool:
    return error.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}


def acquire_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_EX)
        return
    if windows_file_lock is None:
        raise RuntimeError("Scan completion requires operating-system file locking support.")

    while os.fstat(descriptor).st_size == 0:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            os.write(descriptor, b"\0")
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)

    while True:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            windows_file_lock.locking(descriptor, windows_file_lock.LK_NBLCK, 1)
            return
        except OSError as exc:
            if not is_file_lock_contention(exc):
                raise
            time.sleep(0.05)


def release_completion_file_lock(descriptor: int) -> None:
    if posix_file_lock is not None:
        posix_file_lock.flock(descriptor, posix_file_lock.LOCK_UN)
        return
    if windows_file_lock is None:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    windows_file_lock.locking(descriptor, windows_file_lock.LK_UNLCK, 1)
