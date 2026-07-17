from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Iterable

from .errors import EngineError

_SECRET_PATTERNS = [
    re.compile(r"(?i)([\"']?authorization[\"']?)(\s*[=:]\s*[\"']?)(?:(?:bearer|basic)\s+)?([^\s,;\"']+)"),
    re.compile(r"(?i)(api[_-]?key|token|secret|password)(\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"\b(?:sk|ghp|github_pat|xox[baprs])-?[A-Za-z0-9_\-]{12,}\b"),
]
_GIT_REF = re.compile(r"^[A-Za-z0-9._/@+\-~^:]+$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,255}$")


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    digest = hashlib.sha256("\0".join(parts).encode("utf-8", "surrogatepass")).hexdigest()[:length]
    return f"{prefix}_{digest}"


def random_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact(value: str) -> str:
    result = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups >= 3:
            result = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", result)
        else:
            result = pattern.sub("<redacted>", result)
    return result


def require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise EngineError("invalid_argument", f"{field} must be a bounded identifier.", {"field": field})
    return value


def require_git_ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) > 256 or not _GIT_REF.fullmatch(value) or value.startswith("-"):
        raise EngineError("invalid_git_ref", f"{field} is not a safe Git revision.", {"field": field})
    return value


def canonical_workspace(path: str | os.PathLike[str]) -> Path:
    raw = Path(path).expanduser()
    try:
        resolved = raw.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise EngineError("workspace_not_found", f"Workspace does not exist: {raw}") from exc
    if not resolved.is_dir():
        raise EngineError("invalid_workspace", f"Workspace is not a directory: {resolved}")
    return resolved


def resolve_within(root: Path, relative: str | os.PathLike[str], *, must_exist: bool = False) -> Path:
    if not isinstance(relative, (str, os.PathLike)):
        raise EngineError("invalid_path", "Path must be a string.")
    text = os.fspath(relative)
    if "\x00" in text:
        raise EngineError("invalid_path", "Path contains a NUL byte.")
    candidate = Path(text)
    if candidate.is_absolute():
        raise EngineError("path_escape", "Absolute paths are not accepted for workspace-relative inputs.")
    try:
        resolved = (root / candidate).resolve(strict=must_exist)
    except (OSError, RuntimeError) as exc:
        raise EngineError("invalid_path", f"Unable to resolve path: {text}") from exc
    if resolved != root and root not in resolved.parents:
        raise EngineError("path_escape", f"Path escapes workspace boundary: {text}")
    return resolved


def require_export_destination(destination: str, allowed_root: str) -> Path:
    dest = Path(destination).expanduser()
    allow = Path(allowed_root).expanduser()
    try:
        allow_resolved = allow.resolve(strict=True)
    except OSError as exc:
        raise EngineError("invalid_export_root", f"Export root does not exist: {allow}") from exc
    if not allow_resolved.is_dir():
        raise EngineError("invalid_export_root", "Export root must be a directory.")
    parent = dest.parent.resolve(strict=True)
    resolved = parent / dest.name
    if resolved != allow_resolved and allow_resolved not in resolved.parents:
        raise EngineError("export_path_escape", "Export destination is outside the explicitly allowed root.")
    if resolved.exists() and resolved.is_symlink():
        raise EngineError("unsafe_export_path", "Refusing to overwrite a symlink export destination.")
    return resolved


def atomic_write(path: Path, data: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise EngineError("unsafe_artifact_path", f"Refusing to replace symlink: {path}")
    payload = data.encode("utf-8") if isinstance(data, str) else data
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def write_json(path: Path, value: Any) -> None:
    atomic_write(path, json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n")


def run_process(
    executable: str,
    args: Iterable[str],
    *,
    cwd: Path,
    timeout: float = 30,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env_keys = ("PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL")
    env = {key: os.environ[key] for key in env_keys if key in os.environ}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": env.get("LC_ALL", "C.UTF-8")})
    try:
        return subprocess.run(
            [executable, *list(args)],
            cwd=cwd,
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=check,
        )
    except FileNotFoundError as exc:
        raise EngineError("dependency_missing", f"Required executable was not found: {executable}") from exc
    except subprocess.TimeoutExpired as exc:
        raise EngineError("process_timeout", f"{executable} exceeded the {timeout:g}s timeout.") from exc
    except subprocess.CalledProcessError as exc:
        message = redact((exc.stderr or exc.stdout or str(exc)).strip())
        raise EngineError("process_failed", f"{executable} failed: {message[:2000]}") from exc
