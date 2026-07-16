from __future__ import annotations

import hashlib
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
    warnings: list[str] = field(default_factory=list)


_LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescriptreact", ".jsx": "javascriptreact", ".java": "java", ".go": "go",
    ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".sh": "shellscript",
    ".bash": "shellscript", ".zsh": "shellscript", ".kt": "kotlin", ".kts": "kotlin", ".scala": "scala",
}


def language_for(path: Path) -> str:
    return _LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "text")


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


def _git_revision(workspace: Path) -> tuple[bool, str | None]:
    try:
        result = run_process("git", ["rev-parse", "HEAD"], cwd=workspace, timeout=10)
        return True, result.stdout.strip() or None
    except EngineError:
        return False, None


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
) -> Inventory:
    scope_path = resolve_within(workspace, scope, must_exist=True)
    git_available, revision = _git_revision(workspace)
    changed_paths: DiffPaths | None = None
    diff_summary: str | None = None
    if mode == "diff":
        if not git_available:
            raise EngineError("git_required", "Diff scans require a Git worktree with a resolvable HEAD.")
        changed_paths, diff_summary = _diff_paths(
            workspace,
            scope,
            diff_target_kind or "working_tree",
            diff_base_revision,
            diff_head_revision,
        )

    candidates: Iterable[Path]
    if scope_path.is_file():
        candidates = [scope_path]
    else:
        candidates = (path for path in scope_path.rglob("*") if path.is_file())

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
        files.append(SourceFile(resolved, relative, text, language_for(path), size, changed_paths is None or relative in changed_paths.existing))
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
    return Inventory(
        files=files,
        include_paths=[scope],
        exclude_paths=sorted(set(excluded)),
        deferred=deferred,
        revision=revision,
        snapshot_digest=f"kiro-security-snapshot/v1:sha256:{digest.hexdigest()}",
        git_available=git_available,
        diff_summary=diff_summary,
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
    primary = f"{source_file.relative_path}:{sink_line}:{rule_id}:{anchor}"
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
        "identity": {"anchor": anchor, "instance": f"{source_file.relative_path}:{sink_line}"},
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
        "details": details or {},
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


def scan_inventory(
    inventory: Inventory,
    *,
    pass_name: str = "all",
    progress: Callable[[int, int, str], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
    interrupted: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    total = len(inventory.files)
    for completed, source_file in enumerate(inventory.files, start=1):
        if cancelled and cancelled():
            raise CancelledScan()
        if interrupted and interrupted():
            raise InterruptedScan()
        for candidate in scan_source_file(source_file, pass_name=pass_name):
            findings[candidate["fingerprint"]] = candidate
        if progress:
            progress(completed, total, source_file.relative_path)
    return list(findings.values())
