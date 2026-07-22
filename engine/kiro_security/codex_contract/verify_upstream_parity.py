"""Audit direct-port deltas against a supplied Codex Security 0.1.11 tree.

This is deliberately an offline development check: production imports none of
its data and never depends on an installed Codex plugin cache.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "parity_manifest.json"
PROVENANCE_PREFIX = "# Direct-port provenance:\n"


def _port_payload(path: Path) -> str:
    value = path.read_text(encoding="utf-8")
    if value.startswith(PROVENANCE_PREFIX):
        return "\n".join(value.splitlines()[7:]) + ("\n" if value.endswith("\n") else "")
    return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def verify(upstream_root: Path) -> list[str]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    failures: list[str] = []
    for entry in manifest["ports"]:
        source = upstream_root / entry["upstreamPath"]
        local = ROOT / entry["localPath"]
        try:
            source_bytes = source.read_bytes()
            source_text = source_bytes.decode("utf-8")
            ranges = entry.get("upstreamLineRanges")
            if ranges is not None:
                source_lines = source_text.splitlines(keepends=True)
                source_text = "".join(
                    "".join(source_lines[start - 1 : end]) for start, end in ranges
                )
            local_text = _port_payload(local)
        except (OSError, UnicodeDecodeError) as error:
            failures.append(f"{entry['upstreamPath']}: {error}")
            continue
        source_hash = _sha256(source_bytes)
        if source_hash != entry["upstreamSha256"]:
            failures.append(f"{entry['upstreamPath']}: upstream SHA-256 differs ({source_hash})")
            continue
        patch = "".join(difflib.unified_diff(
            source_text.splitlines(keepends=True), local_text.splitlines(keepends=True),
            fromfile=entry["upstreamPath"], tofile=entry["localPath"], n=3,
        ))
        patch_hash = _sha256(patch.encode("utf-8"))
        if patch_hash != entry["allowedDiffSha256"]:
            failures.append(f"{entry['upstreamPath']}: unapproved port delta ({patch_hash})")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    args = parser.parse_args()
    failures = verify(args.upstream.resolve())
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print("PASS direct-port parity")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
