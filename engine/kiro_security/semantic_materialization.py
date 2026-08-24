"""Finalizer input projection from validated semantic artifacts."""

import re
from pathlib import Path

from .artifacts import REPORTABLE_SEVERITIES, canonical_json_bytes
from .errors import WorkbenchError
from .scan_files import ArtifactContractError, atomic_write
from .semantic_contract import coverage_mode


def bind_finalizer_inputs(
    scan,
    manifest,
    findings,
    coverage,
    completed_at,
    target_id,
    threat_model,
):
    if not isinstance(manifest, dict) or not isinstance(findings, dict):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical manifest and findings must be objects.",
        )
    scan_manifest = manifest.get("scan")
    if not isinstance(scan_manifest, dict):
        raise WorkbenchError(
            "invalid_canonical_result",
            "Canonical manifest requires a scan object.",
        )
    scan_manifest["id"] = scan["id"]
    scan_manifest["status"] = "completed"
    scan_manifest["startedAt"] = scan["started_at"]
    scan_manifest["completedAt"] = completed_at
    scan_manifest.pop("sealedAt", None)
    scan_manifest.pop("artifacts", None)
    scan_manifest["coverageRef"] = "coverage.json"
    scan_manifest["findingsRef"] = "findings.json"
    scan_manifest["producer"] = {"name": "Kiro Security", "version": "0.1.0"}
    target = {
        "targetId": target_id,
        "displayName": Path(scan["target_path"]).name,
    }
    if scan["mode"] == "diff":
        target.update(
            {
                "kind": "git_diff",
                "snapshotDigest": scan["target_snapshot_digest"],
                "baseRevision": scan["diff_base_revision"],
                "headRevision": scan["diff_head_revision"],
            }
        )
    elif scan["target_revision"] == "unversioned":
        target.update(
            {
                "kind": "directory_snapshot",
                "snapshotDigest": scan["target_snapshot_digest"],
            }
        )
    else:
        target.update(
            {
                "kind": "git_worktree",
                "revision": scan["target_revision"],
                "snapshotDigest": scan["target_snapshot_digest"],
            }
        )
    scan_manifest["target"] = target
    include_paths = coverage.get("includePaths")
    exclude_paths = coverage.get("excludePaths")
    if include_paths != [scan["scope"]] or not isinstance(exclude_paths, list):
        raise WorkbenchError(
            "coverage_scope_mismatch",
            "Coverage include/exclude paths must match the authoritative scan scope.",
        )
    scan_manifest["scope"] = {
        "includePaths": include_paths,
        "excludePaths": exclude_paths,
        "summary": "Kiro Security %s scan." % scan["mode"],
    }
    scan_manifest["threatModel"] = _project_threat_model(threat_model)
    manifest["documentType"] = "codex-security.scan-manifest"
    manifest["schemaVersion"] = "1.0"
    findings["documentType"] = "codex-security.findings"
    findings["schemaVersion"] = "1.0"
    findings["scanId"] = scan["id"]
    coverage["documentType"] = "codex-security.coverage"
    coverage["schemaVersion"] = "1.0"
    coverage["scanId"] = scan["id"]
    expected_mode = coverage_mode(scan)
    if coverage.get("mode") != expected_mode:
        raise WorkbenchError(
            "coverage_mode_mismatch",
            "Coverage mode must match the authoritative scan mode.",
        )


def _project_threat_model(threat_model):
    projected = {"summary": threat_model["summary"].strip()}
    for key in (
        "assets",
        "trustBoundaries",
        "attackerCapabilities",
        "securityObjectives",
        "assumptions",
    ):
        if key not in threat_model:
            continue
        values = []
        for item in threat_model[key]:
            if isinstance(item, str):
                values.append(item.strip())
                continue
            name = item["name"].strip()
            sensitivity = item.get("sensitivity")
            description = item.get("description")
            if sensitivity is not None:
                name = "%s (%s)" % (name, sensitivity.strip())
            if description is not None:
                name = "%s: %s" % (name, description.strip())
            values.append(name)
        projected[key] = values
    return projected


def materialize_coverage_receipts(root, coverage):
    seen = set()
    for index, surface in enumerate(coverage["surfaces"]):
        surface_id = surface.get("id")
        if not isinstance(surface_id, str) or not surface_id.strip():
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface requires an id.",
            )
        slug = re.sub(r"[^a-z0-9._-]+", "-", surface_id.lower()).strip("-")
        if not slug or slug in seen:
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface ids must produce unique safe receipt names.",
            )
        seen.add(slug)
        receipt = surface.pop("receipt", None)
        if not isinstance(receipt, dict):
            raise WorkbenchError(
                "invalid_coverage_receipt",
                "Coverage surface requires an embedded receipt object.",
            )
        receipt["surfaceId"] = surface_id
        relative = "artifacts/03_coverage/%03d-%s.json" % (index + 1, slug)
        write_output(root, relative, canonical_json_bytes(receipt))
        surface["receiptRefs"] = [relative]


def materialize_derived_writeups(root, findings, writeups):
    supplied_writeups = validate_derived_writeups(findings, writeups)
    for relative, markdown in supplied_writeups.items():
        write_output(root, relative, markdown.encode("utf-8"))


def materialize_derived_hardening(root, manifest, hardening):
    hardening_output = validate_derived_hardening(hardening)
    write_output(
        root,
        "hardening/hardening.md",
        hardening_output["markdown"].encode("utf-8"),
    )
    manifest["scan"]["hardening"] = {
        "portfolioPath": "hardening/hardening.md",
    }


def validate_derived_writeups(findings, writeups):
    finding_values = findings.get("findings", [])
    writeup_paths = {
        finding["writeup"]["reportPath"]
        for finding in finding_values
        if isinstance(finding.get("writeup"), dict)
    }
    supplied_writeups = {
        output["path"]: output["markdown"]
        for output in writeups["outputs"]
    }
    if set(supplied_writeups) != writeup_paths:
        raise WorkbenchError(
            "derived_writeup_mismatch",
            "Derived writeup outputs must exactly match canonical finding references.",
        )
    for relative, markdown in supplied_writeups.items():
        if (
            not relative.startswith("findings/")
            or len(Path(relative).parts) != 3
            or Path(relative).name != ("%s.md" % Path(relative).parent.name)
            or ".." in Path(relative).parts
        ):
            raise WorkbenchError(
                "invalid_derived_path",
                "Finding writeups must use findings/<slug>/<slug>.md.",
            )
    return supplied_writeups


def is_reportable_finding(finding):
    return finding.get("severity", {}).get("level") in REPORTABLE_SEVERITIES


def reportable_findings(findings):
    values = findings.get("findings", [])
    return [finding for finding in values if is_reportable_finding(finding)]


def findings_with_writeups(findings):
    values = findings.get("findings", [])
    return [
        finding
        for finding in values
        if isinstance(finding.get("writeup"), dict)
    ]


def validate_derived_hardening(hardening):
    hardening_outputs = hardening["outputs"]
    if len(hardening_outputs) != 1 or hardening_outputs[0]["path"] != (
        "hardening/hardening.md"
    ):
        raise WorkbenchError(
            "derived_hardening_mismatch",
            "Derived hardening must provide hardening/hardening.md.",
        )
    return hardening_outputs[0]


def write_output(root, relative, content):
    try:
        atomic_write(root, relative, content)
    except ArtifactContractError as exc:
        raise WorkbenchError(
            "unsafe_artifact_path",
            "Artifact output must stay under the scan directory.",
        ) from exc
