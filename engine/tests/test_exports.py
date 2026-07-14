from __future__ import annotations

from kiro_security.exports import build_sarif


def finding() -> dict:
    return {
        "findingId": "kspf_1",
        "occurrenceId": "occ_1",
        "ruleId": "command-injection.shell-execution",
        "fingerprint": "sha256:test",
        "title": "Command injection",
        "summary": "Untrusted input reaches a shell.",
        "severity": {"level": "critical"},
        "confidence": {"level": "high"},
        "validationStatus": "validated",
        "triageStatus": "open",
        "taxonomy": {"category": "command-injection", "cwe": ["CWE-78"]},
        "locations": [
            {"path": "src/app.py", "startLine": 3, "endLine": 3, "role": "source"},
            {"path": "src/app.py", "startLine": 4, "endLine": 4, "role": "sink"},
        ],
        "remediation": "Avoid the shell.",
    }


def test_sarif_mapping_preserves_rule_severity_and_locations() -> None:
    sarif = build_sarif([finding()])
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Kiro Security Power"
    result = run["results"][0]
    assert result["level"] == "error"
    assert result["ruleId"] == "command-injection.shell-execution"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["properties"]["findingId"] == "kspf_1"
