from __future__ import annotations

MODES = ("diff", "standard", "deep")
PHASES = ("preflight", "threat_model", "discovery", "validation", "attack_path", "reporting")
SCAN_STATUSES = ("queued", "running", "interrupted", "completed", "cancelled", "failed")
ACTIVE_SCAN_STATUSES = ("queued", "running")
TERMINAL_SCAN_STATUSES = ("completed", "cancelled", "failed")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
CONFIDENCES = ("high", "medium", "low")
VALIDATION_STATUSES = ("unvalidated", "validated", "rejected", "needs_review")
TRIAGE_DECISIONS = ("open", "accepted_risk", "false_positive", "already_fixed", "wont_fix")
REMEDIATION_STATES = ("requested", "generated", "applied", "verifying", "verified", "failed", "superseded")
EXPORT_FORMATS = ("json", "csv", "sarif", "markdown")
PROTOCOL_VERSION = "1.0"
PRODUCT_NAME = "Kiro Security Power"
ARTIFACT_KINDS = {
    "manifest": "scan-manifest.json",
    "coverage": "coverage.json",
    "findings": "findings.json",
    "markdownReport": "report.md",
    "threatModel": "threat-model.md",
    "discovery": "discovery.json",
    "validation": "validation.json",
    "attackPath": "attack-path.json",
    "hardening": "hardening/hardening.md",
}
DEFAULT_IGNORES = {
    ".git", ".hg", ".svn", ".kiro", ".idea", ".vscode", "node_modules", "vendor",
    "dist", "build", "out", "target", ".next", ".nuxt", ".venv", "venv", "env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".tox", "coverage", "playwright-report",
}
SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".java", ".go",
    ".rb", ".php", ".cs", ".rs", ".sh", ".bash", ".zsh", ".kt", ".kts", ".scala",
}
