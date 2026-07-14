import test from "node:test";
import assert from "node:assert/strict";
import { filterAndSortFindings, progressLabel } from "../packages/webview/src/state";

const findings = [
  { title: "Low path issue", summary: "path traversal", severity: { level: "low" }, confidence: { level: "high" }, validationStatus: "validated", triageStatus: "open", taxonomy: { category: "path-traversal" }, locations: [{ path: "src/path.py" }], updatedAt: "2026-01-01T00:00:00Z" },
  { title: "Critical command issue", summary: "command injection", severity: { level: "critical" }, confidence: { level: "medium" }, validationStatus: "needs_review", triageStatus: "open", taxonomy: { category: "command-injection" }, locations: [{ path: "src/app.py" }], updatedAt: "2026-02-01T00:00:00Z" },
  { title: "Medium SQL issue", summary: "SQL injection", severity: { level: "medium" }, confidence: { level: "high" }, validationStatus: "validated", triageStatus: "accepted_risk", taxonomy: { category: "sql-injection" }, locations: [{ path: "src/db.py" }], updatedAt: "2026-03-01T00:00:00Z" },
];

test("finding filters combine search and lifecycle status", () => {
  const result = filterAndSortFindings(findings, { query: "sql", severity: "", confidence: "high", validation: "validated", triage: "accepted_risk", sort: "severity" });
  assert.equal(result.length, 1);
  assert.equal(result[0].title, "Medium SQL issue");
});

test("severity sorting is deterministic", () => {
  const result = filterAndSortFindings(findings, { query: "", severity: "", confidence: "", validation: "", triage: "", sort: "severity" });
  assert.deepEqual(result.map((finding) => finding.severity.level), ["critical", "medium", "low"]);
});

test("progress labels normalize phases and clamp percentages", () => {
  assert.equal(progressLabel("attack_path", 41.6), "Attack path · 42%");
  assert.equal(progressLabel("reporting", 120), "Reporting · 100%");
});
