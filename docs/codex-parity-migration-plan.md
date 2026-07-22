# Codex Security 0.1.11 plugin-layer parity migration

Status: **ready_for_kiro_smoke is the next gate; migration is not approved complete before real Kiro Desktop evidence.**

Authoritative specification: local Codex Security plugin 0.1.11 top-level workflows, phase skills, shared contracts, schemas, and deterministic finalizer/workbench scripts, with only the approved Kiro differences: `invoke_sub_agent`, `general-task-execution`, four concurrent workers, five Deep rounds, Kiro naming, workspace-local artifacts, and chat-only starts.

## Implemented local structure

- Power routes Standard, Diff, and Deep independently and progressively loads threat model, discovery, validation, attack path, writeup, and hardening.
- Standard and Diff use static row/file/candidate ownership. Deep uses four fresh identical-brief full-worklist workers and coordinator-owned semantic merge/novelty.
- Native capability is checked by the coordinator; Engine capabilities contain no worker/self-proof fields.
- Engine model orchestration files and worker/merge/tail DB tables and MCP methods were removed.
- Scan start creates deterministic context/worklists without a background analysis process.
- Context/progress/coordinator acquire-renew-release/cancel/complete/fail are lifecycle-only.
- Agent-authored canonical JSON and semantic evidence are authoritative; Engine validates and seals without semantic normalization.
- Canonical finding identity excludes line numbers and workflow provenance.
- Every emitted candidate is bound through raw/deduped artifacts and candidate-ledger phase receipts; non-reportable audit chains are preserved.
- Coverage distinguishes complete/partial/unknown and uses safe artifact receipts.
- The readable report is regenerated only from the sealed manifest, findings, and coverage documents; writeups and hardening remain unsealed derived artifacts.
- Zero findings omits writeup/hardening; ignored/deferred audit evidence remains outside reportable findings.
- The legacy heuristic analysis path, profile split, background runner, and related UI/MCP commands are removed; general result, triage, remediation, tracking, and export capabilities remain.

## Removed pre-release design

The prior Engine-owned worker jobs, claims, merge records, semantic merge/novelty, model result normalization, per-finding downstream assignments, completion markers, and background runner were pre-release designs and have no compatibility path. Migration files 007 and 009 and the untracked 011 were removed; 008 now defines only the scan-level coverage ledger.

## Remaining approval gate

Run the complete Desktop prompt in `local-kiro-smoke-test.md`. Independently inspect retained artifacts, SQLite schema/readback, report, tool surface, target diff, and logs. Any P0/P1 returns the same goal to fixing. Do not mark parity complete merely from compile, local smoke, or a Power self-report.
