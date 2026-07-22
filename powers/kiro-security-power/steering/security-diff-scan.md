---
name: security-diff-scan
description: "Use when the user asks for a security review of a pull request, commit, branch diff, working-tree patch, or other Git-backed change set."
---

# Security Diff Scan

Used when a user wants to review a Git-backed change set for security regressions. Keep the scan phases separate and produce the final markdown report.

## Kiro chat-only scan start

Kiro starts Diff scans from chat only. Before substantive work, call `security_get_capabilities`, inspect the live native tool surface for `invoke_sub_agent` with `general-task-execution`, then call `security_start_scan` with `mode: "diff"` and the exact requested Diff target. Retain the one-time coordinator lease token and generation only in this top-level coordinator, following `POWER.md`; a busy lease makes the returned scan read-only until acquired. Immediately load `security_get_scan_context` and treat its immutable Diff target, revision/snapshot binding, SECURITY.md guidance path, rank input, artifact root, and canonical outputs as authoritative.

For a `commit` or `range` target, check out the requested head first and keep the worktree clean outside `.kiro/security-power`; the Engine rejects a different checked-out head or ambiguous local source bytes rather than reviewing one revision against another revision's files.

Run the bundled Kiro capability preflight with profile `security_diff_scan` using verified runtime facts. Continue only on a ready result. There is no app setup flow, dashboard start flow, or fallback scanner. If native delegation is unavailable, preserve the running scan and report the exact limitation; do not claim exhaustive Diff coverage.

## Phase Sequence

Keep these phases distinct and run them in linear order:

1. `$threat-model`
2. `$finding-discovery`
3. `$validation`
4. `$attack-path-analysis`
5. Generate final output

Treat this skill as the top-level orchestrator for the four skills plus the final report assembly step. Do not collapse the phases together.

For each phase:
1. Read that phase's skill.
2. Load only the inputs required for that phase.
3. Complete that phase's workflow and checklist.
4. Only then read the next phase's skill.

Do not read ahead into later-phase skills until the current phase has completed.
Do not amortize effort across phases: complete each phase to the full depth expected by that phase before moving on.
Treat explicit invocation of this exhaustive diff-scan workflow as the user's authorization to use the subagents required by the workflow. If subagents are unavailable in the current environment, explain the limitation instead of claiming exhaustive diff coverage.

## Goal Setup

After the chat-only start has returned a `scanId`, its authoritative context is loaded, and the `security_diff_scan` preflight is ready, create a Kiro goal for the scan if the runtime exposes goal tools and no active goal already covers this scan. The objective should state that the scan must not stop until the resolved diff-scoped files have been covered and the required coverage artifacts prove that closure.

Use objective wording shaped like:

`Run the Kiro Security Power diff scan for <resolved target>; do not stop until every diff-scoped file/worklist row has a completion receipt or explicit deferred closure, every candidate has required ledger receipts, and the final report is written.`

If a compatible active goal already exists, continue under it instead of creating a duplicate. If goal tools are unavailable, state the same coverage objective in the first visible scan update and continue.

Do not mark the goal complete until:

- every `deep_review_input.jsonl` row has a completion receipt in `work_ledger.jsonl`, or an explicit `deferred`, `not_applicable`, or `suppressed` closure with exact reason
- every candidate that reached discovery has the required discovery, validation, and attack-path ledger receipts, or an explicit deferred reason for the missing proof
- the final markdown report has been written to the resolved scan path

## Artifact Resolution

The path references in this skill are the default locations for this phase.
If the user explicitly provides a different path for a required input or output, use the user-provided path instead of the corresponding default path referenced in this skill.
If a required input is still missing, stop and ask the user for it before continuing.
Use the shared scan artifact path conventions in `../references/scan-artifacts.md`.

## Execution Plan

Start this plan only after the chat-only start loaded the authoritative scan context and the `security_diff_scan` capability preflight returned `ready`.

Follow this plan in order. Do not skip ahead to a later phase until the current phase has produced its intended output.

1. Resolve the Git-backed scan target, `repo_name`, `security_scans_dir`, `scan_id`, `scan_dir`, and `artifacts_dir` using `../references/scan-artifacts.md`.
2. Create or adopt the scan goal described in `Goal Setup` for that active scan context.
3. Read `../references/security-guidance.md`, compile the repository's policy to `<context_dir>/security_guidance.md`, and read it before threat modeling or inspecting source code.
4. Run `$threat-model` first.
  - Copy the repository-scoped threat model to the per-scan threat model path without alteration for auditability.
  - Treat the per-scan threat model path as the source of truth threat model for later phases.
5. Run `$finding-discovery` as the second step, against the resolved diff and using the per-scan threat model as context.
  - If discovery produces no technically plausible candidates, stop there, skip validation and attack-path analysis, complete the canonical JSON contract, and finalize the scan.
6. Run `$validation` as the third step, for each candidate that came out of discovery.
  - Pass the resolved diff scope, discovery notes, and candidate inventory to validation. Validation should preserve or suppress the provided instances; it should not independently broaden the review into a repository-wide scan.
  - Each candidate finding's `findings/<candidate_id>/candidate_ledger.jsonl` is part of the validation input. Every candidate finding that came out of discovery must have a discovery receipt before validation starts and a validation receipt before the scan can proceed to final reporting.
7. Run `$attack-path-analysis` as the fourth step, for findings that still need reportability, attack-path, and severity analysis after validation.
  - Each candidate finding's `findings/<candidate_id>/candidate_ledger.jsonl` is part of the attack-path input. Every candidate finding that reaches attack-path analysis must have an attack-path receipt before final reporting, even when the final decision is `ignore`, suppressed, or deferred.
8. Assemble the complete canonical JSON contract last using `../references/final-report.md`; do not author `report.md`.
  - Populate the optional structured details in `../references/finding-detail-fields.md` from the same validated evidence used in the generated report.
  - For every reportable finding, run `$vulnerability-writeup` with exactly one dedicated write-up sub-agent. Give it only that finding, its validation and attack-path evidence, relevant source paths and revision, PoC inputs, and the target output directory.
  - Write the derived report to `findings/<slug>/<slug>.md` with supporting PoC files under `findings/<slug>/poc/`. Verify the report is a regular file, then set that finding's `writeup.reportPath` to the matching safe relative path. Do not add the derived report to the sealed artifact list.
  - After every write-up is ready, run `$propose-security-hardening` once over the complete finding collection, detailed write-ups, threat model, coverage, and relevant source. Write its portfolio to `hardening/hardening.md`, its structured analysis to `hardening/hardening.json`, and any proposals and diagrams below `hardening/`. Verify `hardening/hardening.md` is a regular file, then set `scan.hardening.portfolioPath` to the fixed relative path `hardening/hardening.md`. Do not add these derived files to the sealed artifact list. Skip this step and omit `scan.hardening` when there are no reportable findings.
  - Complete the scan once with the current coordinator lease token and generation, after all write-ups, hardening guidance, and canonical JSON are ready, so finalization projects the validated JSON and derived-document links into `report.md`. In a standalone runtime without `security_complete_scan`, run `python -m kiro_security.codex_contract.finalize_scan_contract --scan-dir <scan_dir> --source-root <repo_root>` directly.

## Phase Scope

- Phase 1 (threat model generation) is repository-scope by default, unless the user explicitly asks for narrower scope or provides an authoritative threat model or sufficiently repository-specific security scan guidance such as `AGENTS.md`.
- Phase 2 onward (finding discovery, validation, attack path analysis) are diff-focused and should follow the changed code and its supporting files.

Treat this asymmetry as intentional:

- use the diff to locate the scan target for later phases
- do not let the diff bias Phase 1 threat model generation, if applicable
- do not let the touched subsystem become the repository threat model unless the user explicitly asks for that narrower scope

## Scan Target

Resolve the exact Git-backed diff before starting:

- PR: compare base branch against current `HEAD`
- commit: scan the target commit against its parent or requested baseline
- branch diff: scan the requested merge-base to head range
- local patch: scan staged and unstaged working-tree changes against the requested base

## Diff-Scoped Discovery

Use `../references/scan-artifacts-and-ledger.md` for the shared scoped file-review, candidate-ledger, subagent, and dedupe rules.

Diff scans should:

- use the immutable Engine-generated `rank_input.jsonl` or the direct `kiro_security.codex_contract.generate_rank_input` helper for the exact requested Diff target
- copy every Diff row into `deep_review_input.jsonl` with the direct helper; never rank away changed rows
- deep-review every file in `deep_review_input.jsonl`
- add directly supporting files only when repository evidence shows they are needed to understand the changed security behavior
- stay anchored to the changed code and directly supporting files rather than broadening into unrelated repository-wide enumeration

## Diff-Scoped Sibling Coverage

For PR, commit, branch, and local-patch scans, stay diff-focused but preserve repeated vulnerable instances that are created or affected by the same changed pattern.

Diff scans should:

- start from the changed files and the supporting files needed to understand the changed behavior
- expand from a changed route, handler, shared helper, guard, template pattern, query builder, serializer/deserializer, filesystem/network sink, config block, or wrapper to sibling instances that the diff also changes, newly reaches, or affects through the same modified shared dependency
- when the diff adds, removes, or reshapes a guard around an existing parser, deserializer, expression evaluator, filesystem/path helper, archive utility, or auth/authz helper, use the adjacent pre-existing sink/control as supporting context for the changed behavior; keep the candidate anchored to the changed guard or newly exposed path unless the user explicitly asks for wider instance expansion
- when a changed wrapper, guard, or API delegates to a shared parser/deserializer/path/archive/auth helper, keep both the wrapper call site and the underlying shared sink/control line addressable; do not replace the root sink/control evidence with wrapper-only evidence
- carry each vulnerable sibling instance through discovery and validation with its own affected location, source, closest control, sink, impact, and suppression evidence
- use unchanged siblings as context and negative controls, but report them only when the diff makes them newly vulnerable or changes the shared control or sink they depend on
- stop when the diff-linked pattern family is exhausted, rather than broadening into repository-wide enumeration

This keeps diff scans precise while avoiding the common failure mode where one representative route or sink hides additional vulnerable siblings introduced by the same patch.

## Final Output

Populate all final report semantics in the canonical manifest, findings, and coverage JSON using `../references/final-report.md`. Generate one detailed `vulnerability-writeup` for every reportable finding, then run `propose-security-hardening` once over the complete collection and record the safe derived-document paths. Complete the scan once after both stages; finalization owns `report.md` generation. Return the generated report and safe artifact links from the completed canonical findings. Commit scans use this same final-output contract because they are a diff-scan target type.

## Hard Rules

Read `../references/shared-hard-rules.md` before applying scan-mode-specific hard rules.

- After the chat-only start has provided a `scanId`, create or adopt the scan goal only after the capability preflight has returned `ready`, and before substantive scan work. Do not complete it until the resolved diff-scoped files/worklist rows, candidate ledgers, and final report meet the `Goal Setup` closure criteria.
- Do not claim diff coverage until every `deep_review_input.jsonl` row has a completion receipt in `work_ledger.jsonl`.
