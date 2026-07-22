# Local and Kiro Desktop smoke test

Local gates do not replace Desktop native-subagent evidence.

## Local checks

- `python3 -m compileall -q engine`
- parse every Engine Python file with Python 3.9 grammar
- `npm run lint` and Node unit/contract tests
- fresh migration schema contains no model workflow tables
- scan start/context creates worklists and no background analysis process
- concurrent identical starts return one fully prepared workspace running scan; incompatible mode/scope/Diff/limit/context requests fail; lease handoff or takeover cannot create a second running row; orphan pointers and direct SQL bypass fail closed
- four simultaneous fresh-DB initializers all observe the same complete migration version without partial-schema errors
- zero- and one-finding canonical completion/index/report/SARIF seal
- pre/post-finalizer target validation, post-finalizer manifest/artifact mutation rejection, future manifest timestamp isolation from DB lifecycle timestamps, and single-authorized-winner concurrent completion
- raw/deduped candidate, worker-local ledger, validation/attack receipt, and coverage projection binding
- report regeneration from sealed manifest/findings/coverage only
- manifest-bound coverage-receipt tamper rejection
- hostile symlink and target-drift rejection
- `git diff --check` and removed-contract search

If the environment lacks existing test dependencies, do not install them; record the collection gap and run dependency-free focused smokes.

Before Desktop testing, build the current VSIX with `npm run package`, record its printed SHA-256, and install that exact file. Run the extension's Agent Integration repair/preparation action, copy its prepared Power folder, and verify it contains `POWER.md`, every phase steering file, and all five files below `references/`. Then use **Powers → Add Custom Power → Import power from a folder**, install that exact prepared folder, return to Setup, and select **Verify after import**. Do not begin the prompt unless Setup detects the namespaced native-Power MCP registration and reports `Verified`; a direct MCP probe is insufficient. Start a new Kiro Agent conversation after verification. Do not reuse an older installed Power directory.

## Self-contained Kiro Desktop prompt

```text
Use the installed Kiro Security Power and its current workspace Power. This is an acceptance test, not a request to trust implementation claims.

Keep one scan-local Goal/Task List active through final completion. Do not edit target source, install dependencies, substitute another analysis path, or use any result-submit/planner API.

1. Capability
- Inspect the actual Kiro tools and directly confirm invoke_sub_agent plus general-task-execution.
- Call security_get_capabilities and verify it reports only Engine/Python/SQLite/Git/workspace/supported modes/canonical finalizer facts, with no worker capacity, fresh-context, profile, or completion self-proof.
- In the first required Deep batch issue four invoke_sub_agent calls in one parallel block and record actual starts/completions. If all fail before start with the same sender-thread resolution error, retry the whole batch once. A partial batch is not complete.

2. Standard
- Start a Standard scan and load context.
- Show deterministic rank/file/tiny-shard ownership with no duplicated authoritative row.
- Execute threat model, discovery, reconciliation, validation, attack path, coordinator canonical assembly, dedicated writeups, one collection hardening task, and one-shot completion as separate phases.
- Verify findings/coverage/manifest/report and DB readback. No alternate analysis fallback.
- Verify every emitted candidate remains linked through raw/deduped artifacts and candidate-ledger phase receipts, including suppressed/deferred candidates that do not appear as reportable findings.

3. Diff
- Create or select an exact working-tree/commit/range target without changing it during the successful run.
- Verify resolved base/head, changed/deleted/renamed behavior, bounded directly supporting context, preserved wrapper and real sink/control, and no repository-wide enumeration.
- In a separate disposable scan, mutate the target after start and verify completion is blocked for drift.
- Complete a clean Diff scan canonically.

4. Deep zero-candidate
- Start Deep and inspect otherRunningDeepScans exactly once before substantive work; if another exists, ask Continue/Cancel.
- Run exactly four fresh workers with independent threat models, identical shared worklists/briefs, and worker-local artifacts.
- Wait for all four to return and become idle before semantic merge.
- Preserve all worker and coverage ledgers, create canonical no-findings discovery/coverage/findings/manifest, omit writeups and hardening, then complete.
- Confirm each emitted worker candidate has a worker-local discovery receipt; an empty candidate set must still retain all four complete worker artifact sets.

5. Deep multi-round
- Use a target where round 1 yields semantic novelty.
- Launch a fresh four-worker round 2 with no prior worker/coordinator result state in prompts.
- Demonstrate coordinator-owned semantic merge using remediation-subsumption and preservation of independent instances/counterevidence/proof gaps.
- Continue to a complete zero-novelty round or explicit round-5 cap; cap must be partial/deferred.

6. One finding
- On one reportable candidate, verify canonical validation threat model, exact source/control/sink/impact, strongest counterevidence, validation receipt, attack-path/policy receipt, severity/reportability separation, one dedicated writeup, one collection hardening output, canonical assembly, completion, and DB finding readback.
- Verify final report is reproducible from sealed manifest/findings/coverage and contains no worker IDs, recurrence, round or merge bookkeeping, internal goal, or novelty calculation.

7. Resume/cancel
- Release the coordinator lease after a completed phase. From a second coordinator, acquire the same durable running scan, continue from immutable artifacts after target revalidation, reuse completed phases, and rerun only the incomplete phase. Confirm no worker assignment or process-session ownership recovery.
- Cancel another active scan and confirm cooperative terminal cancellation; partial artifacts are not promoted.

8. Negative surface and state
- tools/list contains no model plan/checkpoint/status or worker/merge/downstream result-submit APIs.
- Fresh SQLite schema contains no model worker, round, merge, receipt, or assignment tables.
- No target source was modified. No alternate analysis fallback occurred.
- Complete accepts only scanId and reads fixed artifacts.

Return: Kiro version, OS, installed extension version and VSIX SHA-256, exact scan IDs, mode/target for each run, native four-call start/completion evidence, artifact root paths, canonical manifest digest, SQLite table list and finding readback, final reports, coordinator lease handoff/cancel evidence, errors/limitations, and a PASS/FAIL row for every item above. Preserve artifacts and logs for independent review; do not summarize away failures.
```

Real Desktop PASS requires independent inspection of supplied artifacts, DB schema/readback, reports, logs, and target diff. Screenshots are supplementary only.
