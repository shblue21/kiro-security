# Architecture

Kiro Security Power has three deliberately separate layers.

```text
Kiro chat Power coordinator
  -> fresh native Kiro subagents
  -> phase artifacts and ledgers
  -> coordinator semantic merge / novelty / policy
  -> coordinator canonical JSON assembly
  -> one-shot Engine validation, projection, index, and seal
```

The extension owns process lifecycle, workbench UI, findings/report consumption, triage, remediation, tracking, and export. The Python Engine owns deterministic inventory/worklists, scan lifecycle, canonical verification, projection, indexing, and sealing. The Power owns every semantic phase.

## Scan lifecycle

The lifecycle MCP surface is `security_get_capabilities`, `security_start_scan`, `security_acquire_scan_coordinator`, `security_renew_scan_coordinator`, `security_release_scan_coordinator`, `security_get_scan_context`, `security_update_scan_progress`, `security_get_scan`, `security_get_progress`, `security_cancel_scan`, `security_complete_scan`, and `security_fail_scan`. Existing finding, triage, remediation, tracking, and export tools remain adjacent product capabilities.

A scan start canonicalizes its immutable request contract (mode, scope, Diff target, limits, and user context). A running scan without a complete stored `startContract` fails closed as `legacy_scan_incompatible`; no defaults are synthesized. An existing running scan is returned only for an identical contract; incompatible requests fail with `scan_already_running`. Otherwise the Engine stages the scan directory, stable credential-free repository/workspace target ID, immutable per-scan snapshot, compiled guidance, deterministic worklists, and setup artifact digests before any running row exists. `BEGIN IMMEDIATE` then rechecks the workspace invariant and publishes the fully prepared running scan, progress, artifacts, active pointer, and first transient coordinator lease together; a losing identical race discards its unpublished staging directory and returns the winner read-only. A partial unique index on running scan rows is the final database guard. Scan start launches no background analysis process. Context returns target ID, snapshot and Diff metadata, artifact/input/output paths, lifecycle progress, and other running Deep lifecycles. It returns no jobs, next action, candidate body, round/merge state, or analysis profile.

Scan lifecycle is workspace-owned and remains `running` across Engine shutdown or process loss. Execution authority is a separate expiring bearer lease: only its token holder may mutate progress or publish a terminal result, while all clients may read context. Token hashes alone are stored; renewal uses generation CAS; completion, failure, and cancellation delete the lease in the same transaction as the state transition. The token is an arbitration capability, not an OS filesystem boundary, so finalization still verifies artifact and publication digests. Cancel is cooperative at coordinator phase/worker boundaries. Complete reads fixed artifacts. Fail preserves partial artifacts as non-success.

The coordinator lease is an explicit Kiro shared-MCP transport adaptation. Codex binds a workbench to one coordinating thread; Kiro can expose the same workspace DB to multiple Engine clients. The lease restores that single-coordinator execution invariant without adding a scan owner, changing terminal lifecycle semantics, or making Engine process liveness authoritative.

## Skill-driven workflows

Standard, Diff, and Deep are independent top-level steering documents. The coordinator progressively loads only the current phase method. Fresh prompts repeat objective, target, inputs, hard rules, output ownership, and closure checklist because subagents do not inherit Power or coordinator history.

Standard assigns deterministic ranking shards, files/tiny shards, candidates, attack rows, writeups, and one collection hardening task. Diff uses exact changed-file/tiny-shard ownership and bounded directly supporting context. Deep launches four fresh identical-brief full-worklist discovery workers per complete round, merges only after the four-worker barrier, compares semantic novelty, and stops at zero novelty or round five with partial coverage.

The Engine never schedules workers, merges candidates, computes novelty, creates validation/attack semantics, assigns writeups, or decides the next phase.

## Artifact and canonical boundaries

Scan artifacts use phase directories below `artifacts/01_context` through `artifacts/05_findings`, Deep worker directories below `deep_discovery/round-NN/worker-NN`, reportable writeups below `findings/<slug>/`, and collection hardening below `hardening/`.

`findings.json`, `coverage.json`, and sealed `scan-manifest.json` are immutable canonical observations. They contain semantic identity and evidence, not workflow rows. `report.md`, SARIF, writeups, and hardening are derived/supporting artifacts. Mutable triage/remediation/tracking state remains in SQLite.

Completion holds an OS-backed scan-scoped lock, revalidates the immutable target before and after finalization, verifies the returned manifest binding and published manifest/artifact bytes, then immediately enters the SQLite completion transaction. That transaction creates one Engine-owned timestamp after `BEGIN IMMEDIATE`; the manifest's Agent-authored `completedAt` remains canonical document content and never controls scan, progress, artifact, finding, or workspace lifecycle timestamps. The transaction then rechecks the running state, replaces the official artifact/finding indexes, and commits the reporting phase, completion status, and seal digest together. A failed post-finalize target or publication check leaves the scan running without a durable seal or completed indexes; generated projections remain unofficial files. The finalizer also validates strict JSON schemas, deterministic finding fingerprint/ID binding, safe regular-file paths, coverage receipt references, writeup/hardening file availability, and immutable setup artifacts. It does not infer candidate terminal states, coverage frontier semantics, validation, attack paths, or reportability: the Power's phase gates own those decisions before `security_complete_scan`.

## Workbench

The DB retains workspaces, scans, progress, artifacts, findings/occurrences/locations/evidence, events, triage, remediation, tracking, exports, and a scan-level coverage ledger. It contains no worker, round, merge, or assignment tables. Phase artifacts are continuation authority after coordinator lease handoff; progress rows are not.

## UI boundary

The Engine contains no heuristic scanner, semantic validator, attack-path generator, or scan background runner. Standard, Diff, and Deep are chat/Power-only. The Dashboard remains a result and lifecycle consumer.
