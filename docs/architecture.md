# Architecture

This is the normative technical design for the current product. Historical migration plans and parity scorecards are not product contracts. A runtime behavior that conflicts with this document is an implementation defect unless this document and the affected executable contracts are deliberately revised together.

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

A logical security workspace has a random UUID, optional durable task identity, one saved setup, a submitted bit, and a current-result pointer. Routine Engine or Extension registration only reads/adopts a workspace; it never writes Standard defaults over an existing setup. `security_start_scan` is Kiro's chat-only create/save/start facade: without `sessionId` it creates a new logical workspace, while a supplied `sessionId` resumes that workspace. Once the workspace has published its first scan, its setup is immutable; different mode, scope, context, or Diff input requires a new workspace. Deleting or cleaning up a scan result must not unlock the saved setup. The same submitted setup may be run again after a terminal result, replacing the pointer with the new scan.

Start stages the scan directory, credential-free target identity, immutable target snapshot, compiled guidance, deterministic worklists, and setup artifact digests before any running row exists. `BEGIN IMMEDIATE` then rechecks the workspace setup version and per-workspace running-scan invariant and copies the saved workspace columns directly into the scan row. The fully prepared running scan, progress, artifacts, current-result pointer, and first transient coordinator lease publish together. A losing race discards its unpublished staging directory and may return the winner read-only only when the winner has the same saved setup as the request; an incompatible winner is an error and must never be substituted as the requested scan. A partial unique index permits one running scan per logical workspace, while distinct workspaces for the same repository may run concurrently. Scan start launches no background analysis process. Context reads mode, scope, user context, resolved Diff data, target binding, and lifecycle exclusively from the scan row; there is no lifecycle JSON contract.

Scan lifecycle is workspace-owned and remains `running` across Engine shutdown or process loss. `active_scan_id` means the workspace's current scan/result, not merely a running scan; completion, failure, and cancellation keep that pointer. The pointer has `REFERENCES scans(id) ON DELETE SET NULL`, so explicit result cleanup clears the dangling result reference without clearing the workspace's submitted/setup-locked state. Execution authority is a separate expiring bearer lease: only its token holder may mutate progress or publish a terminal result, while all clients may read context. Token hashes alone are stored; renewal uses generation CAS; completion, failure, and cancellation delete the lease in the same transaction as the state transition. The token is an arbitration capability, not an OS filesystem boundary, so finalization still verifies artifact and publication digests. Cancel is cooperative at coordinator phase/worker boundaries. Complete reads fixed artifacts. Fail preserves partial artifacts as non-success.

The coordinator lease is an explicit Kiro shared-MCP transport adaptation. Logical workspace identity and optional task binding remain durable DB state; Engine process sessions do not own scan identity. The lease only arbitrates execution when the same SQLite workbench is exposed to multiple Kiro clients and does not change terminal lifecycle semantics or make process liveness authoritative.

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

The Engine contains no heuristic scanner, semantic validator, attack-path generator, or scan background runner. Standard, Diff, and Deep are chat/Power-only. The Dashboard remains a result and lifecycle consumer. Its selected-workspace projection is read from SQLite at request time, and that workspace's `active_scan_id` is the only authority for its current result. Repository-wide running/history lists may be shown separately but must not replace the selected workspace or result.
