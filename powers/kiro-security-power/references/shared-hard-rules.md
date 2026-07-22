# Shared Hard Rules

Apply these rules for every top-level Kiro Security Power scan workflow before the scan-mode-specific hard rules in that workflow:

- Keep the phases separate.
- Follow the execution plan in order.
- Use the tools to inspect the repository before making decisions.
- Candidate-finding coverage is required. Do not finalize a candidate finding until `findings/<candidate_id>/candidate_ledger.jsonl` shows discovery, validation, and attack-path receipts for that exact candidate, or an explicit deferred reason for the missing proof.
- Avoid destructive commands, interactive editors, and broad unbounded scans.
- Prefer targeted, reversible shell commands.
- `security_fail_scan` is terminal and cannot be continued. Use it only for an unrecoverable blocker after documented recovery is exhausted or when explicit cancellation instructions require it. Do not fail a scan merely because work remains, discovery or workers are still running, partial artifacts exist, or a turn, context window, or goal run is ending. Record meaningful progress and leave the durable scan running so a later coordinator can acquire the lease and continue.
- The top-level coordinator alone holds the transient scan lease token. Never pass it to a worker or write it to repository, artifact, report, event, log, provenance, or error content. A coordinator without the current token and generation has read-only access and must acquire the lease before any mutation.
- For Phase 1 fallback threat model generation, produce a repository-level threat model that would still make sense for an unrelated diff in the same repository.
- Do not let the current scan target bias Phase 1 unless the user explicitly requests a target-scoped threat model.
- For later phases, stay grounded in repository evidence and the actual in-scope code.
- Do not emit a finding unless it survives the final policy-adjustment pass.
