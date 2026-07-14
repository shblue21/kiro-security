# Deep security scan

Deep mode is an Agent-orchestrated repeated discovery workflow. It is not the Standard deterministic scanner with extra passes.

1. Start with `security_start_scan` using `mode: "deep"` and preserve the exact requested scope.
2. Poll `security_deep_get_status`. When `nextAction` is `claim_worker`, run exactly six independent discovery workers for the current round.
3. For each worker, call `security_deep_claim_worker` with:
   - the same selected model identity for all six workers in a round;
   - a fresh unique `delegationId`;
   - runtime metadata that records the Agent/host/reasoning configuration.
4. Treat the returned `brief`, security guidance, and authoritative exhaustive worklist as the complete assignment. Do not expose prior workers or merge output to the worker. Do not edit repository files.
5. Each worker must independently generate a threat model, inspect every worklist row, and return exhaustive `reviewedPaths` plus evidence-grounded candidates. Candidate locations must use `{label, path, lines}` and include concrete source/root-control/sink evidence and remediation.
6. Submit each completed result with `security_deep_submit_worker_result`. Do not fabricate receipts. Use `security_deep_retry_worker` only for an incomplete worker; completed worker artifacts are immutable.
7. After all six workers complete, call `security_deep_claim_merge`. Perform semantic merging neutrally:
   - consume every current `sourceRef` exactly once;
   - preserve every prior canonical candidate;
   - merge only when one remediation closes every upstream candidate;
   - keep independently reachable sibling instances separate.
8. Submit with `security_deep_submit_merge`. If novelty is non-zero, repeat with six fresh workers in the new round. Stop only when a complete round adds zero new canonical candidates, or when round 10 is explicitly capped.
9. After `nextAction` becomes `wait_for_central_validation`, poll `security_get_scan` while the shared engine performs centralized validation, attack-path analysis, and reporting.
10. Read final evidence through `security_list_findings` and `security_get_finding`. Clearly report any capped or deferred coverage.

Never substitute Standard scan output when Deep orchestration cannot be completed. Report the orchestration limitation instead.
