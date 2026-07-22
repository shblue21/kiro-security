-- Codex Security 0.1.11 lifecycle invariant: one running scan per workspace.
-- Existing duplicate running rows intentionally make this migration fail closed;
-- this migration performs no legacy backfill or state reinterpretation.
CREATE UNIQUE INDEX IF NOT EXISTS scans_one_running_per_workspace
ON scans(workspace_id)
WHERE status = 'running';
