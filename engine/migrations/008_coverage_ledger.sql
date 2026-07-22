CREATE TABLE coverage_ledger (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    row_id TEXT NOT NULL,
    path TEXT NOT NULL,
    surface TEXT NOT NULL,
    entrypoint TEXT,
    root_control TEXT,
    sink TEXT,
    disposition TEXT NOT NULL CHECK (disposition IN ('reportable','suppressed','not_applicable','deferred')),
    reason TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    candidate_ids_json TEXT NOT NULL DEFAULT '[]',
    receipt_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, row_id)
);

CREATE INDEX coverage_ledger_by_scan_path ON coverage_ledger(scan_id, path, row_id);
