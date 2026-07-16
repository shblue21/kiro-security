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
    worker_id TEXT,
    receipt_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, row_id)
);

CREATE TABLE deep_worker_coverage_receipts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL REFERENCES deep_workers(id) ON DELETE CASCADE,
    round_number INTEGER NOT NULL CHECK (round_number BETWEEN 1 AND 10),
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
    UNIQUE(worker_id, row_id)
);

CREATE INDEX coverage_ledger_by_scan_path ON coverage_ledger(scan_id, path, row_id);
CREATE INDEX deep_worker_coverage_by_scan_round ON deep_worker_coverage_receipts(scan_id, round_number, row_id);
