CREATE TABLE deep_scan_state (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('awaiting_workers','awaiting_merge','saturated','capped')),
    current_round INTEGER NOT NULL DEFAULT 1 CHECK (current_round BETWEEN 1 AND 10),
    max_rounds INTEGER NOT NULL DEFAULT 10 CHECK (max_rounds BETWEEN 1 AND 10),
    workers_per_round INTEGER NOT NULL DEFAULT 6 CHECK (workers_per_round = 6),
    worklist_digest TEXT NOT NULL,
    worklist_json TEXT NOT NULL,
    canonical_candidates_json TEXT NOT NULL DEFAULT '[]',
    previous_candidate_count INTEGER NOT NULL DEFAULT 0,
    novelty_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE deep_workers (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    round_number INTEGER NOT NULL CHECK (round_number BETWEEN 1 AND 10),
    worker_index INTEGER NOT NULL CHECK (worker_index BETWEEN 1 AND 6),
    status TEXT NOT NULL CHECK (status IN ('pending','claimed','completed','failed')),
    claim_token TEXT,
    delegation_id TEXT,
    model_id TEXT,
    runtime_json TEXT,
    result_json TEXT,
    failure_message TEXT,
    claimed_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, round_number, worker_index),
    UNIQUE(scan_id, round_number, delegation_id)
);

CREATE TABLE deep_merge_records (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    round_number INTEGER NOT NULL CHECK (round_number BETWEEN 1 AND 10),
    status TEXT NOT NULL CHECK (status IN ('pending','claimed','completed')),
    claim_token TEXT,
    consumed_source_refs_json TEXT,
    canonical_candidates_json TEXT,
    novelty_count INTEGER,
    claimed_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, round_number)
);

CREATE INDEX deep_workers_by_scan_round ON deep_workers(scan_id, round_number, worker_index);
CREATE INDEX deep_merge_by_scan_round ON deep_merge_records(scan_id, round_number);
