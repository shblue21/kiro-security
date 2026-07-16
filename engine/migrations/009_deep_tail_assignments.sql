CREATE TABLE deep_tail_assignments (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('threat_model','validation','attack_path','writeup','hardening')),
    subject_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','claimed','completed','failed')),
    attempt INTEGER NOT NULL DEFAULT 1 CHECK (attempt >= 1),
    previous_assignment_id TEXT REFERENCES deep_tail_assignments(id),
    previous_receipt_digest TEXT,
    claim_token TEXT,
    delegation_id TEXT,
    model_id TEXT,
    runtime_json TEXT,
    payload_json TEXT NOT NULL,
    result_json TEXT,
    completion_json TEXT,
    receipt_digest TEXT,
    failure_message TEXT,
    claimed_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, kind, subject_id, attempt),
    UNIQUE(scan_id, delegation_id)
);

CREATE UNIQUE INDEX deep_tail_one_active_subject
ON deep_tail_assignments(scan_id, kind, subject_id)
WHERE status IN ('pending','claimed');

CREATE INDEX deep_tail_by_scan_kind
ON deep_tail_assignments(scan_id, kind, status, created_at);
