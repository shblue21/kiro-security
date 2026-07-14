CREATE TABLE hardening_proposals (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE export_records (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format TEXT NOT NULL CHECK (format IN ('json','csv','sarif','markdown')),
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX exports_by_scan ON export_records(scan_id, created_at DESC);
