CREATE TABLE tracking_records (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    destination TEXT NOT NULL,
    external_id TEXT,
    external_url TEXT,
    payload_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX tracking_by_occurrence ON tracking_records(occurrence_id, created_at DESC);
