CREATE TABLE engine_sessions (
    id TEXT PRIMARY KEY,
    pid INTEGER NOT NULL,
    client_kind TEXT NOT NULL,
    protocol_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    heartbeat_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE engine_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT REFERENCES scans(id) ON DELETE CASCADE,
    event_name TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

ALTER TABLE scans ADD COLUMN sealed_manifest_digest TEXT;
ALTER TABLE scans ADD COLUMN target_device INTEGER;
ALTER TABLE scans ADD COLUMN target_inode INTEGER;

CREATE TABLE scan_coordinator_leases (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash) = 64),
    generation INTEGER NOT NULL CHECK(generation >= 1),
    holder_session_id TEXT REFERENCES engine_sessions(id) ON DELETE SET NULL,
    acquired_at TEXT NOT NULL,
    renewed_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX events_by_scan_sequence ON engine_events(scan_id, sequence);
CREATE INDEX sessions_by_heartbeat ON engine_sessions(heartbeat_at);
CREATE INDEX coordinator_leases_by_expiry ON scan_coordinator_leases(expires_at);
