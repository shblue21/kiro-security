CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    root_path TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    default_scope TEXT NOT NULL DEFAULT '.',
    default_mode TEXT NOT NULL DEFAULT 'standard' CHECK (default_mode IN ('diff','standard','deep')),
    active_scan_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    mode TEXT NOT NULL CHECK (mode IN ('diff','standard','deep')),
    scope TEXT NOT NULL,
    diff_target_kind TEXT CHECK (diff_target_kind IN ('working_tree','commit','range')),
    diff_base_revision TEXT,
    diff_head_revision TEXT,
    status TEXT NOT NULL CHECK (status IN ('running','completed','cancelled','failed')),
    phase TEXT NOT NULL CHECK (phase IN ('preflight','threat_model','discovery','validation','attack_path','reporting')),
    phase_index INTEGER NOT NULL DEFAULT 0 CHECK (phase_index BETWEEN 0 AND 5),
    artifact_dir TEXT NOT NULL UNIQUE,
    target_identity TEXT,
    target_revision TEXT,
    snapshot_digest TEXT,
    cancellation_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancellation_requested IN (0,1)),
    failure_code TEXT,
    failure_message TEXT,
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE scan_progress (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    phase_percent REAL NOT NULL DEFAULT 0 CHECK (phase_percent >= 0 AND phase_percent <= 100),
    overall_percent REAL NOT NULL DEFAULT 0 CHECK (overall_percent >= 0 AND overall_percent <= 100),
    review_items_total INTEGER NOT NULL DEFAULT 0 CHECK (review_items_total >= 0),
    review_items_completed INTEGER NOT NULL DEFAULT 0 CHECK (review_items_completed >= 0),
    reportable_findings_count INTEGER NOT NULL DEFAULT 0 CHECK (reportable_findings_count >= 0),
    message TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE scan_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(scan_id, kind)
);

CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL,
    identity_anchor TEXT NOT NULL,
    identity_instance TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE finding_occurrences (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES findings(id),
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
    severity_score REAL,
    severity_rationale TEXT,
    confidence TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
    confidence_rationale TEXT NOT NULL,
    category TEXT NOT NULL,
    cwe_json TEXT NOT NULL DEFAULT '[]',
    remediation TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    validation_status TEXT NOT NULL DEFAULT 'unvalidated' CHECK (validation_status IN ('unvalidated','validated','rejected','needs_review')),
    triage_status TEXT NOT NULL DEFAULT 'open' CHECK (triage_status IN ('open','accepted_risk','false_positive','already_fixed','wont_fix')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(scan_id, finding_id)
);

CREATE TABLE finding_locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    relative_path TEXT NOT NULL,
    start_line INTEGER NOT NULL CHECK (start_line >= 1),
    end_line INTEGER NOT NULL CHECK (end_line >= start_line),
    role TEXT NOT NULL,
    sort_order INTEGER NOT NULL CHECK (sort_order >= 0),
    UNIQUE(occurrence_id, sort_order)
);

CREATE INDEX scans_by_workspace_updated ON scans(workspace_id, updated_at DESC);
CREATE UNIQUE INDEX scans_one_running_per_workspace
ON scans(workspace_id)
WHERE status = 'running';
CREATE INDEX occurrences_by_scan ON finding_occurrences(scan_id, severity, updated_at DESC);
