CREATE TABLE finding_evidence (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    relative_path TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    language TEXT,
    role TEXT,
    snippet TEXT NOT NULL,
    explanation TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE validation_records (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK (status IN ('validated','rejected','needs_review')),
    method TEXT NOT NULL,
    rationale TEXT NOT NULL,
    evidence_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE TABLE attack_paths (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL UNIQUE REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    narrative TEXT NOT NULL,
    path_json TEXT NOT NULL,
    exploitability TEXT NOT NULL,
    impact TEXT NOT NULL,
    severity_rationale TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE triage_decisions (
    occurrence_id TEXT PRIMARY KEY REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    decision TEXT NOT NULL CHECK (decision IN ('open','accepted_risk','false_positive','already_fixed','wont_fix')),
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE remediation_records (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT NOT NULL REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('requested','generated','applied','verifying','verified','failed','superseded')),
    version INTEGER NOT NULL CHECK (version >= 1),
    summary TEXT,
    artifact_path TEXT,
    patch_digest TEXT,
    verification_summary TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(occurrence_id, version)
);

CREATE INDEX evidence_by_occurrence ON finding_evidence(occurrence_id, created_at);
CREATE INDEX validation_by_occurrence ON validation_records(occurrence_id, created_at DESC);
CREATE INDEX remediation_by_occurrence ON remediation_records(occurrence_id, version DESC);
