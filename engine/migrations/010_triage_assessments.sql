CREATE TABLE triage_assessments (
    id TEXT PRIMARY KEY,
    occurrence_id TEXT REFERENCES finding_occurrences(id) ON DELETE CASCADE,
    input_id TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN (
        'sarif','cve','advisory','scanner_ticket','bug_bounty',
        'codex_security_finding','freeform','unknown'
    )),
    status TEXT NOT NULL CHECK (status IN ('pending','completed','failed')),
    intake_json TEXT NOT NULL,
    result_json TEXT,
    result_digest TEXT,
    intake_artifact_path TEXT NOT NULL,
    result_artifact_path TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX triage_assessments_by_occurrence
ON triage_assessments(occurrence_id, created_at DESC);

CREATE INDEX triage_assessments_by_status
ON triage_assessments(status, created_at);

ALTER TABLE tracking_records ADD COLUMN readback_digest TEXT;
ALTER TABLE tracking_records ADD COLUMN readback_artifact_path TEXT;
ALTER TABLE tracking_records ADD COLUMN payload_artifact_path TEXT;
