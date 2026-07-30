"""Fresh schema and forward migration foundation."""

SCHEMA_VERSION = 1

MIGRATIONS = (
    (
        1,
        "fresh trusted Kiro chat security workbench",
        (
            """
            CREATE TABLE workspaces (
                id TEXT PRIMARY KEY,
                target_path TEXT,
                target_title TEXT,
                target_summary TEXT,
                default_scope TEXT NOT NULL DEFAULT '.',
                default_mode TEXT NOT NULL
                    CHECK (default_mode IN ('diff', 'standard', 'deep')),
                user_context TEXT,
                diff_target_kind TEXT
                    CHECK (diff_target_kind IN ('working_tree', 'commit', 'range')),
                diff_base_revision TEXT,
                diff_head_revision TEXT,
                diff_content_digest TEXT,
                diff_resolution_id TEXT,
                capability_preflight_json TEXT,
                submitted INTEGER NOT NULL DEFAULT 0 CHECK (submitted IN (0, 1)),
                setup_revision INTEGER NOT NULL DEFAULT 0
                    CHECK (setup_revision >= 0),
                owner_session_hash TEXT NOT NULL,
                active_scan_id TEXT REFERENCES scans(id) ON DELETE SET NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
                owner_session_hash TEXT NOT NULL,
                target_path TEXT NOT NULL,
                target_revision TEXT NOT NULL,
                target_snapshot_digest TEXT,
                target_device INTEGER,
                target_inode INTEGER,
                scope TEXT NOT NULL,
                mode TEXT NOT NULL CHECK (mode IN ('diff', 'standard', 'deep')),
                user_context TEXT,
                diff_target_kind TEXT
                    CHECK (diff_target_kind IN ('working_tree', 'commit', 'range')),
                diff_base_revision TEXT,
                diff_head_revision TEXT,
                diff_content_digest TEXT,
                scan_dir TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
                phase TEXT NOT NULL CHECK (
                    phase IN (
                        'preflight',
                        'threat_model',
                        'discovery',
                        'validation',
                        'attack_path',
                        'reporting'
                    )
                ),
                failure_message TEXT,
                canceled_at TEXT,
                seal_manifest_digest TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                CHECK (
                    (mode = 'diff' AND diff_target_kind IS NOT NULL)
                    OR (mode != 'diff' AND diff_target_kind IS NULL)
                )
            )
            """,
            """
            CREATE TABLE scan_progress (
                scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
                review_items_total INTEGER NOT NULL DEFAULT 0
                    CHECK (review_items_total >= 0),
                review_items_completed INTEGER NOT NULL DEFAULT 0
                    CHECK (
                        review_items_completed >= 0
                        AND review_items_completed <= review_items_total
                    ),
                reportable_findings_count INTEGER NOT NULL DEFAULT 0
                    CHECK (reportable_findings_count >= 0),
                deep_review_pass INTEGER
                    CHECK (deep_review_pass IS NULL OR deep_review_pass >= 1),
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE UNIQUE INDEX scans_one_running_per_workspace
            ON scans(workspace_id)
            WHERE status = 'running'
            """,
            """
            CREATE INDEX scans_by_workspace_and_created_at
            ON scans(workspace_id, created_at DESC)
            """,
            """
            CREATE TABLE chat_attestations (
                nonce TEXT PRIMARY KEY,
                session_hash TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE scan_artifacts (
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                kind TEXT NOT NULL CHECK (
                    kind IN ('coverage', 'findings', 'manifest', 'markdownReport')
                ),
                path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (scan_id, kind)
            )
            """,
            """
            CREATE TABLE findings (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                rule_id TEXT NOT NULL,
                identity_anchor TEXT NOT NULL,
                identity_instance TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE finding_occurrences (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('critical', 'high', 'medium', 'low', 'informational')
                ),
                confidence TEXT NOT NULL,
                remediation TEXT,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE (scan_id, finding_id)
            )
            """,
            """
            CREATE INDEX finding_occurrences_by_scan_and_severity
            ON finding_occurrences(scan_id, severity, finding_id)
            """,
            """
            CREATE TABLE finding_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurrence_id TEXT NOT NULL
                    REFERENCES finding_occurrences(id) ON DELETE CASCADE,
                relative_path TEXT NOT NULL,
                start_line INTEGER NOT NULL CHECK (start_line >= 1),
                end_line INTEGER NOT NULL CHECK (end_line >= start_line),
                role TEXT,
                sort_order INTEGER NOT NULL CHECK (sort_order >= 0),
                UNIQUE (occurrence_id, sort_order)
            )
            """,
            """
            CREATE TABLE finding_triage (
                occurrence_id TEXT PRIMARY KEY
                    REFERENCES finding_occurrences(id) ON DELETE CASCADE,
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'closed')),
                close_reason TEXT CHECK (
                    close_reason IS NULL
                    OR close_reason IN ('already_fixed', 'wont_fix', 'false_positive')
                ),
                note TEXT,
                updated_at TEXT NOT NULL,
                CHECK (
                    (status = 'open' AND close_reason IS NULL)
                    OR (status = 'closed' AND close_reason IS NOT NULL)
                ),
                CHECK (
                    close_reason != 'wont_fix'
                    OR (note IS NOT NULL AND length(trim(note)) > 0)
                )
            )
            """,
            """
            CREATE TABLE finding_remediation_attempts (
                request_id TEXT PRIMARY KEY,
                occurrence_id TEXT NOT NULL
                    REFERENCES finding_occurrences(id) ON DELETE CASCADE,
                state TEXT NOT NULL CHECK (
                    state IN (
                        'idle',
                        'requested',
                        'generated',
                        'applied',
                        'verifying',
                        'verified',
                        'failed',
                        'superseded'
                    )
                ),
                version INTEGER NOT NULL CHECK (version >= 1),
                base_revision TEXT,
                base_content_digest TEXT,
                expected_applied_content_digest TEXT,
                applied_content_digest TEXT,
                pending_action TEXT CHECK (
                    pending_action IS NULL
                    OR pending_action IN ('generate', 'apply', 'verify')
                ),
                patch_path TEXT,
                patch_digest TEXT,
                summary TEXT,
                verification_summary TEXT,
                pending_action_claimed_at INTEGER,
                pending_action_claim_token TEXT,
                pending_action_delivered_at INTEGER,
                claimed_session_hash TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE INDEX remediation_attempts_by_occurrence
            ON finding_remediation_attempts(occurrence_id, created_at DESC)
            """,
            """
            CREATE TABLE scan_recovery_requests (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (
                    status IN ('pending', 'claimed', 'delivered', 'canceled')
                ),
                version INTEGER NOT NULL CHECK (version >= 1),
                claimed_session_hash TEXT,
                claim_token TEXT,
                claimed_at INTEGER,
                delivered_at INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE UNIQUE INDEX one_open_scan_recovery_request
            ON scan_recovery_requests(scan_id)
            WHERE status IN ('pending', 'claimed')
            """,
            """
            CREATE TABLE finding_tracking_requests (
                id TEXT PRIMARY KEY,
                occurrence_id TEXT NOT NULL
                    REFERENCES finding_occurrences(id) ON DELETE CASCADE,
                status TEXT NOT NULL CHECK (
                    status IN ('pending', 'claimed', 'delivered', 'canceled')
                ),
                version INTEGER NOT NULL CHECK (version >= 1),
                claimed_session_hash TEXT,
                claim_token TEXT,
                claimed_at INTEGER,
                delivered_at INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE UNIQUE INDEX one_open_finding_tracking_request
            ON finding_tracking_requests(occurrence_id)
            WHERE status IN ('pending', 'claimed')
            """,
        ),
    ),
)
