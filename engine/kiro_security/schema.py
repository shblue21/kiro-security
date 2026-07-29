"""Fresh schema and forward migration foundation."""

SCHEMA_VERSION = 1

MIGRATIONS = (
    (
        1,
        "fresh trusted Kiro chat workspace and scan foundation",
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
        ),
    ),
)
