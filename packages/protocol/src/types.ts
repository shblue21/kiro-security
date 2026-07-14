export const PROTOCOL_VERSION = "1.0" as const;
export const SCAN_PHASES = ["preflight", "threat_model", "discovery", "validation", "attack_path", "reporting"] as const;
export const SCAN_MODES = ["diff", "standard", "deep"] as const;
export const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;

export type ScanMode = (typeof SCAN_MODES)[number];
export type ScanPhase = (typeof SCAN_PHASES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = "high" | "medium" | "low";
export type ValidationStatus = "unvalidated" | "validated" | "rejected" | "needs_review";
export type TriageDecision = "open" | "accepted_risk" | "false_positive" | "already_fixed" | "wont_fix";
export type ExportFormat = "json" | "csv" | "sarif" | "markdown";
export type TrackingProvider = "manual" | "github" | "linear" | "jira";

export type AgentIntegrationScope = "workspace" | "user";
export type AgentIntegrationState = "not_configured" | "configured" | "verified" | "needs_repair" | "error";
export type AgentIntegrationOperation = "idle" | "checking" | "installing" | "verifying" | "removing";
export type AgentAutoApprovePolicy = "none" | "read_only";

export interface RuntimeDependencyStatus {
  available: boolean;
  compatible: boolean;
  minimumVersion: string;
  executable?: string;
  version?: string;
  sqliteVersion?: string;
  source?: "configured" | "environment" | "path" | "common_location";
  error?: string;
}

export interface AgentIntegrationStatus {
  packaged: boolean;
  state: AgentIntegrationState;
  operation: AgentIntegrationOperation;
  configured: boolean;
  verified: boolean;
  serverName: string;
  configScope?: AgentIntegrationScope;
  configLocations: string[];
  directConfigPath?: string;
  steeringPath?: string;
  dependencies: { python: RuntimeDependencyStatus };
  power: {
    packaged: boolean;
    prepared: boolean;
    preparedPath?: string;
    manifestValid: boolean;
    registration: "not_prepared" | "import_required" | "user_confirmed" | "detected";
    importRequiresKiroConfirmation: boolean;
  };
  autoApprovePolicy?: AgentAutoApprovePolicy;
  lastVerifiedAt?: string;
  lastError?: string;
  details: string[];
}

export interface ProgressRecord {
  scan_id: string;
  phase_percent: number;
  overall_percent: number;
  review_items_total: number;
  review_items_completed: number;
  reportable_findings_count: number;
  deep_review_pass: number | null;
  message: string | null;
  updated_at: string;
}

export interface ArtifactRecord {
  kind: string;
  path: string;
  sha256: string;
  media_type?: string;
  mediaType?: string;
  created_at?: string;
  createdAt?: string;
}

export interface ScanRecord {
  id: string;
  workspace_id: string;
  mode: ScanMode;
  scope: string;
  diff_target_kind: "working_tree" | "commit" | "range" | null;
  diff_base_revision: string | null;
  diff_head_revision: string | null;
  status: "queued" | "running" | "interrupted" | "completed" | "cancelled" | "failed";
  phase: ScanPhase;
  phase_index: number;
  artifact_dir: string;
  target_revision: string | null;
  snapshot_digest: string | null;
  cancellation_requested: boolean;
  handoff_state: "none" | "available" | "claimed";
  failure_code: string | null;
  failure_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  files_total: number;
  files_completed: number;
  progress: ProgressRecord | null;
  artifacts: ArtifactRecord[];
  coverage?: CoverageDocument | null;
  capabilities?: Record<string, unknown> | null;
}

export interface FindingLocation {
  path: string;
  startLine: number;
  endLine: number;
  role: string;
}

export interface FindingSummary {
  findingId: string;
  occurrenceId: string;
  scanId: string;
  ruleId: string;
  fingerprint: string;
  identity: { anchor: string; instance?: string | null };
  title: string;
  summary: string;
  severity: { level: Severity; score?: number | null; rationale?: string | null };
  confidence: { level: Confidence; rationale: string };
  taxonomy: { category: string; cwe: string[] };
  locations: FindingLocation[];
  remediation: string;
  validationStatus: ValidationStatus;
  triageStatus: TriageDecision;
  updatedAt: string;
}

export interface FindingDetail extends FindingSummary {
  details: Record<string, unknown>;
  codeEvidence: Array<{
    id: string;
    kind: string;
    label: string;
    path: string;
    startLine: number;
    endLine: number;
    language?: string | null;
    role?: string | null;
    code: string;
    explanation: string;
  }>;
  validation: null | {
    id: string;
    status: Exclude<ValidationStatus, "unvalidated">;
    method: string;
    rationale: string;
    evidence: unknown[];
    createdAt: string;
  };
  attackPath: null | {
    id: string;
    narrative: string;
    path: Array<Record<string, unknown>>;
    exploitability: string;
    impact: string;
    severityRationale: string;
  };
  triage: null | { decision: TriageDecision; note?: string | null; updatedAt: string };
  remediationRecords: Array<Record<string, unknown>>;
  trackingRecords: Array<Record<string, unknown>>;
  artifactLinks: ArtifactRecord[];
  relatedFindings: FindingSummary[];
}

export interface CoverageDocument {
  documentType: string;
  schemaVersion: string;
  scanId: string;
  mode: string;
  completeness: "complete" | "partial" | "unknown";
  inventoryStrategy: string;
  includePaths: string[];
  excludePaths: string[];
  surfaces: Array<Record<string, unknown>>;
  explicitExclusions: Array<Record<string, unknown>>;
  deferred: Array<Record<string, unknown>>;
  openQuestions?: Array<{ question: string }>;
}

export interface DashboardState {
  workspace: {
    id: string;
    root_path: string;
    display_name: string;
    default_scope: string;
    default_mode: ScanMode;
  };
  engine: EngineCapabilities;
  activeScan: ScanRecord | null;
  selectedScan: ScanRecord | null;
  scans: ScanRecord[];
  findings: FindingSummary[];
  latestResumableScan: ScanRecord | null;
}

export interface EngineCapabilities {
  product: string;
  engineVersion: string;
  protocolVersion: string;
  modes: ScanMode[];
  phases: ScanPhase[];
  exports: ExportFormat[];
  triageDecisions: TriageDecision[];
  supports: Record<string, boolean>;
  workspaceRoot: string;
  stateDirectory: string;
  database: { path: string; schemaVersion: number; journalMode: string; integrity: string };
  dependencies?: {
    python: { available: boolean; version?: string; executable?: string };
    sqlite: { available: boolean; version?: string };
    git: { available: boolean; executable?: string | null };
  };
}

export interface RpcRequest {
  jsonrpc: "2.0";
  protocolVersion: typeof PROTOCOL_VERSION;
  id: number;
  method: string;
  params: Record<string, unknown>;
}

export interface RpcSuccess {
  jsonrpc: "2.0";
  protocolVersion: typeof PROTOCOL_VERSION;
  id: number;
  result: unknown;
}

export interface RpcFailure {
  jsonrpc: "2.0";
  protocolVersion: typeof PROTOCOL_VERSION;
  id: number | null;
  error: { code: number; message: string; data?: Record<string, unknown> };
}

export interface RpcNotification {
  jsonrpc: "2.0";
  protocolVersion: typeof PROTOCOL_VERSION;
  method: EngineEventName;
  params: Record<string, unknown>;
}

export type RpcEnvelope = RpcSuccess | RpcFailure | RpcNotification;
export type EngineEventName =
  | "engine.ready"
  | "scan.started"
  | "scan.phaseChanged"
  | "scan.progress"
  | "finding.discovered"
  | "finding.updated"
  | "artifact.created"
  | "scan.completed"
  | "scan.cancelled"
  | "scan.failed"
  | "engine.log";


export type WebviewMessage =
  | { type: "ready" }
  | { type: "refresh" }
  | { type: "startScan"; mode: ScanMode; scope: string; diffTargetKind?: "working_tree" | "commit" | "range"; diffBaseRevision?: string; diffHeadRevision?: string }
  | { type: "resumeScan"; scanId: string }
  | { type: "cancelScan"; scanId: string }
  | { type: "selectScan"; scanId: string }
  | { type: "openFinding"; occurrenceId: string }
  | { type: "openSource"; occurrenceId: string }
  | { type: "validateFinding"; occurrenceId: string }
  | { type: "triageFinding"; occurrenceId: string; decision: TriageDecision; note?: string }
  | { type: "createRemediation"; occurrenceId: string }
  | { type: "createTrackingHandoff"; occurrenceId: string; provider: TrackingProvider }
  | { type: "createHardening"; scanId: string }
  | { type: "cleanupScan"; scanId: string }
  | { type: "exportReport"; scanId: string; format: ExportFormat }
  | { type: "exportFinding"; occurrenceId: string; format: ExportFormat }
  | { type: "openArtifact"; path: string }
  | { type: "copyFindingLink"; occurrenceId: string }
  | { type: "openSettings" }
  | { type: "openLogs" }
  | { type: "copyMcpConfig" }
  | { type: "installAgentIntegration"; scope: AgentIntegrationScope; autoApprovePolicy: AgentAutoApprovePolicy }
  | { type: "verifyAgentIntegration" }
  | { type: "removeAgentIntegration" }
  | { type: "openMcpConfig"; scope?: AgentIntegrationScope }
  | { type: "revealPowerBundle" }
  | { type: "markPowerImported" }
  | { type: "retryEngine" };

export interface WebviewSnapshot {
  workspaceTrusted: boolean;
  workspaceRoot?: string;
  engineStatus: "stopped" | "starting" | "ready" | "error";
  engineError?: string;
  dashboard: DashboardState | null;
  selectedFinding: FindingDetail | null;
  agentIntegration: AgentIntegrationStatus;
  secondarySidebarOnboarded: boolean;
}
