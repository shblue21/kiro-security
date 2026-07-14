import {
  EngineEventName,
  ExportFormat,
  PROTOCOL_VERSION,
  RpcEnvelope,
  SCAN_MODES,
  SEVERITIES,
  TriageDecision,
  TrackingProvider,
  WebviewMessage,
} from "./types";

const EVENT_NAMES = new Set<EngineEventName>([
  "engine.ready",
  "scan.started",
  "scan.phaseChanged",
  "scan.progress",
  "finding.discovered",
  "finding.updated",
  "artifact.created",
  "scan.completed",
  "scan.cancelled",
  "scan.failed",
  "engine.log",
]);
const TRIAGE = new Set<TriageDecision>(["open", "accepted_risk", "false_positive", "already_fixed", "wont_fix"]);
const EXPORTS = new Set<ExportFormat>(["json", "csv", "sarif", "markdown"]);
const TRACKING = new Set<TrackingProvider>(["manual", "github", "linear", "jira"]);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, max = 4096): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max && !value.includes("\0");
}

export function isRpcEnvelope(value: unknown): value is RpcEnvelope {
  if (!isObject(value) || value.jsonrpc !== "2.0" || value.protocolVersion !== PROTOCOL_VERSION) {
    return false;
  }
  if (typeof value.method === "string") {
    return EVENT_NAMES.has(value.method as EngineEventName) && isObject(value.params);
  }
  if (!(typeof value.id === "number" || value.id === null)) {
    return false;
  }
  return "result" in value || (isObject(value.error) && typeof value.error.code === "number" && typeof value.error.message === "string");
}

export function validateWebviewMessage(value: unknown): WebviewMessage | undefined {
  if (!isObject(value) || typeof value.type !== "string") {
    return undefined;
  }
  switch (value.type) {
    case "ready":
    case "refresh":
    case "openSettings":
    case "openLogs":
    case "copyMcpConfig":
    case "verifyAgentIntegration":
    case "removeAgentIntegration":
    case "revealPowerBundle":
    case "markPowerImported":
    case "retryEngine":
      return { type: value.type };
    case "installAgentIntegration":
      return (value.scope === "workspace" || value.scope === "user")
        && (value.autoApprovePolicy === "none" || value.autoApprovePolicy === "read_only")
        ? { type: "installAgentIntegration", scope: value.scope, autoApprovePolicy: value.autoApprovePolicy }
        : undefined;
    case "openMcpConfig":
      return value.scope === undefined || value.scope === "workspace" || value.scope === "user"
        ? { type: "openMcpConfig", scope: value.scope as "workspace" | "user" | undefined }
        : undefined;
    case "startScan": {
      if (!SCAN_MODES.includes(value.mode as never) || !boundedString(value.scope, 4096)) return undefined;
      const message: Extract<WebviewMessage, { type: "startScan" }> = {
        type: "startScan",
        mode: value.mode as Extract<WebviewMessage, { type: "startScan" }>["mode"],
        scope: value.scope,
      };
      if (value.diffTargetKind !== undefined) {
        if (!(["working_tree", "commit", "range"] as const).includes(value.diffTargetKind as never)) return undefined;
        message.diffTargetKind = value.diffTargetKind as "working_tree" | "commit" | "range";
      }
      if (value.diffBaseRevision !== undefined) {
        if (!boundedString(value.diffBaseRevision, 256)) return undefined;
        message.diffBaseRevision = value.diffBaseRevision;
      }
      if (value.diffHeadRevision !== undefined) {
        if (!boundedString(value.diffHeadRevision, 256)) return undefined;
        message.diffHeadRevision = value.diffHeadRevision;
      }
      return message;
    }
    case "resumeScan":
    case "cancelScan":
    case "selectScan":
    case "cleanupScan":
      return boundedString(value.scanId, 256) ? { type: value.type, scanId: value.scanId } : undefined;
    case "openFinding":
    case "openSource":
    case "validateFinding":
    case "createRemediation":
    case "copyFindingLink":
      return boundedString(value.occurrenceId, 256) ? { type: value.type, occurrenceId: value.occurrenceId } : undefined;
    case "createTrackingHandoff":
      return boundedString(value.occurrenceId, 256) && TRACKING.has(value.provider as TrackingProvider)
        ? { type: "createTrackingHandoff", occurrenceId: value.occurrenceId, provider: value.provider as TrackingProvider }
        : undefined;
    case "triageFinding":
      if (!boundedString(value.occurrenceId, 256) || !TRIAGE.has(value.decision as TriageDecision)) return undefined;
      if (value.note !== undefined && (typeof value.note !== "string" || value.note.length > 4000)) return undefined;
      return { type: "triageFinding", occurrenceId: value.occurrenceId, decision: value.decision as TriageDecision, note: value.note as string | undefined };
    case "createHardening":
      return boundedString(value.scanId, 256) ? { type: "createHardening", scanId: value.scanId } : undefined;
    case "exportReport":
      return boundedString(value.scanId, 256) && EXPORTS.has(value.format as ExportFormat)
        ? { type: "exportReport", scanId: value.scanId, format: value.format as ExportFormat }
        : undefined;
    case "exportFinding":
      return boundedString(value.occurrenceId, 256) && EXPORTS.has(value.format as ExportFormat)
        ? { type: "exportFinding", occurrenceId: value.occurrenceId, format: value.format as ExportFormat }
        : undefined;
    case "openArtifact":
      return boundedString(value.path, 8192) ? { type: "openArtifact", path: value.path } : undefined;
    default:
      return undefined;
  }
}

export function isSeverity(value: unknown): value is (typeof SEVERITIES)[number] {
  return SEVERITIES.includes(value as never);
}
