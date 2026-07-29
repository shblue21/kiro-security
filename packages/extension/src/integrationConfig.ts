export const MCP_MANAGED_MARKER = "kiro-security-power-vsix";
export const MCP_SERVER_KEY_PATTERN = /^ksp_[a-z2-7]{20}$/;

export const MCP_TOOL_NAMES = [
  "kiro_security_get_capabilities",
  "kiro_security_create_workspace",
  "kiro_security_get_workspace",
  "kiro_security_save_workspace",
  "kiro_security_start_scan",
  "kiro_security_get_scan_context",
  "kiro_security_update_scan_progress",
  "kiro_security_fail_scan",
  "kiro_security_cancel_scan",
] as const;

export const MANUAL_APPROVAL_MCP_TOOLS = [
  "kiro_security_start_scan",
  "kiro_security_cancel_scan",
] as const;

const manualApproval = new Set<string>(MANUAL_APPROVAL_MCP_TOOLS);
export const AUTO_APPROVED_MCP_TOOLS = MCP_TOOL_NAMES.filter(
  (name) => !manualApproval.has(name),
);

export interface DirectMcpContract {
  readonly serverKey: string;
  readonly toolIds: readonly string[];
  readonly toolMatcher: string;
}

export function buildDirectMcpContract(serverKey: string): DirectMcpContract {
  requireMcpServerKey(serverKey);
  const toolIds = MCP_TOOL_NAMES.map((name) =>
    directMcpToolId(serverKey, name),
  );
  if (new Set(toolIds).size !== toolIds.length) {
    throw new Error("Kiro Security direct MCP tool IDs must be unique.");
  }
  return {
    serverKey,
    toolIds,
    toolMatcher: `^(?:${toolIds.map(escapeRegularExpression).join("|")})$`,
  };
}

export function requireMcpServerKey(value: unknown): string {
  if (typeof value !== "string" || !MCP_SERVER_KEY_PATTERN.test(value)) {
    throw new Error("Kiro Security installation MCP server key is invalid.");
  }
  return value;
}

export function directMcpToolId(
  serverName: string,
  toolName: string,
): string {
  const normalized = `${serverName}_${toolName}`
    .replace(/[\s-]/g, "_")
    .replace(/[^a-zA-Z0-9_]/g, "")
    .toLowerCase();
  const identifier = `mcp_${normalized}`;
  if (identifier.length > 64) {
    throw new Error(
      `Direct MCP tool ID exceeds Kiro's stable 64-character boundary: ${identifier}`,
    );
  }
  return identifier;
}

export interface DirectMcpConfigurationInput {
  readonly serverKey: string;
  readonly pythonExecutable: string;
  readonly launcherPath: string;
  readonly stateRoot: string;
  readonly scanRoot: string;
}

export interface DirectMcpServerConfiguration {
  readonly command: string;
  readonly args: readonly string[];
  readonly env: Readonly<Record<string, string>>;
  readonly timeout: number;
  readonly disabled: false;
  readonly autoApprove: readonly string[];
}

export function buildDirectMcpServerConfiguration(
  input: DirectMcpConfigurationInput,
): DirectMcpServerConfiguration {
  requireMcpServerKey(input.serverKey);
  return {
    command: input.pythonExecutable,
    args: ["-B", "-S", input.launcherPath],
    env: {
      PYTHONIOENCODING: "utf-8",
      PYTHONUNBUFFERED: "1",
      KIRO_SECURITY_STATE_ROOT: input.stateRoot,
      KIRO_SECURITY_SCAN_ROOT: input.scanRoot,
      KIRO_SECURITY_MANAGED_BY: MCP_MANAGED_MARKER,
    },
    timeout: 900_000,
    disabled: false,
    autoApprove: AUTO_APPROVED_MCP_TOOLS.map((name) =>
      directMcpToolId(input.serverKey, name),
    ),
  };
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
