export const POWER_MCP_SERVER_NAME = "kiro-security-workbench";

export const READ_ONLY_MCP_TOOLS = [
  "kiro_security_get_capabilities",
  "kiro_security_get_workspace",
  "kiro_security_get_scan_context",
] as const;

export interface PowerMcpConfigurationInput {
  readonly pythonExecutable: string;
  readonly engineRoot: string;
  readonly stateRoot: string;
  readonly scanRoot: string;
}

export function buildPowerMcpConfiguration(
  input: PowerMcpConfigurationInput,
): object {
  return {
    mcpServers: {
      [POWER_MCP_SERVER_NAME]: {
        command: input.pythonExecutable,
        args: ["-B", "-S", "-m", "kiro_security.mcp_server"],
        env: {
          PYTHONPATH: input.engineRoot,
          PYTHONIOENCODING: "utf-8",
          PYTHONUNBUFFERED: "1",
          KIRO_SECURITY_STATE_ROOT: input.stateRoot,
          KIRO_SECURITY_SCAN_ROOT: input.scanRoot,
        },
        timeout: 900_000,
        disabled: false,
        autoApprove: [...READ_ONLY_MCP_TOOLS],
      },
    },
  };
}
