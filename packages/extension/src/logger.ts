import * as vscode from "vscode";

const SECRET_PATTERNS = [
  /\b(sk|ghp|github_pat|xox[baprs])[-_A-Za-z0-9]{10,}\b/gi,
  /(api[_-]?key|token|secret|password|authorization)(\s*[=:]\s*)([^\s,;]+)/gi,
];

export function redact(value: string): string {
  return SECRET_PATTERNS.reduce((text, pattern) =>
    text.replace(pattern, (...args: string[]) => {
      if (args.length >= 5 && /api|token|secret|password|authorization/i.test(args[1] ?? "")) {
        return `${args[1]}${args[2]}<redacted>`;
      }
      return "<redacted>";
    }), value);
}

export class StructuredLogger {
  constructor(private readonly channel: vscode.OutputChannel) {}

  log(level: "debug" | "info" | "warning" | "error", message: string, fields: Record<string, unknown> = {}): void {
    const safeFields = JSON.parse(redact(JSON.stringify(fields))) as Record<string, unknown>;
    this.channel.appendLine(JSON.stringify({ timestamp: new Date().toISOString(), level, message: redact(message), ...safeFields }));
  }

  show(): void {
    this.channel.show(true);
  }
}
