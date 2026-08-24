export const SCAN_PROMPT = "Scan this repository for security vulnerabilities.";

export function recoveryPrompt(recovery: {
  readonly id: string;
  readonly version: number;
}): string {
  return [
    "Resume this Kiro Security scan in this chat.",
    `Recovery request: ${recovery.id}`,
    `Expected version: ${recovery.version}`,
    "Claim the exact recovery request, then deliver it through the recovery form of kiro_security_get_scan_context.",
  ].join("\n");
}

export function remediationPrompt(
  requestId: string,
  version: number,
  action: "generate" | "apply" | "verify",
): string {
  return [
    `Continue Kiro Security remediation ${action}.`,
    `Request: ${requestId}`,
    `Expected version: ${version}`,
    "Claim the exact remediation action and load its authoritative context before changing any source.",
  ].join("\n");
}

export function trackingPrompt(
  tracking: { readonly requestId: string; readonly version: number },
  occurrenceId: string,
): string {
  return [
    "Track this completed Kiro Security finding.",
    `Tracking request: ${tracking.requestId}`,
    `Expected version: ${tracking.version}`,
    `Occurrence: ${occurrenceId}`,
    "Claim and deliver the exact tracking request before provider access. Then verify the sealed source, check duplicates, preview the exact provider payload and visibility, ask for approval, write once, and read back using one selected provider.",
  ].join("\n");
}
