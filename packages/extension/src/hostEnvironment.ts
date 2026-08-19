export interface EditorHostEnvironment {
  readonly appName: string;
  readonly uriScheme: string;
}

export function isSupportedKiroHost(
  environment: EditorHostEnvironment,
): boolean {
  return environment.appName === "Kiro" && environment.uriScheme === "kiro";
}

export function requireSupportedKiroHost(
  environment: EditorHostEnvironment,
): void {
  if (!isSupportedKiroHost(environment)) {
    throw new Error("Kiro Security Power requires Kiro IDE.");
  }
}
