import { randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import * as path from "node:path";

import { applyEdits, modify } from "jsonc-parser";
import { Document, parseDocument } from "yaml";

import {
  buildDirectMcpContract,
  type DirectMcpPermissionRule,
} from "./integrationConfig";
import type {
  IntegrationFileInspection,
  IntegrationMutation,
} from "./integrationFiles";
import { findDuplicateJsonObjectKey } from "./jsonSafety";

const MAX_PERMISSION_BYTES = 1024 * 1024;
const RULE_FIELDS = new Set(["capability", "effect", "match", "exclude"]);

type PermissionFormat = "yaml" | "json";

type PermissionDocument =
  | {
      readonly kind: "absent";
      readonly filePath: string;
      readonly format: PermissionFormat;
    }
  | {
      readonly kind: "unsafe";
      readonly filePath: string;
      readonly format: PermissionFormat;
      readonly detail: string;
    }
  | {
      readonly kind: "file";
      readonly filePath: string;
      readonly format: PermissionFormat;
      readonly contents: string;
      readonly mode: number;
      readonly rules: readonly unknown[];
    };

export function getUserPermissionsPaths(
  homeDirectory: string = homedir(),
): { readonly yaml: string; readonly json: string } {
  const settings = path.join(homeDirectory, ".kiro", "settings");
  return {
    yaml: path.join(settings, "permissions.yaml"),
    json: path.join(settings, "permissions.json"),
  };
}

export async function getActiveUserPermissionsPath(
  homeDirectory: string = homedir(),
): Promise<string> {
  return (await readActiveDocument(homeDirectory)).filePath;
}

export async function inspectPermissions(input: {
  readonly homeDirectory?: string;
  readonly serverKey: string;
}): Promise<IntegrationFileInspection> {
  const permissionRules = buildDirectMcpContract(input.serverKey).permissionRules;
  const document = await readActiveDocument(input.homeDirectory);
  if (document.kind === "unsafe") {
    return { state: "conflict", detail: document.detail };
  }
  if (
    document.kind === "file" &&
    hasAllManagedPermissionRules(document.rules, permissionRules)
  ) {
    return {
      state: "installed",
      detail: "The exact Kiro Security Trust v2 MCP allow and ask rules are installed.",
    };
  }
  return {
    state: "absent",
    detail: "The Kiro Security Trust v2 MCP allow and ask rules are not installed.",
  };
}

export async function installPermissions(input: {
  readonly homeDirectory?: string;
  readonly serverKey: string;
}): Promise<IntegrationMutation> {
  const permissionRules = buildDirectMcpContract(input.serverKey).permissionRules;
  const document = await readActiveDocument(input.homeDirectory);
  if (document.kind === "unsafe") {
    throw new Error(document.detail);
  }
  if (
    document.kind === "file" &&
    hasAllManagedPermissionRules(document.rules, permissionRules)
  ) {
    return { changed: false };
  }
  const updated = addManagedRules(document, permissionRules);
  await writeDocument(document, updated);
  return { changed: true };
}

function addManagedRules(
  document: PermissionDocument,
  permissionRules: readonly DirectMcpPermissionRule[],
): string {
  const currentRules = document.kind === "file" ? document.rules : [];
  const missing = permissionRules.filter(
    (expected) => !currentRules.some((rule) => isExactPermissionRule(rule, expected)),
  );
  if (document.kind === "absent") {
    return document.format === "json"
      ? `${JSON.stringify({ rules: missing }, null, 2)}\n`
      : freshYamlPermissionsText(missing);
  }
  if (document.kind === "unsafe") {
    throw new Error(document.detail);
  }
  if (document.format === "json") {
    let updated = document.contents;
    for (const rule of missing) {
      updated = applyEdits(
        updated,
        modify(
          updated,
          ["rules", validatedRules(JSON.parse(updated)).length],
          rule,
          { formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" } },
        ),
      );
    }
    return updated;
  }
  const parsed = parseYaml(document.contents);
  for (const rule of missing) {
    parsed.addIn(["rules"], rule);
  }
  return parsed.toString({ lineWidth: 0 });
}

async function readActiveDocument(
  homeDirectory: string = homedir(),
): Promise<PermissionDocument> {
  const paths = getUserPermissionsPaths(homeDirectory);
  const yaml = await readCandidate(paths.yaml, "yaml");
  if (yaml.kind === "unsafe") {
    return yaml;
  }
  if (yaml.kind === "file" && yaml.contents.trim().length > 0) {
    return parseCandidate(yaml);
  }
  const json = await readCandidate(paths.json, "json");
  if (json.kind === "unsafe") {
    return json;
  }
  if (json.kind === "file" && json.contents.trim().length > 0) {
    return parseCandidate(json);
  }
  if (yaml.kind === "file") {
    return emptyCandidate(yaml);
  }
  return { kind: "absent", filePath: paths.yaml, format: "yaml" };
}

async function readCandidate(
  filePath: string,
  format: PermissionFormat,
): Promise<
  | { readonly kind: "absent"; readonly filePath: string; readonly format: PermissionFormat }
  | { readonly kind: "unsafe"; readonly filePath: string; readonly format: PermissionFormat; readonly detail: string }
  | { readonly kind: "file"; readonly filePath: string; readonly format: PermissionFormat; readonly contents: string; readonly mode: number }
> {
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    if (isMissing(error)) {
      return { kind: "absent", filePath, format };
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    return {
      kind: "unsafe",
      filePath,
      format,
      detail: "The active Kiro user permissions path is a symlink or non-regular file and will not be modified.",
    };
  }
  if (metadata.size > MAX_PERMISSION_BYTES) {
    return {
      kind: "unsafe",
      filePath,
      format,
      detail: "The active Kiro user permissions file is too large to modify safely.",
    };
  }
  return {
    kind: "file",
    filePath,
    format,
    contents: await readFile(filePath, "utf8"),
    mode: metadata.mode,
  };
}

function parseCandidate(
  candidate: Extract<Awaited<ReturnType<typeof readCandidate>>, { kind: "file" }>,
): PermissionDocument {
  try {
    const parsed =
      candidate.format === "json"
        ? parseJsonPermissions(candidate.contents)
        : parseYaml(candidate.contents).toJS();
    const rules = validatedRules(parsed);
    return { ...candidate, rules };
  } catch (error) {
    return {
      kind: "unsafe",
      filePath: candidate.filePath,
      format: candidate.format,
      detail: `The active Kiro user permissions file is invalid: ${errorMessage(error)}`,
    };
  }
}

function parseJsonPermissions(contents: string): unknown {
  const parsed: unknown = JSON.parse(contents);
  const duplicateKey = findDuplicateJsonObjectKey(contents, {
    allowTrailingComma: false,
    disallowComments: true,
  });
  if (duplicateKey !== undefined) {
    throw new Error(`duplicate JSON object key ${JSON.stringify(duplicateKey)}`);
  }
  return parsed;
}

function emptyCandidate(
  candidate: Extract<Awaited<ReturnType<typeof readCandidate>>, { kind: "file" }>,
): PermissionDocument {
  return { ...candidate, rules: [] };
}

function parseYaml(contents: string) {
  const document = parseDocument(contents || "rules: []\n", {
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    throw document.errors[0];
  }
  return document;
}

function validatedRules(value: unknown): readonly unknown[] {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("the document must be an object");
  }
  const rules = (value as { rules?: unknown }).rules;
  if (!Array.isArray(rules)) {
    throw new Error("rules must be an array");
  }
  for (const rule of rules) {
    if (typeof rule !== "object" || rule === null || Array.isArray(rule)) {
      throw new Error("each rule must be an object");
    }
    const record = rule as Record<string, unknown>;
    if (
      Object.keys(record).some((key) => !RULE_FIELDS.has(key)) ||
      typeof record.capability !== "string" ||
      !["allow", "ask", "deny"].includes(String(record.effect)) ||
      (record.match !== undefined && !isStringArray(record.match)) ||
      (record.exclude !== undefined && !isStringArray(record.exclude))
    ) {
      throw new Error("a rule does not match Kiro's permissions schema");
    }
  }
  return rules;
}

function hasAllManagedPermissionRules(
  rules: readonly unknown[],
  permissionRules: readonly DirectMcpPermissionRule[],
): boolean {
  return permissionRules.every((expected) =>
    rules.some((rule) => isExactPermissionRule(rule, expected)),
  );
}

function isExactPermissionRule(
  value: unknown,
  expected: DirectMcpPermissionRule,
): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const rule = value as Record<string, unknown>;
  return (
    Object.keys(rule).length === 4 &&
    rule.capability === expected.capability &&
    rule.effect === expected.effect &&
    isSameStringSet(rule.match, expected.match) &&
    Array.isArray(rule.exclude) &&
    rule.exclude.length === 0
  );
}

function isSameStringSet(value: unknown, expected: readonly string[]): boolean {
  return (
    isStringArray(value) &&
    value.length === expected.length &&
    [...value].sort().every((item, index) => item === [...expected].sort()[index])
  );
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function freshYamlPermissionsText(
  rules: readonly DirectMcpPermissionRule[],
): string {
  const document = new Document({ rules: [] });
  for (const rule of rules) {
    document.addIn(["rules"], rule);
  }
  return document.toString({ lineWidth: 0 });
}

async function writeDocument(
  snapshot: PermissionDocument,
  contents: string,
): Promise<void> {
  if (snapshot.kind === "unsafe") {
    throw new Error(snapshot.detail);
  }
  const directory = path.dirname(snapshot.filePath);
  await ensureSharedDirectory(directory);
  const staging = path.join(
    directory,
    `.${path.basename(snapshot.filePath)}.staging-${randomUUID()}`,
  );
  const mode = snapshot.kind === "file" ? snapshot.mode & 0o777 : 0o600;
  try {
    await writeFile(staging, contents, {
      encoding: "utf8",
      flag: "wx",
      mode,
    });
    if (process.platform !== "win32") {
      await chmod(staging, mode);
    }
    const latest = await readCandidate(snapshot.filePath, snapshot.format);
    if (
      snapshot.kind === "absent"
        ? latest.kind !== "absent"
        : latest.kind !== "file" || latest.contents !== snapshot.contents
    ) {
      throw new Error("The Kiro user permissions file changed during installation.");
    }
    await rename(staging, snapshot.filePath);
  } catch (error) {
    await rm(staging, { force: true });
    throw error;
  }
}

async function ensureSharedDirectory(directoryPath: string): Promise<void> {
  try {
    const metadata = await lstat(directoryPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw new Error(`Refusing to use a symlink or non-directory path: ${directoryPath}`);
    }
    return;
  } catch (error) {
    if (!isMissing(error)) {
      throw error;
    }
  }
  await mkdir(directoryPath, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") {
    await chmod(directoryPath, 0o700);
  }
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as NodeJS.ErrnoException).code === "ENOENT"
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
