import {
  access,
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
import { randomUUID } from "node:crypto";

import { isMap, isSeq, parseDocument } from "yaml";

import {
  AUTO_APPROVED_MCP_TOOLS,
  MANUAL_APPROVAL_MCP_TOOLS,
  requireMcpServerKey,
} from "./integrationConfig";
import { findDuplicateJsonObjectKey } from "./jsonSafety";
import { isMissing } from "./localFileSafety";
import { withSharedFileLock } from "./sharedFileLock";

const MAX_POLICY_BYTES = 1024 * 1024;
const STEERING_NAME = "kiro-security";
const RULE_FIELDS = new Set(["capability", "effect", "match", "exclude"]);
const RULE_EFFECTS = new Set(["allow", "ask", "deny"]);

export type ApprovalPolicyState =
  | "absent"
  | "installed"
  | "mismatch"
  | "conflict";

export interface ApprovalPolicyInspection {
  readonly state: ApprovalPolicyState;
  readonly detail: string;
  readonly path: string;
}

export interface KiroPermissionRule {
  readonly capability: string;
  readonly match: readonly string[];
  readonly effect: "allow" | "ask";
}

type PolicyEffect = "allow" | "ask" | "deny";

interface ParsedPermissionRule {
  readonly capability: string;
  readonly effect: PolicyEffect;
  readonly match?: readonly string[];
  readonly exclude?: readonly string[];
}

export function buildApprovalPolicyRules(
  serverKey: string,
): readonly KiroPermissionRule[] {
  requireMcpServerKey(serverKey);
  return [
    {
      capability: "skill",
      match: [STEERING_NAME],
      effect: "allow",
    },
    {
      capability: "mcp",
      match: AUTO_APPROVED_MCP_TOOLS.map(
        (toolName) => `${serverKey}/${toolName}`,
      ),
      effect: "allow",
    },
    {
      capability: "mcp",
      match: MANUAL_APPROVAL_MCP_TOOLS.map(
        (toolName) => `${serverKey}/${toolName}`,
      ),
      effect: "ask",
    },
  ];
}

export async function inspectApprovalPolicy(input: {
  readonly serverKey: string;
  readonly homeDirectory?: string;
}): Promise<ApprovalPolicyInspection> {
  const policyPath = await resolveUserPolicyPath(input.homeDirectory);
  const snapshot = await readPolicy(policyPath);
  if (snapshot.kind === "absent") {
    return {
      state: "absent",
      detail: "The Kiro Security chat approval rules are not installed.",
      path: policyPath,
    };
  }
  if (snapshot.kind === "unsafe") {
    return {
      state: "conflict",
      detail: snapshot.detail,
      path: policyPath,
    };
  }
  const required = buildApprovalPolicyRules(input.serverKey);
  const conflict = approvalPolicyConflict(snapshot.rules, required);
  if (conflict) {
    return {
      state: "conflict",
      detail: conflict,
      path: policyPath,
    };
  }
  const missing = missingRules(
    snapshot.rules,
    required,
  );
  if (missing.length === 0) {
    return {
      state: "installed",
      detail: "The Kiro Security user approval rules are installed without conflicts.",
      path: policyPath,
    };
  }
  return {
    state: "mismatch",
    detail: "The Kiro Security chat approval rules are incomplete.",
    path: policyPath,
  };
}

export async function installApprovalPolicy(input: {
  readonly serverKey: string;
  readonly homeDirectory?: string;
  readonly staleServerKeys?: readonly string[];
}): Promise<{ readonly changed: boolean }> {
  const staleServerKeys = [...new Set(input.staleServerKeys ?? [])]
    .filter((serverKey) => serverKey !== input.serverKey)
    .map(requireMcpServerKey);
  const policyPath = await resolveUserPolicyPath(input.homeDirectory);
  return withSharedFileLock(
    policyPath,
    "The Kiro user permission file",
    () =>
      installApprovalPolicyLocked(
        input.serverKey,
        staleServerKeys,
        policyPath,
      ),
  );
}

async function installApprovalPolicyLocked(
  serverKey: string,
  staleServerKeys: readonly string[],
  policyPath: string,
): Promise<{ readonly changed: boolean }> {
  const snapshot = await readPolicy(policyPath);
  if (snapshot.kind === "unsafe") {
    throw new Error(snapshot.detail);
  }
  const required = buildApprovalPolicyRules(serverKey);
  const existingRules = snapshot.kind === "file" ? snapshot.rules : [];
  const conflict = approvalPolicyConflict(existingRules, required);
  if (conflict) {
    throw new Error(conflict);
  }
  const missing = missingRules(existingRules, required);
  if (
    missing.length === 0 &&
    !hasStaleGeneratedRules(existingRules, staleServerKeys)
  ) {
    return { changed: false };
  }

  const format = policyPath.endsWith(".json") ? "json" : "yaml";
  const source =
    snapshot.kind === "file"
      ? snapshot.contents
      : format === "json"
        ? '{\n  "rules": []\n}\n'
        : "rules: []\n";
  const document = parseDocument(source, {
    prettyErrors: false,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    throw new Error("The Kiro user permission file is invalid.");
  }
  const rulesNode = document.get("rules", true);
  if (isSeq(rulesNode)) {
    rulesNode.flow = false;
  }
  removeStaleGeneratedRules(rulesNode, staleServerKeys);
  for (const rule of missing) {
    document.addIn(["rules"], {
      capability: rule.capability,
      match: [...rule.match],
      effect: rule.effect,
    });
  }
  const updated =
    format === "json"
      ? `${JSON.stringify(document.toJS(), null, 2)}\n`
      : document.toString();
  const verified = parsePolicyContents(updated, format);
  if (
    missingRules(verified, required).length > 0 ||
    approvalPolicyConflict(verified, required) ||
    hasStaleGeneratedRules(verified, staleServerKeys)
  ) {
    throw new Error("The Kiro Security approval policy failed verification.");
  }
  await writePolicy(policyPath, snapshot, updated);
  return { changed: true };
}

function removeStaleGeneratedRules(
  rulesNode: unknown,
  staleServerKeys: readonly string[],
): void {
  if (!isSeq(rulesNode) || staleServerKeys.length === 0) {
    return;
  }
  rulesNode.items = rulesNode.items.filter((ruleNode) => {
    return (
      !isMap(ruleNode) ||
      !isStaleGeneratedRule(
        ruleNode.toJSON() as ParsedPermissionRule,
        staleServerKeys,
      )
    );
  });
}

function hasStaleGeneratedRules(
  rules: readonly unknown[],
  staleServerKeys: readonly string[],
): boolean {
  return rules.some(
    (rule) =>
      typeof rule === "object" &&
      rule !== null &&
      !Array.isArray(rule) &&
      isStaleGeneratedRule(
        rule as ParsedPermissionRule,
        staleServerKeys,
      ),
  );
}

function isStaleGeneratedRule(
  rule: ParsedPermissionRule,
  staleServerKeys: readonly string[],
): boolean {
  if (
    rule.capability !== "mcp" ||
    (rule.effect !== "allow" && rule.effect !== "ask") ||
    !Array.isArray(rule.match) ||
    rule.match.length === 0 ||
    (Array.isArray(rule.exclude) && rule.exclude.length > 0)
  ) {
    return false;
  }
  const toolNames =
    rule.effect === "allow"
      ? AUTO_APPROVED_MCP_TOOLS
      : MANUAL_APPROVAL_MCP_TOOLS;
  const staleMatches = new Set(
    staleServerKeys.flatMap((serverKey) =>
      toolNames.map((toolName) => `${serverKey}/${toolName}`),
    ),
  );
  return rule.match.every((match) => staleMatches.has(match));
}

type PolicySnapshot =
  | { readonly kind: "absent" }
  | { readonly kind: "unsafe"; readonly detail: string }
  | {
      readonly kind: "file";
      readonly contents: string;
      readonly rules: readonly unknown[];
      readonly mode: number;
    };

async function resolveUserPolicyPath(
  homeDirectory: string = homedir(),
): Promise<string> {
  const settingsDirectory = path.join(homeDirectory, ".kiro", "settings");
  const yamlPath = path.join(settingsDirectory, "permissions.yaml");
  const jsonPath = path.join(settingsDirectory, "permissions.json");
  if (await hasNonEmptyContents(yamlPath)) {
    return yamlPath;
  }
  if (await hasNonEmptyContents(jsonPath)) {
    return jsonPath;
  }
  return yamlPath;
}

async function hasNonEmptyContents(filePath: string): Promise<boolean> {
  try {
    return (await readFile(filePath, "utf8")).trim().length > 0;
  } catch (error) {
    return !isMissing(error);
  }
}

async function readPolicy(filePath: string): Promise<PolicySnapshot> {
  let metadata;
  try {
    metadata = await lstat(filePath);
  } catch (error) {
    if (isMissing(error)) {
      return { kind: "absent" };
    }
    throw error;
  }
  if (metadata.isSymbolicLink() || !metadata.isFile()) {
    return {
      kind: "unsafe",
      detail: "The Kiro user permission path is a symlink or non-regular file and will not be modified.",
    };
  }
  if (metadata.size > MAX_POLICY_BYTES) {
    return {
      kind: "unsafe",
      detail: "The Kiro user permission file is too large to modify safely.",
    };
  }
  const contents = await readFile(filePath, "utf8");
  const format = filePath.endsWith(".json") ? "json" : "yaml";
  let rules: readonly unknown[];
  try {
    rules = parsePolicyContents(contents, format);
  } catch (error) {
    return {
      kind: "unsafe",
      detail: error instanceof Error ? error.message : String(error),
    };
  }
  return {
    kind: "file",
    contents,
    rules,
    mode: metadata.mode,
  };
}

function parsePolicyContents(
  contents: string,
  format: "json" | "yaml",
): readonly unknown[] {
  let parsed: unknown;
  if (format === "json") {
    parsed = JSON.parse(contents);
    const duplicateKey = findDuplicateJsonObjectKey(contents, {
      allowTrailingComma: false,
      disallowComments: true,
    });
    if (duplicateKey !== undefined) {
      throw new Error(
        `The Kiro user permission file contains duplicate JSON object key ${JSON.stringify(duplicateKey)} and will not be modified.`,
      );
    }
  } else {
    const document = parseDocument(contents, {
      prettyErrors: false,
      uniqueKeys: true,
    });
    if (document.errors.length > 0) {
      throw new Error("The Kiro user permission file is invalid YAML.");
    }
    parsed = document.toJS();
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    Array.isArray(parsed) ||
    !Array.isArray((parsed as { rules?: unknown }).rules)
  ) {
    throw new Error("The Kiro user permission file must contain a rules array.");
  }
  const rules = (parsed as { rules: unknown[] }).rules;
  if (!rules.every(isValidRule)) {
    throw new Error("The Kiro user permission file contains an invalid rule.");
  }
  return rules;
}

function isValidRule(value: unknown): boolean {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const rule = value as Readonly<Record<string, unknown>>;
  if (
    Object.keys(rule).some((key) => !RULE_FIELDS.has(key)) ||
    typeof rule.capability !== "string" ||
    typeof rule.effect !== "string" ||
    !RULE_EFFECTS.has(rule.effect)
  ) {
    return false;
  }
  return (
    isOptionalStringArray(rule.match) &&
    isOptionalStringArray(rule.exclude)
  );
}

function isOptionalStringArray(value: unknown): boolean {
  return (
    value === undefined ||
    (Array.isArray(value) && value.every((entry) => typeof entry === "string"))
  );
}

function missingRules(
  existing: readonly unknown[],
  required: readonly KiroPermissionRule[],
): KiroPermissionRule[] {
  const missing: KiroPermissionRule[] = [];
  for (const requirement of required) {
    const covered = new Set<string>();
    for (const candidate of existing) {
      if (
        typeof candidate !== "object" ||
        candidate === null ||
        Array.isArray(candidate)
      ) {
        continue;
      }
      const rule = candidate as {
        capability?: unknown;
        effect?: unknown;
        match?: unknown;
        exclude?: unknown;
      };
      if (
        rule.capability === requirement.capability &&
        rule.effect === requirement.effect &&
        Array.isArray(rule.match) &&
        (!Array.isArray(rule.exclude) || rule.exclude.length === 0)
      ) {
        for (const match of rule.match) {
          if (typeof match === "string") {
            covered.add(match);
          }
        }
      }
    }
    const matches = requirement.match.filter((match) => !covered.has(match));
    if (matches.length > 0) {
      missing.push({ ...requirement, match: matches });
    }
  }
  return missing;
}

function approvalPolicyConflict(
  existing: readonly unknown[],
  required: readonly KiroPermissionRule[],
): string | undefined {
  for (const requirement of required) {
    for (const resource of requirement.match) {
      for (const rule of existing as readonly ParsedPermissionRule[]) {
        if (
          policyRuleApplies(rule, requirement.capability, resource) &&
          ((requirement.effect === "allow" && rule.effect !== "allow") ||
            (requirement.effect === "ask" && rule.effect === "deny"))
        ) {
          return `The existing Kiro user permission rules apply ${rule.effect} to ${resource}, but Kiro Security requires ${requirement.effect}. The existing rules were not modified.`;
        }
      }
    }
  }
  return undefined;
}

function policyRuleApplies(
  rule: ParsedPermissionRule,
  capability: string,
  resource: string,
): boolean {
  if (!policyCapabilityCovers(rule.capability, capability)) {
    return false;
  }
  const included =
    rule.match === undefined ||
    rule.match.length === 0 ||
    rule.match.some((pattern) => kiroPatternMatches(pattern, resource));
  return (
    included &&
    !rule.exclude?.some((pattern) => kiroPatternMatches(pattern, resource))
  );
}

function policyCapabilityCovers(
  ruleCapability: string,
  capability: string,
): boolean {
  if (ruleCapability === capability || ruleCapability === "all") {
    return true;
  }
  return capability === "skill" && ruleCapability === "builtin";
}

function kiroPatternMatches(pattern: string, resource: string): boolean {
  const normalized = pattern.replace(/\*\*/g, "*");
  let patternIndex = 0;
  let resourceIndex = 0;
  let wildcardIndex = -1;
  let wildcardResourceIndex = 0;
  while (resourceIndex < resource.length) {
    if (
      patternIndex < normalized.length &&
      normalized[patternIndex] === resource[resourceIndex]
    ) {
      patternIndex += 1;
      resourceIndex += 1;
    } else if (
      patternIndex < normalized.length &&
      normalized[patternIndex] === "*"
    ) {
      wildcardIndex = patternIndex;
      patternIndex += 1;
      wildcardResourceIndex = resourceIndex;
    } else if (wildcardIndex >= 0) {
      patternIndex = wildcardIndex + 1;
      wildcardResourceIndex += 1;
      resourceIndex = wildcardResourceIndex;
    } else {
      return false;
    }
  }
  while (
    patternIndex < normalized.length &&
    normalized[patternIndex] === "*"
  ) {
    patternIndex += 1;
  }
  return patternIndex === normalized.length;
}

async function writePolicy(
  filePath: string,
  snapshot: PolicySnapshot,
  contents: string,
): Promise<void> {
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stagingPath = path.join(
    directory,
    `.${path.basename(filePath)}.staging-${randomUUID()}`,
  );
  try {
    await writeFile(stagingPath, contents, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    if (process.platform !== "win32") {
      await chmod(
        stagingPath,
        snapshot.kind === "file" ? snapshot.mode & 0o777 : 0o600,
      );
    }
    if (snapshot.kind === "absent") {
      try {
        await access(filePath);
        throw new Error("The Kiro user permission file changed during setup.");
      } catch (error) {
        if (!isMissing(error)) {
          throw error;
        }
      }
    } else if (snapshot.kind === "file") {
      const latest = await readFile(filePath, "utf8");
      if (latest !== snapshot.contents) {
        throw new Error("The Kiro user permission file changed during setup.");
      }
    } else {
      throw new Error(snapshot.detail);
    }
    await rename(stagingPath, filePath);
  } catch (error) {
    await rm(stagingPath, { force: true });
    throw error;
  }
}
