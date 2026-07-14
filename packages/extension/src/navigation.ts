import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as vscode from "vscode";
import { FindingLocation } from "../../protocol/src";

export function isPathWithin(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

export async function safeWorkspaceUri(workspaceRoot: string, relativePath: string): Promise<vscode.Uri | undefined> {
  if (!relativePath || path.isAbsolute(relativePath) || relativePath.includes("\0")) return undefined;
  const candidate = path.resolve(workspaceRoot, relativePath);
  if (!isPathWithin(workspaceRoot, candidate)) return undefined;
  try {
    const [realRoot, realCandidate] = await Promise.all([fs.realpath(workspaceRoot), fs.realpath(candidate)]);
    if (!isPathWithin(realRoot, realCandidate)) return undefined;
    return vscode.Uri.file(realCandidate);
  } catch {
    return undefined;
  }
}

export async function openSourceLocation(workspaceRoot: string, location: FindingLocation): Promise<boolean> {
  const uri = await safeWorkspaceUri(workspaceRoot, location.path);
  if (!uri) return false;
  const document = await vscode.workspace.openTextDocument(uri);
  const startLine = Math.max(0, Math.min(document.lineCount - 1, location.startLine - 1));
  const endLine = Math.max(startLine, Math.min(document.lineCount - 1, (location.endLine || location.startLine) - 1));
  const start = new vscode.Position(startLine, 0);
  const end = new vscode.Position(endLine, document.lineAt(endLine).text.length);
  const editor = await vscode.window.showTextDocument(document, { preview: false, preserveFocus: false });
  editor.selection = new vscode.Selection(start, end);
  editor.revealRange(new vscode.Range(start, end), vscode.TextEditorRevealType.InCenterIfOutsideViewport);
  return true;
}
