import {
  parseTree,
  type Node,
  type ParseError,
  type ParseOptions,
} from "jsonc-parser";

export function findDuplicateJsonObjectKey(
  contents: string,
  options: ParseOptions,
): string | undefined {
  const errors: ParseError[] = [];
  const root = parseTree(contents, errors, options);
  if (root === undefined || errors.length > 0) {
    return undefined;
  }

  const pending: Node[] = [root];
  while (pending.length > 0) {
    const node = pending.pop();
    if (node === undefined) {
      continue;
    }
    if (node.type === "object") {
      const keys = new Set<string>();
      for (const property of node.children ?? []) {
        const key = property.children?.[0]?.value;
        if (typeof key !== "string") {
          continue;
        }
        if (keys.has(key)) {
          return key;
        }
        keys.add(key);
      }
    }
    pending.push(...(node.children ?? []));
  }
  return undefined;
}
