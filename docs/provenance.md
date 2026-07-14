# Provenance

Kiro Security Power was developed by migrating authorized architecture, workflows, schemas, and implementation concepts from Codex Security.

Kiro Security Power is not an official OpenAI or Codex product.

## Source record

- Source package identity: `codex-security` version `0.1.11`.
- Source manifest author: OpenAI.
- Source manifest license: `Proprietary`.
- Verified source archive SHA-256: `028349a53c19790e182279f44c20d7780c64594a8d5b5f034b461035a297d34d`.
- Authorized migration input supplied by the user for this task.

## What was migrated

The implementation deliberately preserves the reference product's scan modes, six-phase workflow, workbench concepts, durable progress/cancellation/recovery, finding identity and occurrence split, evidence/source-to-sink model, validation/attack-path/triage/remediation records, artifact sealing, exports, and companion MCP integration. These were adapted to a VSIX-first architecture with a typed TypeScript extension host and a Python/SQLite engine.

## What was not copied

The reference archive is not in the repository or VSIX. The complete reference source tree, compressed MCP runtime, compressed MCP App UI, product logo, connector identifiers, and official branding were not copied. The compressed runtime was not decompressed or reverse engineered. A new MCP adapter and Webview were written from the visible contracts.

## Public wording and distribution

Do not describe this product as official OpenAI or Codex software. Public README wording such as “Developed with reference to Codex Security” may be used only after legal and authorization review. That wording must not obscure the actual migration provenance recorded here.
