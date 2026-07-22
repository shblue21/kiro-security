# Kiro Security Power capability preflight

Run capability preflight from the chat-only coordinator before the first semantic phase. It is read-only and evaluates the direct Kiro port of the Codex Security 0.1.11 capability profile.

Resolve the bundled Python interpreter, then run the direct-port helper with current runtime facts:

```text
<python_command> -m kiro_security.codex_contract.config_preflight --profile <security_scan|security_diff_scan|deep_security_scan> --registry <engine>/kiro_security/codex_contract/preflight/capability-profiles.toml --cwd <workspace> --runtime-check delegation_available=<true|false> --runtime-check nested_delegation_available=<true|false> --runtime-check goal_tools_available=<true|false> --multi-agent-runtime-owner native --multi-agent-runtime-version v1 --multi-agent-worker-slots <observed-usable-slots> --multi-agent-runtime-provenance tool-surface --available-plugin-skill <Kiro-skill>
```

The coordinator derives every runtime fact from the live Kiro tool surface. `invoke_sub_agent` with `general-task-execution` is the only acceptable delegated-worker capability. Standard, Diff, and Deep may create no more than four concurrent workers. Deep requires the five named phase Skills, delegation, nested delegation, and at least four runtime-observed usable worker slots. A configured or documented default is not runtime evidence for the Deep block gate; omit `--multi-agent-worker-slots` when the live runtime does not expose a trustworthy value so preflight remains incomplete. Deep must not reduce the round size or replace the workflow when those facts are unavailable.

Use the helper result as the deterministic preflight record. A `ready` result allows the selected workflow. A `warn` or `suggest` result must be disclosed when it affects coverage or continuation. A `blocked`, `incomplete`, or helper-error result preserves any already-created running scan for later lease handoff; do not fabricate a result, invoke a fallback scanner, restore dashboard scan start, or make a persistent host configuration change.

Kiro is chat-only for scan start. Do not open an app setup workspace, await an app handoff, or direct the user to a dashboard Start button.
