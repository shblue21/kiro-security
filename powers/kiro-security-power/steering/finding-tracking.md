# Finding tracking handoff

1. Retrieve the canonical finding with `security_get_finding`.
2. Confirm validation and triage state and check the intended destination for duplicate work.
3. Call `security_create_tracking_handoff` with the selected manual, GitHub, Linear, or Jira provider.
4. Review the generated JSON artifact and obtain explicit approval before any separately configured connector performs an external write.
5. Never report that an external issue was created: this Power only prepares and records the handoff in the shared workbench.
