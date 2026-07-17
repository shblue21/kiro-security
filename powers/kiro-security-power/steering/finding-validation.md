# Finding validation
Inspect the finding's scan profile first. For VSIX Fast findings, call `security_validate_finding` and preserve uncertainty as `needs_review`. For model Standard/Diff/Deep scans, use the completed tail `validation` and `attackPath` returned by `security_get_finding`; do not call the deterministic validator or overwrite authoritative model proof.
