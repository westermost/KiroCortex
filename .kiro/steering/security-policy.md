# Security Policy — Audit Redaction & Secrets

## What IS Logged

rule_id, severity, field_path, redacted_preview, risk_level, finding_type, action_taken, fingerprint (optional).

## What is NEVER Logged

Raw secret values (`matched_text`), full injection payloads, full tool_response, full user prompt, file contents.

## Redaction Format

| Type | Format |
|---|---|
| Secret ≥8 chars | First 4 + `****` + last 4: `AKIA****MPLE` |
| Secret <8 chars | `****` |
| Injection | First 50 chars + `...` if longer |
| Structural | Description only |

## Fingerprint

`log.include_fingerprint = true` (default: false): SHA-256 of raw value, truncated to 16 hex chars.

## Code Rules

- `matched_text` field must NEVER be written to any file, log, STDERR, or STDOUT.
- Use `redacted_preview` for all external output.
- `AuditFinding` struct intentionally has no `matched_text` field — this is the enforcement boundary.
