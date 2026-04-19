# Human-in-the-Loop Contract (v1.5)

## 1. allow-once — Interactive Override

### Subcommand

`kiro-kiro-cortex allow-once <rule-id> --session <session-id>`

### Flow

1. PreToolUse blocks tool → exit 2, STDERR includes finding details + override hint
2. STDERR format (appended to existing block message):
   ```
   To override: kiro-cortex allow-once <rule-id> --session <session-id>
   ```
3. User runs command → appends rule-id to session allowlist
4. User retries action → PreToolUse checks session allowlist → rule skipped, other rules still enforced

### Session Allowlist

- File: `/tmp/cortex-session-<session-id>.allow`
- Format: one rule-id per line, append-only
- TTL: 1 hour from last write, or until session ends
- PreToolUse check order: session allowlist → extra_allow → path deny → content scan

### Security

- Requires explicit CLI command by user. Agent CANNOT trigger allow-once.
- Session-scoped. Does not persist across sessions.
- Overrides specific rule only. Other rules still enforced.
- Audit logged as `action_taken: "overridden"` with `override_rule_id`.

### MCP Proxy Override

`allow-once` also works for proxy blocks. Proxy checks same session allowlist file.

## 2. report — User Feedback

### Subcommand

`kiro-kiro-cortex report <finding-id> <false-positive|confirmed> [--note "reason"]`

### Finding ID

`SHA-256(rule_id + field_path + redacted_preview)` truncated to 8 hex chars. Displayed in:
- STDERR block/warn messages
- Audit log entries
- Session summary

### Storage

Append to `~/.kiro/cortex-feedback.jsonl`:
```json
{
  "timestamp": "2026-04-17T08:00:00Z",
  "finding_id": "a1b2c3d4",
  "rule_id": "generic-api-key",
  "verdict": "false-positive",
  "note": "Test fixture, not real key",
  "session_id": "abc-123"
}
```

### Integration

- `audit summary` includes: per-rule FP rate from feedback data
- `audit summary --noisy` highlights rules with high FP rate + low entropy average

## 3. Session Summary

### Trigger

Kiro `stop` hook: `kiro-kiro-cortex hook stop`

Or manual: `kiro-cortex session summary --session <id>`

### Output (STDERR)

```
─── Kiro Cortex Session Summary ───
  Blocked: 2 (sf-dotenv, openai-api-key)
  Warned:  3 (injection ×2, aws-access-key ×1)
  Proxied: 12 calls (2 redacted, 0 blocked)
  Clean:   47 tool calls
  Overrides: 1 (sf-dotenv via allow-once)
─────────────────────────────────
```

### Config

```toml
[session]
summary = true  # default: true in enforce, false in audit
```

### Hook Setup

```json
"stop": [{ "command": "kiro-cortex hook stop" }]
```

Added by `kiro-kiro-cortex init` (becomes 5th hook).
