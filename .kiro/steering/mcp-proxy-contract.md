# MCP Proxy Contract (v1.5)

## Overview

`kiro-kiro-cortex proxy --target <command>` sits between Kiro and an MCP server. Intercepts responses, scans, redacts, optionally blocks.

## Protocol

MCP uses JSON-RPC 2.0 over stdio. Proxy MUST:
- Pass-through: `initialize`, `initialized`, `tools/list`, `notifications/*`, `ping`
- Intercept: `tools/call` responses only
- Preserve: request IDs, JSON-RPC envelope, error objects

## Response Processing Pipeline

```
MCP Server response
  → Parse result field
  → Secret scan ALL string values
  → Injection scan risky fields (per tool family, same as PostToolUse policy)
  → Assess overall_risk
  → If risk >= threshold: return JSON-RPC error { code: -32001, message: "Blocked by Kiro Cortex" }
  → If secrets found: replace matched_text with "[REDACTED by Kiro Cortex]" in response
  → If injection found: strip role markers, annotation boundaries around suspicious content
  → Return modified response to agent
```

## Config

```toml
[proxy]
enabled = true
risk_threshold = "high"       # "low"|"medium"|"high"|"critical". Block at this level or above.
redact_secrets = true          # Replace secrets with [REDACTED by Kiro Cortex]
neutralize_injection = true    # Strip injection markers
```

## Setup

`kiro-kiro-cortex init --proxy` rewrites `.kiro/settings.json`:

```json
// Before:
{ "mcpServers": { "gmail": { "command": "npx", "args": ["@gmail/mcp-server"] } } }

// After:
{ "mcpServers": { "gmail": { "command": "kiro-cortex", "args": ["proxy", "--target", "npx @gmail/mcp-server"] } } }
```

Original command preserved in `--target`. `kiro-kiro-cortex uninstall --proxy` reverses.

## Audit Logging

Every proxied `tools/call` logged as AuditEntry with:
- `hook_type: "mcpProxy"`
- `tool_name: "@gmail/get_message"` (full namespaced)
- findings, action_taken (`redacted`/`blocked`/`none`), latency_ms

## Performance

Same guardrails as PreToolUse content scanning:
- max_scan_bytes: 1MB per string
- max_scan_depth: 10 levels
- max_strings: 1000

## Exit / Lifecycle

- Proxy process lives as long as the MCP server child process
- Child exits → proxy exits with same code
- Proxy crash → Kiro sees MCP server died, shows error to user
