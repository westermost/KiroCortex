# Kiro Cortex — Product Overview

Kiro Cortex is a Rust CLI binary that protects AI agents (Kiro CLI/IDE) from prompt injection and sensitive data leakage via Kiro Hooks.

## Core Capabilities

- **PreToolUse BLOCKING**: Block reading sensitive files AND block tool inputs containing secrets. Exit 2.
- **PostToolUse DETECTION**: Detect secrets/injection in tool responses. STDERR warn only — cannot modify response.
- **UserPromptSubmit DETECTION**: Detect secrets in prompts. Context inject OR warn (mutually exclusive).
- **AgentSpawn DEFENSE**: Inject defense instructions into LLM context (enforce mode only).
- **MCP Proxy (v1.5)**: Man-in-the-middle between agent and MCP servers. Scan, redact secrets, neutralize injection, block critical-risk responses.
- **Interactive Override (v1.5)**: `allow-once` lets user override specific blocks per session.
- **User Feedback (v1.5)**: `report` command for false-positive/confirmed verdicts. Feeds into noisy rule detection.
- **Session Summary (v1.5)**: End-of-session digest of all findings, blocks, and overrides.

## Key Constraints

- Only PreToolUse can block (exit 2). All other hooks detect + warn.
- PostToolUse cannot mutate tool_response. UserPromptSubmit cannot block.
- STDOUT and STDERR never both populated in one invocation.
- Audit mode = zero behavior change (no block, no warn, no context injection).
- No ML in v1. Regex-only. Binary ~3-5MB.

## Tech Stack

- Language: Rust
- Config: TOML (.kiro/cortex.toml)
- Crates: clap, serde, serde_json, toml, regex, unicode-normalization, base64, glob, dirs, anyhow, chrono, once_cell
