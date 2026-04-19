# Path Extraction Contract

## Tool → Field Mapping

| Tool | Input field | Extraction |
|---|---|---|
| `read`, `fs_read` | `tool_input.operations[].path` | Direct array iteration |
| `write`, `fs_write` | Path: N/A. Content: all string values. | **Path not scanned** (not exfiltration). **Content IS scanned** for secrets — `write("f", "AKIA...")` → exit 2. |
| `shell`, `execute_bash` | `tool_input.command` | Shell parser below |
| `@mcp/*`, unknown | All string values | Heuristic scan |

## Shell Parser Algorithm

**Step 1**: Tokenize ENTIRE command string respecting single/double quotes and backslash escapes. MUST happen before operator splitting.

**Step 2**: Split token stream at unquoted `&&`, `||`, `;`, `|`. Recognize `$()` and backtick subshells.

**Step 3**: Per sub-command, extract paths:

| Command | Path args |
|---|---|
| cat, tac, less, more, head, tail, bat, nl | All non-flag args |
| grep, rg, ag, ack | Last arg(s) that look like paths |
| vim, nano, vi, code, open | All non-flag args |
| cp, mv, rsync, scp | All args except last |
| tar with -xf/-cf | Arg after -f |
| unzip, gunzip, zcat, bzcat | First non-flag arg |
| base64, xxd, od, hexdump | First non-flag arg |
| python -c | Regex: `open\(['"]([^'"]+)['"]\)` |
| node -e | Regex: `readFileSync\(['"]([^'"]+)['"]\)` |
| ruby -e | Regex: `File\.read\(['"]([^'"]+)['"]\)` |

**Step 4 — Fallback**: Scan entire command string for denylist basename matches.

**Path resolution**: Relative to `cwd`. `~` expanded to home.

## MCP / Unknown Tool Heuristic

Walk all string values in `tool_input`. Flag if contains `/` or `\` AND matches denylist, OR matches denylist basename exactly.

## PreToolUse Content Scanning

Beyond path matching, scan ALL string values in `tool_input` for secret patterns (~40 rules + custom rules). This applies to **every tool** including `write`/`fs_write` (content field), `shell` (command), `read` (though unlikely), and MCP/unknown tools. Exit 2 on match.

### Precedence / Short-Circuit Order

1. `extra_allow` — path matches allowlist → skip path deny, proceed to content scan.
2. Path deny (built-in + extra_deny):
   - `action=block` → exit 2 immediately. No content scan.
   - `action=warn` → exit 1 STDERR, tool allowed. Content scan still runs after.
3. Content scan ALL strings → match → exit 2.
4. All clean → exit 0.

Key: `extra_allow` overrides path deny but NOT content scan. A file can be path-allowed but content-blocked.

### Performance Guardrails

- `max_scan_bytes`: 1MB per string value. Truncate beyond, log warning.
- `max_scan_depth`: 10 levels JSON nesting. Skip deeper.
- `max_strings`: 1000 string values per tool_input. Skip beyond.
- When limit hit: scan within limits, log `structural_flag` with `flag_type = "scan_truncated"`, proceed with partial results. Never block due to size alone.
