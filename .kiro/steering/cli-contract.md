# CLI Contract — scan & audit summary

## `kiro-kiro-cortex scan <path>`

- Scans: secret detection + prompt injection detection (both).
- Input: file path or directory (recursive).
- Flags:
  - `--format human` (default): colored table, grouped by file.
  - `--format json`: array of AuditFinding objects, one JSON object per line.
- Exit codes: 0 = clean, 1 = findings detected, 2 = error (file not found, permission denied, binary file).
- Directory scan: walks files, skips binary (>50% non-UTF8 bytes), respects `.gitignore`.
- Respects config: allowlist, custom rules, entropy threshold. Ignores `mode` (always scans).

## `kiro-kiro-cortex audit summary`

- Parses audit log file (from `log.path` config).
- Flags:
  - `--since <duration>`: filter by time. Accepts `7d`, `24h`, `30m`. Default: all.
  - `--format table` (default): human-readable summary.
  - `--format json`: machine-readable summary object.
- Output fields: total_events, blocked_count, warned_count, clean_count, top_rules (sorted by trigger count), time_range.
- Exit codes: 0 = success, 2 = error (log file not found, parse error).
