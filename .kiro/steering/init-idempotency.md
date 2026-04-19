# Init/Uninstall Idempotency Rules

## Hook Ownership Detection

Regex: `^kiro-cortex(\s|$)` (case-sensitive). Matches `"kiro-cortex"`, `"kiro-cortex hook pre-tool"`. Does NOT match `"my-cortex-wrapper"`, `"/path/to/cortex-fork"`.

## `kiro-kiro-cortex init [--force] [--proxy]`

- Config (.kiro/cortex.toml): create if not exists. Skip if exists (unless --force).
- Agent config (.kiro/agents/default.json): for each hook type, check if owned hook exists.
  - Exists AND NOT --force → skip.
  - --force → remove owned hooks first, then append new.
  - Not exists → append at END of array.
- Write back: pretty JSON, 2-space indent.
- v1.5: adds `stop` hook (5th hook) for session summary.
- `--proxy`: rewrite `.kiro/settings.json` mcpServers to wrap with `kiro-kiro-cortex proxy --target`. Preserves original command.

## `kiro-kiro-cortex uninstall [--proxy]`

- Remove hooks matching `^kiro-cortex(\s|$)`. Clean empty arrays/objects.
- `--proxy`: restore original mcpServers commands from `--target` args.
- Config file NOT deleted. Idempotent.

## Invariants

- Non-Kiro Cortex hooks NEVER modified, reordered, or removed.
- Non-hook fields (name, tools, model...) NEVER touched.
- init twice = identical file. uninstall twice = safe.

## Required Test Cases

1. init clean project → creates config + 5 hooks (4 + stop)
2. init twice → skip ×5, file identical
3. init with user hooks → Kiro Cortex appended, user hooks untouched
4. init --force → Kiro Cortex replaced, user hooks preserved
5. uninstall → Kiro Cortex removed, config kept
6. uninstall twice → "nothing to uninstall"
7. Agent config has name/model/tools → never modified
8. init --proxy → mcpServers wrapped with kiro-cortex proxy
9. uninstall --proxy → mcpServers restored to original
10. init --proxy twice → idempotent, no double-wrapping
