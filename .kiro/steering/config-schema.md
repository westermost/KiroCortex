# Config Schema v1

## Struct Definition

```rust
struct Config {
    mode: Mode,                            // default: Audit
    log: LogConfig,
    injection: InjectionConfig,
    prompt_scan: PromptScanConfig,
    sensitive_files: SensitiveFilesConfig,
    secret_rules: Vec<CustomSecretRule>,
    allowlist: AllowlistConfig,
}

enum Mode { Audit, Enforce }               // default: Audit

struct LogConfig {
    path: String,              // default: "~/.kiro/cortex-audit.jsonl"
    max_size_mb: u32,          // default: 50
    max_files: u32,            // default: 5
    include_fingerprint: bool, // default: false
}

struct InjectionConfig {
    enable_tier1: bool,                        // default: true
    defense_instructions: Option<String>,      // inline override
    defense_instructions_file: Option<String>, // file override (precedence over inline)
}

struct PromptScanConfig {
    enabled: bool,                  // default: true
    on_detect: PromptScanAction,    // default: Context
}

enum PromptScanAction { Context, Warn }

struct SensitiveFilesConfig {
    disable_builtin: Vec<String>,  // built-in rule IDs to disable
    extra_deny: Vec<SensitiveFileEntry>,
    extra_allow: Vec<String>,      // path-level overrides
}

struct SensitiveFileEntry {
    pattern: String,
    match_type: MatchType,   // default: Glob
    action: FileAction,      // default: Block
}

enum MatchType { Glob, Basename, Exact, Directory }
enum FileAction { Block, Warn }

struct CustomSecretRule {
    id: String,                    // [required] unique
    regex: String,                 // [required]
    description: Option<String>,
    keywords: Vec<String>,         // default: []
    entropy: Option<f64>,
    severity: Severity,            // default: Medium
    action: SecretAction,          // v1: always Detect
}

enum Severity { Low, Medium, High }
enum SecretAction { Detect }       // v1: detect-only config value.
// NOTE: SecretAction controls PostToolUse/UserPromptSubmit behavior only.
// At PreToolUse, ALL secret rules (built-in + custom) trigger exit 2 (block)
// regardless of this field — because PreToolUse is the enforcement boundary.

struct AllowlistConfig {
    regexes: Vec<String>,
    stopwords: Vec<String>,
    paths: Vec<String>,
}
```

## Naming Convention

**snake_case everywhere**: `on_detect`, `max_size_mb`, `match_type`, `extra_deny`, `enable_tier1`, `defense_instructions_file`, `include_fingerprint`, `disable_builtin`.

CLI flags mirror: `--on-detect`, `--mode`.

## Search Order & Merge

1. `.kiro/cortex.toml` (project-local, highest priority)
2. `~/.kiro/cortex.toml` (user-global)
3. Built-in defaults (compiled into binary)

- Scalars: last wins.
- `secret_rules`, `extra_deny`: append.
- `disable_builtin`: accumulated. Named built-in rules disabled by ID.
- `extra_allow`, `allowlist.*`: append.
- No implicit removal of built-in rules.

## Validation

Collect all errors, report together:

| Condition | Error |
|---|---|
| regex doesn't compile | `"Invalid regex in rule '{id}': {err}"` |
| allowlist regex invalid | `"Invalid allowlist regex at index {i}: {err}"` |
| duplicate rule id | `"Duplicate rule id: '{id}'"` |
| id collides with built-in | `"Rule id '{id}' conflicts with built-in rule"` |
| invalid enum value | `"Invalid {field}: '{val}'. Expected {options}"` |
| max_size_mb is 0 | `"max_size_mb must be > 0"` |
| instructions file missing | `"Defense instructions file not found: '{path}'"` |
| TOML parse error | `"Config parse error at {path}: {err}"` |
