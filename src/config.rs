use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Audit,
    Enforce,
}

impl Default for Mode {
    fn default() -> Self { Mode::Enforce }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PromptScanAction {
    Context,
    Warn,
}

impl Default for PromptScanAction {
    fn default() -> Self { PromptScanAction::Context }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Glob,
    Basename,
    Exact,
    Directory,
}

impl Default for MatchType {
    fn default() -> Self { MatchType::Glob }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FileAction {
    Block,
    Warn,
}

impl Default for FileAction {
    fn default() -> Self { FileAction::Block }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Default for Severity {
    fn default() -> Self { Severity::Medium }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretAction {
    Detect,
}

impl Default for SecretAction {
    fn default() -> Self { SecretAction::Detect }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_path")]
    pub path: String,
    #[serde(default = "default_max_size")]
    pub max_size_mb: u32,
    #[serde(default = "default_max_files")]
    pub max_files: u32,
    #[serde(default)]
    pub include_fingerprint: bool,
}

fn default_log_path() -> String { "~/.kiro/cortex-audit.jsonl".into() }
fn default_max_size() -> u32 { 50 }
fn default_max_files() -> u32 { 5 }

impl Default for LogConfig {
    fn default() -> Self {
        Self { path: default_log_path(), max_size_mb: 50, max_files: 5, include_fingerprint: false }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct InjectionConfig {
    #[serde(default = "default_true")]
    pub enable_tier1: bool,
    pub defense_instructions: Option<String>,
    pub defense_instructions_file: Option<String>,
}

fn default_true() -> bool { true }

impl Default for InjectionConfig {
    fn default() -> Self {
        Self { enable_tier1: true, defense_instructions: None, defense_instructions_file: None }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PromptScanConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub on_detect: PromptScanAction,
}

impl Default for PromptScanConfig {
    fn default() -> Self { Self { enabled: true, on_detect: PromptScanAction::Context } }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SensitiveFileEntry {
    pub pattern: String,
    #[serde(default)]
    pub match_type: MatchType,
    #[serde(default)]
    pub action: FileAction,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SensitiveFilesConfig {
    #[serde(default)]
    pub disable_builtin: Vec<String>,
    #[serde(default)]
    pub extra_deny: Vec<SensitiveFileEntry>,
    #[serde(default)]
    pub extra_allow: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CustomSecretRule {
    pub id: String,
    pub regex: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub severity: Severity,
    #[allow(dead_code)]
    #[serde(default)]
    pub action: SecretAction,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub injection: InjectionConfig,
    #[serde(default)]
    pub prompt_scan: PromptScanConfig,
    #[serde(default)]
    pub sensitive_files: SensitiveFilesConfig,
    #[serde(default)]
    pub secret_rules: Vec<CustomSecretRule>,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
}

impl Default for Config {
    fn default() -> Self {
        toml::from_str("").unwrap()
    }
}

impl Config {
    pub fn load(cwd: &Path) -> Result<Self> {
        let project = cwd.join(".kiro").join("cortex.toml");
        let global = dirs::home_dir().map(|h| h.join(".kiro").join("cortex.toml"));

        let mut base = Config::default();

        if let Some(g) = global {
            if g.exists() {
                let content = std::fs::read_to_string(&g)
                    .with_context(|| format!("Failed to read {}", g.display()))?;
                let content = content.trim_start_matches('\u{FEFF}'); // Strip BOM
                let raw: toml::Value = toml::from_str(content)
                    .with_context(|| format!("Config parse error at {}", g.display()))?;
                let parsed: Config = toml::from_str(content)
                    .with_context(|| format!("Config parse error at {}", g.display()))?;
                base.merge(parsed, &raw);
            }
        }

        if project.exists() {
            let content = std::fs::read_to_string(&project)
                .with_context(|| format!("Failed to read {}", project.display()))?;
            let content = content.trim_start_matches('\u{FEFF}'); // Strip BOM
            let raw: toml::Value = toml::from_str(content)
                .with_context(|| format!("Config parse error at {}", project.display()))?;
            let parsed: Config = toml::from_str(content)
                .with_context(|| format!("Config parse error at {}", project.display()))?;
            base.merge(parsed, &raw);
        }

        base.validate()?;
        Ok(base)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn from_toml(toml_str: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(toml_str).context("TOML parse error")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn merge(&mut self, other: Config, raw: &toml::Value) {
        // Scalars: only override if explicitly set in the other config
        if raw.get("mode").is_some() { self.mode = other.mode; }

        // Nested tables: merge field-by-field
        if let Some(log) = raw.get("log").and_then(|v| v.as_table()) {
            if log.contains_key("path") { self.log.path = other.log.path; }
            if log.contains_key("max_size_mb") { self.log.max_size_mb = other.log.max_size_mb; }
            if log.contains_key("max_files") { self.log.max_files = other.log.max_files; }
            if log.contains_key("include_fingerprint") { self.log.include_fingerprint = other.log.include_fingerprint; }
        }
        if let Some(inj) = raw.get("injection").and_then(|v| v.as_table()) {
            if inj.contains_key("enable_tier1") { self.injection.enable_tier1 = other.injection.enable_tier1; }
            if inj.contains_key("defense_instructions") { self.injection.defense_instructions = other.injection.defense_instructions; }
            if inj.contains_key("defense_instructions_file") { self.injection.defense_instructions_file = other.injection.defense_instructions_file; }
        }
        if let Some(ps) = raw.get("prompt_scan").and_then(|v| v.as_table()) {
            if ps.contains_key("enabled") { self.prompt_scan.enabled = other.prompt_scan.enabled; }
            if ps.contains_key("on_detect") { self.prompt_scan.on_detect = other.prompt_scan.on_detect; }
        }

        // Lists: always append
        self.secret_rules.extend(other.secret_rules);
        self.sensitive_files.disable_builtin.extend(other.sensitive_files.disable_builtin);
        self.sensitive_files.extra_deny.extend(other.sensitive_files.extra_deny);
        self.sensitive_files.extra_allow.extend(other.sensitive_files.extra_allow);
        self.allowlist.regexes.extend(other.allowlist.regexes);
        self.allowlist.stopwords.extend(other.allowlist.stopwords);
        self.allowlist.paths.extend(other.allowlist.paths);
    }

    fn validate(&self) -> Result<()> {
        let mut errors: Vec<String> = Vec::new();

        if self.log.max_size_mb == 0 {
            errors.push("max_size_mb must be > 0".into());
        }

        let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for rule in &self.secret_rules {
            if !seen_ids.insert(&rule.id) {
                errors.push(format!("Duplicate rule id: '{}'", rule.id));
            }
            if let Err(e) = regex::Regex::new(&rule.regex) {
                errors.push(format!("Invalid regex in rule '{}': {}", rule.id, e));
            }
        }

        for (i, r) in self.allowlist.regexes.iter().enumerate() {
            if let Err(e) = regex::Regex::new(r) {
                errors.push(format!("Invalid allowlist regex at index {}: {}", i, e));
            }
        }

        if let Some(ref path) = self.injection.defense_instructions_file {
            let resolved = if PathBuf::from(path).is_absolute() {
                PathBuf::from(path)
            } else {
                // Resolve relative to config search path, not process CWD
                // Best effort: check project .kiro dir first
                PathBuf::from(path)
            };
            if !resolved.exists() {
                errors.push(format!("Defense instructions file not found: '{}'", path));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!("Config validation errors:\n  - {}", errors.join("\n  - "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 2.1 Defaults ---

    #[test]
    fn default_mode_is_enforce() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Enforce);
    }

    #[test]
    fn default_log_path_set() {
        let cfg = Config::default();
        assert_eq!(cfg.log.path, "~/.kiro/cortex-audit.jsonl");
    }

    #[test]
    fn default_log_max_size() {
        let cfg = Config::default();
        assert_eq!(cfg.log.max_size_mb, 50);
    }

    #[test]
    fn default_prompt_scan_context() {
        let cfg = Config::default();
        assert_eq!(cfg.prompt_scan.on_detect, PromptScanAction::Context);
    }

    #[test]
    fn default_injection_enabled() {
        let cfg = Config::default();
        assert!(cfg.injection.enable_tier1);
    }

    // --- 2.2 Parsing ---

    #[test]
    fn parse_minimal_toml() {
        let cfg = Config::from_toml(r#"mode = "enforce""#).unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.log.max_size_mb, 50); // default preserved
    }

    #[test]
    fn parse_full_toml() {
        let cfg = Config::from_toml(r#"
            mode = "enforce"
            [log]
            path = "/tmp/audit.jsonl"
            max_size_mb = 100
            max_files = 10
            include_fingerprint = true
            [injection]
            enable_tier1 = false
            [prompt_scan]
            enabled = false
            on_detect = "warn"
            [sensitive_files]
            disable_builtin = ["sf-dotenv"]
            extra_allow = [".env.example"]
            [allowlist]
            regexes = ["(?i)example"]
            stopwords = ["test"]
        "#).unwrap();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert_eq!(cfg.log.path, "/tmp/audit.jsonl");
        assert_eq!(cfg.log.max_size_mb, 100);
        assert!(cfg.log.include_fingerprint);
        assert!(!cfg.injection.enable_tier1);
        assert!(!cfg.prompt_scan.enabled);
        assert_eq!(cfg.prompt_scan.on_detect, PromptScanAction::Warn);
        assert_eq!(cfg.sensitive_files.disable_builtin, vec!["sf-dotenv"]);
        assert_eq!(cfg.sensitive_files.extra_allow, vec![".env.example"]);
    }

    #[test]
    fn parse_unknown_field_ignored() {
        let cfg = Config::from_toml(r#"
            mode = "audit"
            unknown_field = "ignored"
        "#);
        // toml crate with serde default ignores unknown fields
        assert!(cfg.is_ok());
    }

    #[test]
    fn parse_invalid_toml() {
        let result = Config::from_toml("mode = ");
        assert!(result.is_err());
    }

    #[test]
    fn parse_invalid_enum() {
        let result = Config::from_toml(r#"mode = "xyz""#);
        assert!(result.is_err());
    }

    #[test]
    fn parse_secret_rules() {
        let cfg = Config::from_toml(r#"
            [[secret_rules]]
            id = "my-key"
            regex = 'myco_[a-zA-Z0-9]{32}'
            keywords = ["myco_"]
            severity = "high"
            action = "detect"
        "#).unwrap();
        assert_eq!(cfg.secret_rules.len(), 1);
        assert_eq!(cfg.secret_rules[0].id, "my-key");
        assert_eq!(cfg.secret_rules[0].severity, Severity::High);
    }

    #[test]
    fn parse_per_rule_entropy() {
        let cfg = Config::from_toml(r#"
            [[secret_rules]]
            id = "test"
            regex = "test"
            entropy = 4.0
        "#).unwrap();
        assert_eq!(cfg.secret_rules[0].entropy, Some(4.0));
    }

    // --- 2.3 Merge ---

    #[test]
    fn merge_scalars_last_wins() {
        let mut base = Config::from_toml(r#"mode = "audit""#).unwrap();
        let raw: toml::Value = toml::from_str(r#"mode = "enforce""#).unwrap();
        let other = Config::from_toml(r#"mode = "enforce""#).unwrap();
        base.merge(other, &raw);
        assert_eq!(base.mode, Mode::Enforce);
    }

    #[test]
    fn merge_secret_rules_appended() {
        let mut base = Config::from_toml(r#"
            [[secret_rules]]
            id = "rule-a"
            regex = "a"
        "#).unwrap();
        let toml_str = r#"
            [[secret_rules]]
            id = "rule-b"
            regex = "b"
        "#;
        let raw: toml::Value = toml::from_str(toml_str).unwrap();
        let other = Config::from_toml(toml_str).unwrap();
        base.merge(other, &raw);
        assert_eq!(base.secret_rules.len(), 2);
        assert_eq!(base.secret_rules[0].id, "rule-a");
        assert_eq!(base.secret_rules[1].id, "rule-b");
    }

    #[test]
    fn merge_disable_builtin_accumulated() {
        let mut base = Config::from_toml(r#"
            [sensitive_files]
            disable_builtin = ["sf-dotenv"]
        "#).unwrap();
        let toml_str = r#"
            [sensitive_files]
            disable_builtin = ["sf-pem"]
        "#;
        let raw: toml::Value = toml::from_str(toml_str).unwrap();
        let other = Config::from_toml(toml_str).unwrap();
        base.merge(other, &raw);
        assert_eq!(base.sensitive_files.disable_builtin, vec!["sf-dotenv", "sf-pem"]);
    }

    #[test]
    fn merge_extra_allow_appended() {
        let mut base = Config::from_toml(r#"
            [sensitive_files]
            extra_allow = [".env.example"]
        "#).unwrap();
        let toml_str = r#"
            [sensitive_files]
            extra_allow = [".env.template"]
        "#;
        let raw: toml::Value = toml::from_str(toml_str).unwrap();
        let other = Config::from_toml(toml_str).unwrap();
        base.merge(other, &raw);
        assert_eq!(base.sensitive_files.extra_allow, vec![".env.example", ".env.template"]);
    }

    #[test]
    fn merge_allowlist_appended() {
        let mut base = Config::from_toml(r#"
            [allowlist]
            stopwords = ["test"]
        "#).unwrap();
        let toml_str = r#"
            [allowlist]
            stopwords = ["dummy"]
        "#;
        let raw: toml::Value = toml::from_str(toml_str).unwrap();
        let other = Config::from_toml(toml_str).unwrap();
        base.merge(other, &raw);
        assert_eq!(base.allowlist.stopwords, vec!["test", "dummy"]);
    }

    #[test]
    fn merge_nested_field_preserves_unset() {
        // Global sets prompt_scan.enabled = false
        let mut base = Config::from_toml(r#"
            [prompt_scan]
            enabled = false
        "#).unwrap();
        assert!(!base.prompt_scan.enabled);
        // Project only sets mode, doesn't mention prompt_scan
        let toml_str = r#"mode = "enforce""#;
        let raw: toml::Value = toml::from_str(toml_str).unwrap();
        let other = Config::from_toml(toml_str).unwrap();
        base.merge(other, &raw);
        // prompt_scan.enabled should still be false (not reset to default true)
        assert!(!base.prompt_scan.enabled);
        assert_eq!(base.mode, Mode::Enforce);
    }

    // --- 2.4 Validation ---

    #[test]
    fn validate_invalid_regex() {
        let result = Config::from_toml(r#"
            [[secret_rules]]
            id = "bad"
            regex = "[invalid"
        "#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid regex in rule 'bad'"));
    }

    #[test]
    fn validate_duplicate_rule_id() {
        let result = Config::from_toml(r#"
            [[secret_rules]]
            id = "dup"
            regex = "a"
            [[secret_rules]]
            id = "dup"
            regex = "b"
        "#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Duplicate rule id: 'dup'"));
    }

    #[test]
    fn validate_max_size_zero() {
        let result = Config::from_toml(r#"
            [log]
            max_size_mb = 0
        "#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max_size_mb must be > 0"));
    }

    #[test]
    fn validate_invalid_allowlist_regex() {
        let result = Config::from_toml(r#"
            [allowlist]
            regexes = ["[bad"]
        "#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Invalid allowlist regex"));
    }

    #[test]
    fn validate_multiple_errors_reported() {
        let result = Config::from_toml(r#"
            [log]
            max_size_mb = 0
            [[secret_rules]]
            id = "bad"
            regex = "[invalid"
        "#);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("max_size_mb"));
        assert!(err.contains("Invalid regex"));
    }

    #[test]
    fn validate_valid_config_ok() {
        let result = Config::from_toml(r#"
            mode = "enforce"
            [[secret_rules]]
            id = "good"
            regex = "sk-[a-z]+"
        "#);
        assert!(result.is_ok());
    }

    #[test]
    fn default_config_loads_without_file() {
        let cfg = Config::default();
        assert_eq!(cfg.mode, Mode::Enforce);
        assert!(cfg.secret_rules.is_empty());
    }
}
