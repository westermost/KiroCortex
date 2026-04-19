use crate::config::{FileAction, MatchType, SensitiveFilesConfig};
use std::path::Path;

pub struct SensitiveFileRule {
    pub id: String,
    pub pattern: String,
    pub match_type: MatchType,
    pub action: FileAction,
}

pub fn builtin_sensitive_files() -> Vec<SensitiveFileRule> {
    let rules = vec![
        ("sf-dotenv", ".env", MatchType::Basename, FileAction::Block),
        ("sf-dotenv-wildcard", ".env.*", MatchType::Glob, FileAction::Block),
        ("sf-pem", "*.pem", MatchType::Glob, FileAction::Block),
        ("sf-key", "*.key", MatchType::Glob, FileAction::Block),
        ("sf-p12", "*.p12", MatchType::Glob, FileAction::Block),
        ("sf-pfx", "*.pfx", MatchType::Glob, FileAction::Block),
        ("sf-jks", "*.jks", MatchType::Glob, FileAction::Block),
        ("sf-keychain", "*.keychain-db", MatchType::Glob, FileAction::Block),
        ("sf-id-rsa", "id_rsa", MatchType::Basename, FileAction::Block),
        ("sf-id-ed25519", "id_ed25519", MatchType::Basename, FileAction::Block),
        ("sf-id-ecdsa", "id_ecdsa", MatchType::Basename, FileAction::Block),
        ("sf-id-dsa", "id_dsa", MatchType::Basename, FileAction::Block),
        ("sf-kubeconfig", "kubeconfig", MatchType::Basename, FileAction::Block),
        ("sf-credentials", "credentials", MatchType::Basename, FileAction::Block),
        ("sf-npmrc", ".npmrc", MatchType::Basename, FileAction::Block),
        ("sf-pypirc", ".pypirc", MatchType::Basename, FileAction::Block),
        ("sf-netrc", ".netrc", MatchType::Basename, FileAction::Block),
        ("sf-pgpass", ".pgpass", MatchType::Basename, FileAction::Block),
        ("sf-mycnf", ".my.cnf", MatchType::Basename, FileAction::Block),
        ("sf-tfvars", "terraform.tfvars", MatchType::Basename, FileAction::Block),
        ("sf-tfstate", "*.tfstate", MatchType::Glob, FileAction::Block),
        ("sf-secrets-yaml", "secrets.yaml", MatchType::Basename, FileAction::Block),
        ("sf-secrets-yml", "secrets.yml", MatchType::Basename, FileAction::Block),
        ("sf-docker-config", ".docker/config.json", MatchType::Exact, FileAction::Block),
        ("sf-aws-credentials", ".aws/credentials", MatchType::Exact, FileAction::Block),
        ("sf-ssh-dir", ".ssh/*", MatchType::Glob, FileAction::Block),
        ("sf-mobileprovision", "*.mobileprovision", MatchType::Glob, FileAction::Block),
        ("sf-vault-json", "vault.json", MatchType::Basename, FileAction::Block),
        ("sf-htpasswd", ".htpasswd", MatchType::Basename, FileAction::Block),
    ];
    rules.into_iter().map(|(id, pat, mt, act)| SensitiveFileRule {
        id: id.into(), pattern: pat.into(), match_type: mt, action: act,
    }).collect()
}

pub struct PathMatchResult {
    pub rule_id: String,
    pub pattern: String,
    pub match_type: MatchType,
    pub action: FileAction,
    pub matched_path: String,
}

pub fn match_path(
    path: &str,
    config: &SensitiveFilesConfig,
    disabled: &[String],
) -> Option<PathMatchResult> {
    // 1. Check extra_allow first
    let basename = Path::new(path).file_name().and_then(|f| f.to_str()).unwrap_or("");
    for allow in &config.extra_allow {
        if basename == allow || path.ends_with(allow) {
            return None; // Allowed, skip path deny
        }
    }

    // 2. Check built-in rules (minus disabled)
    let builtins = builtin_sensitive_files();
    for rule in &builtins {
        if disabled.contains(&rule.id) {
            continue;
        }
        if matches_rule(path, basename, &rule.pattern, &rule.match_type) {
            return Some(PathMatchResult {
                rule_id: rule.id.clone(), pattern: rule.pattern.clone(),
                match_type: rule.match_type.clone(), action: rule.action.clone(),
                matched_path: path.into(),
            });
        }
    }

    // 3. Check extra_deny
    for entry in &config.extra_deny {
        if matches_rule(path, basename, &entry.pattern, &entry.match_type) {
            return Some(PathMatchResult {
                rule_id: format!("custom:{}", entry.pattern), pattern: entry.pattern.clone(),
                match_type: entry.match_type.clone(), action: entry.action.clone(),
                matched_path: path.into(),
            });
        }
    }

    None
}

fn matches_rule(path: &str, basename: &str, pattern: &str, match_type: &MatchType) -> bool {
    match match_type {
        MatchType::Basename => basename == pattern,
        MatchType::Exact => path.ends_with(pattern),
        MatchType::Glob => glob_match(basename, pattern) || glob_match(path, pattern),
        MatchType::Directory => path.contains(&format!("/{}/", pattern)) || path.starts_with(&format!("{}/", pattern)),
    }
}

fn glob_match(text: &str, pattern: &str) -> bool {
    if pattern == "*" { return true; }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return text.ends_with(&format!(".{}", suffix));
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        let base = Path::new(text).file_name().and_then(|f| f.to_str()).unwrap_or("");
        return base.starts_with(&format!("{}.", prefix)) || base == prefix;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return text.starts_with(&format!("{}/", prefix)) || text.contains(&format!("/{}/", prefix));
    }
    text == pattern
}

// --- Path extraction from tool_input ---

use serde_json::Value;

pub fn extract_paths(tool_name: &str, tool_input: &Value) -> Vec<String> {
    match tool_name {
        "read" | "fs_read" => extract_read_paths(tool_input),
        "write" | "fs_write" => vec![], // Not scanned for paths in v1
        "shell" | "execute_bash" => {
            if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
                parse_shell_paths(cmd)
            } else {
                vec![]
            }
        }
        _ => extract_heuristic_paths(tool_input),
    }
}

fn extract_read_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(ops) = input.get("operations") {
        match ops {
            Value::Array(arr) => {
                for op in arr {
                    if let Some(p) = op.get("path").and_then(|v| v.as_str()) {
                        paths.push(p.to_string());
                    }
                }
            }
            Value::Object(_) => {
                // Single object instead of array
                if let Some(p) = ops.get("path").and_then(|v| v.as_str()) {
                    paths.push(p.to_string());
                }
            }
            _ => {}
        }
    }
    // Fallback: direct path field
    if paths.is_empty() {
        if let Some(p) = input.get("path").and_then(|v| v.as_str()) {
            paths.push(p.to_string());
        }
    }
    paths
}

fn extract_heuristic_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_string_values(input, &mut paths);
    paths.retain(|s| (s.contains('/') || s.contains('\\')) && !s.starts_with("http"));
    paths
}

fn collect_string_values(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(arr) => arr.iter().for_each(|v| collect_string_values(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_string_values(v, out)),
        _ => {}
    }
}

// --- Shell parser ---

pub fn parse_shell_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Extract subshell commands first and parse them recursively
    paths.extend(extract_subshell_paths(command));

    let tokens = tokenize_shell(command);
    let subcmds = split_on_operators(&tokens);

    for subcmd in &subcmds {
        if subcmd.is_empty() { continue; }
        let cmd_name = subcmd[0].as_str();
        let args: Vec<&str> = subcmd[1..].iter().map(|s| s.as_str()).collect();
        paths.extend(extract_cmd_paths(cmd_name, &args));
    }

    // Fallback: scan entire command for denylist basenames
    if paths.is_empty() {
        let builtins = builtin_sensitive_files();
        for rule in &builtins {
            if command.contains(&rule.pattern) || command.contains(
                Path::new(&rule.pattern).file_name().and_then(|f| f.to_str()).unwrap_or("")
            ) {
                for token in &tokens {
                    let base = Path::new(token.as_str()).file_name().and_then(|f| f.to_str()).unwrap_or("");
                    if base == rule.pattern || glob_match(base, &rule.pattern) {
                        paths.push(token.clone());
                    }
                }
            }
        }
    }

    paths
}

fn extract_subshell_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Handle $(...) subshells
    let re_dollar = regex::Regex::new(r"\$\(([^)]+)\)").unwrap();
    for cap in re_dollar.captures_iter(command) {
        paths.extend(parse_shell_paths(&cap[1]));
    }

    // Handle backtick subshells
    let re_backtick = regex::Regex::new(r"`([^`]+)`").unwrap();
    for cap in re_backtick.captures_iter(command) {
        paths.extend(parse_shell_paths(&cap[1]));
    }

    paths
}

fn tokenize_shell(cmd: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = cmd.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        match c {
            '\\' if !in_single => {
                if let Some(&next) = chars.peek() {
                    current.push(next);
                    chars.next();
                }
            }
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            ';' | '|' if !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(c.to_string());
            }
            '&' if !in_single && !in_double => {
                if chars.peek() == Some(&'&') {
                    chars.next();
                    if !current.is_empty() {
                        tokens.push(std::mem::take(&mut current));
                    }
                    tokens.push("&&".into());
                } else {
                    current.push(c);
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn split_on_operators(tokens: &[String]) -> Vec<Vec<String>> {
    let mut result = Vec::new();
    let mut current = Vec::new();
    for token in tokens {
        match token.as_str() {
            "&&" | "||" | ";" | "|" => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(token.clone()),
        }
    }
    if !current.is_empty() {
        result.push(current);
    }
    result
}

fn extract_cmd_paths(cmd: &str, args: &[&str]) -> Vec<String> {
    let non_flags: Vec<&str> = args.iter().filter(|a| !a.starts_with('-')).copied().collect();

    match cmd {
        "cat" | "tac" | "less" | "more" | "head" | "tail" | "bat" | "nl" => {
            non_flags.into_iter().map(String::from).collect()
        }
        "grep" | "rg" | "ag" | "ack" => {
            // Last non-flag args that look like paths
            non_flags.iter().skip(1).filter(|a| looks_like_path(a)).map(|a| a.to_string()).collect()
        }
        "vim" | "nano" | "vi" | "code" | "open" => {
            non_flags.into_iter().map(String::from).collect()
        }
        "cp" | "mv" | "rsync" | "scp" => {
            if non_flags.len() > 1 { non_flags[..non_flags.len()-1].iter().map(|a| a.to_string()).collect() }
            else { vec![] }
        }
        "base64" | "xxd" | "od" | "hexdump" | "unzip" | "gunzip" | "zcat" | "bzcat" => {
            non_flags.first().map(|a| vec![a.to_string()]).unwrap_or_default()
        }
        "python" | "python3" => extract_python_paths(args),
        "node" => extract_node_paths(args),
        "ruby" => extract_ruby_paths(args),
        _ => vec![],
    }
}

fn looks_like_path(s: &str) -> bool {
    s.contains('/') || s.contains('.') || s.contains('~')
}

fn extract_python_paths(args: &[&str]) -> Vec<String> {
    let joined = args.join(" ");
    if !joined.contains("-c") { return vec![]; }
    let re = regex::Regex::new(r#"open\(['"]([^'"]+)['"]\)"#).unwrap();
    re.captures_iter(&joined).map(|c| c[1].to_string()).collect()
}

fn extract_node_paths(args: &[&str]) -> Vec<String> {
    let joined = args.join(" ");
    if !joined.contains("-e") { return vec![]; }
    let re = regex::Regex::new(r#"readFileSync\(['"]([^'"]+)['"]\)"#).unwrap();
    re.captures_iter(&joined).map(|c| c[1].to_string()).collect()
}

fn extract_ruby_paths(args: &[&str]) -> Vec<String> {
    let joined = args.join(" ");
    if !joined.contains("-e") { return vec![]; }
    let re = regex::Regex::new(r#"File\.read\(['"]([^'"]+)['"]\)"#).unwrap();
    re.captures_iter(&joined).map(|c| c[1].to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- 3.1 Built-in denylist ---

    fn default_config() -> SensitiveFilesConfig { SensitiveFilesConfig::default() }

    #[test]
    fn dotenv_blocked() {
        let r = match_path(".env", &default_config(), &[]);
        assert!(r.is_some());
        assert_eq!(r.unwrap().rule_id, "sf-dotenv");
    }

    #[test]
    fn dotenv_production_blocked() {
        let r = match_path(".env.production", &default_config(), &[]);
        assert!(r.is_some());
        assert_eq!(r.unwrap().rule_id, "sf-dotenv-wildcard");
    }

    #[test]
    fn id_rsa_blocked() {
        let r = match_path("id_rsa", &default_config(), &[]);
        assert!(r.is_some());
    }

    #[test]
    fn aws_credentials_blocked() {
        let r = match_path(".aws/credentials", &default_config(), &[]);
        assert!(r.is_some());
    }

    #[test]
    fn pem_blocked() {
        let r = match_path("server.pem", &default_config(), &[]);
        assert!(r.is_some());
    }

    #[test]
    fn tfvars_blocked() {
        let r = match_path("terraform.tfvars", &default_config(), &[]);
        assert!(r.is_some());
    }

    #[test]
    fn readme_allowed() {
        assert!(match_path("README.md", &default_config(), &[]).is_none());
    }

    #[test]
    fn src_main_allowed() {
        assert!(match_path("src/main.rs", &default_config(), &[]).is_none());
    }

    #[test]
    fn disable_builtin_works() {
        let r = match_path(".env.production", &default_config(), &["sf-dotenv-wildcard".into()]);
        assert!(r.is_none());
    }

    // --- 3.2 extra_allow ---

    #[test]
    fn extra_allow_overrides_deny() {
        let mut cfg = default_config();
        cfg.extra_allow = vec![".env.example".into()];
        assert!(match_path(".env.example", &cfg, &[]).is_none());
    }

    #[test]
    fn extra_allow_template() {
        let mut cfg = default_config();
        cfg.extra_allow = vec![".env.template".into()];
        assert!(match_path(".env.template", &cfg, &[]).is_none());
    }

    #[test]
    fn dotenv_still_blocked_without_allow() {
        let mut cfg = default_config();
        cfg.extra_allow = vec![".env.example".into()];
        assert!(match_path(".env", &cfg, &[]).is_some());
    }

    // --- 3.3 Path extraction ---

    #[test]
    fn extract_read_paths_from_operations() {
        let input: Value = serde_json::json!({"operations": [{"mode": "Line", "path": "/project/.env"}]});
        let paths = extract_paths("read", &input);
        assert_eq!(paths, vec!["/project/.env"]);
    }

    #[test]
    fn extract_write_no_paths() {
        let input: Value = serde_json::json!({"path": "/project/out.txt", "content": "hello"});
        let paths = extract_paths("write", &input);
        assert!(paths.is_empty());
    }

    #[test]
    fn extract_unknown_tool_heuristic() {
        let input: Value = serde_json::json!({"file": "/project/.env", "data": "test"});
        let paths = extract_paths("@mcp/custom", &input);
        assert_eq!(paths, vec!["/project/.env"]);
    }

    #[test]
    fn extract_read_operations_single_object() {
        let input: Value = serde_json::json!({"operations": {"mode": "Line", "path": "/etc/shadow"}});
        let paths = extract_paths("read", &input);
        assert_eq!(paths, vec!["/etc/shadow"]);
    }

    // --- 3.4 Shell parser ---

    #[test]
    fn shell_cat_env() {
        let paths = parse_shell_paths("cat .env");
        assert_eq!(paths, vec![".env"]);
    }

    #[test]
    fn shell_cat_quoted() {
        let paths = parse_shell_paths("cat '.env'");
        assert_eq!(paths, vec![".env"]);
    }

    #[test]
    fn shell_cat_double_quoted() {
        let paths = parse_shell_paths(r#"cat "file with spaces.txt""#);
        assert_eq!(paths, vec!["file with spaces.txt"]);
    }

    #[test]
    fn shell_split_and() {
        let paths = parse_shell_paths("cat .env && echo hello");
        assert_eq!(paths, vec![".env"]);
    }

    #[test]
    fn shell_split_semicolon() {
        let paths = parse_shell_paths("cat .env; head id_rsa");
        assert!(paths.contains(&".env".to_string()));
        assert!(paths.contains(&"id_rsa".to_string()));
    }

    #[test]
    fn shell_pipe() {
        let paths = parse_shell_paths("grep pattern .env | head");
        assert!(paths.contains(&".env".to_string()));
    }

    #[test]
    fn shell_python_open() {
        let paths = parse_shell_paths(r#"python -c "open('.env').read()""#);
        assert_eq!(paths, vec![".env"]);
    }

    #[test]
    fn shell_echo_no_paths() {
        let paths = parse_shell_paths("echo hello");
        assert!(paths.is_empty());
    }

    #[test]
    fn shell_base64() {
        let paths = parse_shell_paths("base64 id_rsa");
        assert_eq!(paths, vec!["id_rsa"]);
    }

    #[test]
    fn shell_cp() {
        let paths = parse_shell_paths("cp .env /tmp/");
        assert_eq!(paths, vec![".env"]);
    }

    #[test]
    fn shell_fallback_basename_match() {
        let paths = parse_shell_paths("some-unknown-cmd .env");
        assert!(paths.contains(&".env".to_string()));
    }

    #[test]
    fn shell_subshell_dollar_paren() {
        let paths = parse_shell_paths("echo $(cat .env)");
        assert!(paths.contains(&".env".to_string()));
    }

    #[test]
    fn shell_subshell_backtick() {
        let paths = parse_shell_paths("echo `cat .env`");
        assert!(paths.contains(&".env".to_string()));
    }

    #[test]
    fn shell_nested_subshell() {
        let paths = parse_shell_paths("echo $(head .aws/credentials)");
        assert!(paths.contains(&".aws/credentials".to_string()));
    }
}
