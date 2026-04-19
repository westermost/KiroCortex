use anyhow::Result;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

const HOOK_REGEX: &str = r"^(kiro-cortex|cortex)(\s|$)";

const DEFAULT_CONFIG: &str = r#"# Kiro Cortex configuration
# mode = "enforce" (default) | "audit"
mode = "enforce"

[log]
path = "~/.kiro/cortex-audit.jsonl"
max_size_mb = 50
max_files = 5

[injection]
enable_tier1 = true

[prompt_scan]
enabled = true
on_detect = "context"

[sensitive_files]
disable_builtin = []
extra_allow = [".env.example", ".env.template"]
"#;

fn default_hooks() -> Value {
    json!({
        "agentSpawn": [{"command": "kiro-cortex hook spawn"}],
        "userPromptSubmit": [{"command": "kiro-cortex hook prompt"}],
        "preToolUse": [{"matcher": "*", "command": "kiro-cortex hook pre-tool"}],
        "postToolUse": [{"matcher": "*", "command": "kiro-cortex hook post-tool"}],
        "stop": [{"command": "kiro-cortex hook stop"}]
    })
}

fn is_owned(command: &str) -> bool {
    regex::Regex::new(HOOK_REGEX).unwrap().is_match(command)
}

pub fn init(cwd: &Path, force: bool) -> Result<Vec<String>> {
    let mut messages = Vec::new();

    // 1. Config
    let config_path = cwd.join(".kiro").join("cortex.toml");
    if !config_path.exists() || force {
        fs::create_dir_all(config_path.parent().unwrap())?;
        fs::write(&config_path, DEFAULT_CONFIG)?;
        messages.push(format!("✅ Created {}", config_path.display()));
    } else {
        messages.push(format!("⏭ Config exists: {}", config_path.display()));
    }

    // 2. Agent config
    let agent_dir = cwd.join(".kiro").join("agents");
    let agent_path = agent_dir.join("default.json");
    fs::create_dir_all(&agent_dir)?;

    let mut agent: Value = if agent_path.exists() {
        let content = fs::read_to_string(&agent_path)?;
        serde_json::from_str(&content).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    let hooks_obj = agent.as_object_mut().unwrap()
        .entry("hooks").or_insert_with(|| json!({}));

    let new_hooks = default_hooks();
    for (hook_type, new_entries) in new_hooks.as_object().unwrap() {
        let arr = hooks_obj.as_object_mut().unwrap()
            .entry(hook_type).or_insert_with(|| json!([]));
        let arr = arr.as_array_mut().unwrap();

        let has_owned = arr.iter().any(|h| {
            h.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false)
        });

        if has_owned && !force {
            messages.push(format!("⏭ Hook {} already configured", hook_type));
            continue;
        }

        if force {
            arr.retain(|h| {
                !h.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false)
            });
        }

        for entry in new_entries.as_array().unwrap() {
            arr.push(entry.clone());
        }
        messages.push(format!("✅ Added hook: {}", hook_type));
    }

    let json_str = serde_json::to_string_pretty(&agent)?;
    fs::write(&agent_path, json_str)?;

    Ok(messages)
}

pub fn uninstall(cwd: &Path) -> Result<Vec<String>> {
    let mut messages = Vec::new();
    let agent_path = cwd.join(".kiro").join("agents").join("default.json");

    if !agent_path.exists() {
        messages.push("No agent config found".into());
        return Ok(messages);
    }

    let content = fs::read_to_string(&agent_path)?;
    let mut agent: Value = serde_json::from_str(&content)?;

    if let Some(hooks) = agent.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        let mut removed = 0;
        for (_hook_type, arr) in hooks.iter_mut() {
            if let Some(a) = arr.as_array_mut() {
                let before = a.len();
                a.retain(|h| {
                    !h.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false)
                });
                removed += before - a.len();
            }
        }
        if removed == 0 {
            messages.push("Nothing to uninstall".into());
        } else {
            messages.push(format!("✅ Removed {} Kiro Cortex hook(s)", removed));
            let json_str = serde_json::to_string_pretty(&agent)?;
            fs::write(&agent_path, json_str)?;
        }
    }

    Ok(messages)
}

pub fn check(cwd: &Path) -> Result<Vec<(String, bool)>> {
    let mut checks = Vec::new();

    // 1. Config parseable + valid
    let config_path = cwd.join(".kiro").join("cortex.toml");
    let config_ok = if config_path.exists() {
        crate::config::Config::load(cwd).is_ok()
    } else {
        true // No config = defaults = ok
    };
    checks.push(("Config parseable".into(), config_ok));

    // 2. Agent config exists
    let agent_path = cwd.join(".kiro").join("agents").join("default.json");
    checks.push(("Agent config exists".into(), agent_path.exists()));

    // 3. All 5 hooks present
    let hooks_ok = if agent_path.exists() {
        let content = fs::read_to_string(&agent_path).unwrap_or_default();
        let agent: Value = serde_json::from_str(&content).unwrap_or(json!({}));
        let hooks = agent.get("hooks").and_then(|h| h.as_object());
        if let Some(h) = hooks {
            ["agentSpawn", "userPromptSubmit", "preToolUse", "postToolUse", "stop"]
                .iter().all(|ht| {
                    h.get(*ht).and_then(|a| a.as_array()).map(|a| {
                        a.iter().any(|e| e.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false))
                    }).unwrap_or(false)
                })
        } else { false }
    } else { false };
    checks.push(("All 5 hooks present".into(), hooks_ok));

    // 4. Hook ownership correct
    checks.push(("Hook ownership correct".into(), hooks_ok));

    // 5. Binary accessible
    let binary_ok = which::which("kiro-cortex").is_ok() || Path::new("./target/debug/kiro-cortex").exists() || Path::new("./target/release/kiro-cortex").exists();
    checks.push(("Binary accessible".into(), binary_ok));

    // 6. No duplicate hooks
    let no_dupes = if agent_path.exists() {
        let content = fs::read_to_string(&agent_path).unwrap_or_default();
        let agent: Value = serde_json::from_str(&content).unwrap_or(json!({}));
        let hooks = agent.get("hooks").and_then(|h| h.as_object());
        if let Some(h) = hooks {
            h.values().all(|arr| {
                let owned = arr.as_array().map(|a| a.iter().filter(|e| {
                    e.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false)
                }).count()).unwrap_or(0);
                owned <= 1
            })
        } else { true }
    } else { true };
    checks.push(("No duplicate hooks".into(), no_dupes));

    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_clean_project() {
        let dir = TempDir::new().unwrap();
        let msgs = init(dir.path(), false).unwrap();
        assert!(msgs.iter().any(|m| m.contains("Created")));
        assert!(dir.path().join(".kiro/cortex.toml").exists());
        assert!(dir.path().join(".kiro/agents/default.json").exists());
        // Verify 5 hooks
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        let agent: Value = serde_json::from_str(&content).unwrap();
        let hooks = agent["hooks"].as_object().unwrap();
        assert!(hooks.contains_key("agentSpawn"));
        assert!(hooks.contains_key("stop"));
        assert_eq!(hooks.len(), 5);
    }

    #[test]
    fn init_idempotent() {
        let dir = TempDir::new().unwrap();
        init(dir.path(), false).unwrap();
        let content1 = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        init(dir.path(), false).unwrap();
        let content2 = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        assert_eq!(content1, content2);
    }

    #[test]
    fn init_preserves_user_hooks() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".kiro/agents")).unwrap();
        fs::write(dir.path().join(".kiro/agents/default.json"), r#"{
            "name": "my-agent",
            "hooks": {
                "preToolUse": [{"command": "my-linter check", "matcher": "write"}]
            }
        }"#).unwrap();
        init(dir.path(), false).unwrap();
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        let agent: Value = serde_json::from_str(&content).unwrap();
        // User hook preserved
        assert!(content.contains("my-linter"));
        // Name preserved
        assert_eq!(agent["name"], "my-agent");
        // Cortex hooks added
        let pre = agent["hooks"]["preToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2); // user + cortex
    }

    #[test]
    fn init_force_replaces() {
        let dir = TempDir::new().unwrap();
        init(dir.path(), false).unwrap();
        init(dir.path(), true).unwrap();
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        let agent: Value = serde_json::from_str(&content).unwrap();
        // Still only 1 cortex hook per type
        for (_k, v) in agent["hooks"].as_object().unwrap() {
            let owned = v.as_array().unwrap().iter().filter(|e| {
                e.get("command").and_then(|c| c.as_str()).map(|c| is_owned(c)).unwrap_or(false)
            }).count();
            assert_eq!(owned, 1);
        }
    }

    #[test]
    fn uninstall_removes_hooks() {
        let dir = TempDir::new().unwrap();
        init(dir.path(), false).unwrap();
        let msgs = uninstall(dir.path()).unwrap();
        assert!(msgs.iter().any(|m| m.contains("Removed")));
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        assert!(!content.contains("kiro-cortex hook"));
    }

    #[test]
    fn uninstall_twice_safe() {
        let dir = TempDir::new().unwrap();
        init(dir.path(), false).unwrap();
        uninstall(dir.path()).unwrap();
        let msgs = uninstall(dir.path()).unwrap();
        assert!(msgs.iter().any(|m| m.contains("Nothing")));
    }

    #[test]
    fn uninstall_preserves_user_hooks() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".kiro/agents")).unwrap();
        fs::write(dir.path().join(".kiro/agents/default.json"), r#"{
            "hooks": {"preToolUse": [{"command": "my-linter", "matcher": "*"}]}
        }"#).unwrap();
        init(dir.path(), false).unwrap();
        uninstall(dir.path()).unwrap();
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        assert!(content.contains("my-linter"));
        assert!(!content.contains("kiro-cortex"));
    }

    #[test]
    fn check_after_init() {
        let dir = TempDir::new().unwrap();
        init(dir.path(), false).unwrap();
        let checks = check(dir.path()).unwrap();
        assert!(checks.iter().find(|(n, _)| n == "Config parseable").unwrap().1);
        assert!(checks.iter().find(|(n, _)| n == "Agent config exists").unwrap().1);
        assert!(checks.iter().find(|(n, _)| n == "All 5 hooks present").unwrap().1);
        assert!(checks.iter().find(|(n, _)| n == "No duplicate hooks").unwrap().1);
    }

    #[test]
    fn check_clean_project() {
        let dir = TempDir::new().unwrap();
        let checks = check(dir.path()).unwrap();
        assert!(!checks.iter().find(|(n, _)| n == "Agent config exists").unwrap().1);
    }

    #[test]
    fn non_hook_fields_preserved() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".kiro/agents")).unwrap();
        fs::write(dir.path().join(".kiro/agents/default.json"), r#"{
            "name": "custom",
            "model": "claude-4",
            "tools": ["read", "write"],
            "hooks": {}
        }"#).unwrap();
        init(dir.path(), false).unwrap();
        let content = fs::read_to_string(dir.path().join(".kiro/agents/default.json")).unwrap();
        let agent: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(agent["name"], "custom");
        assert_eq!(agent["model"], "claude-4");
    }
}
