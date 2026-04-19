use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct FeedbackEntry {
    rule_id: Option<String>,
    verdict: String,
    #[allow(dead_code)]
    finding_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TuneSuggestion {
    pub rule_id: String,
    pub total_triggers: usize,
    pub false_positives: usize,
    pub fp_rate: f64,
    pub action: TuneAction,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum TuneAction {
    AddAllowlistRegex(String),
    DisableBuiltin(String),
    RaiseEntropy { rule_id: String, current: f64, suggested: f64 },
}

impl std::fmt::Display for TuneAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TuneAction::AddAllowlistRegex(r) => write!(f, "Add to [allowlist] regexes: \"{}\"", r),
            TuneAction::DisableBuiltin(id) => write!(f, "Add to [sensitive_files] disable_builtin: \"{}\"", id),
            TuneAction::RaiseEntropy { rule_id, current, suggested } => {
                write!(f, "Raise entropy for rule '{}': {:.1} → {:.1}", rule_id, current, suggested)
            }
        }
    }
}

fn feedback_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".kiro").join("cortex-feedback.jsonl"))
        .unwrap_or_else(|| PathBuf::from("cortex-feedback.jsonl"))
}

fn load_feedback() -> Result<Vec<FeedbackEntry>> {
    let path = feedback_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path).context("Failed to read feedback file")?;
    let entries: Vec<FeedbackEntry> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    Ok(entries)
}

pub fn analyze() -> Result<Vec<TuneSuggestion>> {
    let feedback = load_feedback()?;
    if feedback.is_empty() {
        return Ok(vec![]);
    }

    // Aggregate by rule_id
    let mut stats: HashMap<String, (usize, usize)> = HashMap::new(); // (total_reports, false_positives)
    for entry in &feedback {
        let rule_id = entry.rule_id.clone().unwrap_or_else(|| "unknown".into());
        let (total, fps) = stats.entry(rule_id).or_insert((0, 0));
        *total += 1;
        if entry.verdict == "false-positive" {
            *fps += 1;
        }
    }

    let mut suggestions = Vec::new();

    for (rule_id, (total, fps)) in &stats {
        if *total == 0 { continue; }
        let fp_rate = *fps as f64 / *total as f64;
        let tps = *total - *fps;

        // Guardrail: skip if total sample too small AND rule has any true positives
        if *total < 3 && tps > 0 { continue; }

        // Suggest action based on FP rate
        if fp_rate >= 0.5 && *fps >= 3 {
            // High FP rate + enough samples → suggest disable or allowlist
            if rule_id.starts_with("sf-") {
                suggestions.push(TuneSuggestion {
                    rule_id: rule_id.clone(),
                    total_triggers: *total,
                    false_positives: *fps,
                    fp_rate,
                    action: TuneAction::DisableBuiltin(rule_id.clone()),
                    reason: format!("{}/{} reports are false-positive ({:.0}%)", fps, total, fp_rate * 100.0),
                });
            } else if rule_id.starts_with("generic-") {
                suggestions.push(TuneSuggestion {
                    rule_id: rule_id.clone(),
                    total_triggers: *total,
                    false_positives: *fps,
                    fp_rate,
                    action: TuneAction::RaiseEntropy {
                        rule_id: rule_id.clone(),
                        current: 3.5,
                        suggested: 4.0,
                    },
                    reason: format!("Generic rule with {:.0}% FP rate — raise entropy threshold", fp_rate * 100.0),
                });
            } else {
                // Cannot auto-generate allowlist regex from rule_id alone.
                // Suggest user add pattern based on the false-positive values they reported.
                suggestions.push(TuneSuggestion {
                    rule_id: rule_id.clone(),
                    total_triggers: *total,
                    false_positives: *fps,
                    fp_rate,
                    action: TuneAction::AddAllowlistRegex(format!("# TODO: add pattern for values triggering '{}' — check cortex-feedback.jsonl notes", rule_id)),
                    reason: format!("{}/{} reports are false-positive ({:.0}%). Review feedback notes and add a specific allowlist pattern for the false-positive values.", fps, total, fp_rate * 100.0),
                });
            }
        } else if fp_rate >= 0.3 && *fps >= 2 {
            suggestions.push(TuneSuggestion {
                rule_id: rule_id.clone(),
                total_triggers: *total,
                false_positives: *fps,
                fp_rate,
                action: TuneAction::AddAllowlistRegex(format!("# TODO: add pattern for '{}' FP values", rule_id)),
                reason: format!("{:.0}% FP rate — review feedback notes and add allowlist pattern for the specific false-positive values", fp_rate * 100.0),
            });
        }
    }

    suggestions.sort_by(|a, b| b.fp_rate.partial_cmp(&a.fp_rate).unwrap_or(std::cmp::Ordering::Equal));
    Ok(suggestions)
}

pub fn apply_suggestions(config_path: &Path, suggestions: &[TuneSuggestion]) -> Result<Vec<String>> {
    let mut applied = Vec::new();

    if suggestions.is_empty() {
        return Ok(applied);
    }

    let content = if config_path.exists() {
        std::fs::read_to_string(config_path)?
    } else {
        String::new()
    };

    // Backup config before modifying
    if config_path.exists() {
        let backup = config_path.with_extension("toml.bak");
        std::fs::copy(config_path, &backup)?;
        applied.push(format!("Backup saved: {}", backup.display()));
    }

    let mut new_content = content.clone();

    for s in suggestions {
        match &s.action {
            TuneAction::AddAllowlistRegex(regex) => {
                if new_content.contains("[allowlist]") {
                    // Find regexes line and append
                    if let Some(pos) = new_content.find("regexes = [") {
                        if let Some(bracket) = new_content[pos..].find(']') {
                            let insert_pos = pos + bracket;
                            let comma = if new_content[pos..insert_pos].contains('\'') || new_content[pos..insert_pos].contains('"') { ", " } else { "" };
                            new_content.insert_str(insert_pos, &format!("{}'{}'" , comma, regex));
                            applied.push(format!("Added allowlist regex: '{}'", regex));
                        }
                    } else {
                        // No regexes line, add one
                        let insert = format!("\nregexes = ['{}']", regex);
                        if let Some(pos) = new_content.find("[allowlist]") {
                            new_content.insert_str(pos + "[allowlist]".len(), &insert);
                            applied.push(format!("Added allowlist regex: '{}'", regex));
                        }
                    }
                } else {
                    new_content.push_str(&format!("\n[allowlist]\nregexes = ['{}']\n", regex));
                    applied.push(format!("Added [allowlist] with regex: '{}'", regex));
                }
            }
            TuneAction::DisableBuiltin(id) => {
                if new_content.contains("disable_builtin = [") {
                    if let Some(pos) = new_content.find("disable_builtin = [") {
                        if let Some(bracket) = new_content[pos..].find(']') {
                            let insert_pos = pos + bracket;
                            let comma = if new_content[pos..insert_pos].contains('"') { ", " } else { "" };
                            new_content.insert_str(insert_pos, &format!("{}\"{}\"", comma, id));
                            applied.push(format!("Disabled builtin rule: '{}'", id));
                        }
                    }
                } else if new_content.contains("[sensitive_files]") {
                    if let Some(pos) = new_content.find("[sensitive_files]") {
                        new_content.insert_str(pos + "[sensitive_files]".len(), &format!("\ndisable_builtin = [\"{}\"]", id));
                        applied.push(format!("Disabled builtin rule: '{}'", id));
                    }
                } else {
                    new_content.push_str(&format!("\n[sensitive_files]\ndisable_builtin = [\"{}\"]\n", id));
                    applied.push(format!("Added [sensitive_files] with disable_builtin: '{}'", id));
                }
            }
            TuneAction::RaiseEntropy { rule_id, suggested, .. } => {
                // Can't easily modify [[secret_rules]] TOML programmatically
                // Just report as suggestion
                applied.push(format!("⚠ Manual: set entropy = {:.1} for rule '{}' in [[secret_rules]]", suggested, rule_id));
            }
        }
    }

    if new_content != content {
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(config_path, &new_content)?;
    }

    // Write audit trail
    if !applied.is_empty() {
        let audit_path = config_path.with_file_name("cortex-tune-audit.jsonl");
        let entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "config_path": config_path.to_string_lossy(),
            "suggestions_count": suggestions.len(),
            "applied": &applied,
            "rules_affected": suggestions.iter().map(|s| &s.rule_id).collect::<Vec<_>>(),
        });
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&audit_path)?;
        use std::io::Write;
        writeln!(file, "{}", serde_json::to_string(&entry)?)?;
        applied.push(format!("Audit trail: {}", audit_path.display()));
    }

    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn no_feedback_no_suggestions() {
        let suggestions = analyze();
        // May or may not have feedback file — just verify no panic
        assert!(suggestions.is_ok());
    }

    #[test]
    fn apply_allowlist_to_empty_config() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("cortex.toml");
        std::fs::write(&config, "mode = \"enforce\"\n").unwrap();

        let suggestions = vec![TuneSuggestion {
            rule_id: "test-rule".into(),
            total_triggers: 10,
            false_positives: 8,
            fp_rate: 0.8,
            action: TuneAction::AddAllowlistRegex("(?i)test-pattern".into()),
            reason: "test".into(),
        }];

        let applied = apply_suggestions(&config, &suggestions).unwrap();
        assert!(!applied.is_empty());

        let content = std::fs::read_to_string(&config).unwrap();
        assert!(content.contains("[allowlist]"));
        assert!(content.contains("test-pattern"));
    }

    #[test]
    fn apply_disable_builtin() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("cortex.toml");
        std::fs::write(&config, "mode = \"enforce\"\n\n[sensitive_files]\ndisable_builtin = []\n").unwrap();

        let suggestions = vec![TuneSuggestion {
            rule_id: "sf-dotenv-wildcard".into(),
            total_triggers: 5,
            false_positives: 4,
            fp_rate: 0.8,
            action: TuneAction::DisableBuiltin("sf-dotenv-wildcard".into()),
            reason: "test".into(),
        }];

        let applied = apply_suggestions(&config, &suggestions).unwrap();
        assert!(!applied.is_empty());

        let content = std::fs::read_to_string(&config).unwrap();
        assert!(content.contains("sf-dotenv-wildcard"));
    }

    #[test]
    fn apply_entropy_is_manual() {
        let dir = TempDir::new().unwrap();
        let config = dir.path().join("cortex.toml");
        std::fs::write(&config, "mode = \"enforce\"\n").unwrap();

        let suggestions = vec![TuneSuggestion {
            rule_id: "generic-api-key".into(),
            total_triggers: 10,
            false_positives: 7,
            fp_rate: 0.7,
            action: TuneAction::RaiseEntropy { rule_id: "generic-api-key".into(), current: 3.5, suggested: 4.0 },
            reason: "test".into(),
        }];

        let applied = apply_suggestions(&config, &suggestions).unwrap();
        assert!(applied.iter().any(|a| a.contains("Manual")));
    }
}
