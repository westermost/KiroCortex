use anyhow::Result;
use chrono::Utc;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

// --- allow-once ---

fn session_allowlist_path(session_id: &str) -> PathBuf {
    // Sanitize: only keep alphanumeric + dash to prevent path traversal
    let safe_id: String = session_id.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-')
        .take(64)
        .collect();
    let safe_id = if safe_id.is_empty() { "unknown".to_string() } else { safe_id };
    std::env::temp_dir().join(format!("cortex-session-{}.allow", safe_id))
}

pub fn allow_once(rule_id: &str, session_id: &str) -> Result<String> {
    let path = session_allowlist_path(session_id);
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", rule_id)?;
    Ok(format!("✅ Rule '{}' overridden for session {}", rule_id, session_id))
}

pub fn is_overridden(rule_id: &str, session_id: &str) -> bool {
    let path = session_allowlist_path(session_id);
    if let Ok(content) = fs::read_to_string(&path) {
        content.lines().any(|l| l.trim() == rule_id)
    } else {
        false
    }
}

fn feedback_path() -> PathBuf {
    dirs::home_dir()
        .map(|h| h.join(".kiro").join("cortex-feedback.jsonl"))
        .unwrap_or_else(|| PathBuf::from("cortex-feedback.jsonl"))
}

// --- report ---

fn report_to_path(path: &PathBuf, finding_id: &str, verdict: &str, note: Option<&str>, session_id: Option<&str>, rule_id: Option<&str>) -> Result<String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let entry = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "finding_id": finding_id,
        "rule_id": rule_id.unwrap_or(""),
        "verdict": verdict,
        "note": note.unwrap_or(""),
        "session_id": session_id.unwrap_or(""),
    });

    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", serde_json::to_string(&entry)?)?;

    Ok(format!("✅ Reported {} as {}", finding_id, verdict))
}

pub fn report(finding_id: &str, verdict: &str, note: Option<&str>, session_id: Option<&str>, rule_id: Option<&str>) -> Result<String> {
    let path = feedback_path();
    report_to_path(&path, finding_id, verdict, note, session_id, rule_id)
}

// --- session summary ---

#[cfg_attr(not(test), allow(dead_code))]
pub fn session_summary(_session_id: &str, blocked: usize, warned: usize, clean: usize, overrides: usize) -> String {
    if blocked == 0 && warned == 0 && overrides == 0 {
        return String::new(); // Clean session, no output
    }
    format!(
        "─── Kiro Cortex Session Summary ───\n  Blocked: {}\n  Warned:  {}\n  Clean:   {} tool calls\n  Overrides: {}\n───────────────────────────────────",
        blocked, warned, clean, overrides
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_once_creates_file() {
        let sid = "test-allow-once-1";
        let _ = fs::remove_file(session_allowlist_path(sid));
        allow_once("sf-dotenv", sid).unwrap();
        assert!(is_overridden("sf-dotenv", sid));
        assert!(!is_overridden("sf-pem", sid));
        let _ = fs::remove_file(session_allowlist_path(sid));
    }

    #[test]
    fn allow_once_multiple_rules() {
        let sid = "test-allow-once-2";
        let _ = fs::remove_file(session_allowlist_path(sid));
        allow_once("sf-dotenv", sid).unwrap();
        allow_once("sf-pem", sid).unwrap();
        assert!(is_overridden("sf-dotenv", sid));
        assert!(is_overridden("sf-pem", sid));
        assert!(!is_overridden("sf-key", sid));
        let _ = fs::remove_file(session_allowlist_path(sid));
    }

    #[test]
    fn different_session_not_overridden() {
        let sid1 = "test-allow-once-3a";
        let sid2 = "test-allow-once-3b";
        let _ = fs::remove_file(session_allowlist_path(sid1));
        let _ = fs::remove_file(session_allowlist_path(sid2));
        allow_once("sf-dotenv", sid1).unwrap();
        assert!(!is_overridden("sf-dotenv", sid2));
        let _ = fs::remove_file(session_allowlist_path(sid1));
    }

    #[test]
    fn report_writes_feedback() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("cortex-feedback.jsonl");
        let msg = report_to_path(&path, "abcd1234", "false-positive", Some("test fixture"), Some("s1"), Some("test-rule")).unwrap();
        assert!(msg.contains("false-positive"));
        let written = fs::read_to_string(path).unwrap();
        assert!(written.contains("\"rule_id\":\"test-rule\""));
    }

    #[test]
    fn session_summary_clean() {
        let s = session_summary("s1", 0, 0, 50, 0);
        assert!(s.is_empty());
    }

    #[test]
    fn session_summary_with_findings() {
        let s = session_summary("s1", 2, 3, 47, 1);
        assert!(s.contains("Blocked: 2"));
        assert!(s.contains("Warned:  3"));
        assert!(s.contains("Overrides: 1"));
    }
}
