#![cfg_attr(not(test), allow(dead_code))]

use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub hook_type: String,
    pub tool_name: Option<String>,
    pub mode: String,
    pub findings: Vec<AuditFinding>,
    pub action_taken: String,
    pub exit_code: u8,
    pub latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct AuditFinding {
    pub finding_type: String,
    pub finding_id: String,
    pub rule_id: String,
    pub severity: String,
    pub field_path: String,
    pub redacted_preview: String,
    pub risk_level: String,
    pub entropy_value: Option<f64>,
}

pub fn finding_id(rule_id: &str, field_path: &str, redacted: &str) -> String {
    let mut h = Sha256::new();
    h.update(rule_id.as_bytes());
    h.update(field_path.as_bytes());
    h.update(redacted.as_bytes());
    let result = h.finalize();
    hex::encode(&result[..4])
}

// Inline hex encode (avoid extra dep)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

pub struct AuditLogger {
    path: PathBuf,
    max_size_bytes: u64,
    max_files: u32,
}

impl AuditLogger {
    pub fn new(path: &str, max_size_mb: u32, max_files: u32) -> Self {
        let expanded = if path.starts_with("~/") {
            dirs::home_dir().map(|h| h.join(&path[2..])).unwrap_or_else(|| PathBuf::from(path))
        } else {
            PathBuf::from(path)
        };
        Self { path: expanded, max_size_bytes: max_size_mb as u64 * 1_048_576, max_files }
    }

    pub fn log(&self, entry: &AuditEntry) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.rotate_if_needed()?;
        let line = serde_json::to_string(entry)?;
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }

    fn rotate_if_needed(&self) -> Result<()> {
        if !self.path.exists() { return Ok(()); }
        let size = fs::metadata(&self.path)?.len();
        if size < self.max_size_bytes { return Ok(()); }

        // Delete oldest if at max
        for i in (1..self.max_files).rev() {
            let old = rotated_path(&self.path, i);
            let new = rotated_path(&self.path, i + 1);
            if old.exists() {
                if i + 1 >= self.max_files { fs::remove_file(&old)?; }
                else { fs::rename(&old, &new)?; }
            }
        }
        let first = rotated_path(&self.path, 1);
        fs::rename(&self.path, &first)?;
        Ok(())
    }
}

fn rotated_path(base: &Path, n: u32) -> PathBuf {
    let name = base.file_name().unwrap().to_str().unwrap();
    base.with_file_name(format!("{}.{}", name, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::TempDir;

    fn test_entry() -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            session_id: "test-session".into(),
            hook_type: "preToolUse".into(),
            tool_name: Some("read".into()),
            mode: "enforce".into(),
            findings: vec![AuditFinding {
                finding_type: "sensitive_file".into(),
                finding_id: "abcd1234".into(),
                rule_id: "sf-dotenv".into(),
                severity: "high".into(),
                field_path: "path".into(),
                redacted_preview: ".env".into(),
                risk_level: "high".into(),
                entropy_value: None,
            }],
            action_taken: "blocked".into(),
            exit_code: 2,
            latency_ms: 0.5,
        }
    }

    #[test]
    fn finding_id_deterministic() {
        let a = finding_id("rule1", "field", "preview");
        let b = finding_id("rule1", "field", "preview");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8);
    }

    #[test]
    fn finding_id_different_inputs() {
        let a = finding_id("rule1", "field", "preview");
        let b = finding_id("rule2", "field", "preview");
        assert_ne!(a, b);
    }

    #[test]
    fn log_creates_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.to_str().unwrap(), 50, 5);
        logger.log(&test_entry()).unwrap();
        assert!(path.exists());
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("sf-dotenv"));
        assert!(content.contains("preToolUse"));
    }

    #[test]
    fn log_appends() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.to_str().unwrap(), 50, 5);
        logger.log(&test_entry()).unwrap();
        logger.log(&test_entry()).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    fn log_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Use a real small size instead of 0MB.
        let logger = AuditLogger { path: path.clone(), max_size_bytes: 10, max_files: 3 };
        logger.log(&test_entry()).unwrap();
        logger.log(&test_entry()).unwrap(); // Should trigger rotation
        // After rotation, original file should exist (new) and .1 should exist
        assert!(path.exists());
    }

    #[test]
    fn no_matched_text_in_log() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.to_str().unwrap(), 50, 5);
        logger.log(&test_entry()).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        // AuditFinding has no matched_text field
        assert!(!content.contains("matched_text"));
    }

    #[test]
    fn entropy_value_logged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(path.to_str().unwrap(), 50, 5);
        let mut entry = test_entry();
        entry.findings[0].entropy_value = Some(3.7);
        logger.log(&entry).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("3.7"));
    }
}
