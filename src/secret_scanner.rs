#![cfg_attr(not(test), allow(dead_code))]

use crate::config::{AllowlistConfig, CustomSecretRule, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

#[derive(Debug, Clone)]
pub struct SecretRule {
    pub id: String,
    pub regex: Regex,
    pub keywords: Vec<String>,
    pub entropy: Option<f64>,
    pub severity: Severity,
}

#[derive(Debug, Clone)]
pub struct SecretFinding {
    pub rule_id: String,
    #[cfg_attr(test, allow(dead_code))]
    pub severity: Severity,
    pub matched_text: String,
    pub redacted_preview: String,
    pub field_path: String,
    #[cfg_attr(test, allow(dead_code))]
    pub byte_offset: usize,
    pub line_number: u32,
    pub entropy_value: Option<f64>,
}

pub fn redact(text: &str) -> String {
    if text.len() >= 8 {
        let first4: String = text.chars().take(4).collect();
        let last4: String = text.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        format!("{}****{}", first4, last4)
    } else {
        "****".into()
    }
}

pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in text.as_bytes() { freq[b as usize] += 1; }
    let len = text.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

static BUILTIN_RULES: Lazy<Vec<SecretRule>> = Lazy::new(|| {
    let defs: Vec<(&str, &str, &[&str], Option<f64>, Severity)> = vec![
        ("aws-access-key", r"(?:^|[^A-Za-z0-9])(?P<m>(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})(?:[^A-Za-z0-9]|$)", &["AKIA", "ASIA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA", "A3T"], None, Severity::High),
        ("aws-secret-key", r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_key|aws_access_key)\s*[:=]\s*['"]?(?P<m>[A-Za-z0-9/+=]{40})['"]?"#, &["aws_secret", "secret_key", "secret_access", "aws_access_key"], Some(3.5), Severity::High),
        ("openai-api-key", r"(?P<m>sk-proj-[A-Za-z0-9\-_]{20,})", &["sk-proj-"], None, Severity::High),
        ("openai-api-key-legacy", r"(?:^|[^A-Za-z0-9])(?P<m>sk-[A-Za-z0-9]{20,})(?:[^A-Za-z0-9]|$)", &["sk-"], None, Severity::High),
        ("anthropic-api-key", r"(?P<m>sk-ant-[A-Za-z0-9\-_]{20,})", &["sk-ant-"], None, Severity::High),
        ("github-pat", r"(?P<m>ghp_[A-Za-z0-9]{36})", &["ghp_"], None, Severity::High),
        ("github-fine-grained", r"(?P<m>github_pat_[A-Za-z0-9]{22,})", &["github_pat_"], None, Severity::High),
        ("gitlab-pat", r"(?P<m>glpat-[A-Za-z0-9\-]{20,})", &["glpat-"], None, Severity::High),
        ("stripe-secret", r"(?P<m>sk_live_[A-Za-z0-9]{24,})", &["sk_live_"], None, Severity::High),
        ("stripe-restricted", r"(?P<m>rk_live_[A-Za-z0-9]{24,})", &["rk_live_"], None, Severity::High),
        ("slack-bot-token", r"(?P<m>xoxb-[0-9]{10,}-[A-Za-z0-9\-]+)", &["xoxb-"], None, Severity::High),
        ("slack-user-token", r"(?P<m>xoxp-[0-9]{10,}-[A-Za-z0-9\-]+)", &["xoxp-"], None, Severity::High),
        ("sendgrid-api-key", r"(?P<m>SG\.[A-Za-z0-9\-_]{22,})", &["SG."], None, Severity::High),
        ("npm-token", r"(?P<m>npm_[A-Za-z0-9]{36})", &["npm_"], None, Severity::High),
        ("pypi-token", r"(?P<m>pypi-[A-Za-z0-9]{50,})", &["pypi-"], None, Severity::High),
        ("digitalocean-token", r"(?P<m>dop_v1_[a-f0-9]{64})", &["dop_v1_"], None, Severity::High),
        ("databricks-token", r"(?P<m>dapi[a-f0-9]{32})", &["dapi"], None, Severity::High),
        ("private-key-pem", r"(?P<m>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)", &["PRIVATE KEY"], None, Severity::High),
        ("jwt-token", r"(?P<m>eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)", &["eyJ"], None, Severity::Medium),
        ("postgres-uri", r#"(?P<m>postgres(?:ql)?://[^\s'"]+:[^\s'"]+@[^\s'"]+)"#, &["postgres://", "postgresql://"], None, Severity::High),
        ("mysql-uri", r#"(?P<m>mysql://[^\s'"]+:[^\s'"]+@[^\s'"]+)"#, &["mysql://"], None, Severity::High),
        ("mongodb-uri", r#"(?P<m>mongodb(?:\+srv)?://[^\s'"]+:[^\s'"]+@[^\s'"]+)"#, &["mongodb://", "mongodb+srv://"], None, Severity::High),
        ("generic-api-key", r#"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*['"]?(?P<m>[A-Za-z0-9\-_]{16,})['"]?"#, &["api_key", "api-key", "apikey", "API_KEY"], Some(3.5), Severity::Low),
        ("generic-secret", r#"(?i)(?:secret)\s*[:=]\s*['"]?(?P<m>[A-Za-z0-9\-_]{16,})['"]?"#, &["secret"], Some(3.5), Severity::Low),
        ("generic-password", r#"(?i)(?:password|passwd)\s*[:=]\s*['"]?(?P<m>[^\s'"]{8,})['"]?"#, &["password", "passwd"], Some(3.5), Severity::Low),
    ];
    defs.into_iter().map(|(id, re, kw, ent, sev)| SecretRule {
        id: id.into(),
        regex: Regex::new(re).unwrap(),
        keywords: kw.iter().map(|s| s.to_string()).collect(),
        entropy: ent,
        severity: sev,
    }).collect()
});

pub struct SecretScanner {
    rules: Vec<SecretRule>,
    allowlist_regexes: Vec<Regex>,
    stopwords: Vec<String>,
}

impl SecretScanner {
    pub fn new(custom_rules: &[CustomSecretRule], allowlist: &AllowlistConfig) -> Self {
        let mut rules = BUILTIN_RULES.clone();
        for cr in custom_rules {
            if let Ok(re) = Regex::new(&cr.regex) {
                rules.push(SecretRule {
                    id: cr.id.clone(), regex: re,
                    keywords: cr.keywords.clone(), entropy: cr.entropy,
                    severity: cr.severity.clone(),
                });
            }
        }
        let allowlist_regexes = allowlist.regexes.iter()
            .filter_map(|r| Regex::new(r).ok()).collect();
        Self { rules, allowlist_regexes, stopwords: allowlist.stopwords.clone() }
    }

    pub fn scan(&self, text: &str, field_path: &str) -> Vec<SecretFinding> {
        let mut findings = Vec::new();
        let text_lower = text.to_lowercase();

        for rule in &self.rules {
            // Keyword pre-filter
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|kw| text_lower.contains(&kw.to_lowercase())) {
                continue;
            }
            for mat in rule.regex.find_iter(text) {
                let caps = match rule.regex.captures(mat.as_str()) {
                    Some(c) => c,
                    None => continue,
                };
                let matched = caps.name("m").map(|m| m.as_str()).unwrap_or(mat.as_str());
                // Find actual position of the named group in original text
                let match_offset = if let Some(m) = caps.name("m") {
                    mat.start() + m.start()
                } else {
                    mat.start()
                };
                // Entropy check
                if let Some(threshold) = rule.entropy {
                    if shannon_entropy(matched) < threshold { continue; }
                }
                // Allowlist check
                if self.is_allowed(matched) { continue; }
                let line_number = text[..match_offset].matches('\n').count() as u32 + 1;
                findings.push(SecretFinding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    matched_text: matched.to_string(),
                    redacted_preview: redact(matched),
                    field_path: field_path.to_string(),
                    byte_offset: match_offset,
                    line_number,
                    entropy_value: Some(shannon_entropy(matched)),
                });
            }
        }
        findings
    }

    fn is_allowed(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();
        if self.stopwords.iter().any(|sw| text_lower.contains(&sw.to_lowercase())) {
            return true;
        }
        // Built-in: skip well-known placeholder keys (exact match only)
        const KNOWN_PLACEHOLDERS: &[&str] = &[
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "sk-proj-example",
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ];
        if KNOWN_PLACEHOLDERS.iter().any(|p| text == *p) {
            return true;
        }
        self.allowlist_regexes.iter().any(|re| re.is_match(text))
    }

    pub fn builtin_rule_ids() -> Vec<&'static str> {
        BUILTIN_RULES.iter().map(|r| r.id.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> SecretScanner {
        SecretScanner::new(&[], &AllowlistConfig::default())
    }

    fn scanner_with_allowlist() -> SecretScanner {
        SecretScanner::new(&[], &AllowlistConfig {
            regexes: vec!["(?i)example".into(), "AKIAIOSFODNN7EXAMPLE".into()],
            stopwords: vec!["test".into(), "dummy".into()],
            paths: vec![],
        })
    }

    // --- 4.1 Built-in rules ---

    #[test]
    fn builtin_rules_loaded() {
        assert!(BUILTIN_RULES.len() >= 20);
    }

    #[test]
    fn builtin_rule_ids_unique() {
        let ids = SecretScanner::builtin_rule_ids();
        let set: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), set.len());
    }

    // --- 4.3 Regex matching ---

    #[test]
    fn detect_aws_access_key() {
        let f = scanner().scan("key=AKIAIOSFODNN7REALKEY", "text");
        assert!(!f.is_empty());
        assert_eq!(f[0].rule_id, "aws-access-key");
    }

    #[test]
    fn detect_openai_key() {
        let f = scanner().scan("sk-proj-FAKEabc123def456ghi789jkl", "text");
        assert!(!f.is_empty());
        assert!(f.iter().any(|f| f.rule_id == "openai-api-key"));
    }

    #[test]
    fn detect_github_pat() {
        let f = scanner().scan("ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE", "text");
        assert!(f.iter().any(|f| f.rule_id == "github-pat"));
    }

    #[test]
    fn detect_stripe_secret() {
        let test_key = format!("{}_{}", "sk_live", "00FAKE0TEST0VALUE0000000"); let f = scanner().scan(&test_key, "text");
        assert!(f.iter().any(|f| f.rule_id == "stripe-secret"));
    }

    #[test]
    fn detect_private_key() {
        let f = scanner().scan("-----BEGIN RSA PRIVATE KEY-----", "text");
        assert!(f.iter().any(|f| f.rule_id == "private-key-pem"));
    }

    #[test]
    fn detect_postgres_uri() {
        let f = scanner().scan("postgres://user:pass@host/db", "text");
        assert!(f.iter().any(|f| f.rule_id == "postgres-uri"));
    }

    #[test]
    fn clean_text_no_match() {
        let f = scanner().scan("hello world, this is normal text", "text");
        assert!(f.is_empty());
    }

    // --- 4.4 Entropy ---

    #[test]
    fn high_entropy_passes() {
        assert!(shannon_entropy("AKIAIOSFODNN7REALKEY") > 3.5);
    }

    #[test]
    fn low_entropy_filtered() {
        // generic-api-key with low entropy value
        let f = scanner().scan("api_key=aaaaaaaaaaaaaaaa", "text");
        // Should be filtered by entropy check
        let generic = f.iter().filter(|f| f.rule_id == "generic-api-key").count();
        assert_eq!(generic, 0);
    }

    #[test]
    fn per_rule_entropy_override() {
        let custom = vec![CustomSecretRule {
            id: "strict".into(), regex: r"CUSTOM_[A-Za-z0-9]{16}".into(),
            description: None, keywords: vec!["CUSTOM_".into()],
            entropy: Some(4.5), severity: Severity::High,
            action: crate::config::SecretAction::Detect,
        }];
        let s = SecretScanner::new(&custom, &AllowlistConfig::default());
        // Low entropy match should be filtered
        let f = s.scan("CUSTOM_aaaaaaaaaaaaaaaa", "text");
        assert!(f.iter().filter(|f| f.rule_id == "strict").count() == 0);
    }

    // --- 4.5 Allowlist ---

    #[test]
    fn allowlist_example_filtered() {
        let f = scanner_with_allowlist().scan("key=AKIAIOSFODNN7EXAMPLE", "text");
        assert!(f.is_empty());
    }

    #[test]
    fn stopword_test_filtered() {
        let f = scanner_with_allowlist().scan("api_key=test_key_1234567890abcdef", "text");
        let generic = f.iter().filter(|f| f.rule_id == "generic-api-key").count();
        assert_eq!(generic, 0);
    }

    #[test]
    fn real_key_not_filtered() {
        let f = scanner_with_allowlist().scan("sk-proj-FAKEkey12345678901234567", "text");
        assert!(!f.is_empty());
    }

    // --- 4.6 Redaction ---

    #[test]
    fn redact_long() {
        assert_eq!(redact("AKIAIOSFODNN7REALKEY"), "AKIA****LKEY");
    }

    #[test]
    fn redact_medium() {
        assert_eq!(redact("sk-proj-FAKE12"), "sk-p****KE12");
    }

    #[test]
    fn redact_short() {
        assert_eq!(redact("short"), "****");
    }

    #[test]
    fn redact_tiny() {
        assert_eq!(redact("ab"), "****");
    }

    // --- 4.7 Finding output ---

    #[test]
    fn finding_has_entropy_value() {
        let f = scanner().scan("key=AKIAIOSFODNN7REALKEY", "body");
        assert!(!f.is_empty());
        assert!(f[0].entropy_value.is_some());
        assert!(f[0].entropy_value.unwrap() > 0.0);
    }

    #[test]
    fn finding_has_line_number() {
        let f = scanner().scan("line1\nline2\nAKIAIOSFODNN7REALKEY", "text");
        assert!(!f.is_empty());
        assert_eq!(f[0].line_number, 3);
    }

    #[test]
    fn finding_has_field_path() {
        let f = scanner().scan("AKIAIOSFODNN7REALKEY", "data.body");
        assert_eq!(f[0].field_path, "data.body");
    }

    // --- 4.8 Custom rules ---

    #[test]
    fn custom_rule_matches() {
        let custom = vec![CustomSecretRule {
            id: "myco-key".into(), regex: r"myco_[a-zA-Z0-9]{16}".into(),
            description: None, keywords: vec!["myco_".into()],
            entropy: None, severity: Severity::High,
            action: crate::config::SecretAction::Detect,
        }];
        let s = SecretScanner::new(&custom, &AllowlistConfig::default());
        let f = s.scan("token=myco_abcdef1234567890", "text");
        assert!(f.iter().any(|f| f.rule_id == "myco-key"));
    }
}
