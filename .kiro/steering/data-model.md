# Findings Data Model

All scanner tasks MUST use these exact types. No per-task variations.

```rust
#[derive(Ord)]
enum RiskLevel { Low, Medium, High, Critical }

struct SecretFinding {
    rule_id: String,           // "aws-access-token"
    severity: Severity,
    matched_text: String,      // NEVER logged — in-memory only
    redacted_preview: String,  // "AKIA****MPLE"
    field_path: String,        // "body", "data[0].subject", "prompt:line3"
    byte_offset: usize,
    line_number: u32,          // 1-based
    entropy_value: Option<f64>, // Shannon entropy of matched text (for tuning)
}

struct InjectionFinding {
    pattern_id: String,        // "ignore_previous"
    category: String,          // "instruction_override"
    severity: Severity,
    matched_text: String,      // NEVER logged
    field_path: String,
    risk_level: RiskLevel,
}

struct StructuralFlag {
    flag_type: String,         // "excessive_length"|"high_entropy"|"nested_markers"|"suspicious_formatting"
    severity: Severity,
    detail: String,
    field_path: String,
}

struct ScanResult {
    secrets: Vec<SecretFinding>,
    injections: Vec<InjectionFinding>,
    structural_flags: Vec<StructuralFlag>,
    overall_risk: RiskLevel,
    scan_latency_ms: f64,
}

enum ActionTaken {
    None,
    Blocked { reason: String },
    Warned { stderr_message: String },
    ContextInjected { stdout_text: String },
    Overridden { rule_id: String },        // v1.5: allow-once used
    Redacted { fields_count: u32 },        // v1.5: MCP proxy redaction
}

struct AuditEntry {
    timestamp: String,         // ISO 8601 UTC
    session_id: String,
    hook_type: String,         // includes "mcpProxy" for proxy events
    tool_name: Option<String>,
    mode: String,              // "audit"|"enforce"
    findings: Vec<AuditFinding>,
    action_taken: String,      // "none"|"blocked"|"warned"|"context_injected"|"overridden"|"redacted"
    exit_code: u8,
    latency_ms: f64,
}

struct AuditFinding {
    finding_type: String,      // "secret"|"injection"|"structural"
    finding_id: String,        // SHA-256(rule_id+field_path+redacted_preview)[:8] for feedback reference
    rule_id: String,
    severity: String,
    field_path: String,
    redacted_preview: String,
    risk_level: String,
    entropy_value: Option<f64>, // v1.0: logged for tuning
    fingerprint: Option<String>, // SHA-256 truncated 16 hex (if enabled)
}
```

## Critical Invariant

`matched_text` exists ONLY in-memory. NEVER written to audit log, STDERR, STDOUT, or any file. Use `redacted_preview` for all external output. `AuditFinding` struct intentionally has no `matched_text` field.

## Redaction Format

| Type | Format |
|---|---|
| Secret ≥8 chars | First 4 + `****` + last 4: `AKIA****MPLE` |
| Secret <8 chars | `****` |
| Injection | First 50 chars + `...` if longer |
| Structural | Description only |
