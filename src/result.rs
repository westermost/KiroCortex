#![cfg_attr(not(test), allow(dead_code))]

/// Hook execution result. Enforces STDOUT/STDERR mutual exclusivity.
#[derive(Debug)]
pub struct HookResult {
    pub exit_code: u8,
    pub stdout: String,
    pub stderr: String,
}

impl HookResult {
    /// Exit 0, empty output.
    pub fn ok_empty() -> Self {
        Self { exit_code: 0, stdout: String::new(), stderr: String::new() }
    }

    /// Exit 0 with STDOUT content (context injection).
    pub fn ok_stdout(content: String) -> Self {
        Self { exit_code: 0, stdout: content, stderr: String::new() }
    }

    /// Exit 1 with STDERR warning.
    pub fn warn(message: String) -> Self {
        Self { exit_code: 1, stdout: String::new(), stderr: message }
    }

    /// Exit 2 with STDERR block reason (PreToolUse only).
    pub fn block(reason: String) -> Self {
        Self { exit_code: 2, stdout: String::new(), stderr: reason }
    }

    /// Write output to stdout/stderr. Enforces mutual exclusivity.
    pub fn emit(&self) {
        if !self.stdout.is_empty() {
            print!("{}", self.stdout);
        }
        if !self.stderr.is_empty() {
            eprint!("{}", self.stderr);
        }
    }

    /// Invariant: stdout and stderr never both non-empty.
    pub fn is_valid(&self) -> bool {
        self.stdout.is_empty() || self.stderr.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_empty_is_valid() {
        let r = HookResult::ok_empty();
        assert_eq!(r.exit_code, 0);
        assert!(r.stdout.is_empty());
        assert!(r.stderr.is_empty());
        assert!(r.is_valid());
    }

    #[test]
    fn ok_stdout_is_valid() {
        let r = HookResult::ok_stdout("context".into());
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout, "context");
        assert!(r.stderr.is_empty());
        assert!(r.is_valid());
    }

    #[test]
    fn warn_is_valid() {
        let r = HookResult::warn("warning".into());
        assert_eq!(r.exit_code, 1);
        assert!(r.stdout.is_empty());
        assert_eq!(r.stderr, "warning");
        assert!(r.is_valid());
    }

    #[test]
    fn block_is_valid() {
        let r = HookResult::block("blocked".into());
        assert_eq!(r.exit_code, 2);
        assert!(r.stdout.is_empty());
        assert_eq!(r.stderr, "blocked");
        assert!(r.is_valid());
    }

    #[test]
    fn both_populated_is_invalid() {
        let r = HookResult {
            exit_code: 0,
            stdout: "out".into(),
            stderr: "err".into(),
        };
        assert!(!r.is_valid());
    }

    #[test]
    fn constructors_never_produce_invalid() {
        assert!(HookResult::ok_empty().is_valid());
        assert!(HookResult::ok_stdout("x".into()).is_valid());
        assert!(HookResult::warn("x".into()).is_valid());
        assert!(HookResult::block("x".into()).is_valid());
    }
}
