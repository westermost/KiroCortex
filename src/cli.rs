use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kiro-cortex", about = "Kiro Cortex — Guard + Proxy + Memory for AI Agents")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Hook handlers (called by Kiro)
    Hook {
        #[command(subcommand)]
        subcommand: HookSubcommand,
    },
    /// Scan file or directory for secrets + injection
    Scan {
        /// Path to scan
        path: String,
        /// Output format
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Setup Kiro Cortex hooks and config
    Init {
        /// Overwrite existing config and hooks
        #[arg(long)]
        force: bool,
        /// Wrap MCP servers with proxy
        #[arg(long)]
        proxy: bool,
        /// Setup globally (~/.kiro/) instead of project-local
        #[arg(long)]
        global: bool,
        /// Target project directory (default: current directory)
        #[arg(long)]
        path: Option<String>,
    },
    /// Remove Kiro Cortex hooks
    Uninstall {
        /// Restore MCP servers
        #[arg(long)]
        proxy: bool,
        /// Remove from global (~/.kiro/)
        #[arg(long)]
        global: bool,
        /// Target project directory
        #[arg(long)]
        path: Option<String>,
    },
    /// Validate setup
    Check {
        #[arg(long, default_value = "human")]
        format: String,
        /// Check global install (~/.kiro/)
        #[arg(long)]
        global: bool,
        /// Check specific project directory
        #[arg(long)]
        path: Option<String>,
    },
    /// Audit log operations
    Audit {
        #[command(subcommand)]
        subcommand: AuditSubcommand,
    },
    /// Override a block for current session
    AllowOnce {
        /// Rule ID to override
        rule: String,
        /// Session ID
        #[arg(long)]
        session: String,
    },
    /// Report finding as false-positive or confirmed
    Report {
        /// Finding ID (8 hex chars)
        finding_id: String,
        /// Verdict: false-positive or confirmed
        verdict: String,
        /// Rule ID (shown in STDERR output)
        #[arg(long)]
        rule: Option<String>,
        /// Optional note
        #[arg(long)]
        note: Option<String>,
    },
    /// Memory operations
    Memory {
        #[command(subcommand)]
        subcommand: MemorySubcommand,
    },
    /// MCP Proxy — intercept and scan MCP responses
    Proxy {
        /// Target MCP server command
        #[arg(long)]
        target: String,
    },
    /// Auto-tune rules based on feedback data
    Tune {
        /// Apply suggestions to config (default: dry-run)
        #[arg(long)]
        apply: bool,
        /// Target config file path
        #[arg(long)]
        config: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum HookSubcommand {
    /// AgentSpawn hook
    Spawn,
    /// UserPromptSubmit hook
    Prompt,
    /// PreToolUse hook
    PreTool,
    /// PostToolUse hook
    PostTool,
    /// Stop hook (session end)
    Stop,
}

#[derive(Subcommand, Debug, Clone)]
pub enum AuditSubcommand {
    /// Show audit summary
    Summary {
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        noisy: bool,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum MemorySubcommand {
    /// Search memory
    Search {
        query: String,
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Memory statistics
    Stats,
    /// Import conversation history
    Import { path: String },
    /// Delete old memories
    Forget {
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        chunk_id: Option<String>,
    },
    /// Download embedding model for semantic search
    Init,
    /// Backfill/rebuild vectors for all existing chunks
    Reindex,
}

pub fn parse() -> Command {
    Cli::parse().command
}
