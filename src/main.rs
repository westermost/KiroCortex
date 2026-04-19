mod audit;
mod cli;
mod config;
#[cfg(feature = "embedding")]
mod embedding;
mod handlers;
mod hitl;
mod hook_event;
mod init;
mod injection_scanner;
mod memory;
mod path_matcher;
mod proxy;
mod result;
mod secret_scanner;
mod tune;

use anyhow::Result;
use std::process;

fn main() {
    let exit_code = match run() {
        Ok(r) => { r.emit(); r.exit_code }
        Err(e) => { eprintln!("cortex: {e:#}"); 1 }
    };
    process::exit(exit_code as i32);
}

fn run() -> Result<result::HookResult> {
    let cmd = cli::parse();
    match cmd {
        cli::Command::Hook { subcommand } => {
            let event = hook_event::HookEvent::from_stdin()?;
            let cfg = config::Config::load(std::path::Path::new(&event.cwd))?;
            handlers::handle_hook(subcommand, &event, &cfg)
        }
        cli::Command::Scan { path, format } => handlers::handle_scan(&path, &format),
        cli::Command::Init { force, proxy, global, path } => handlers::handle_init(force, proxy, global, path),
        cli::Command::Uninstall { proxy, global, path } => handlers::handle_uninstall(proxy, global, path),
        cli::Command::Check { format, global, path } => handlers::handle_check(&format, global, path),
        cli::Command::Audit { subcommand } => handlers::handle_audit(subcommand),
        cli::Command::AllowOnce { rule, session } => handlers::handle_allow_once(&rule, &session),
        cli::Command::Report { finding_id, verdict, note, rule } => {
            handlers::handle_report(&finding_id, &verdict, note.as_deref(), rule.as_deref())
        }
        cli::Command::Memory { subcommand } => handlers::handle_memory(subcommand),
        cli::Command::Proxy { target } => {
            let cfg = config::Config::load(&std::env::current_dir()?).unwrap_or_default();
            proxy::run_proxy(&target, &cfg)?;
            Ok(result::HookResult::ok_empty())
        }
        cli::Command::Tune { apply, config: config_path } => {
            handlers::handle_tune(apply, config_path)
        }
    }
}
