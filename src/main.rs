mod git;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process;

/// AI Barometer: attach AI coding agent session logs to Git commits via git notes.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "ai-barometer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install AI Barometer: set up git hooks and run initial hydration.
    Install {
        /// Optional GitHub org filter for push scoping.
        #[arg(long)]
        org: Option<String>,
    },

    /// Git hook entry points.
    Hook {
        #[command(subcommand)]
        hook_command: HookCommand,
    },

    /// Backfill AI session notes for recent commits.
    Hydrate {
        /// How far back to scan, e.g. "7d" for 7 days.
        #[arg(long, default_value = "7d")]
        since: String,

        /// Push notes to remote after hydration.
        #[arg(long)]
        push: bool,
    },

    /// Retry attaching notes for pending (unresolved) commits.
    Retry,

    /// Show AI Barometer status for the current repository.
    Status,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook: attempt to attach AI session note to HEAD.
    PostCommit,
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

fn run_install(org: Option<String>) -> Result<()> {
    eprintln!(
        "[ai-barometer] install: org={:?} (not yet implemented)",
        org
    );
    Ok(())
}

fn run_hook_post_commit() -> Result<()> {
    eprintln!("[ai-barometer] hook post-commit (not yet implemented)");
    Ok(())
}

fn run_hydrate(since: &str, push: bool) -> Result<()> {
    eprintln!(
        "[ai-barometer] hydrate: since={}, push={} (not yet implemented)",
        since, push
    );
    Ok(())
}

fn run_retry() -> Result<()> {
    eprintln!("[ai-barometer] retry (not yet implemented)");
    Ok(())
}

fn run_status() -> Result<()> {
    eprintln!("[ai-barometer] status (not yet implemented)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Install { org } => run_install(org),
        Command::Hook { hook_command } => match hook_command {
            HookCommand::PostCommit => run_hook_post_commit(),
        },
        Command::Hydrate { since, push } => run_hydrate(&since, push),
        Command::Retry => run_retry(),
        Command::Status => run_status(),
    };

    if let Err(e) = result {
        eprintln!("[ai-barometer] error: {}", e);
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_install() {
        let cli = Cli::parse_from(["ai-barometer", "install"]);
        assert!(matches!(cli.command, Command::Install { org: None }));
    }

    #[test]
    fn cli_parses_install_with_org() {
        let cli = Cli::parse_from(["ai-barometer", "install", "--org", "my-org"]);
        match cli.command {
            Command::Install { org } => assert_eq!(org.as_deref(), Some("my-org")),
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit() {
        let cli = Cli::parse_from(["ai-barometer", "hook", "post-commit"]);
        assert!(matches!(
            cli.command,
            Command::Hook {
                hook_command: HookCommand::PostCommit
            }
        ));
    }

    #[test]
    fn cli_parses_hydrate_defaults() {
        let cli = Cli::parse_from(["ai-barometer", "hydrate"]);
        match cli.command {
            Command::Hydrate { since, push } => {
                assert_eq!(since, "7d");
                assert!(!push);
            }
            _ => panic!("expected Hydrate command"),
        }
    }

    #[test]
    fn cli_parses_hydrate_with_flags() {
        let cli = Cli::parse_from(["ai-barometer", "hydrate", "--since", "30d", "--push"]);
        match cli.command {
            Command::Hydrate { since, push } => {
                assert_eq!(since, "30d");
                assert!(push);
            }
            _ => panic!("expected Hydrate command"),
        }
    }

    #[test]
    fn cli_parses_retry() {
        let cli = Cli::parse_from(["ai-barometer", "retry"]);
        assert!(matches!(cli.command, Command::Retry));
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::parse_from(["ai-barometer", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    fn run_install_returns_ok() {
        assert!(run_install(None).is_ok());
    }

    #[test]
    fn run_hook_post_commit_returns_ok() {
        assert!(run_hook_post_commit().is_ok());
    }

    #[test]
    fn run_hydrate_returns_ok() {
        assert!(run_hydrate("7d", false).is_ok());
    }

    #[test]
    fn run_retry_returns_ok() {
        assert!(run_retry().is_ok());
    }

    #[test]
    fn run_status_returns_ok() {
        assert!(run_status().is_ok());
    }

    // -----------------------------------------------------------------------
    // Negative CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer", "frobnicate"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hook_without_sub_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer", "hook"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hydrate_since_missing_value() {
        let result = Cli::try_parse_from(["ai-barometer", "hydrate", "--since"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_no_subcommand() {
        let result = Cli::try_parse_from(["ai-barometer"]);
        assert!(result.is_err());
    }
}
