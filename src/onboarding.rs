//! Onboarding flow for collecting user email attribution and repo scope.

use anyhow::{Result, bail};
use clap::ValueEnum;
use std::io::{self, IsTerminal, Write};
use std::path::Path;

const EMAIL_CONFIG_KEY: &str = "ai.session-commit-linker.email";
const SCOPE_CONFIG_KEY: &str = "ai.session-commit-linker.scope";
const SCOPE_CURRENT_REPO_KEY: &str = "ai.session-commit-linker.scope.current-repo";
const SCOPE_CURRENT_REPO_KEY_LEGACY: &str = "ai.session-commit-linker.scope.current_repo";
const SCOPE_SELECTED_REPOS_KEY: &str = "ai.session-commit-linker.scope.selected";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ScopeMode {
    Current,
    All,
    Selected,
}

impl ScopeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ScopeMode::Current => "current",
            ScopeMode::All => "all",
            ScopeMode::Selected => "selected",
        }
    }
}

/// Return the configured onboarding email, if present.
pub fn get_email() -> Option<String> {
    match crate::git::config_get_global(EMAIL_CONFIG_KEY) {
        Ok(Some(email)) if !email.trim().is_empty() => Some(email.trim().to_string()),
        _ => None,
    }
}

/// Detect the user's email from `git config --global user.email`.
///
/// This is the GitHub-associated email that most developers already have
/// configured. Returns `None` if unset or empty.
fn detect_git_email() -> Option<String> {
    match crate::git::config_get_global("user.email") {
        Ok(Some(raw)) => normalize_email(&raw),
        _ => None,
    }
}

/// Validate and persist onboarding email in global git config.
pub fn set_email(email: &str) -> Result<String> {
    let normalized = normalize_email(email).ok_or_else(|| anyhow::anyhow!("invalid email"))?;
    crate::git::config_set_global(EMAIL_CONFIG_KEY, &normalized)?;
    Ok(normalized)
}

/// Return configured scope mode, defaulting to `All` for backwards compatibility.
pub fn get_scope_mode() -> ScopeMode {
    match crate::git::config_get_global(SCOPE_CONFIG_KEY) {
        Ok(Some(v)) => parse_scope_mode(&v).unwrap_or(ScopeMode::All),
        _ => ScopeMode::All,
    }
}

/// Persist scope mode globally.
pub fn set_scope_mode(mode: ScopeMode) -> Result<()> {
    crate::git::config_set_global(SCOPE_CONFIG_KEY, mode.as_str())
}

/// Set scope mode and update supporting repo config where needed.
pub fn set_scope_mode_with_context(mode: ScopeMode, repo_path: Option<&str>) -> Result<()> {
    set_scope_mode(mode)?;
    match mode {
        ScopeMode::All => Ok(()),
        ScopeMode::Current => {
            let repo = match repo_path {
                Some(p) => canonical_repo_root(p)?,
                None => current_repo_root_str()?,
            };
            crate::git::config_set_global(SCOPE_CURRENT_REPO_KEY, &repo)?;
            Ok(())
        }
        ScopeMode::Selected => {
            let mut repos = get_selected_repos();
            if let Some(path) = repo_path {
                let repo = canonical_repo_root(path)?;
                if !repos.contains(&repo) {
                    repos.push(repo);
                }
                save_selected_repos(&repos)?;
            }
            Ok(())
        }
    }
}

/// Return whether repo is in configured scope.
pub fn is_repo_in_scope(repo_root: &Path) -> bool {
    let repo_str = match repo_root.canonicalize() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => repo_root.to_string_lossy().to_string(),
    };

    match get_scope_mode() {
        ScopeMode::All => true,
        ScopeMode::Current => current_scope_repo().is_some_and(|current| current == repo_str),
        ScopeMode::Selected => get_selected_repos().iter().any(|r| r == &repo_str),
    }
}

/// Add a repo to selected allowlist.
pub fn add_selected_repo(path: &str) -> Result<String> {
    let repo = canonical_repo_root(path)?;
    let mut repos = get_selected_repos();
    if !repos.contains(&repo) {
        repos.push(repo.clone());
        save_selected_repos(&repos)?;
    }
    Ok(repo)
}

/// Remove a repo from selected allowlist.
pub fn remove_selected_repo(path: &str) -> Result<String> {
    let repo = canonical_repo_root(path)?;
    let mut repos = get_selected_repos();
    repos.retain(|r| r != &repo);
    save_selected_repos(&repos)?;
    Ok(repo)
}

/// Return selected allowlist repos.
pub fn get_selected_repos() -> Vec<String> {
    let raw = match crate::git::config_get_global(SCOPE_SELECTED_REPOS_KEY) {
        Ok(Some(v)) => v,
        _ => return Vec::new(),
    };
    serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default()
}

/// Install-time onboarding for email and repo scope.
pub fn run_install_onboarding(force_first_time_experience: bool) -> Result<()> {
    if force_first_time_experience {
        print_ftue_banner();
    }
    ensure_email_on_install(force_first_time_experience)?;
    ensure_scope_on_install(force_first_time_experience)?;
    if force_first_time_experience {
        print_ftue_completion();
    }
    Ok(())
}

/// Install-time onboarding: auto-detect email from git config.
///
/// Uses `git config --global user.email` (the GitHub-associated email)
/// rather than prompting the user. Falls back gracefully if not set.
pub fn ensure_email_on_install(force_prompt: bool) -> Result<()> {
    if !force_prompt && let Some(existing) = get_email() {
        eprintln!(
            "[ai-session-commit-linker] Onboarding: using existing email {}",
            existing
        );
        return Ok(());
    }

    // Auto-detect from git config user.email
    if let Some(detected) = detect_git_email() {
        let saved = set_email(&detected)?;
        eprintln!(
            "[ai-session-commit-linker] Onboarding: detected email from git config: {}",
            saved
        );
        return Ok(());
    }

    eprintln!(
        "[ai-session-commit-linker] Onboarding: no git user.email found; run `ai-session-commit-linker onboard --email <you@example.com>` to set"
    );
    Ok(())
}

/// Install-time scope onboarding.
///
/// In non-interactive mode, defaults to `all`.
pub fn ensure_scope_on_install(force_prompt: bool) -> Result<()> {
    if !force_prompt {
        let existing = crate::git::config_get_global(SCOPE_CONFIG_KEY)
            .ok()
            .flatten()
            .and_then(|v| parse_scope_mode(&v));
        if let Some(mode) = existing {
            eprintln!(
                "[ai-session-commit-linker] Scope: using existing mode {}",
                mode.as_str()
            );
            return Ok(());
        }
    }

    if !io::stdin().is_terminal() {
        set_scope_mode(ScopeMode::All)?;
        eprintln!(
            "[ai-session-commit-linker] Scope: no TTY; defaulting to all repos (manage later with `ai-session-commit-linker scope ...`)"
        );
        return Ok(());
    }

    eprintln!("[ai-session-commit-linker] Scope setup:");
    if read_yes_no("Run in all repos? [y/N]: ", false)? {
        set_scope_mode(ScopeMode::All)?;
        eprintln!("[ai-session-commit-linker] Scope set: all repos");
        return Ok(());
    }

    if read_yes_no("Use selected repos allowlist? [y/N]: ", false)? {
        set_scope_mode(ScopeMode::Selected)?;
        collect_selected_repos_interactively()?;
        eprintln!("[ai-session-commit-linker] Scope set: selected repos");
        return Ok(());
    }

    if set_scope_mode_with_context(ScopeMode::Current, None).is_ok() {
        eprintln!("[ai-session-commit-linker] Scope set: current repo");
    } else {
        set_scope_mode(ScopeMode::All)?;
        eprintln!("[ai-session-commit-linker] Scope set: all repos (not currently in a git repo)");
    }

    Ok(())
}

/// Run explicit onboarding command.
///
/// With `--email`: use the provided value.
/// Without: auto-detect from `git config --global user.email`.
pub fn run_onboarding(email: Option<&str>) -> Result<()> {
    if let Some(value) = email {
        let saved = set_email(value)?;
        eprintln!(
            "[ai-session-commit-linker] Saved onboarding email: {}",
            saved
        );
        return Ok(());
    }

    // Auto-detect from git config user.email
    if let Some(detected) = detect_git_email() {
        let saved = set_email(&detected)?;
        eprintln!(
            "[ai-session-commit-linker] Detected email from git config: {}",
            saved
        );
        return Ok(());
    }

    bail!("no git user.email found; use --email <you@example.com> to set manually");
}

fn collect_selected_repos_interactively() -> Result<()> {
    let mut selected = get_selected_repos();
    if let Ok(current) = current_repo_root_str() {
        eprintln!(
            "[ai-session-commit-linker] Add current repo to selected list? {} [Y/n]",
            current
        );
        let mut yn = String::new();
        io::stdin().read_line(&mut yn)?;
        if (yn.trim().is_empty() || yn.trim().eq_ignore_ascii_case("y"))
            && !selected.contains(&current)
        {
            selected.push(current);
        }
    }

    loop {
        eprint!("Add repo path (blank to finish): ");
        io::stderr().flush().ok();
        let mut path = String::new();
        io::stdin().read_line(&mut path)?;
        let path = path.trim();
        if path.is_empty() {
            break;
        }
        match canonical_repo_root(path) {
            Ok(repo) => {
                if !selected.contains(&repo) {
                    selected.push(repo.clone());
                }
                eprintln!("[ai-session-commit-linker] Added {}", repo);
            }
            Err(e) => {
                eprintln!(
                    "[ai-session-commit-linker] warning: {} is not a git repo: {}",
                    path, e
                );
            }
        }
    }

    save_selected_repos(&selected)?;
    Ok(())
}

fn canonical_repo_root(path: &str) -> Result<String> {
    let repo = crate::git::repo_root_at(Path::new(path))?;
    Ok(match repo.canonicalize() {
        Ok(c) => c.to_string_lossy().to_string(),
        Err(_) => repo.to_string_lossy().to_string(),
    })
}

fn current_repo_root_str() -> Result<String> {
    let repo = crate::git::repo_root()?;
    Ok(match repo.canonicalize() {
        Ok(c) => c.to_string_lossy().to_string(),
        Err(_) => repo.to_string_lossy().to_string(),
    })
}

fn save_selected_repos(repos: &[String]) -> Result<()> {
    let serialized = serde_json::to_string(repos)?;
    crate::git::config_set_global(SCOPE_SELECTED_REPOS_KEY, &serialized)
}

fn current_scope_repo() -> Option<String> {
    if let Ok(Some(v)) = crate::git::config_get_global(SCOPE_CURRENT_REPO_KEY) {
        return Some(v);
    }
    // Legacy fallback for development snapshots that used an underscore key.
    match crate::git::config_get_global(SCOPE_CURRENT_REPO_KEY_LEGACY) {
        Ok(Some(v)) => Some(v),
        _ => None,
    }
}

fn parse_scope_mode(raw: &str) -> Option<ScopeMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "current" => Some(ScopeMode::Current),
        "all" => Some(ScopeMode::All),
        "selected" => Some(ScopeMode::Selected),
        _ => None,
    }
}

fn print_ftue_banner() {
    eprintln!();
    eprintln!("{}", crate::ui::title("Cadence CLI First-Time Setup"));
    eprintln!();
    eprintln!("{}", crate::ui::info("How it works:"));
    eprintln!(
        "{}",
        crate::ui::info(
            "On each commit, a hook links your latest AI session to that commit as a git note."
        )
    );
    eprintln!();
}

fn print_ftue_completion() {
    eprintln!();
    eprintln!("{}", crate::ui::info("Configured repository scope:"));
    match get_scope_mode() {
        ScopeMode::All => {
            eprintln!("   - all repositories");
        }
        ScopeMode::Current => {
            if let Some(repo) = current_scope_repo() {
                eprintln!("   - {}", repo);
            } else {
                eprintln!("   - current repo (not available right now)");
            }
        }
        ScopeMode::Selected => {
            let selected = get_selected_repos();
            if selected.is_empty() {
                eprintln!("   - (none selected yet)");
            } else {
                for repo in selected {
                    eprintln!("   - {}", repo);
                }
            }
        }
    }
    eprintln!();
}

fn read_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    eprint!("{}", prompt);
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

fn normalize_email(input: &str) -> Option<String> {
    let email = input.trim().to_ascii_lowercase();
    if email.is_empty() || email.contains(' ') {
        return None;
    }

    let (local, domain) = email.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return None;
    }
    if !domain.contains('.') {
        return None;
    }
    Some(email)
}

#[cfg(test)]
mod tests {
    use super::{ScopeMode, normalize_email, parse_scope_mode};

    #[test]
    fn normalize_email_accepts_basic() {
        assert_eq!(
            normalize_email("User@Example.com"),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn normalize_email_rejects_invalid() {
        assert_eq!(normalize_email(""), None);
        assert_eq!(normalize_email("foo"), None);
        assert_eq!(normalize_email("foo@bar"), None);
        assert_eq!(normalize_email("foo@bar."), None);
        assert_eq!(normalize_email("foo bar@example.com"), None);
    }

    #[test]
    fn parse_scope_mode_values() {
        assert_eq!(parse_scope_mode("current"), Some(ScopeMode::Current));
        assert_eq!(parse_scope_mode("all"), Some(ScopeMode::All));
        assert_eq!(parse_scope_mode("selected"), Some(ScopeMode::Selected));
        assert_eq!(parse_scope_mode("unknown"), None);
    }
}
