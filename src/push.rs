//! Push decision logic for AI session notes.
//!
//! Orchestrates the decision of whether to push notes to the remote after
//! attaching them locally. The decision depends on several factors:
//!
//! 1. **Has upstream**: selected remote must exist.
//! 2. **Org filter**: if `git config --global ai.cadence.org` is set,
//!    the selected remote must belong to that org. Otherwise, notes are
//!    attached locally only (no push).
//!
//! Note: The per-repo enabled check (`git config ai.cadence.enabled`) is
//! handled by [`git::check_enabled()`] in the git module, since it gates
//! ALL processing (not just push).
//!
//! Push failures are always non-fatal: logged to stderr, never block the
//! commit, never retry automatically in the hook.

use crate::{git, output};
use anyhow::{Context, Result};
use console::style;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::path::Path;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Determine whether notes should be pushed for a specific remote.
///
/// Orchestrates all checks: enabled (already checked by caller), has upstream,
/// org filter.
///
/// Returns `true` if all conditions are met and notes should be pushed.
/// Returns `false` if any condition prevents pushing.
pub fn should_push_remote(remote: &str) -> bool {
    if remote.is_empty() || remote == "." {
        return false;
    }

    // Check 1: Does the remote exist?
    match git::remote_url(remote) {
        Ok(Some(_)) => {}
        _ => return false,
    }

    // Check 2: Org filter
    if !check_org_filter_remote(remote) {
        return false;
    }

    true
}

/// Attempt to push notes to the remote. Handles failure gracefully.
///
/// On success: silent (no output).
/// On failure: logs a note to stderr. Never blocks, never retries.
pub fn attempt_push_remote(remote: &str) {
    if let Err(e) = git::push_notes(remote) {
        output::note(&format!("Could not push notes: {}", e));
    }
}

/// Sync notes with the provided remote:
/// fetch notes, merge into local notes ref, then push notes to the remote.
pub fn sync_notes_for_remote(remote: &str) {
    let start = std::time::Instant::now();
    let use_progress = output::is_stderr_tty() && !output::is_verbose();
    let cadence_label = if output::is_stderr_tty() {
        style("[Cadence]").bold().green().to_string()
    } else {
        "[Cadence]".to_string()
    };
    let progress = if use_progress {
        let pb = ProgressBar::new_spinner();
        pb.set_draw_target(ProgressDrawTarget::stderr());
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        pb.set_message(format!(
            "{} Syncing attached agent sessions with {}",
            cadence_label, remote
        ));
        Some(pb)
    } else {
        output::success("Cadence", &format!("Syncing notes with {}", remote));
        None
    };

    let result = sync_notes_for_remote_inner(remote);
    if let Some(pb) = progress {
        match &result {
            Ok(()) => pb.finish_with_message(format!(
                "✔ {} Synced attached agent sessions with {}",
                cadence_label, remote
            )),
            Err(_) => pb.finish_and_clear(),
        }
        eprintln!();
    }

    if let Err(e) = result {
        output::note(&format!("Could not sync notes with {}: {}", remote, e));
    } else if !use_progress {
        output::success(
            "Cadence",
            &format!("Notes sync done in {} ms", start.elapsed().as_millis()),
        );
        eprintln!();
    }
}

fn sync_notes_for_remote_inner(remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }

    let phase = std::time::Instant::now();
    let local_hash = local_notes_hash().context("failed to read local notes ref")?;
    let remote_hash = remote_notes_hash(remote).context("failed to read remote notes ref")?;
    if output::is_verbose() {
        output::detail(&format!(
            "Hashes local={:?} remote={:?} ({} ms)",
            local_hash,
            remote_hash,
            phase.elapsed().as_millis()
        ));
    }

    match (&local_hash, &remote_hash) {
        (None, None) => {
            if output::is_verbose() {
                output::detail("Sync skipped (no local/remote notes)");
            }
            return Ok(());
        }
        (Some(l), Some(r)) if l == r => {
            if output::is_verbose() {
                output::detail("Sync skipped (hashes match)");
            }
            return Ok(());
        }
        _ => {}
    }

    let temp_ref = format!("refs/notes/ai-sessions-remote/{}", remote);
    let fetch_spec = format!("{}:{}", git::NOTES_REF, temp_ref);

    let fetch_start = std::time::Instant::now();
    let fetch_status = git::run_git_output_at(None, &["fetch", remote, &fetch_spec], &[])
        .context("failed to execute git fetch for notes")?;
    if output::is_verbose() {
        output::detail(&format!(
            "Fetch in {} ms",
            fetch_start.elapsed().as_millis()
        ));
    }

    let fetched = fetch_status.status.success();
    if !fetched {
        let stderr = String::from_utf8_lossy(&fetch_status.stderr);
        output::note(&format!(
            "Could not fetch notes from {}: {}",
            remote,
            stderr.trim()
        ));
    }

    if fetched {
        let merge_start = std::time::Instant::now();
        let merge_status = git::run_git_output_at(
            None,
            &["notes", "--ref", git::NOTES_REF, "merge", &temp_ref],
            &[],
        )
        .context("failed to execute git notes merge")?;
        if output::is_verbose() {
            output::detail(&format!(
                "Merge in {} ms",
                merge_start.elapsed().as_millis()
            ));
        }

        if !merge_status.status.success() {
            let stderr = String::from_utf8_lossy(&merge_status.stderr);
            output::note(&format!(
                "Could not merge notes from {}: {}",
                remote,
                stderr.trim()
            ));
        }

        let _ = git::run_git_output_at(None, &["update-ref", "-d", &temp_ref], &[]);
    }

    let post_hash_start = std::time::Instant::now();
    let post_merge_hash = local_notes_hash().context("failed to read local notes ref")?;
    if output::is_verbose() {
        output::detail(&format!(
            "Post-merge hash={:?} ({} ms)",
            post_merge_hash,
            post_hash_start.elapsed().as_millis()
        ));
    }
    if let (Some(local), Some(remote)) = (&post_merge_hash, &remote_hash)
        && local == remote
    {
        if output::is_verbose() {
            output::detail("Sync push skipped (hash unchanged)");
        }
        return Ok(());
    }

    let push_start = std::time::Instant::now();
    if output::is_verbose() {
        output::detail("Pushing notes");
    }
    let push_status = git::run_git_output_at(
        None,
        &["push", "--no-verify", remote, git::NOTES_REF],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git push for notes")?;
    if output::is_verbose() {
        output::detail(&format!("Push in {} ms", push_start.elapsed().as_millis()));
    }

    if !push_status.status.success() {
        let stderr = String::from_utf8_lossy(&push_status.stderr);
        let stderr_trim = stderr.trim();
        if stderr_trim.contains("cannot lock ref")
            && stderr_trim.contains(git::NOTES_REF)
            && stderr_trim.contains("expected")
        {
            output::note("Notes ref changed on remote; retrying sync once");
            return sync_notes_for_remote_retry(remote);
        }
        anyhow::bail!("git push notes failed: {}", stderr_trim);
    }

    Ok(())
}

fn sync_notes_for_remote_retry(remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }

    let temp_ref = format!("refs/notes/ai-sessions-remote/{}", remote);
    let fetch_spec = format!("{}:{}", git::NOTES_REF, temp_ref);

    let fetch_status = git::run_git_output_at(None, &["fetch", remote, &fetch_spec], &[])
        .context("failed to execute git fetch for notes")?;

    if !fetch_status.status.success() {
        let stderr = String::from_utf8_lossy(&fetch_status.stderr);
        let stderr_trim = stderr.trim();
        if !(stderr_trim.contains("couldn't find remote ref")
            && stderr_trim.contains(git::NOTES_REF))
        {
            anyhow::bail!("git fetch notes failed: {}", stderr_trim);
        }
    }

    let merge_status = git::run_git_output_at(
        None,
        &["notes", "--ref", git::NOTES_REF, "merge", &temp_ref],
        &[],
    )
    .context("failed to execute git notes merge")?;

    if !merge_status.status.success() {
        let stderr = String::from_utf8_lossy(&merge_status.stderr);
        anyhow::bail!("git notes merge failed: {}", stderr.trim());
    }

    let _ = git::run_git_output_at(None, &["update-ref", "-d", &temp_ref], &[]);

    let push_status = git::run_git_output_at(
        None,
        &["push", "--no-verify", remote, git::NOTES_REF],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git push for notes")?;

    if !push_status.status.success() {
        let stderr = String::from_utf8_lossy(&push_status.stderr);
        anyhow::bail!("git push notes failed: {}", stderr.trim());
    }

    Ok(())
}

fn local_notes_hash() -> Result<Option<String>> {
    let output = git::run_git_output_at(
        None,
        &["show-ref", "--verify", "--hash", git::NOTES_REF],
        &[],
    )
    .context("failed to execute git show-ref")?;

    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    let hash = stdout.trim();
    if hash.is_empty() {
        Ok(None)
    } else {
        Ok(Some(hash.to_string()))
    }
}

fn remote_notes_hash(remote: &str) -> Result<Option<String>> {
    let start = std::time::Instant::now();
    let output = git::run_git_output_at(
        None,
        &[
            "-c",
            "protocol.version=2",
            "ls-remote",
            "--refs",
            remote,
            git::NOTES_REF,
        ],
        &[("GIT_TERMINAL_PROMPT", "0"), ("GIT_OPTIONAL_LOCKS", "0")],
    )
    .context("failed to execute git ls-remote")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git ls-remote failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    if output::is_verbose() {
        output::detail(&format!("ls-remote in {} ms", start.elapsed().as_millis()));
    }
    let line = stdout.lines().next().unwrap_or("");
    let hash = line.split_whitespace().next().unwrap_or("");
    if hash.is_empty() {
        Ok(None)
    } else {
        Ok(Some(hash.to_string()))
    }
}

/// Check the org filter: if a global org is configured, verify that the
/// selected remote belongs to that org.
///
/// Reads `git config --global ai.cadence.org`. If not set, the filter
/// passes (no org restriction). If set, extracts the org from the selected
/// remote and checks for a match.
///
/// Returns `true` if push is allowed (no filter, or filter matches).
/// Returns `false` if the org filter is set and the remote does not match.
pub fn check_org_filter_remote(remote: &str) -> bool {
    let configured_org = match git::config_get_global("ai.cadence.org") {
        Ok(Some(org)) => org,
        // No org filter configured: allow push
        _ => return true,
    };

    let url = match git::remote_url(remote) {
        Ok(Some(u)) => u,
        _ => return false,
    };

    let remote_org = match git::parse_org_from_url(&url) {
        Some(org) => org,
        None => return false,
    };

    remote_org.eq_ignore_ascii_case(&configured_org)
}

/// Pure-logic helper: check whether any of the `remote_orgs` matches the
/// `configured_org` using case-insensitive comparison.
///
/// This is extracted from [`check_org_filter`] for testability — the
/// orchestration function reads from global git config which is hard to
/// isolate in tests, but this pure function can be tested directly.
#[allow(dead_code)]
pub fn org_matches(configured_org: &str, remote_orgs: &[String]) -> bool {
    remote_orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(configured_org))
}

/// Fetch and merge notes from the remote for a specific repository.
pub fn fetch_merge_notes_for_remote_at(repo: &Path, remote: &str) -> Result<()> {
    fetch_merge_notes_for_remote_inner(Some(repo), remote)
}

fn fetch_merge_notes_for_remote_inner(repo: Option<&Path>, remote: &str) -> Result<()> {
    if remote.is_empty() || remote == "." {
        anyhow::bail!("invalid remote name");
    }

    let temp_ref = format!("refs/notes/ai-sessions-remote/{}", remote);
    let fetch_spec = format!("{}:{}", git::NOTES_REF, temp_ref);

    let fetch_status = git::run_git_output_at(
        repo,
        &["fetch", remote, &fetch_spec],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git fetch for notes")?;

    if !fetch_status.status.success() {
        let stderr = String::from_utf8_lossy(&fetch_status.stderr);
        let stderr_trim = stderr.trim();
        if stderr_trim.contains("couldn't find remote ref") && stderr_trim.contains(git::NOTES_REF)
        {
            return Ok(());
        }
        anyhow::bail!("git fetch notes failed: {}", stderr_trim);
    }

    let merge_status = git::run_git_output_at(
        repo,
        &["notes", "--ref", git::NOTES_REF, "merge", &temp_ref],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git notes merge")?;

    if !merge_status.status.success() {
        let stderr = String::from_utf8_lossy(&merge_status.stderr);
        anyhow::bail!("git notes merge failed: {}", stderr.trim());
    }

    let _ = git::run_git_output_at(
        repo,
        &["update-ref", "-d", &temp_ref],
        &[("GIT_TERMINAL_PROMPT", "0")],
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        // Override hooksPath to prevent the global post-commit hook from firing
        run_git(path, &["config", "core.hooksPath", "/dev/null"]);
        std::fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    fn run_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .expect("failed to run git");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {:?} failed: {}", args, stderr);
        }
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Helper: get a stable directory to use as a fallback CWD.
    fn safe_cwd() -> PathBuf {
        match std::env::current_dir() {
            Ok(cwd) if cwd.exists() => cwd,
            _ => {
                let fallback = std::env::temp_dir();
                std::env::set_current_dir(&fallback).ok();
                fallback
            }
        }
    }

    // -----------------------------------------------------------------------
    // check_org_filter
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_org_filter_no_config_allows_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:my-org/my-repo.git",
            ],
        );

        // Use an empty global config so we don't depend on the developer's
        // real global git config (which might have ai.cadence.org set).
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // No global org config -- filter should pass
        assert!(check_org_filter_remote("origin"));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_org_filter_matching_org_allows_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with a known org
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:my-org/my-repo.git",
            ],
        );

        // Create a global config with matching org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = my-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // check_org_filter should pass because the remote org matches
        assert!(check_org_filter_remote("origin"));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_org_filter_no_remote_denies_push() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Create a global config with an org filter set
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = required-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // No remotes configured -- org filter should deny (no remote matches)
        assert!(!check_org_filter_remote("origin"));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // should_push
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_should_push_no_remote_returns_false() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote -- should_push_remote should return false
        assert!(!should_push_remote("origin"));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_should_push_with_remote() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/test-repo.git",
            ],
        );

        // should_push_remote should return true (remote exists, no org filter)
        assert!(should_push_remote("origin"));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // remote_orgs with multiple remotes
    // -----------------------------------------------------------------------
    #[test]
    #[serial]
    fn test_remote_orgs_multiple_remotes() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add multiple remotes with different orgs
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:org-one/repo1.git",
            ],
        );
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/org-two/repo2.git",
            ],
        );

        let orgs = git::remote_orgs().unwrap();
        assert_eq!(orgs.len(), 2);
        assert!(orgs.contains(&"org-one".to_string()));
        assert!(orgs.contains(&"org-two".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_remote_orgs_deduplicates() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add two remotes with the same org
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:same-org/repo1.git",
            ],
        );
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "fork",
                "https://github.com/same-org/repo2.git",
            ],
        );

        let orgs = git::remote_orgs().unwrap();
        assert_eq!(orgs.len(), 1);
        assert_eq!(orgs[0], "same-org");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // org_matches (pure-logic unit tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_org_matches_exact() {
        let orgs = vec!["my-org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_case_insensitive() {
        let orgs = vec!["my-org".to_string()];
        assert!(org_matches("My-Org", &orgs));
        assert!(org_matches("MY-ORG", &orgs));
    }

    #[test]
    fn test_org_matches_reverse_case() {
        // Configured is lowercase, remote is mixed case
        let orgs = vec!["My-Org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_no_match() {
        let orgs = vec!["other-org".to_string()];
        assert!(!org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_empty_remotes() {
        let orgs: Vec<String> = vec![];
        assert!(!org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_multiple_remotes_one_matches() {
        let orgs = vec!["unrelated".to_string(), "my-org".to_string()];
        assert!(org_matches("my-org", &orgs));
    }

    #[test]
    fn test_org_matches_multiple_remotes_none_match() {
        let orgs = vec!["org-a".to_string(), "org-b".to_string()];
        assert!(!org_matches("my-org", &orgs));
    }

    // -----------------------------------------------------------------------
    // should_push with org filter
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_should_push_org_filter_denies_returns_false() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "actual-org"
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:actual-org/repo.git",
            ],
        );

        // Create a temp global config file with a different org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = required-org\n").unwrap();

        // Point GIT_CONFIG_GLOBAL to our fake global config
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // should_push should return false because "actual-org" != "required-org"
        assert!(!should_push_remote("origin"));

        // Restore GIT_CONFIG_GLOBAL
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_should_push_org_filter_allows_matching_org() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "my-org"
        run_git(
            dir.path(),
            &["remote", "add", "origin", "git@github.com:my-org/repo.git"],
        );

        // Create a global config file with matching org filter
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = my-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // should_push should return true because "my-org" matches
        assert!(should_push_remote("origin"));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_org_filter_end_to_end_with_global_config() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote with org "test-org"
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:test-org/repo.git",
            ],
        );

        // Create a global config with matching org
        let global_config = dir.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = Test-Org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Case-insensitive match: "Test-Org" should match "test-org"
        assert!(check_org_filter_remote("origin"));

        // Now test with non-matching org
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = other-org\n").unwrap();

        assert!(!check_org_filter_remote("origin"));

        // Restore
        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // attempt_push — always succeeds (never panics)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_attempt_push_failure_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote configured -- push will fail, but should not panic
        attempt_push_remote("origin");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_sync_notes_failure_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote configured -- sync should warn but not panic
        sync_notes_for_remote("origin");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_attempt_push_with_unreachable_remote_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // Add a remote that doesn't actually exist
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:nonexistent/repo.git",
            ],
        );

        // This will fail (can't connect) but should not panic or block
        attempt_push_remote("origin");

        std::env::set_current_dir(original_cwd).unwrap();
    }
}
