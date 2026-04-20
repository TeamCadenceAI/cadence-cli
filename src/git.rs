//! Git utility helpers.
//!
//! All functions shell out to `git` via `tokio::process::Command`.
//! The notes ref used throughout is `refs/cadence/sessions/data`.

use crate::output;
use anyhow::{Context, Result, bail};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;
use tokio::process::Command;

/// The dedicated git notes ref for AI session data.
#[cfg(test)]
pub const NOTES_REF: &str = "refs/cadence/sessions/data";

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Run a git command and return its stdout as a trimmed `String`.
/// Returns an error if the command exits with a non-zero status.
async fn git_output(args: &[&str]) -> Result<String> {
    let output = run_git_output_at(None, args, &[]).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git {} failed (exit {}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        );
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(stdout.trim().to_string())
}

async fn git_output_in(repo: &Path, args: &[&str]) -> Result<String> {
    let output = run_git_output_at(Some(repo), args, &[]).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(stdout.trim().to_string())
}

pub(crate) async fn run_git_output_at(
    repo: Option<&Path>,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<Output> {
    let mut cmd = Command::new("git");
    let mut display_parts = vec!["git".to_string()];

    if let Some(repo) = repo {
        let repo_str = repo.to_string_lossy().to_string();
        cmd.args(["-C", &repo_str]);
        display_parts.push("-C".to_string());
        display_parts.push(repo_str);
    }

    for (key, value) in envs {
        cmd.env(key, value);
    }

    let repo_for_log = repo.map(crate::tracing::sanitize_path);
    let env_keys = envs
        .iter()
        .map(|(key, _)| (*key).to_string())
        .collect::<Vec<_>>();
    display_parts.extend(args.iter().map(|s| s.to_string()));
    ::tracing::trace!(
        event = "git_command_started",
        repo = repo_for_log.as_deref().unwrap_or(""),
        args = ?args,
        env_keys = ?env_keys
    );
    let verbose = output::is_verbose();
    if verbose {
        output::detail(&display_parts.join(" "));
        let output = cmd
            .args(args)
            .output()
            .await
            .context("failed to execute git")?;
        log_git_command_completed(repo, args, &output, verbose);
        if !output.stdout.is_empty() {
            output::detail("stdout:");
            emit_stream_chunk(&output.stdout);
        }
        if !output.stderr.is_empty() {
            output::detail("stderr:");
            emit_stream_chunk(&output.stderr);
        }
        return Ok(output);
    }

    let output = cmd
        .args(args)
        .output()
        .await
        .context("failed to execute git")?;
    log_git_command_completed(repo, args, &output, verbose);
    Ok(output)
}

fn log_git_command_completed(repo: Option<&Path>, args: &[&str], output: &Output, verbose: bool) {
    let repo_for_log = repo.map(crate::tracing::sanitize_path);
    let status = output.status.code();
    if verbose || !output.status.success() {
        ::tracing::trace!(
            event = "git_command_completed",
            repo = repo_for_log.as_deref().unwrap_or(""),
            args = ?args,
            status = ?status,
            stdout_bytes = output.stdout.len(),
            stderr_bytes = output.stderr.len(),
            stdout = crate::tracing::truncate_text(String::from_utf8_lossy(&output.stdout), 2048),
            stderr = crate::tracing::truncate_text(String::from_utf8_lossy(&output.stderr), 2048),
        );
        return;
    }
    ::tracing::trace!(
        event = "git_command_completed",
        repo = repo_for_log.as_deref().unwrap_or(""),
        args = ?args,
        status = ?status,
        stdout_bytes = output.stdout.len(),
        stderr_bytes = output.stderr.len(),
    );
}

fn emit_stream_chunk(chunk: &[u8]) {
    let text = String::from_utf8_lossy(chunk);
    for segment in text.split('\n') {
        if segment.is_empty() {
            continue;
        }
        let line = segment.trim_end_matches('\r');
        output::detail(&format!("  {}", line));
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether Cadence CLI is enabled for the current repository.
///
/// Reads `git config ai.cadence.enabled`. If the value is exactly
/// `"false"`, returns `false` -- the caller should skip ALL processing
/// (session scanning, session-ref updates, pending records, push, retry).
/// Any other value (including unset) returns `true`.
///
/// This is placed in the `git` module (not `push`) because it gates
/// the entire hook lifecycle, not just the push decision.
pub async fn check_enabled() -> bool {
    match config_get("ai.cadence.enabled").await {
        Ok(Some(val)) => val != "false",
        // Unset or error: default to enabled
        _ => true,
    }
}

/// Check whether Cadence CLI is enabled for a specific repository directory.
///
/// This is the directory-parameterised version of [`check_enabled`], for use
/// by commands that operate on repos other than the CWD (e.g., `backfill`).
///
/// Reads `git -C <repo> config ai.cadence.enabled`. If the value is exactly
/// `"false"`, returns `false`. Any other value (including unset) returns `true`.
pub(crate) async fn check_enabled_at(repo: &Path) -> bool {
    let output = match run_git_output_at(
        Some(repo),
        &["config", "--get", "ai.cadence.enabled"],
        &[],
    )
    .await
    {
        Ok(o) => o,
        Err(_) => return true,
    };

    if output.status.success() {
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        value != "false"
    } else {
        // Unset (exit code 1) or error: default to enabled
        true
    }
}

/// Return the repository root (`git rev-parse --show-toplevel`).
pub async fn repo_root() -> Result<PathBuf> {
    let path = git_output(&["rev-parse", "--show-toplevel"]).await?;
    Ok(PathBuf::from(path))
}

/// Return the repository root for a given working directory.
///
/// Runs `git -C <dir> rev-parse --show-toplevel`. This handles the case
/// where `dir` is a subdirectory of the repo.
pub(crate) async fn repo_root_at(dir: &Path) -> Result<PathBuf> {
    let output = run_git_output_at(Some(dir), &["rev-parse", "--show-toplevel"], &[])
        .await
        .context("failed to execute git rev-parse --show-toplevel")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse --show-toplevel failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(PathBuf::from(stdout.trim()))
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RepoRootResolutionDiagnostics {
    pub requested_cwd: PathBuf,
    pub cwd_exists: bool,
    pub direct_error: Option<String>,
    pub nearest_existing_ancestor: Option<PathBuf>,
    pub ancestor_error: Option<String>,
    pub candidate_repo_names: Vec<String>,
    pub candidate_owner_repo_roots: Vec<PathBuf>,
    pub matched_worktree_owner_repo_root: Option<PathBuf>,
    pub matched_worktree_path: Option<PathBuf>,
    pub alternative_repo_roots: Vec<PathBuf>,
    pub resolved_via: Option<&'static str>,
}

#[derive(Debug, Clone)]
pub(crate) struct RepoRootResolution {
    pub repo_root: PathBuf,
    pub diagnostics: RepoRootResolutionDiagnostics,
}

#[derive(Debug, Clone)]
struct WorktreeEntry {
    path: PathBuf,
}

pub(crate) async fn resolve_repo_root_with_fallbacks(
    cwd: &Path,
) -> std::result::Result<RepoRootResolution, RepoRootResolutionDiagnostics> {
    let mut diagnostics = RepoRootResolutionDiagnostics {
        requested_cwd: cwd.to_path_buf(),
        cwd_exists: tokio::fs::try_exists(cwd).await.unwrap_or(false),
        ..RepoRootResolutionDiagnostics::default()
    };

    match repo_root_at(cwd).await {
        Ok(repo_root) => {
            diagnostics.resolved_via = Some("cwd");
            diagnostics.alternative_repo_roots = alternative_repo_roots_for_repo(&repo_root).await;
            return Ok(RepoRootResolution {
                repo_root,
                diagnostics,
            });
        }
        Err(err) => diagnostics.direct_error = Some(err.to_string()),
    }

    if let Some(existing_ancestor) = nearest_existing_ancestor(cwd).await {
        diagnostics.nearest_existing_ancestor = Some(existing_ancestor.clone());
        match repo_root_at(&existing_ancestor).await {
            Ok(repo_root) => {
                diagnostics.resolved_via = Some("existing_ancestor");
                diagnostics.alternative_repo_roots =
                    alternative_repo_roots_for_repo(&repo_root).await;
                return Ok(RepoRootResolution {
                    repo_root,
                    diagnostics,
                });
            }
            Err(err) => diagnostics.ancestor_error = Some(err.to_string()),
        }
    }

    let candidate_repo_names = worktree_repo_name_candidates(cwd);
    diagnostics.candidate_repo_names = candidate_repo_names.clone();
    let candidate_owner_repo_roots = candidate_owner_repo_roots(cwd, &candidate_repo_names).await;
    diagnostics.candidate_owner_repo_roots = candidate_owner_repo_roots.clone();

    for candidate_repo_root in candidate_owner_repo_roots {
        let worktrees = match worktree_list_at(&candidate_repo_root).await {
            Ok(worktrees) => worktrees,
            Err(_) => continue,
        };
        if let Some(entry) = worktrees
            .into_iter()
            .find(|entry| cwd == entry.path || cwd.starts_with(&entry.path))
        {
            diagnostics.resolved_via = Some("worktree_owner_repo");
            diagnostics.matched_worktree_owner_repo_root = Some(candidate_repo_root.clone());
            diagnostics.matched_worktree_path = Some(entry.path);
            diagnostics.alternative_repo_roots =
                alternative_repo_roots_for_repo(&candidate_repo_root).await;
            return Ok(RepoRootResolution {
                repo_root: candidate_repo_root,
                diagnostics,
            });
        }
    }

    Err(diagnostics)
}

async fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = Some(path);
    while let Some(candidate) = current {
        if tokio::fs::try_exists(candidate).await.unwrap_or(false) {
            return Some(candidate.to_path_buf());
        }
        current = candidate.parent();
    }
    None
}

async fn git_common_dir_at(repo: &Path) -> Result<Option<PathBuf>> {
    let output = run_git_output_at(
        Some(repo),
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        &[],
    )
    .await
    .context("failed to execute git rev-parse --git-common-dir")?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    let common_dir = stdout.trim();
    if common_dir.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(common_dir)))
}

async fn alternative_repo_roots_for_repo(repo: &Path) -> Vec<PathBuf> {
    let mut roots = BTreeSet::new();
    roots.insert(repo.to_path_buf());

    if let Ok(Some(common_dir)) = git_common_dir_at(repo).await
        && common_dir.file_name().and_then(|name| name.to_str()) == Some(".git")
        && let Some(main_repo_root) = common_dir.parent()
    {
        roots.insert(main_repo_root.to_path_buf());
    }

    if let Ok(worktrees) = worktree_list_at(repo).await {
        for worktree in worktrees {
            roots.insert(worktree.path);
        }
    }

    roots.into_iter().filter(|path| path != repo).collect()
}

async fn worktree_list_at(repo: &Path) -> Result<Vec<WorktreeEntry>> {
    let output = run_git_output_at(Some(repo), &["worktree", "list", "--porcelain"], &[])
        .await
        .context("failed to execute git worktree list --porcelain")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git worktree list --porcelain failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    let mut entries = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    for line in stdout.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            if let Some(path) = current_path.take() {
                entries.push(WorktreeEntry { path });
            }
            current_path = Some(PathBuf::from(path.trim()));
        } else if line.trim().is_empty()
            && let Some(path) = current_path.take()
        {
            entries.push(WorktreeEntry { path });
        }
    }
    if let Some(path) = current_path.take() {
        entries.push(WorktreeEntry { path });
    }
    Ok(entries)
}

fn worktree_repo_name_candidates(cwd: &Path) -> Vec<String> {
    let mut names = Vec::new();
    let segments = cwd
        .iter()
        .map(|segment| segment.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    for (idx, segment) in segments.iter().enumerate() {
        if !segment.to_ascii_lowercase().contains("worktree") {
            continue;
        }
        let after = segments.get(idx + 1).cloned();
        let after_after = segments.get(idx + 2).cloned();
        if let Some(candidate) = after.clone().filter(|value| is_repo_name_candidate(value)) {
            names.push(candidate);
        } else if let Some(candidate) = after_after.filter(|value| is_repo_name_candidate(value)) {
            names.push(candidate);
        }
    }
    let mut seen = BTreeSet::new();
    names
        .into_iter()
        .filter(|name| seen.insert(name.to_ascii_lowercase()))
        .collect()
}

fn is_repo_name_candidate(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let lowercase = value.to_ascii_lowercase();
    if lowercase == "worktrees" || lowercase.ends_with("worktrees") {
        return false;
    }
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }
    true
}

async fn candidate_owner_repo_roots(cwd: &Path, repo_names: &[String]) -> Vec<PathBuf> {
    let mut candidates = BTreeSet::new();
    let Some(home) = crate::agents::home_dir() else {
        return Vec::new();
    };

    // Only probe `~/Desktop` once the user has been explicitly asked for that
    // permission (either on first install or via `cadence permissions
    // request-desktop`). This prevents re-runs on existing machines from
    // surfacing an unexpected macOS TCC prompt.
    let include_desktop = crate::permissions::desktop_access_requested().await;

    let mut parents: Vec<PathBuf> = vec![
        home.join("dev"),
        home.join("Documents").join("GitHub"),
        home.join("src"),
        home.join("code"),
        home.join("Projects"),
        home.join("workspaces"),
    ];
    if include_desktop {
        parents.push(home.join("Desktop"));
        parents.push(home.join("Desktop").join("GitHub"));
    }

    for repo_name in repo_names {
        for parent in &parents {
            let candidate = parent.join(repo_name);
            if tokio::fs::try_exists(candidate.join(".git"))
                .await
                .unwrap_or(false)
            {
                candidates.insert(candidate);
            }
        }
    }

    if let Some(existing_ancestor) = nearest_existing_ancestor(cwd).await {
        let mut current = Some(existing_ancestor.as_path());
        while let Some(candidate) = current {
            if tokio::fs::try_exists(candidate.join(".git"))
                .await
                .unwrap_or(false)
            {
                candidates.insert(candidate.to_path_buf());
            }
            current = candidate.parent();
        }
    }

    candidates.into_iter().collect()
}

/// Return the current branch name for a repo, if HEAD is attached.
pub(crate) async fn current_branch_at(repo: &Path) -> Result<Option<String>> {
    let output = run_git_output_at(
        Some(repo),
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
        &[],
    )
    .await
    .context("failed to execute git symbolic-ref")?;
    if !output.status.success() {
        return Ok(None);
    }
    let branch = String::from_utf8(output.stdout).context("branch output was not valid UTF-8")?;
    let branch = branch.trim();
    if branch.is_empty() {
        Ok(None)
    } else {
        Ok(Some(branch.to_string()))
    }
}

/// Return the current HEAD commit SHA for a repo.
pub(crate) async fn head_sha_at(repo: &Path) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["rev-parse", "HEAD"], &[])
        .await
        .context("failed to execute git rev-parse HEAD")?;

    if !output.status.success() {
        return Ok(None);
    }

    let sha = String::from_utf8(output.stdout).context("head sha output was not valid UTF-8")?;
    let sha = sha.trim();
    if sha.is_empty() {
        Ok(None)
    } else {
        Ok(Some(sha.to_string()))
    }
}

/// Push the AI-session notes ref to the provided remote.
///
/// Note: Production push paths now use inline force-with-lease pushes
/// (see `push.rs`). This function is retained for test use.
#[cfg(test)]
pub async fn push_notes(remote: &str) -> Result<()> {
    push_notes_at(None, remote).await
}

/// Push the AI-session notes ref to the provided remote within a test repository.
#[cfg(test)]
pub async fn push_notes_at(repo: Option<&Path>, remote: &str) -> Result<()> {
    let output = run_git_output_at(
        repo,
        &["push", "--no-verify", remote, NOTES_REF],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .await
    .context("failed to execute git push")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git push notes failed: {}", stderr.trim());
    }
    Ok(())
}

/// Check whether the repository has at least one configured remote.
///
/// Returns `Ok(false)` if `git remote` fails (e.g., not in a git repository)
/// rather than propagating the error. This matches the `git_succeeds` pattern
/// used by `note_exists` and makes the function safe to call defensively.
#[cfg(test)]
pub async fn has_upstream() -> Result<bool> {
    match git_output(&["remote"]).await {
        Ok(remotes) => Ok(!remotes.is_empty()),
        Err(_) => Ok(false),
    }
}

/// Resolve the push remote for the current repository.
///
/// Resolution order:
/// 1) branch.<name>.pushRemote
/// 2) remote.pushDefault
/// 3) branch.<name>.remote
/// 4) if exactly one remote exists, use it
/// 5) otherwise return None
///
/// Returns `Ok(None)` when HEAD is detached or the remote is "."/empty.
#[cfg(test)]
pub async fn resolve_push_remote() -> Result<Option<String>> {
    let output = run_git_output_at(None, &["symbolic-ref", "--quiet", "--short", "HEAD"], &[])
        .await
        .context("failed to execute git symbolic-ref")?;

    if !output.status.success() {
        return Ok(None);
    }

    let branch =
        String::from_utf8(output.stdout).context("git symbolic-ref output was not valid UTF-8")?;
    let branch = branch.trim();
    if branch.is_empty() {
        return Ok(None);
    }

    let push_remote_key = format!("branch.{}.pushRemote", branch);
    if let Ok(Some(remote)) = config_get(&push_remote_key).await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    if let Ok(Some(remote)) = config_get("remote.pushDefault").await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let branch_remote_key = format!("branch.{}.remote", branch);
    if let Ok(Some(remote)) = config_get(&branch_remote_key).await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let remotes = match git_output(&["remote"]).await {
        Ok(list) => list,
        Err(_) => return Ok(None),
    };
    let mut names = remotes.lines().filter(|r| !r.is_empty());
    let first = names.next();
    if first.is_none() || names.next().is_some() {
        return Ok(None);
    }

    Ok(first.map(|s| s.to_string()))
}

/// Return the URL for a named remote in a specific repository (if any).
pub async fn remote_url_at(repo: &Path, remote: &str) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["remote", "get-url", remote], &[])
        .await
        .context("failed to execute git remote get-url")?;

    if !output.status.success() {
        return Ok(None);
    }

    let url = String::from_utf8(output.stdout)
        .context("git remote get-url output was not valid UTF-8")?;
    Ok(Some(url.trim().to_string()))
}

/// Return all configured remote URLs for a repository.
pub async fn remote_urls_at(repo: &Path) -> Result<Vec<String>> {
    let output = run_git_output_at(Some(repo), &["remote"], &[])
        .await
        .context("failed to execute git remote")?;
    if !output.status.success() {
        return Ok(Vec::new());
    }

    let remotes =
        String::from_utf8(output.stdout).context("git remote output was not valid UTF-8")?;
    let mut urls = BTreeSet::new();
    for remote in remotes.lines().filter(|name| !name.trim().is_empty()) {
        if let Some(url) = remote_url_at(repo, remote).await?
            && !url.trim().is_empty()
        {
            urls.insert(url);
        }
    }
    Ok(urls.into_iter().collect())
}

/// Return the canonical repo root plus linked worktree roots for a repository.
pub async fn repo_and_worktree_roots_at(repo: &Path) -> Vec<String> {
    let mut roots = Vec::with_capacity(1);
    roots.push(repo.to_string_lossy().to_string());
    roots.extend(
        alternative_repo_roots_for_repo(repo)
            .await
            .into_iter()
            .map(|path| path.to_string_lossy().to_string()),
    );
    roots.sort();
    roots.dedup();
    roots
}

/// Resolve the push remote for a specific repository.
pub async fn resolve_push_remote_at(repo: &Path) -> Result<Option<String>> {
    let output = run_git_output_at(
        Some(repo),
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
        &[],
    )
    .await
    .context("failed to execute git symbolic-ref")?;

    if !output.status.success() {
        return Ok(None);
    }

    let branch =
        String::from_utf8(output.stdout).context("git symbolic-ref output was not valid UTF-8")?;
    let branch = branch.trim();
    if branch.is_empty() {
        return Ok(None);
    }

    let push_remote_key = format!("branch.{}.pushRemote", branch);
    if let Ok(Some(remote)) = config_get_at(repo, &push_remote_key).await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    if let Ok(Some(remote)) = config_get_at(repo, "remote.pushDefault").await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let branch_remote_key = format!("branch.{}.remote", branch);
    if let Ok(Some(remote)) = config_get_at(repo, &branch_remote_key).await
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let remotes = match git_output_in(repo, &["remote"]).await {
        Ok(list) => list,
        Err(_) => return Ok(None),
    };
    let mut names = remotes.lines().filter(|r| !r.is_empty());
    let first = names.next();
    if first.is_none() || names.next().is_some() {
        return Ok(None);
    }

    Ok(first.map(|s| s.to_string()))
}

/// Return the URL of the first configured remote for the repo at `repo`.
///
/// Returns `None` if no remotes are configured. Returns an error only if
/// the git commands themselves fail unexpectedly.
pub(crate) async fn first_remote_url_at(repo: &Path) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["remote"], &[])
        .await
        .context("failed to execute git remote")?;

    if !output.status.success() {
        return Ok(None);
    }

    let remotes =
        String::from_utf8(output.stdout).context("git remote output was not valid UTF-8")?;
    let first = match remotes.lines().next() {
        Some(name) if !name.is_empty() => name,
        _ => return Ok(None),
    };

    let url_output = run_git_output_at(Some(repo), &["remote", "get-url", first], &[])
        .await
        .context("failed to execute git remote get-url")?;

    if !url_output.status.success() {
        return Ok(None);
    }

    let url = String::from_utf8(url_output.stdout)
        .context("git remote get-url output was not valid UTF-8")?;
    Ok(Some(url.trim().to_string()))
}

/// Resolve the best available remote URL for uploads.
///
/// Prefers the configured push remote, then falls back to `origin`, then to the
/// first configured remote URL. This keeps uploads working in repos where the
/// current branch has not been wired to a remote yet.
pub(crate) async fn preferred_remote_url_at(repo: &Path) -> Result<Option<String>> {
    if let Some(remote) = resolve_push_remote_at(repo).await?
        && let Some(url) = remote_url_at(repo, &remote).await?
        && !url.trim().is_empty()
    {
        return Ok(Some(url));
    }

    if let Some(url) = remote_url_at(repo, "origin").await?
        && !url.trim().is_empty()
    {
        return Ok(Some(url));
    }

    Ok(first_remote_url_at(repo)
        .await?
        .filter(|url| !url.trim().is_empty()))
}

/// Extract owner/org from ALL remote URLs.
///
/// Returns a deduplicated list of org names extracted from all configured
/// remotes. Deduplication is case-insensitive (e.g., `My-Org` and `my-org`
/// from different remotes are considered the same org; only the first
/// encountered variant is kept). This is used for org filtering: "Extract
/// owner from **all** Git remotes. If **any** remote matches org, allowed."
/// (PLAN.md)
///
/// Returns an empty Vec if no remotes are configured or no URLs can be parsed.
#[cfg(test)]
pub async fn remote_orgs() -> Result<Vec<String>> {
    let remotes = git_output(&["remote"]).await?;
    let mut orgs = Vec::new();

    for remote_name in remotes.lines() {
        if remote_name.is_empty() {
            continue;
        }
        if let Ok(url) = git_output(&["remote", "get-url", remote_name]).await
            && let Some(org) = parse_org_from_url(&url)
            && !orgs
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&org))
        {
            orgs.push(org);
        }
    }

    Ok(orgs)
}

/// Extract owner/org from ALL remote URLs in a specific repository.
///
/// Returns a deduplicated list of org names extracted from all configured
/// remotes. Deduplication is case-insensitive.
pub async fn remote_orgs_at(repo: &Path) -> Result<Vec<String>> {
    let remotes = git_output_in(repo, &["remote"]).await?;
    let mut orgs = Vec::new();

    for remote_name in remotes.lines() {
        if remote_name.is_empty() {
            continue;
        }
        if let Ok(url) = git_output_in(repo, &["remote", "get-url", remote_name]).await
            && let Some(org) = parse_org_from_url(&url)
            && !orgs
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&org))
        {
            orgs.push(org);
        }
    }

    Ok(orgs)
}

/// Parse the owner/org segment from a git remote URL.
///
/// This is a pure function extracted for testability.
pub fn parse_org_from_url(url: &str) -> Option<String> {
    // SSH: git@github.com:org/repo.git
    if let Some(after_colon) = url.strip_prefix("git@").and_then(|s| {
        // Find the colon that separates host from path
        s.split_once(':').map(|(_, path)| path)
    }) {
        let org = after_colon.split('/').next()?;
        if org.is_empty() {
            return None;
        }
        return Some(org.to_string());
    }

    // HTTPS: https://github.com/org/repo.git
    if url.starts_with("https://") || url.starts_with("http://") {
        // Split on '/' and take the path segments after the host
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let mut segments = without_scheme.split('/');
        let _host = segments.next(); // e.g. "github.com"
        let org = segments.next()?;
        if org.is_empty() {
            return None;
        }
        return Some(org.to_string());
    }

    None
}

/// Read a git config value. Returns `Ok(None)` if the key is not set.
///
/// Distinguishes exit code 1 (key not set) from other exit codes (e.g., 2 for
/// invalid config file) to avoid silently swallowing genuine errors.
pub async fn config_get(key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(None, &["config", "--get", key], &[])
        .await
        .context("failed to execute git config --get")?;

    if !output.status.success() {
        // Exit code 1 means the key is not set — that is not an error.
        // Any other non-zero exit (e.g., code 2 for corrupt config) is a real error.
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Read a git config value from a specific repo. Returns `Ok(None)` if unset.
pub async fn config_get_at(repo: &Path, key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["config", "--get", key], &[])
        .await
        .context("failed to execute git config --get")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Read a repo-local git config value (ignores global/system). Returns `Ok(None)` if unset.
pub async fn config_get_local_at(repo: &Path, key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["config", "--local", "--get", key], &[])
        .await
        .context("failed to execute git config --local --get")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --local --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Read a git config value from global scope. Returns `Ok(None)` if the key is not set.
///
/// Uses `--global` flag to read only the global config, not repo-local.
/// This is used for settings like `ai.cadence.org` that are set at install time.
pub async fn config_get_global(key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(None, &["config", "--global", "--get", key], &[])
        .await
        .context("failed to execute git config --global --get")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --global --get {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
        }
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Check org filter for a specific repository. If a global org is configured,
/// verify that at least one remote matches that org (case-insensitive).
pub async fn repo_matches_org_filter(repo: &Path) -> Result<bool> {
    let configured_org = match config_get_global("ai.cadence.org").await {
        Ok(Some(org)) => org,
        _ => return Ok(true),
    };

    let remote_orgs = remote_orgs_at(repo).await?;
    Ok(remote_orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(&configured_org)))
}

/// Write a git config value (repo-local scope).
#[cfg(test)]
pub async fn config_set(key: &str, value: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", key, value], &[])
        .await
        .context("failed to execute git config set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config set failed: {}", stderr.trim());
    }
    Ok(())
}

/// Write a git config value in global scope (`--global`).
///
/// Used by the `install` subcommand to persist settings like
/// `core.hooksPath` and `ai.cadence.org` globally.
pub async fn config_set_global(key: &str, value: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", "--global", key, value], &[])
        .await
        .context("failed to execute git config --global set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config --global set failed: {}", stderr.trim());
    }
    Ok(())
}

/// Unset a global git config key.
///
/// Uses `--unset-all` so repeated keys are removed. Returns `Ok(())` if the
/// key does not exist (git exits with code 5 or 1 in that case).
pub async fn config_unset_global(key: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", "--global", "--unset-all", key], &[])
        .await
        .context("failed to execute git config --global --unset-all")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        // Exit code 5 = key not found, 1 = section/key invalid — both are fine for unset
        if code != 5 && code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git config --global --unset-all failed: {}", stderr.trim());
        }
    }
    Ok(())
}

/// Unset a local git config key at a specific repo path.
///
/// Uses `--unset-all` so repeated keys are removed. Returns `Ok(())` if the
/// key does not exist.
pub async fn config_unset_local_at(repo: &Path, key: &str) -> Result<()> {
    let output = run_git_output_at(Some(repo), &["config", "--local", "--unset-all", key], &[])
        .await
        .context("failed to execute git config --local --unset-all")?;

    if !output.status.success() {
        let code = output.status.code().unwrap_or(-1);
        if code != 5 && code != 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git config --local --unset-all failed: {}", stderr.trim());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var(key).ok(),
            }
        }

        fn set_path(&self, value: &std::path::Path) {
            unsafe { std::env::set_var(self.key, value) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    fn portable_test_path(path: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            let raw = path.as_os_str().to_string_lossy();
            if let Some(stripped) = raw.strip_prefix(r"\\?\") {
                return PathBuf::from(stripped);
            }
        }

        path.to_path_buf()
    }

    async fn canonical_test_path(path: &Path) -> PathBuf {
        let canonical = tokio::fs::canonicalize(path)
            .await
            .unwrap_or_else(|_| path.to_path_buf());
        portable_test_path(&canonical)
    }

    /// Helper: create a temporary git repo with one commit.
    /// Returns the TempDir (which cleans up on drop) and sets the
    /// working directory for the test by returning a guard.
    ///
    /// Note: since we cannot change the process-wide CWD safely in
    /// parallel tests, all git commands in tests must use `-C <path>`.
    /// We provide a `git_in` helper for this.
    async fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        // git init
        run_git(path, &["init"]).await;
        // Set required user config for commits
        run_git(path, &["config", "user.email", "test@test.com"]).await;
        run_git(path, &["config", "user.name", "Test User"]).await;
        // Override hooksPath to prevent the global post-commit hook from firing
        run_git(path, &["config", "core.hooksPath", "/dev/null"]).await;
        // Create an initial commit
        tokio::fs::write(path.join("README.md"), "hello")
            .await
            .unwrap();
        run_git(path, &["add", "README.md"]).await;
        run_git(path, &["commit", "-m", "initial commit"]).await;

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    async fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = run_git_output_at(Some(dir), args, &[])
            .await
            .expect("failed to run git");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {:?} failed: {}", args, stderr);
        }
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// Run one of our git module functions inside a specific directory
    /// by temporarily overriding GIT_DIR behaviour via `-C`.
    /// Since our public functions don't take a path arg (they rely on cwd),
    /// we use a wrapper approach: spawn a git command with `-C`.
    async fn git_output_in(dir: &std::path::Path, args: &[&str]) -> Result<String> {
        let output = run_git_output_at(Some(dir), args, &[])
            .await
            .context("failed to execute git")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }

        let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
        Ok(stdout.trim().to_string())
    }

    // -----------------------------------------------------------------------
    // repo_root — tested via direct git command in temp dir
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_repo_root() {
        let dir = init_temp_repo().await;
        let root = git_output_in(dir.path(), &["rev-parse", "--show-toplevel"])
            .await
            .unwrap();
        let root_path = PathBuf::from(&root);
        // The root should be the temp dir (possibly canonicalized)
        assert!(root_path.exists());
        // The root should contain the README we created
        assert!(root_path.join("README.md").exists());
    }

    #[tokio::test]
    async fn test_resolve_repo_root_with_fallbacks_uses_existing_ancestor() {
        let dir = init_temp_repo().await;
        let missing = dir.path().join("missing").join("nested");

        let resolution = resolve_repo_root_with_fallbacks(&missing)
            .await
            .expect("resolve repo root with fallbacks");

        assert_eq!(
            resolution
                .repo_root
                .canonicalize()
                .expect("canonical repo root"),
            dir.path().canonicalize().expect("canonical temp repo")
        );
        assert_eq!(
            resolution.diagnostics.resolved_via,
            Some("existing_ancestor")
        );
        assert_eq!(
            resolution.diagnostics.nearest_existing_ancestor,
            Some(dir.path().to_path_buf())
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_repo_root_with_fallbacks_uses_worktree_owner_repo() {
        let home = TempDir::new().expect("home tempdir");
        let canonical_home = canonical_test_path(home.path()).await;
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(&canonical_home);

        let repo_root = canonical_home.join("dev").join("cadence-cli");
        tokio::fs::create_dir_all(repo_root.parent().expect("repo parent"))
            .await
            .expect("create repo parent");
        run_git(
            repo_root.parent().expect("repo parent"),
            &["init", "cadence-cli"],
        )
        .await;
        run_git(&repo_root, &["config", "user.email", "test@test.com"]).await;
        run_git(&repo_root, &["config", "user.name", "Test User"]).await;
        run_git(&repo_root, &["config", "core.hooksPath", "/dev/null"]).await;
        tokio::fs::write(repo_root.join("README.md"), "hello")
            .await
            .expect("write readme");
        run_git(&repo_root, &["add", "README.md"]).await;
        run_git(&repo_root, &["commit", "-m", "initial commit"]).await;
        run_git(&repo_root, &["branch", "feature"]).await;

        let worktree_path = canonical_home
            .join(".claude-worktrees")
            .join("cadence-cli")
            .join("vigorous-engelbart");
        tokio::fs::create_dir_all(worktree_path.parent().expect("worktree parent"))
            .await
            .expect("create worktree parent");
        run_git(
            &repo_root,
            &[
                "worktree",
                "add",
                worktree_path.to_str().expect("worktree path utf8"),
                "feature",
            ],
        )
        .await;

        tokio::fs::remove_dir_all(&worktree_path)
            .await
            .expect("remove worktree directory");

        let resolution = resolve_repo_root_with_fallbacks(&worktree_path)
            .await
            .expect("resolve repo root via worktree owner");

        assert_eq!(
            resolution
                .repo_root
                .canonicalize()
                .expect("canonical repo root"),
            repo_root.canonicalize().expect("canonical main repo")
        );
        assert_eq!(
            resolution.diagnostics.resolved_via,
            Some("worktree_owner_repo")
        );
        assert_eq!(
            resolution.diagnostics.candidate_repo_names,
            vec!["cadence-cli".to_string()]
        );
        assert_eq!(
            resolution.diagnostics.matched_worktree_owner_repo_root,
            Some(repo_root.clone())
        );
        assert_eq!(
            resolution.diagnostics.matched_worktree_path,
            Some(worktree_path.clone())
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_repo_root_with_fallbacks_uses_worktree_owner_repo_for_missing_subdir() {
        let home = TempDir::new().expect("home tempdir");
        let canonical_home = canonical_test_path(home.path()).await;
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(&canonical_home);

        let repo_root = canonical_home.join("dev").join("cadence-cli");
        tokio::fs::create_dir_all(repo_root.parent().expect("repo parent"))
            .await
            .expect("create repo parent");
        run_git(
            repo_root.parent().expect("repo parent"),
            &["init", "cadence-cli"],
        )
        .await;
        run_git(&repo_root, &["config", "user.email", "test@test.com"]).await;
        run_git(&repo_root, &["config", "user.name", "Test User"]).await;
        run_git(&repo_root, &["config", "core.hooksPath", "/dev/null"]).await;
        tokio::fs::write(repo_root.join("README.md"), "hello")
            .await
            .expect("write readme");
        run_git(&repo_root, &["add", "README.md"]).await;
        run_git(&repo_root, &["commit", "-m", "initial commit"]).await;
        run_git(&repo_root, &["branch", "feature"]).await;

        let worktree_path = canonical_home
            .join(".claude-worktrees")
            .join("cadence-cli")
            .join("vigorous-engelbart");
        tokio::fs::create_dir_all(worktree_path.parent().expect("worktree parent"))
            .await
            .expect("create worktree parent");
        run_git(
            &repo_root,
            &[
                "worktree",
                "add",
                worktree_path.to_str().expect("worktree path utf8"),
                "feature",
            ],
        )
        .await;

        tokio::fs::remove_dir_all(&worktree_path)
            .await
            .expect("remove worktree directory");

        let missing_subdir = worktree_path.join("src").join("nested");
        let resolution = resolve_repo_root_with_fallbacks(&missing_subdir)
            .await
            .expect("resolve repo root via worktree owner");

        assert_eq!(
            resolution
                .repo_root
                .canonicalize()
                .expect("canonical repo root"),
            repo_root.canonicalize().expect("canonical main repo")
        );
        assert_eq!(
            resolution.diagnostics.resolved_via,
            Some("worktree_owner_repo")
        );
        assert_eq!(
            resolution.diagnostics.matched_worktree_owner_repo_root,
            Some(repo_root.clone())
        );
        assert_eq!(
            resolution.diagnostics.matched_worktree_path,
            Some(worktree_path.clone())
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_alternative_repo_roots_include_linked_worktrees() {
        let dir = init_temp_repo().await;
        run_git(dir.path(), &["branch", "feature"]).await;
        let worktree_root = TempDir::new().expect("worktree tempdir");
        let canonical_worktree_root = canonical_test_path(worktree_root.path()).await;
        let worktree_path = canonical_worktree_root.join("feature-worktree");
        run_git(
            dir.path(),
            &[
                "worktree",
                "add",
                worktree_path.to_str().expect("worktree path utf8"),
                "feature",
            ],
        )
        .await;

        let alternatives = alternative_repo_roots_for_repo(dir.path()).await;
        let canonical_worktree_path = tokio::fs::canonicalize(&worktree_path)
            .await
            .expect("canonicalize linked worktree");

        assert!(alternatives.into_iter().any(|candidate| {
            std::fs::canonicalize(candidate)
                .map(|path| path == canonical_worktree_path)
                .unwrap_or(false)
        }));
    }

    #[test]
    fn test_worktree_repo_name_candidates_cover_common_agent_layouts() {
        let claude = worktree_repo_name_candidates(Path::new(
            "/Users/zack/.claude-worktrees/cadence-cli/vigorous-engelbart",
        ));
        assert_eq!(claude, vec!["cadence-cli".to_string()]);

        let codex =
            worktree_repo_name_candidates(Path::new("/Users/zack/.codex/worktrees/3139/cadence"));
        assert_eq!(codex, vec!["cadence".to_string()]);
    }

    // -----------------------------------------------------------------------
    // head_hash
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_head_hash() {
        let dir = init_temp_repo().await;
        let hash = git_output_in(dir.path(), &["rev-parse", "HEAD"])
            .await
            .unwrap();
        // Full SHA is 40 hex characters
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // head_timestamp
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_head_timestamp() {
        let dir = init_temp_repo().await;
        let ts_str = git_output_in(dir.path(), &["show", "-s", "--format=%ct", "HEAD"])
            .await
            .unwrap();
        let ts: i64 = ts_str.parse().unwrap();
        // Should be a reasonable Unix timestamp (after 2020)
        assert!(ts > 1_577_836_800);
    }

    // -----------------------------------------------------------------------
    // has_upstream
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_has_upstream_false_when_no_remote() {
        let dir = init_temp_repo().await;
        let remotes = git_output_in(dir.path(), &["remote"]).await.unwrap();
        assert!(remotes.is_empty());
    }

    #[tokio::test]
    async fn test_has_upstream_true_when_remote_added() {
        let dir = init_temp_repo().await;
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        )
        .await;
        let remotes = git_output_in(path, &["remote"]).await.unwrap();
        assert!(!remotes.is_empty());
    }

    // -----------------------------------------------------------------------
    // remote_org (via parse_org_from_url — pure function)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_org_from_ssh_url() {
        let org = parse_org_from_url("git@github.com:my-org/my-repo.git");
        assert_eq!(org, Some("my-org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_https_url() {
        let org = parse_org_from_url("https://github.com/other-org/some-repo.git");
        assert_eq!(org, Some("other-org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_http_url() {
        let org = parse_org_from_url("http://github.com/http-org/repo.git");
        assert_eq!(org, Some("http-org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_unknown_url() {
        let org = parse_org_from_url("svn://example.com/repo");
        assert_eq!(org, None);
    }

    #[tokio::test]
    async fn test_parse_org_empty_url() {
        let org = parse_org_from_url("");
        assert_eq!(org, None);
    }

    // -----------------------------------------------------------------------
    // parse_org_from_url (integration test with temp repo)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_org_from_url_integration() {
        let dir = init_temp_repo().await;
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:acme-corp/widgets.git",
            ],
        )
        .await;
        let url = git_output_in(path, &["remote", "get-url", "origin"])
            .await
            .unwrap();
        let org = parse_org_from_url(&url);
        assert_eq!(org, Some("acme-corp".to_string()));
    }

    // -----------------------------------------------------------------------
    // config_get + config_set
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_config_get_missing_key() {
        let dir = init_temp_repo().await;
        let path = dir.path();
        let output = run_git_output_at(
            Some(path),
            &["config", "--get", "ai.cadence.nonexistent"],
            &[],
        )
        .await
        .unwrap();
        // Should exit non-zero (key not set)
        assert!(!output.status.success());
    }

    #[tokio::test]
    async fn test_config_set_then_get() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        // Set a config value
        run_git(path, &["config", "ai.cadence.enabled", "true"]).await;

        // Read it back
        let value = git_output_in(path, &["config", "--get", "ai.cadence.enabled"])
            .await
            .unwrap();
        assert_eq!(value, "true");
    }

    #[tokio::test]
    async fn test_config_overwrite() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        run_git(path, &["config", "ai.cadence.org", "first-org"]).await;
        run_git(path, &["config", "ai.cadence.org", "second-org"]).await;

        let value = git_output_in(path, &["config", "--get", "ai.cadence.org"])
            .await
            .unwrap();
        assert_eq!(value, "second-org");
    }

    // -----------------------------------------------------------------------
    // Multiple commits — verify head_hash changes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_head_hash_changes_after_new_commit() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        let hash1 = run_git(path, &["rev-parse", "HEAD"]).await;

        // Make another commit
        tokio::fs::write(path.join("file2.txt"), "content")
            .await
            .unwrap();
        run_git(path, &["add", "file2.txt"]).await;
        run_git(path, &["commit", "-m", "second commit"]).await;

        let hash2 = run_git(path, &["rev-parse", "HEAD"]).await;

        assert_ne!(hash1, hash2);
        assert_eq!(hash2.len(), 40);
    }

    // -----------------------------------------------------------------------
    // parse_org_from_url — edge cases
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_org_from_url_https_with_trailing_slash() {
        // Trailing slash after org — org segment should still parse
        let org = parse_org_from_url("https://github.com/org/");
        assert_eq!(org, Some("org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_url_https_host_only() {
        // No org segment after host
        let org = parse_org_from_url("https://github.com/");
        assert_eq!(org, None);
    }

    #[tokio::test]
    async fn test_parse_org_from_url_https_host_no_trailing_slash() {
        let org = parse_org_from_url("https://github.com");
        assert_eq!(org, None);
    }

    #[tokio::test]
    async fn test_parse_org_from_url_ssh_nested_path() {
        // SSH with nested paths — org is the first segment after the colon
        let org = parse_org_from_url("git@github.com:org/sub/repo.git");
        assert_eq!(org, Some("org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_url_https_with_port() {
        let org = parse_org_from_url("https://github.com:443/org/repo.git");
        // The host segment is "github.com:443", org is next path segment
        assert_eq!(org, Some("org".to_string()));
    }

    #[tokio::test]
    async fn test_parse_org_from_url_https_with_auth() {
        // URL with authentication credentials embedded
        let org = parse_org_from_url("https://user:pass@github.com/org/repo.git");
        // "user:pass@github.com" is treated as host, "org" is the org
        assert_eq!(org, Some("org".to_string()));
    }

    // -----------------------------------------------------------------------
    // Public API tests — use set_current_dir, must run serially
    //
    // These tests exercise the actual Rust wrapper functions against temp
    // repos to ensure the wrappers (argument order, trim, error mapping)
    // work correctly, not just the underlying git commands.
    // -----------------------------------------------------------------------

    /// Helper: create a temp repo and chdir into it. Returns the TempDir
    /// (must be kept alive to prevent cleanup) and the original cwd for
    /// restoration.
    async fn enter_temp_repo() -> (TempDir, PathBuf) {
        let original_cwd = std::env::current_dir().expect("failed to get cwd");
        let dir = init_temp_repo().await;
        std::env::set_current_dir(dir.path()).expect("failed to chdir into temp repo");
        (dir, original_cwd)
    }

    #[tokio::test]
    #[serial]
    async fn test_api_repo_root() {
        let (_dir, original_cwd) = enter_temp_repo().await;
        let root = repo_root().await.expect("repo_root failed");
        assert!(root.join("README.md").exists());
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_api_has_upstream_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo().await;
        assert!(!has_upstream().await.expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_api_has_upstream_with_remote() {
        let (dir, original_cwd) = enter_temp_repo().await;
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        )
        .await;
        assert!(has_upstream().await.expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // resolve_push_remote
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn test_resolve_push_remote_prefers_branch_push_remote() {
        let (dir, original_cwd) = enter_temp_repo().await;
        let branch = run_git(dir.path(), &["symbolic-ref", "--short", "HEAD"]).await;

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/example/upstream.git",
            ],
        )
        .await;
        run_git(
            dir.path(),
            &[
                "config",
                &format!("branch.{}.pushRemote", branch),
                "upstream",
            ],
        )
        .await;

        let resolved = resolve_push_remote()
            .await
            .expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("upstream".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_push_remote_uses_push_default() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "fork",
                "https://github.com/example/fork.git",
            ],
        )
        .await;
        run_git(dir.path(), &["config", "remote.pushDefault", "fork"]).await;

        let resolved = resolve_push_remote()
            .await
            .expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("fork".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_push_remote_uses_branch_remote() {
        let (dir, original_cwd) = enter_temp_repo().await;
        let branch = run_git(dir.path(), &["symbolic-ref", "--short", "HEAD"]).await;

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/origin.git",
            ],
        )
        .await;
        run_git(
            dir.path(),
            &["config", &format!("branch.{}.remote", branch), "origin"],
        )
        .await;

        let resolved = resolve_push_remote()
            .await
            .expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("origin".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_push_remote_uses_single_remote_fallback() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "solo",
                "https://github.com/example/solo.git",
            ],
        )
        .await;

        let resolved = resolve_push_remote()
            .await
            .expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("solo".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_resolve_push_remote_detached_head_returns_none() {
        let (dir, original_cwd) = enter_temp_repo().await;
        run_git(dir.path(), &["checkout", "--detach", "HEAD"]).await;

        let resolved = resolve_push_remote()
            .await
            .expect("resolve_push_remote failed");
        assert_eq!(resolved, None);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_preferred_remote_url_uses_origin_when_branch_remote_is_unset() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/origin.git",
            ],
        )
        .await;
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/example/upstream.git",
            ],
        )
        .await;

        let resolved = preferred_remote_url_at(dir.path())
            .await
            .expect("preferred_remote_url_at failed");
        assert_eq!(
            resolved,
            Some("https://github.com/example/origin.git".to_string())
        );

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_api_config_get_missing() {
        let (_dir, original_cwd) = enter_temp_repo().await;
        let val = config_get("ai.cadence.nonexistent")
            .await
            .expect("config_get failed");
        assert_eq!(val, None);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_api_config_set_then_get() {
        let (_dir, original_cwd) = enter_temp_repo().await;
        config_set("ai.cadence.enabled", "true")
            .await
            .expect("config_set failed");
        let val = config_get("ai.cadence.enabled")
            .await
            .expect("config_get failed");
        assert_eq!(val, Some("true".to_string()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // check_enabled
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn test_check_enabled_default_true() {
        let (_dir, original_cwd) = enter_temp_repo().await;

        // No config set -- should default to enabled
        assert!(check_enabled().await);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_check_enabled_explicitly_true() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(dir.path(), &["config", "ai.cadence.enabled", "true"]).await;
        assert!(check_enabled().await);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_check_enabled_explicitly_false() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(dir.path(), &["config", "ai.cadence.enabled", "false"]).await;
        assert!(!check_enabled().await);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_check_enabled_other_value_treated_as_true() {
        let (dir, original_cwd) = enter_temp_repo().await;

        run_git(dir.path(), &["config", "ai.cadence.enabled", "yes"]).await;
        assert!(check_enabled().await);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: detached HEAD
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_head_hash_works_in_detached_head() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        // Get the current HEAD hash, then detach HEAD
        let hash = run_git(path, &["rev-parse", "HEAD"]).await;
        run_git(path, &["checkout", "--detach", "HEAD"]).await;

        // `git rev-parse HEAD` should still return the same hash in detached state
        let detached_hash = git_output_in(path, &["rev-parse", "HEAD"]).await.unwrap();
        assert_eq!(hash, detached_hash);
        assert_eq!(detached_hash.len(), 40);
    }

    #[tokio::test]
    async fn test_head_timestamp_works_in_detached_head() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        // Get the timestamp before detaching
        let ts_before = git_output_in(path, &["show", "-s", "--format=%ct", "HEAD"])
            .await
            .unwrap();

        run_git(path, &["checkout", "--detach", "HEAD"]).await;

        // Timestamp should still be readable in detached state
        let ts_after = git_output_in(path, &["show", "-s", "--format=%ct", "HEAD"])
            .await
            .unwrap();
        assert_eq!(ts_before, ts_after);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: repo with no remotes
    // -----------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn test_push_notes_fails_gracefully_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo().await;

        // push_notes should fail (no remote) but not panic
        let result = push_notes("origin");
        assert!(result.await.is_err());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn test_remote_orgs_empty_when_no_remotes() {
        let (_dir, original_cwd) = enter_temp_repo().await;

        let orgs = remote_orgs().await.expect("remote_orgs failed");
        assert!(orgs.is_empty());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[tokio::test]
    async fn test_remote_orgs_at_collects_orgs() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        run_git(
            path,
            &["remote", "add", "origin", "git@github.com:org-one/repo.git"],
        )
        .await;
        run_git(
            path,
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/org-two/repo.git",
            ],
        )
        .await;

        let orgs = remote_orgs_at(path).await.expect("remote_orgs_at failed");
        assert_eq!(orgs.len(), 2);
        assert!(orgs.contains(&"org-one".to_string()));
        assert!(orgs.contains(&"org-two".to_string()));
    }

    #[tokio::test]
    #[serial]
    async fn test_repo_matches_org_filter() {
        let dir = init_temp_repo().await;
        let path = dir.path();

        run_git(
            path,
            &["remote", "add", "origin", "git@github.com:my-org/repo.git"],
        )
        .await;

        let global_config = path.join("fake-global-gitconfig");
        tokio::fs::write(&global_config, "[ai \"cadence\"]\n    org = my-org\n")
            .await
            .unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let matches = repo_matches_org_filter(path)
            .await
            .expect("repo_matches_org_filter failed");
        assert!(matches);

        tokio::fs::write(&global_config, "[ai \"cadence\"]\n    org = other-org\n")
            .await
            .unwrap();
        let matches = repo_matches_org_filter(path)
            .await
            .expect("repo_matches_org_filter failed");
        assert!(!matches);

        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // candidate_owner_repo_roots — Desktop gating
    //
    // On macOS, Desktop scanning is gated by a marker file written after the
    // user has been prompted for TCC access. On Linux/Windows there is no
    // TCC equivalent, so Desktop is always scanned — the `without marker`
    // test is macOS-only.
    // -----------------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[serial]
    async fn candidate_owner_repo_roots_excludes_desktop_without_marker() {
        let home = TempDir::new().expect("home tempdir");
        let canonical_home = canonical_test_path(home.path()).await;
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(&canonical_home);

        let desktop_repo = canonical_home.join("Desktop").join("demo");
        tokio::fs::create_dir_all(desktop_repo.join(".git"))
            .await
            .expect("create desktop repo stub");

        let candidates = candidate_owner_repo_roots(&canonical_home, &["demo".to_string()]).await;

        assert!(
            !candidates.contains(&desktop_repo),
            "Desktop should not be probed before marker is written: {candidates:?}"
        );
    }

    #[tokio::test]
    #[serial]
    async fn candidate_owner_repo_roots_includes_desktop_once_marker_present() {
        let home = TempDir::new().expect("home tempdir");
        let canonical_home = canonical_test_path(home.path()).await;
        let home_guard = EnvGuard::new("HOME");
        home_guard.set_path(&canonical_home);

        crate::permissions::prompt_first_install_folder_access()
            .await
            .expect("first install folder access probe should write marker");

        let desktop_repo = canonical_home.join("Desktop").join("demo");
        tokio::fs::create_dir_all(desktop_repo.join(".git"))
            .await
            .expect("create desktop repo stub");

        let candidates = candidate_owner_repo_roots(&canonical_home, &["demo".to_string()]).await;

        assert!(
            candidates.contains(&desktop_repo),
            "Desktop repo should be detected once marker is present: {candidates:?}"
        );
    }
}
