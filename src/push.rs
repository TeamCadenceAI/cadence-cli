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
use std::collections::HashSet;
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

/// Attempt to push notes for a specific repository with a spinner and timing.
///
/// Shows a spinner while pushing (if stderr is a TTY) and reports the elapsed
/// time on completion. On failure: logs a note to stderr.
pub fn attempt_push_remote_at(repo: &Path, remote: &str) {
    let push_start = std::time::Instant::now();
    let use_spinner = output::is_stderr_tty();

    let spinner = if use_spinner {
        let pb = ProgressBar::new_spinner();
        pb.set_draw_target(ProgressDrawTarget::stderr());
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(120));
        pb.set_message(format!("Syncing notes with {}", remote));
        Some(pb)
    } else {
        None
    };

    // Fetch and merge remote notes before pushing to avoid overwriting
    // notes pushed by other users.
    let result = (|| -> Result<()> {
        // Capture the remote hash BEFORE fetch for force-with-lease.
        let pre_fetch_remote_hash = remote_notes_hash_at(repo, remote).unwrap_or(None);

        fetch_merge_notes_for_remote_at(repo, remote)?;

        // After fetch-merge, check if the local notes ref exists. If the repo
        // has no attached sessions (and the remote didn't have any either),
        // there's nothing to push — skip to avoid a spurious error.
        let has_local_notes = git::run_git_output_at(
            Some(repo),
            &["show-ref", "--verify", "--quiet", git::NOTES_REF],
            &[],
        )
        .map(|o| o.status.success())
        .unwrap_or(false);

        if !has_local_notes {
            return Ok(());
        }

        // Prepare the notes ref for push (ensures payload blobs are referenced).
        prepare_notes_for_push(Some(repo))?;

        // Force-push with lease for safety.
        let lease = force_with_lease_arg(&pre_fetch_remote_hash);
        let push_status = git::run_git_output_at(
            Some(repo),
            &["push", "--no-verify", &lease, remote, git::NOTES_REF],
            &[("GIT_TERMINAL_PROMPT", "0")],
        )
        .context("failed to execute git push for notes")?;

        if !push_status.status.success() {
            let stderr = String::from_utf8_lossy(&push_status.stderr);
            anyhow::bail!("git push notes failed: {}", stderr.trim());
        }
        Ok(())
    })();

    if let Some(pb) = spinner {
        pb.finish_and_clear();
    }

    match result {
        Ok(()) => {
            output::detail(&format!(
                "Synced notes with {} in {} ms",
                remote,
                push_start.elapsed().as_millis()
            ));
        }
        Err(e) => {
            output::note(&format!("Could not sync notes with {}: {}", remote, e));
        }
    }
}

/// Inner push logic that returns a Result instead of logging.
/// Used by tests to verify failure behaviour without panicking.
#[cfg(test)]
fn try_push_remote(remote: &str) -> Result<()> {
    git::push_notes(remote)
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
    let fetch_spec = format!("+{}:{}", git::NOTES_REF, temp_ref);

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
            &[
                "notes",
                "--ref",
                git::NOTES_REF,
                "merge",
                "--strategy=union",
                &temp_ref,
            ],
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
            // Abort the failed merge to clean up .git/NOTES_MERGE_* state.
            let _ = git::run_git_output_at(
                None,
                &["notes", "--ref", git::NOTES_REF, "merge", "--abort"],
                &[],
            );
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

    // Prepare the notes ref for push (ensures payload blobs are referenced).
    let prepare_start = std::time::Instant::now();
    prepare_notes_for_push(None).context("failed to prepare notes ref")?;
    if output::is_verbose() {
        output::detail(&format!(
            "Prepare in {} ms",
            prepare_start.elapsed().as_millis()
        ));
    }

    let push_start = std::time::Instant::now();
    if output::is_verbose() {
        output::detail("Pushing notes (force-with-lease)");
    }
    let lease = force_with_lease_arg(&remote_hash);
    let push_status = git::run_git_output_at(
        None,
        &["push", "--no-verify", &lease, remote, git::NOTES_REF],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git push for notes")?;
    if output::is_verbose() {
        output::detail(&format!("Push in {} ms", push_start.elapsed().as_millis()));
    }

    if !push_status.status.success() {
        let stderr = String::from_utf8_lossy(&push_status.stderr);
        let stderr_trim = stderr.trim();
        let is_lock_conflict = stderr_trim.contains("cannot lock ref")
            && stderr_trim.contains(git::NOTES_REF)
            && stderr_trim.contains("expected");
        let is_non_fast_forward = stderr_trim.contains("non-fast-forward");
        let is_lease_rejected =
            stderr_trim.contains("stale info") || stderr_trim.contains("failed to push");
        if is_lock_conflict || is_non_fast_forward || is_lease_rejected {
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

    // Capture remote hash before fetch for force-with-lease.
    let retry_remote_hash = remote_notes_hash(remote).unwrap_or(None);

    let temp_ref = format!("refs/notes/ai-sessions-remote/{}", remote);
    let fetch_spec = format!("+{}:{}", git::NOTES_REF, temp_ref);

    // Clean up any stale temp ref before fetching to avoid merge conflicts.
    let _ = git::run_git_output_at(None, &["update-ref", "-d", &temp_ref], &[]);

    // Abort any in-progress notes merge left by a previous failed attempt.
    let _ = git::run_git_output_at(
        None,
        &["notes", "--ref", git::NOTES_REF, "merge", "--abort"],
        &[],
    );

    let fetch_status = git::run_git_output_at(None, &["fetch", remote, &fetch_spec], &[])
        .context("failed to execute git fetch for notes")?;

    let fetched = fetch_status.status.success();
    if !fetched {
        let stderr = String::from_utf8_lossy(&fetch_status.stderr);
        let stderr_trim = stderr.trim();
        if !(stderr_trim.contains("couldn't find remote ref")
            && stderr_trim.contains(git::NOTES_REF))
        {
            anyhow::bail!("git fetch notes failed: {}", stderr_trim);
        }
    }

    if fetched {
        let merge_status = git::run_git_output_at(
            None,
            &[
                "notes",
                "--ref",
                git::NOTES_REF,
                "merge",
                "--strategy=union",
                &temp_ref,
            ],
            &[],
        )
        .context("failed to execute git notes merge")?;

        if !merge_status.status.success() {
            let stderr = String::from_utf8_lossy(&merge_status.stderr);
            anyhow::bail!("git notes merge failed: {}", stderr.trim());
        }

        let _ = git::run_git_output_at(None, &["update-ref", "-d", &temp_ref], &[]);
    }

    // Prepare the notes ref for push (ensures payload blobs are referenced).
    prepare_notes_for_push(None).context("failed to prepare notes ref on retry")?;

    let lease = force_with_lease_arg(&retry_remote_hash);
    let push_status = git::run_git_output_at(
        None,
        &["push", "--no-verify", &lease, remote, git::NOTES_REF],
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

// ---------------------------------------------------------------------------
// Notes ref preparation for push
// ---------------------------------------------------------------------------

/// Prepare the notes ref for pushing by ensuring payload blobs are referenced.
///
/// Creates a new commit on the notes ref that includes a `_payload/` subtree
/// referencing all v2 payload blobs, so they survive GC and are included in
/// push packs. The commit preserves history by using the current notes tip
/// as its parent (or creates an initial commit if no history exists).
///
/// Returns the SHA of the new commit.
fn prepare_notes_for_push(repo: Option<&Path>) -> Result<String> {
    // 1. Get the current tree from the notes ref.
    let tree_rev = format!("{}^{{tree}}", git::NOTES_REF);
    let current_tree =
        git::rev_parse_at(repo, &tree_rev).context("failed to resolve notes tree")?;

    // 2. Scan all notes for v2 payload_blob references.
    let notes = git::list_notes_at(repo)?;
    let mut payload_blobs: HashSet<String> = HashSet::new();

    for (note_sha, _commit) in &notes {
        // Pointer notes are always plaintext v2 YAML; extract payload_blob SHAs.
        if let Ok(blob_data) = git::read_blob_at(repo, note_sha) {
            let content = String::from_utf8_lossy(&blob_data);
            for line in content.lines() {
                if let Some(blob_sha) = line.strip_prefix("payload_blob: ") {
                    let blob_sha = blob_sha.trim();
                    if blob_sha.len() == 40 && blob_sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                        payload_blobs.insert(blob_sha.to_string());
                    }
                }
            }
        }
    }

    // 3. Build the augmented tree with _payload subtree.
    let final_tree = if payload_blobs.is_empty() {
        // No payload blobs — use the existing tree as-is.
        current_tree
    } else {
        // Read existing _payload entries (from previous prepare or remote merge).
        let top_entries = git::ls_tree_at(repo, &tree_rev)?;
        let mut existing_payload_shas: HashSet<String> = HashSet::new();

        for entry in &top_entries {
            // Look for the _payload tree entry: "040000 tree <sha>\t_payload"
            if entry.ends_with("\t_payload")
                && let Some(tree_sha) = entry.split_whitespace().nth(2)
            {
                // Read its children to preserve existing blobs.
                if let Ok(children) = git::ls_tree_at(repo, tree_sha) {
                    for child in &children {
                        if let Some(name) = child.split('\t').nth(1) {
                            existing_payload_shas.insert(name.to_string());
                        }
                    }
                }
            }
        }

        // Merge existing + new payload blob SHAs.
        payload_blobs.extend(existing_payload_shas);

        // Create the _payload subtree.
        let mut payload_entries: Vec<String> = payload_blobs
            .iter()
            .map(|sha| format!("100644 blob {}\t{}", sha, sha))
            .collect();
        payload_entries.sort(); // deterministic order

        let payload_tree =
            git::mktree_at(repo, &payload_entries).context("failed to create _payload subtree")?;

        // Rebuild top-level tree: keep everything except old _payload, add new one.
        let mut new_entries: Vec<String> = top_entries
            .into_iter()
            .filter(|line| !line.ends_with("\t_payload"))
            .collect();
        new_entries.push(format!("040000 tree {}\t_payload", payload_tree));

        git::mktree_at(repo, &new_entries).context("failed to create augmented notes tree")?
    };

    // 4. Create commit with current notes tip as parent (preserves merge history).
    let current_tip = git::rev_parse_at(repo, git::NOTES_REF).ok();
    let new_commit =
        git::commit_tree_at(repo, &final_tree, "cadence notes", current_tip.as_deref())
            .context("failed to create notes commit")?;

    // 5. Update ref.
    git::update_ref_at(repo, git::NOTES_REF, &new_commit).context("failed to update notes ref")?;

    if output::is_verbose() {
        output::detail(&format!("Prepared notes ref -> {}", &new_commit[..8]));
    }

    Ok(new_commit)
}

/// Get the remote notes ref hash for a specific repo via `ls-remote`.
///
/// Returns `None` if the remote doesn't have the notes ref.
fn remote_notes_hash_at(repo: &Path, remote: &str) -> Result<Option<String>> {
    let output = git::run_git_output_at(
        Some(repo),
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
    let line = stdout.lines().next().unwrap_or("");
    let hash = line.split_whitespace().next().unwrap_or("");
    if hash.is_empty() {
        Ok(None)
    } else {
        Ok(Some(hash.to_string()))
    }
}

/// Build the `--force-with-lease` argument for a push.
///
/// If `remote_hash` is `Some`, uses it as the expected value.
/// If `None` (remote ref doesn't exist), uses the zero OID (only push if
/// the ref still doesn't exist on the remote).
fn force_with_lease_arg(remote_hash: &Option<String>) -> String {
    match remote_hash {
        Some(hash) => format!("--force-with-lease={}:{}", git::NOTES_REF, hash),
        None => format!(
            "--force-with-lease={}:{}",
            git::NOTES_REF,
            "0000000000000000000000000000000000000000"
        ),
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
    let fetch_spec = format!("+{}:{}", git::NOTES_REF, temp_ref);

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
        &[
            "notes",
            "--ref",
            git::NOTES_REF,
            "merge",
            "--strategy=union",
            &temp_ref,
        ],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
    .context("failed to execute git notes merge")?;

    if !merge_status.status.success() {
        let stderr = String::from_utf8_lossy(&merge_status.stderr);
        // Abort the failed merge to clean up .git/NOTES_MERGE_* state.
        let _ = git::run_git_output_at(
            repo,
            &["notes", "--ref", git::NOTES_REF, "merge", "--abort"],
            &[("GIT_TERMINAL_PROMPT", "0")],
        );
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
    // attempt_push — fetch-merge-push
    // -----------------------------------------------------------------------

    /// Helper: create a bare remote and clone it to get a local repo with a
    /// proper origin.  Returns (local_dir, bare_dir) — both TempDirs so they
    /// stay alive for the duration of the test.
    fn init_repo_with_remote() -> (TempDir, TempDir) {
        // Create bare remote
        let bare = TempDir::new().expect("failed to create bare dir");
        run_git(bare.path(), &["init", "--bare"]);

        // Clone it to get a local repo with origin pointing at the bare
        let local = TempDir::new().expect("failed to create local dir");
        let bare_url = format!("file://{}", bare.path().display());
        // Clone into the tempdir (clone creates a subdir, so we use '.' trick)
        let output = Command::new("git")
            .args(["clone", &bare_url, local.path().to_str().unwrap()])
            .output()
            .expect("failed to clone");
        // Clone may fail because the bare repo is empty — that's fine, we'll
        // re-init the local directory in that case.
        if !output.status.success() {
            run_git(local.path(), &["init"]);
            run_git(local.path(), &["remote", "add", "origin", &bare_url]);
        }

        run_git(local.path(), &["config", "user.email", "test@test.com"]);
        run_git(local.path(), &["config", "user.name", "Test User"]);
        run_git(local.path(), &["config", "core.hooksPath", "/dev/null"]);

        // Create an initial commit and push it so the remote is non-empty.
        std::fs::write(local.path().join("README.md"), "hello").unwrap();
        run_git(local.path(), &["add", "README.md"]);
        run_git(local.path(), &["commit", "-m", "initial commit"]);
        run_git(local.path(), &["push", "-u", "origin", "HEAD"]);

        (local, bare)
    }

    /// Return the commit hash of HEAD in the given repo.
    fn head_hash(dir: &Path) -> String {
        run_git(dir, &["rev-parse", "HEAD"])
    }

    #[test]
    #[serial]
    fn test_attempt_push_merges_remote_notes() {
        let (local, bare) = init_repo_with_remote();

        // Create two commits so we can attach different notes to each.
        let commit1 = head_hash(local.path());

        std::fs::write(local.path().join("file2.txt"), "second").unwrap();
        run_git(local.path(), &["add", "file2.txt"]);
        run_git(local.path(), &["commit", "-m", "second commit"]);
        let commit2 = head_hash(local.path());
        run_git(local.path(), &["push", "origin", "HEAD"]);

        // Simulate another user: clone the bare repo into a second working
        // copy, attach a note to commit1, and push it to the shared remote.
        let other = TempDir::new().expect("failed to create other dir");
        let bare_url = format!("file://{}", bare.path().display());
        let output = Command::new("git")
            .args(["clone", &bare_url, other.path().to_str().unwrap()])
            .output()
            .expect("failed to clone for other user");
        assert!(output.status.success(), "other clone failed");
        run_git(other.path(), &["config", "user.email", "other@test.com"]);
        run_git(other.path(), &["config", "user.name", "Other User"]);
        run_git(other.path(), &["config", "core.hooksPath", "/dev/null"]);

        run_git(
            other.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "note-from-other-user",
                &commit1,
            ],
        );
        run_git(other.path(), &["push", "origin", crate::git::NOTES_REF]);

        // Meanwhile, the local user attaches a note to commit2 (only).
        run_git(
            local.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "note-from-local-user",
                &commit2,
            ],
        );

        // At this point:
        //   remote has: commit1 -> "note-from-other-user"
        //   local  has: commit2 -> "note-from-local-user"
        // A blind push would overwrite the remote note on commit1.

        // Use attempt_push_remote_at — should fetch-merge-push.
        attempt_push_remote_at(local.path(), "origin");

        // Fetch back from remote and verify both notes are present.
        run_git(
            local.path(),
            &[
                "fetch",
                "origin",
                &format!("+{}:{}", crate::git::NOTES_REF, crate::git::NOTES_REF),
            ],
        );

        let note1 = run_git(
            local.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit1],
        );
        let note2 = run_git(
            local.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit2],
        );

        assert_eq!(note1, "note-from-other-user");
        assert_eq!(note2, "note-from-local-user");
    }

    // -----------------------------------------------------------------------
    // attempt_push — skip when no local notes ref
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_attempt_push_skips_when_no_local_notes() {
        // Phase 3: When a repo has no local notes ref after fetch-merge,
        // attempt_push_remote_at should succeed silently (no push error).
        let (local, _bare) = init_repo_with_remote();

        // Verify there's no local notes ref
        let output = Command::new("git")
            .args([
                "-C",
                local.path().to_str().unwrap(),
                "show-ref",
                "--verify",
                "--quiet",
                crate::git::NOTES_REF,
            ])
            .output()
            .expect("failed to run git");
        assert!(
            !output.status.success(),
            "precondition: no local notes ref should exist"
        );

        // This should complete without errors (previously would fail trying
        // to push a non-existent notes ref).
        attempt_push_remote_at(local.path(), "origin");

        // Verify the remote also has no notes ref (nothing was pushed)
        let ls = run_git(
            local.path(),
            &["ls-remote", "--refs", "origin", crate::git::NOTES_REF],
        );
        assert!(ls.is_empty(), "no notes should have been pushed to remote");
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
        let _ = try_push_remote("origin");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_sync_notes_failure_does_not_panic() {
        let dir = init_temp_repo();
        let original_cwd = safe_cwd();
        std::env::set_current_dir(dir.path()).expect("failed to chdir");

        // No remote configured -- sync should fail but not panic.
        // Call the inner function directly to avoid stderr output from
        // the public wrapper.
        let _ = sync_notes_for_remote_inner("origin");

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
        let _ = try_push_remote("origin");

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 2: prepare_notes_for_push
    // -----------------------------------------------------------------------

    #[test]
    fn test_prepare_creates_commit_with_parent() {
        let dir = init_temp_repo();
        let commit = head_hash(dir.path());

        // Attach a note (creates the initial notes ref commit).
        run_git(
            dir.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "some note",
                &commit,
            ],
        );

        // Record the notes tip before prepare.
        let pre_tip = run_git(dir.path(), &["rev-parse", crate::git::NOTES_REF]);

        // Prepare.
        prepare_notes_for_push(Some(dir.path())).expect("prepare failed");

        // Verify the notes ref now points to a commit with the previous tip as parent.
        let parent_line = run_git(
            dir.path(),
            &["log", "--format=%P", "-1", crate::git::NOTES_REF],
        );
        assert_eq!(
            parent_line, pre_tip,
            "expected parent to be the previous notes tip"
        );

        // Verify the note is still readable.
        let note = run_git(
            dir.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit],
        );
        assert_eq!(note, "some note");
    }

    #[test]
    fn test_prepare_includes_payload_blobs_in_tree() {
        let dir = init_temp_repo();
        let commit = head_hash(dir.path());

        // Store a payload blob.
        let payload_data = b"test payload data for blob inclusion";
        let blob_sha =
            crate::git::store_blob_at(Some(dir.path()), payload_data).expect("store_blob failed");

        // Create a v2-style pointer note referencing the payload blob.
        let note_content = format!(
            "---\ncadence_version: 2\npayload_blob: {}\npayload_encoding: zstd\n---\n",
            blob_sha
        );
        run_git(
            dir.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                &note_content,
                &commit,
            ],
        );

        // Prepare.
        prepare_notes_for_push(Some(dir.path())).expect("prepare failed");

        // Verify _payload subtree exists and contains the blob.
        let tree_rev = format!("{}^{{tree}}", crate::git::NOTES_REF);
        let entries = crate::git::ls_tree_at(Some(dir.path()), &tree_rev).expect("ls_tree failed");

        let has_payload_tree = entries.iter().any(|e| e.ends_with("\t_payload"));
        assert!(
            has_payload_tree,
            "_payload subtree not found in prepared tree. Entries: {:?}",
            entries
        );

        // Read the _payload subtree and verify our blob is there.
        let payload_tree_entry = entries.iter().find(|e| e.ends_with("\t_payload")).unwrap();
        let payload_tree_sha = payload_tree_entry.split_whitespace().nth(2).unwrap();
        let payload_children =
            crate::git::ls_tree_at(Some(dir.path()), payload_tree_sha).expect("ls_tree failed");

        let has_our_blob = payload_children
            .iter()
            .any(|e| e.contains(&blob_sha) && e.ends_with(&format!("\t{}", blob_sha)));
        assert!(
            has_our_blob,
            "payload blob {} not found in _payload subtree. Children: {:?}",
            blob_sha, payload_children
        );

        // Verify the payload blob is readable from the tree.
        let read_back =
            crate::git::read_blob_at(Some(dir.path()), &blob_sha).expect("read_blob failed");
        assert_eq!(read_back, payload_data);
    }

    #[test]
    fn test_prepare_preserves_existing_payload_entries() {
        let dir = init_temp_repo();
        let commit = head_hash(dir.path());

        // Store two payload blobs.
        let blob1_sha =
            crate::git::store_blob_at(Some(dir.path()), b"payload one").expect("store_blob failed");
        let blob2_sha =
            crate::git::store_blob_at(Some(dir.path()), b"payload two").expect("store_blob failed");

        // Create a v2 note referencing blob1.
        let note1 = format!(
            "---\ncadence_version: 2\npayload_blob: {}\n---\n",
            blob1_sha
        );
        run_git(
            dir.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                &note1,
                &commit,
            ],
        );

        // First prepare — should include blob1 in _payload.
        prepare_notes_for_push(Some(dir.path())).expect("first prepare failed");

        // Add a second commit and note referencing blob2.
        std::fs::write(dir.path().join("file2.txt"), "second").unwrap();
        run_git(dir.path(), &["add", "file2.txt"]);
        run_git(dir.path(), &["commit", "-m", "second"]);
        let commit2 = head_hash(dir.path());

        let note2 = format!(
            "---\ncadence_version: 2\npayload_blob: {}\n---\n",
            blob2_sha
        );
        run_git(
            dir.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                &note2,
                &commit2,
            ],
        );

        // Second prepare — should include both blob1 and blob2.
        prepare_notes_for_push(Some(dir.path())).expect("second prepare failed");

        // Verify both blobs are in _payload.
        let tree_rev = format!("{}^{{tree}}", crate::git::NOTES_REF);
        let entries = crate::git::ls_tree_at(Some(dir.path()), &tree_rev).expect("ls_tree failed");
        let payload_tree_entry = entries.iter().find(|e| e.ends_with("\t_payload")).unwrap();
        let payload_tree_sha = payload_tree_entry.split_whitespace().nth(2).unwrap();
        let payload_children =
            crate::git::ls_tree_at(Some(dir.path()), payload_tree_sha).expect("ls_tree failed");

        assert!(
            payload_children.iter().any(|e| e.contains(&blob1_sha)),
            "blob1 {} not found after second prepare",
            blob1_sha
        );
        assert!(
            payload_children.iter().any(|e| e.contains(&blob2_sha)),
            "blob2 {} not found after second prepare",
            blob2_sha
        );
    }

    #[test]
    fn test_prepare_no_payload_blobs_still_works() {
        let dir = init_temp_repo();
        let commit = head_hash(dir.path());

        // Attach a legacy v1-style note (no payload_blob field).
        run_git(
            dir.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "---\nagent: claude-code\n---\nlegacy payload",
                &commit,
            ],
        );

        // Prepare should succeed — no _payload subtree needed.
        prepare_notes_for_push(Some(dir.path())).expect("prepare failed");

        // Verify note is still intact.
        let note = run_git(
            dir.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit],
        );
        assert!(note.contains("legacy payload"));

        // Verify no _payload subtree.
        let tree_rev = format!("{}^{{tree}}", crate::git::NOTES_REF);
        let entries = crate::git::ls_tree_at(Some(dir.path()), &tree_rev).expect("ls_tree failed");
        assert!(
            !entries.iter().any(|e| e.ends_with("\t_payload")),
            "_payload should not exist for legacy-only notes"
        );
    }

    #[test]
    #[serial]
    fn test_prepare_push_end_to_end() {
        // End-to-end test: attach v2 notes, prepare, force-push to remote.
        let (local, bare) = init_repo_with_remote();
        let commit = head_hash(local.path());

        // Store a payload blob and attach a v2 note.
        let blob_sha = crate::git::store_blob_at(Some(local.path()), b"session log data")
            .expect("store_blob failed");
        let note_content = format!(
            "---\ncadence_version: 2\npayload_blob: {}\npayload_encoding: zstd\n---\n",
            blob_sha
        );
        run_git(
            local.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                &note_content,
                &commit,
            ],
        );

        // Push using attempt_push_remote_at (which prepares internally).
        attempt_push_remote_at(local.path(), "origin");

        // Verify the remote has the notes ref.
        let ls = run_git(
            local.path(),
            &["ls-remote", "--refs", "origin", crate::git::NOTES_REF],
        );
        assert!(
            !ls.is_empty(),
            "notes ref should exist on remote after push"
        );

        // Clone to a new working copy and verify the note and payload blob
        // are both accessible.
        let other = TempDir::new().expect("failed to create other dir");
        let bare_url = format!("file://{}", bare.path().display());
        let output = Command::new("git")
            .args(["clone", &bare_url, other.path().to_str().unwrap()])
            .output()
            .expect("failed to clone");
        assert!(output.status.success(), "clone failed");

        // Fetch the notes ref.
        run_git(
            other.path(),
            &[
                "fetch",
                "origin",
                &format!("+{}:{}", crate::git::NOTES_REF, crate::git::NOTES_REF),
            ],
        );

        // Verify the note is readable.
        let note = run_git(
            other.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit],
        );
        assert!(
            note.contains(&blob_sha),
            "note should contain payload_blob reference"
        );

        // Verify the payload blob is accessible (it's in the _payload subtree).
        let read_back = crate::git::read_blob_at(Some(other.path()), &blob_sha)
            .expect("payload blob should be accessible on the other clone");
        assert_eq!(read_back, b"session log data");
    }

    #[test]
    #[serial]
    fn test_prepare_push_merges_with_remote_notes() {
        // Two users push notes; after merge + prepare, both notes survive.
        let (local, bare) = init_repo_with_remote();

        // Create two commits.
        let commit1 = head_hash(local.path());
        std::fs::write(local.path().join("file2.txt"), "second").unwrap();
        run_git(local.path(), &["add", "file2.txt"]);
        run_git(local.path(), &["commit", "-m", "second commit"]);
        let commit2 = head_hash(local.path());
        run_git(local.path(), &["push", "origin", "HEAD"]);

        // Simulate another user: clone, add note to commit1, push.
        let other = TempDir::new().expect("failed to create other dir");
        let bare_url = format!("file://{}", bare.path().display());
        let output = Command::new("git")
            .args(["clone", &bare_url, other.path().to_str().unwrap()])
            .output()
            .expect("failed to clone for other user");
        assert!(output.status.success(), "other clone failed");
        run_git(other.path(), &["config", "user.email", "other@test.com"]);
        run_git(other.path(), &["config", "user.name", "Other User"]);
        run_git(other.path(), &["config", "core.hooksPath", "/dev/null"]);

        run_git(
            other.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "note-from-other-user",
                &commit1,
            ],
        );
        run_git(other.path(), &["push", "origin", crate::git::NOTES_REF]);

        // Local user adds note to commit2.
        run_git(
            local.path(),
            &[
                "notes",
                "--ref",
                crate::git::NOTES_REF,
                "add",
                "-m",
                "note-from-local-user",
                &commit2,
            ],
        );

        // Push via attempt_push_remote_at (fetch-merge-prepare-force-push).
        attempt_push_remote_at(local.path(), "origin");

        // Fetch back and verify both notes are present.
        run_git(
            local.path(),
            &[
                "fetch",
                "origin",
                &format!("+{}:{}", crate::git::NOTES_REF, crate::git::NOTES_REF),
            ],
        );

        let note1 = run_git(
            local.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit1],
        );
        let note2 = run_git(
            local.path(),
            &["notes", "--ref", crate::git::NOTES_REF, "show", &commit2],
        );

        assert_eq!(note1, "note-from-other-user");
        assert_eq!(note2, "note-from-local-user");
    }

    #[test]
    fn test_force_with_lease_arg_with_hash() {
        let hash = Some("abcdef0123456789abcdef0123456789abcdef01".to_string());
        let arg = force_with_lease_arg(&hash);
        assert_eq!(
            arg,
            "--force-with-lease=refs/notes/ai-sessions:abcdef0123456789abcdef0123456789abcdef01"
        );
    }

    #[test]
    fn test_force_with_lease_arg_without_hash() {
        let arg = force_with_lease_arg(&None);
        assert_eq!(
            arg,
            "--force-with-lease=refs/notes/ai-sessions:0000000000000000000000000000000000000000"
        );
    }
}
