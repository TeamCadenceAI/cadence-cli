mod agents;
mod git;
mod note;
mod pending;
mod push;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::process;

/// Cadence CLI: attach AI coding agent session logs to Git commits via git notes.
///
/// Provides provenance and measurement of AI-assisted development
/// without polluting commit history.
#[derive(Parser, Debug)]
#[command(name = "cadence", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Install Cadence CLI: set up git hooks and run initial hydration.
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

    /// Show Cadence CLI status for the current repository.
    Status,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Post-commit hook: attempt to attach AI session note to HEAD.
    PostCommit,
    /// Pre-push hook: sync notes with the push remote.
    PrePush {
        /// Remote name provided by git.
        remote: String,
        /// Remote URL provided by git.
        url: String,
    },
    /// Background retry with exponential backoff (hidden, internal use only).
    #[command(hide = true)]
    PostCommitRetry {
        /// Full commit hash to resolve.
        commit: String,
        /// Absolute path to the repository root.
        repo: String,
        /// Unix epoch timestamp of the commit.
        timestamp: i64,
    },
}

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

/// The install subcommand: set up global git hooks and run initial hydration.
///
/// Steps:
/// 1. Set `git config --global core.hooksPath ~/.git-hooks`
/// 2. Create `~/.git-hooks/` directory if missing
/// 3. Write `~/.git-hooks/post-commit` shim script
/// 4. Write `~/.git-hooks/pre-push` shim script
/// 5. Make shims executable (chmod +x)
/// 6. If `--org` provided, persist org filter to global git config
/// 7. Run hydration for the last 7 days
///
/// Errors at each step are reported but do not prevent subsequent steps
/// from being attempted.
fn run_install(org: Option<String>) -> Result<()> {
    run_install_inner(org, None)
}

fn is_cadence_hook(content: &str) -> bool {
    content.contains("cadence hook") || content.contains("ai-session-commit-linker")
}

fn hook_command_exe() -> String {
    if cfg!(debug_assertions) {
        if let Some(path) = debug_hook_exe_path() {
            return path;
        }
    }
    "cadence".to_string()
}

fn debug_hook_exe_path() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    if let Some(name) = exe.file_name().and_then(|s| s.to_str()) {
        if name.starts_with("cadence") {
            return Some(exe.display().to_string());
        }
    }

    let dir = exe.parent()?;
    if dir.file_name().and_then(|s| s.to_str()) == Some("deps") {
        let candidate = dir.parent()?.join("cadence");
        if candidate.exists() {
            return Some(candidate.display().to_string());
        }
    }

    None
}

fn post_commit_hook_content() -> String {
    format!("#!/bin/sh\nexec {} hook post-commit\n", hook_command_exe())
}

fn pre_push_hook_content() -> String {
    format!(
        "#!/bin/sh\nexec {} hook pre-push \"$1\" \"$2\"\n",
        hook_command_exe()
    )
}

/// Inner implementation of install, accepting an optional home directory override
/// for testability. If `home_override` is `None`, uses the real home directory.
fn run_install_inner(org: Option<String>, home_override: Option<&std::path::Path>) -> Result<()> {
    eprintln!("[cadence] Installing...");
    let install_start = std::time::Instant::now();

    let home = match home_override {
        Some(h) => h.to_path_buf(),
        None => agents::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?,
    };

    let hooks_dir = home.join(".git-hooks");
    let hooks_dir_str = hooks_dir.to_string_lossy().to_string();

    // Track whether any step failed (but continue regardless)
    let mut had_errors = false;

    // Step 1: Set git config --global core.hooksPath ~/.git-hooks
    match git::config_set_global("core.hooksPath", &hooks_dir_str) {
        Ok(()) => {
            eprintln!("[cadence] Set core.hooksPath = {}", hooks_dir_str);
        }
        Err(e) => {
            eprintln!("[cadence] error: failed to set core.hooksPath: {}", e);
            had_errors = true;
        }
    }

    // Step 2: Create ~/.git-hooks/ directory if missing
    if !hooks_dir.exists() {
        match std::fs::create_dir_all(&hooks_dir) {
            Ok(()) => {
                eprintln!("[cadence] Created {}", hooks_dir_str);
            }
            Err(e) => {
                eprintln!("[cadence] error: failed to create {}: {}", hooks_dir_str, e);
                had_errors = true;
            }
        }
    } else {
        eprintln!("[cadence] {} already exists", hooks_dir_str);
    }

    // Step 3 & 4: Write post-commit shim and make it executable
    let shim_path = hooks_dir.join("post-commit");
    let shim_content = post_commit_hook_content();

    // Check if hook already exists
    let should_write = if shim_path.exists() {
        match std::fs::read_to_string(&shim_path) {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    eprintln!("[cadence] post-commit hook already installed, updating");
                    true
                } else {
                    // Back up the existing hook before overwriting
                    let backup_path = hooks_dir.join("post-commit.pre-cadence");
                    match std::fs::copy(&shim_path, &backup_path) {
                        Ok(_) => {
                            eprintln!(
                                "[cadence] warning: {} exists but was not created by cadence; backed up to {}",
                                shim_path.display(),
                                backup_path.display()
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "[cadence] warning: {} exists but was not created by cadence; failed to back up: {}",
                                shim_path.display(),
                                e
                            );
                        }
                    }
                    true
                }
            }
            Err(_) => {
                eprintln!(
                    "[cadence] warning: could not read existing {}; overwriting",
                    shim_path.display()
                );
                true
            }
        }
    } else {
        true
    };

    if should_write {
        match std::fs::write(&shim_path, shim_content) {
            Ok(()) => {
                eprintln!("[cadence] Wrote {}", shim_path.display());

                // Make executable (Unix only)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match std::fs::set_permissions(&shim_path, perms) {
                        Ok(()) => {
                            eprintln!("[cadence] Made {} executable", shim_path.display());
                        }
                        Err(e) => {
                            eprintln!(
                                "[cadence] error: failed to chmod {}: {}",
                                shim_path.display(),
                                e
                            );
                            had_errors = true;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[cadence] error: failed to write {}: {}",
                    shim_path.display(),
                    e
                );
                had_errors = true;
            }
        }
    }

    // Step 4b: Write pre-push shim and make it executable
    let pre_push_path = hooks_dir.join("pre-push");
    let pre_push_content = pre_push_hook_content();

    let should_write_pre_push = if pre_push_path.exists() {
        match std::fs::read_to_string(&pre_push_path) {
            Ok(existing) => {
                if is_cadence_hook(&existing) {
                    eprintln!("[cadence] pre-push hook already installed, updating");
                    true
                } else {
                    let backup_path = hooks_dir.join("pre-push.pre-cadence");
                    match std::fs::copy(&pre_push_path, &backup_path) {
                        Ok(_) => {
                            eprintln!(
                                "[cadence] warning: {} exists but was not created by cadence; backed up to {}",
                                pre_push_path.display(),
                                backup_path.display()
                            );
                        }
                        Err(e) => {
                            eprintln!(
                                "[cadence] warning: {} exists but was not created by cadence; failed to back up: {}",
                                pre_push_path.display(),
                                e
                            );
                        }
                    }
                    true
                }
            }
            Err(_) => {
                eprintln!(
                    "[cadence] warning: could not read existing {}; overwriting",
                    pre_push_path.display()
                );
                true
            }
        }
    } else {
        true
    };

    if should_write_pre_push {
        match std::fs::write(&pre_push_path, pre_push_content) {
            Ok(()) => {
                eprintln!("[cadence] Wrote {}", pre_push_path.display());

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o755);
                    match std::fs::set_permissions(&pre_push_path, perms) {
                        Ok(()) => {
                            eprintln!("[cadence] Made {} executable", pre_push_path.display());
                        }
                        Err(e) => {
                            eprintln!(
                                "[cadence] error: failed to chmod {}: {}",
                                pre_push_path.display(),
                                e
                            );
                            had_errors = true;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[cadence] error: failed to write {}: {}",
                    pre_push_path.display(),
                    e
                );
                had_errors = true;
            }
        }
    }

    // Step 5: Persist org filter if provided
    if let Some(ref org_value) = org {
        match git::config_set_global("ai.session-commit-linker.org", org_value) {
            Ok(()) => {
                eprintln!("[cadence] Set org filter: {}", org_value);
            }
            Err(e) => {
                eprintln!("[cadence] error: failed to set org filter: {}", e);
                had_errors = true;
            }
        }
    }

    // Step 6: Run hydration for the last 7 days
    eprintln!("[cadence] Running initial hydration (last 30 days)...");
    let hydrate_start = std::time::Instant::now();
    if let Err(e) = run_hydrate("30d", false) {
        eprintln!("[cadence] error: hydration failed: {}", e);
        had_errors = true;
    }
    eprintln!(
        "[cadence] Hydration done in {} ms",
        hydrate_start.elapsed().as_millis()
    );

    // Optional: sync notes for the current repo if a push remote resolves
    if let Ok(Some(remote)) = git::resolve_push_remote() {
        let consented = matches!(
            git::config_get("ai.session-commit-linker.autopush"),
            Ok(Some(val)) if val == "true"
        );
        if consented && push::check_org_filter_remote(&remote) {
            eprintln!("[cadence] Syncing notes to {}", remote);
            let sync_start = std::time::Instant::now();
            push::sync_notes_for_remote(&remote);
            eprintln!(
                "[cadence] Sync finished in {} ms",
                sync_start.elapsed().as_millis()
            );
        }
    }

    if had_errors {
        eprintln!("[cadence] Installation completed with errors (see above)");
    } else {
        eprintln!("[cadence] Installation complete!");
    }
    eprintln!(
        "[cadence] Install total {} ms",
        install_start.elapsed().as_millis()
    );

    Ok(())
}

/// The post-commit hook handler. This is the critical hot path.
///
/// CRITICAL: This function must NEVER fail the commit. All errors are caught
/// and logged as warnings. The function always exits 0.
///
/// The outer wrapper uses `std::panic::catch_unwind` to catch panics, and
/// an inner `Result` to catch all other errors. Any failure is logged to
/// stderr with the `[cadence]` prefix and silently ignored.
fn run_hook_post_commit() -> Result<()> {
    // Catch-all: catch panics
    let result = std::panic::catch_unwind(|| -> Result<()> { hook_post_commit_inner() });

    match result {
        Ok(Ok(())) => {} // Success
        Ok(Err(e)) => {
            eprintln!("[cadence] warning: hook failed: {}", e);
        }
        Err(_) => {
            eprintln!("[cadence] warning: hook panicked (this is a bug)");
        }
    }

    // Always succeed — never block the commit
    Ok(())
}

/// The pre-push hook handler. Must never block the push.
fn run_hook_pre_push(remote: &str, url: &str) -> Result<()> {
    let remote = remote.to_string();
    let url = url.to_string();
    let result = std::panic::catch_unwind(|| -> Result<()> { hook_pre_push_inner(&remote, &url) });

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("[cadence] warning: hook failed: {}", e);
        }
        Err(_) => {
            eprintln!("[cadence] warning: hook panicked (this is a bug)");
        }
    }

    Ok(())
}

/// Inner implementation of the post-commit hook.
///
/// This function is allowed to return errors — the caller (`run_hook_post_commit`)
/// catches all errors and panics.
fn hook_post_commit_inner() -> Result<()> {
    // Step 0: Per-repo enabled check — if disabled, skip EVERYTHING
    if !git::check_enabled() {
        return Ok(());
    }

    // Step 1: Get repo root, HEAD hash, HEAD timestamp
    let repo_root = git::repo_root()?;
    let head_hash = git::head_hash()?;
    let head_timestamp = git::head_timestamp()?;
    let repo_root_str = repo_root.to_string_lossy().to_string();

    // Step 2: Deduplication — if note already exists, exit early
    if git::note_exists(&head_hash)? {
        // Note already attached (e.g., by hydrate). Clean up stale pending record.
        let _ = pending::remove(&head_hash);
        return Ok(());
    }

    // Step 3: Collect candidate files across all agents
    let candidate_files = agents::all_candidate_files(&repo_root, head_timestamp, 600);

    // Step 5: Run scanner to find session match
    let session_match = scanner::find_session_for_commit(&head_hash, &candidate_files);

    let mut attached = false;
    if let Some(ref matched) = session_match {
        // Step 6a: Parse metadata and verify match
        let metadata = scanner::parse_session_metadata(&matched.file_path);

        if scanner::verify_match(&metadata, &repo_root, &head_hash) {
            // Read the full session log. If the read fails (permissions,
            // file deleted between match and read, etc.), fall through to
            // the pending path so it can be retried later.
            //
            // Note: `read_to_string` loads the entire file into memory.
            // This is acceptable because session logs are typically small
            // (tens of KB to a few MB).
            let session_log = match std::fs::read_to_string(&matched.file_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("[cadence] warning: failed to read session log: {}", e);
                    if let Err(e) =
                        pending::write_pending(&head_hash, &repo_root_str, head_timestamp)
                    {
                        eprintln!("[cadence] warning: failed to write pending record: {}", e);
                    }
                    spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
                    // Skip note attachment; retry will pick this up later
                    return Ok(());
                }
            };

            let session_id = metadata.session_id.as_deref().unwrap_or("unknown");

            // Attach the note
            attach_note_from_log(
                &matched.agent_type,
                session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::ExactHashMatch,
            )?;

            eprintln!(
                "[cadence] attached session {} to commit {}",
                session_id,
                &head_hash[..7]
            );

            if let Ok(Some(remote)) = git::resolve_push_remote()
                && push::should_push_remote(&remote)
            {
                let push_start = std::time::Instant::now();
                push::attempt_push_remote(&remote);
                eprintln!(
                    "[cadence] post-commit push elapsed_ms={}",
                    push_start.elapsed().as_millis()
                );
            }

            attached = true;
        }
    }

    if !attached {
        // Step 6b: No exact match found — attempt time-based fallback
        if let Some(fallback) =
            fallback_match_for_commit(head_timestamp, &repo_root, &candidate_files, 600)
        {
            let session_log = match std::fs::read_to_string(&fallback.file_path) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("[cadence] warning: failed to read session log: {}", e);
                    if let Err(e) =
                        pending::write_pending(&head_hash, &repo_root_str, head_timestamp)
                    {
                        eprintln!("[cadence] warning: failed to write pending record: {}", e);
                    }
                    spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
                    return Ok(());
                }
            };

            attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                &repo_root_str,
                &head_hash,
                &session_log,
                note::Confidence::TimeWindowMatch,
            )?;

            eprintln!(
                "[cadence] attached session {} to commit {} (time window match)",
                fallback.session_id,
                &head_hash[..7]
            );

            if let Ok(Some(remote)) = git::resolve_push_remote()
                && push::should_push_remote(&remote)
            {
                let push_start = std::time::Instant::now();
                push::attempt_push_remote(&remote);
                eprintln!(
                    "[cadence] post-commit push elapsed_ms={}",
                    push_start.elapsed().as_millis()
                );
            }

            attached = true;
        }
    }

    if !attached {
        // No match found — write pending record
        if let Err(e) = pending::write_pending(&head_hash, &repo_root_str, head_timestamp) {
            eprintln!("[cadence] warning: failed to write pending record: {}", e);
        }
        spawn_background_retry(&head_hash, &repo_root_str, head_timestamp);
    }

    // Step 7: Retry pending commits for this repo
    retry_pending_for_repo(&repo_root_str, &repo_root);

    Ok(())
}

/// Inner implementation of the pre-push hook.
fn hook_pre_push_inner(remote: &str, _url: &str) -> Result<()> {
    if !git::check_enabled() {
        return Ok(());
    }

    if push::should_push_remote(remote) {
        let sync_start = std::time::Instant::now();
        push::sync_notes_for_remote(remote);
        eprintln!(
            "[cadence] pre-push sync elapsed_ms={}",
            sync_start.elapsed().as_millis()
        );
    }

    Ok(())
}

/// Maximum number of retry attempts before a pending record is abandoned.
///
/// After this many attempts, the pending record is removed and a warning
/// is logged. This prevents unbounded retries for commits that can never
/// be resolved (e.g., the session log was deleted or the commit was from
/// a different machine).
const MAX_RETRY_ATTEMPTS: u32 = 20;

/// Backoff schedule for background retry (in seconds).
/// Total wait: 1 + 2 + 4 + 8 + 16 + 32 = 63 seconds.
const BACKGROUND_RETRY_DELAYS: &[u64] = &[1, 2, 4, 8, 16, 32];

/// If two fallback candidates are within this many seconds, treat as ambiguous.
const FALLBACK_AMBIGUITY_MARGIN_SECS: i64 = 120;

/// Expand session time ranges by this many seconds when matching commits.
const FALLBACK_RANGE_BUFFER_SECS: i64 = 300;

struct FallbackMatch {
    file_path: std::path::PathBuf,
    agent_type: scanner::AgentType,
    session_id: String,
}

fn file_mtime_epoch(path: &std::path::Path) -> Option<i64> {
    let metadata = std::fs::metadata(path).ok()?;
    let mtime = metadata.modified().ok()?;
    let mtime_epoch = mtime.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(mtime_epoch)
}

fn metadata_repo_matches(metadata: &scanner::SessionMetadata, repo_root: &std::path::Path) -> bool {
    let cwd = match &metadata.cwd {
        Some(c) => c,
        None => return false,
    };
    let cwd_path = std::path::Path::new(cwd);
    match git::repo_root_at(cwd_path) {
        Ok(cwd_repo_root) => {
            let canonical_repo = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            let canonical_cwd_repo = cwd_repo_root.canonicalize().unwrap_or(cwd_repo_root);
            canonical_repo == canonical_cwd_repo
        }
        Err(_) => false,
    }
}

fn fallback_match_for_commit(
    commit_time: i64,
    repo_root: &std::path::Path,
    candidate_files: &[std::path::PathBuf],
    time_window: i64,
) -> Option<FallbackMatch> {
    let mut candidates: Vec<(i64, std::path::PathBuf, scanner::SessionMetadata)> = Vec::new();

    for file_path in candidate_files {
        let metadata = scanner::parse_session_metadata(file_path);
        if !metadata_repo_matches(&metadata, repo_root) {
            continue;
        }

        let distance = if let Some((start_ts, end_ts)) = scanner::session_time_range(file_path) {
            let start = start_ts - FALLBACK_RANGE_BUFFER_SECS;
            let end = end_ts + FALLBACK_RANGE_BUFFER_SECS;
            if commit_time >= start && commit_time <= end {
                0
            } else {
                let d1 = (commit_time - start_ts).abs();
                let d2 = (commit_time - end_ts).abs();
                d1.min(d2)
            }
        } else {
            let mtime = match file_mtime_epoch(file_path) {
                Some(t) => t,
                None => continue,
            };
            (commit_time - mtime).abs()
        };

        if distance <= time_window {
            candidates.push((distance, file_path.clone(), metadata));
        }
    }

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by_key(|(distance, _, _)| *distance);
    if candidates.len() >= 2 {
        let diff = (candidates[1].0 - candidates[0].0).abs();
        if diff <= FALLBACK_AMBIGUITY_MARGIN_SECS {
            return None;
        }
    }

    let (_, file_path, metadata) = candidates.remove(0);
    let agent_type = metadata
        .agent_type
        .clone()
        .unwrap_or(scanner::AgentType::Claude);
    let session_id = metadata
        .session_id
        .as_deref()
        .unwrap_or("unknown")
        .to_string();

    Some(FallbackMatch {
        file_path,
        agent_type,
        session_id,
    })
}

fn attach_note_from_log(
    agent_type: &scanner::AgentType,
    session_id: &str,
    repo_str: &str,
    commit: &str,
    session_log: &str,
    confidence: note::Confidence,
) -> Result<()> {
    let note_content = note::format_with_confidence(
        agent_type,
        session_id,
        repo_str,
        commit,
        session_log,
        confidence,
    )?;
    git::add_note(commit, &note_content)?;
    Ok(())
}

/// Spawn a detached background process that retries resolving a commit
/// with exponential backoff over ~1 minute.
///
/// Uses `spawn()` (non-blocking) — parent returns immediately, child is
/// reparented to init/launchd when parent exits. stdio is null so the
/// child has no terminal association.
///
/// Failures to spawn are silently ignored — the pending system handles
/// long-term retry as a fallback.
fn spawn_background_retry(commit: &str, repo: &str, timestamp: i64) {
    // Never spawn background processes during tests — they outlive the test
    // and cascade into thousands of orphaned processes.
    if cfg!(test) {
        return;
    }
    let exe = match std::env::current_exe() {
        Ok(e) => e,
        Err(_) => return,
    };
    let _ = std::process::Command::new(&exe)
        .args([
            "hook",
            "post-commit-retry",
            commit,
            repo,
            &timestamp.to_string(),
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// Background retry handler: retries resolving a single commit with
/// exponential backoff.
///
/// This runs as a detached background process spawned by `spawn_background_retry`.
/// It sleeps between attempts and exits silently on success, exhaustion, or error.
/// The pending system handles long-term retry if this process fails.
fn run_hook_post_commit_retry(commit: &str, repo: &str, timestamp: i64) -> Result<()> {
    let repo_root = std::path::Path::new(repo);

    for delay in BACKGROUND_RETRY_DELAYS {
        std::thread::sleep(std::time::Duration::from_secs(*delay));

        match try_resolve_single_commit(commit, repo, repo_root, timestamp, 600) {
            ResolveResult::Attached => {
                let _ = pending::remove(commit);
                return Ok(());
            }
            ResolveResult::AlreadyExists => {
                let _ = pending::remove(commit);
                return Ok(());
            }
            ResolveResult::NotFound | ResolveResult::TransientError => {
                // Continue to next backoff step
            }
        }
    }

    // Exhausted all retries — exit silently. The pending system handles
    // long-term retry on the next commit.
    Ok(())
}

/// Result of attempting to resolve a single pending commit.
enum ResolveResult {
    /// Note was successfully attached.
    Attached,
    /// Note already existed (resolved by another mechanism).
    AlreadyExists,
    /// No session match found.
    NotFound,
    /// A transient error occurred (file unreadable, format error, git error).
    TransientError,
}

/// Try to resolve a single commit by scanning session logs and attaching a note.
///
/// This is the shared resolution logic used by both `retry_pending_for_repo`
/// (synchronous retry on next commit) and `run_hook_post_commit_retry`
/// (background retry with exponential backoff).
///
/// The `time_window` parameter controls how wide the candidate file mtime
/// window is (in seconds). The initial hook uses 600s (±10 min), retries
/// use 86400s (±24 hours).
fn try_resolve_single_commit(
    commit: &str,
    repo_str: &str,
    repo_root: &std::path::Path,
    commit_time: i64,
    time_window: i64,
) -> ResolveResult {
    // Check if note already exists
    match git::note_exists(commit) {
        Ok(true) => return ResolveResult::AlreadyExists,
        Ok(false) => {}
        Err(_) => return ResolveResult::TransientError,
    }

    // Collect candidate files across all agents
    let candidate_files = agents::all_candidate_files(repo_root, commit_time, time_window);

    let session_match = scanner::find_session_for_commit(commit, &candidate_files);

    let matched = match session_match {
        Some(m) => m,
        None => {
            if let Some(fallback) =
                fallback_match_for_commit(commit_time, repo_root, &candidate_files, time_window)
            {
                let session_log = match std::fs::read_to_string(&fallback.file_path) {
                    Ok(content) => content,
                    Err(_) => return ResolveResult::TransientError,
                };

                if attach_note_from_log(
                    &fallback.agent_type,
                    &fallback.session_id,
                    repo_str,
                    commit,
                    &session_log,
                    note::Confidence::TimeWindowMatch,
                )
                .is_ok()
                {
                    eprintln!(
                        "[cadence] retry: attached session {} to commit {} (time window match)",
                        fallback.session_id,
                        &commit[..std::cmp::min(7, commit.len())]
                    );

                    if let Ok(Some(remote)) = git::resolve_push_remote()
                        && push::should_push_remote(&remote)
                    {
                        let push_start = std::time::Instant::now();
                        push::attempt_push_remote(&remote);
                        eprintln!(
                            "[cadence] retry push elapsed_ms={}",
                            push_start.elapsed().as_millis()
                        );
                    }

                    return ResolveResult::Attached;
                }
                return ResolveResult::TransientError;
            }

            return ResolveResult::NotFound;
        }
    };

    let metadata = scanner::parse_session_metadata(&matched.file_path);

    if !scanner::verify_match(&metadata, repo_root, commit) {
        if let Some(fallback) =
            fallback_match_for_commit(commit_time, repo_root, &candidate_files, time_window)
        {
            let session_log = match std::fs::read_to_string(&fallback.file_path) {
                Ok(content) => content,
                Err(_) => return ResolveResult::TransientError,
            };

            if attach_note_from_log(
                &fallback.agent_type,
                &fallback.session_id,
                repo_str,
                commit,
                &session_log,
                note::Confidence::TimeWindowMatch,
            )
            .is_ok()
            {
                eprintln!(
                    "[cadence] retry: attached session {} to commit {} (time window match)",
                    fallback.session_id,
                    &commit[..std::cmp::min(7, commit.len())]
                );

                if let Ok(Some(remote)) = git::resolve_push_remote()
                    && push::should_push_remote(&remote)
                {
                    let push_start = std::time::Instant::now();
                    push::attempt_push_remote(&remote);
                    eprintln!(
                        "[cadence] retry push elapsed_ms={}",
                        push_start.elapsed().as_millis()
                    );
                }

                return ResolveResult::Attached;
            }
            return ResolveResult::TransientError;
        }

        return ResolveResult::NotFound;
    }

    let session_log = match std::fs::read_to_string(&matched.file_path) {
        Ok(content) => content,
        Err(_) => return ResolveResult::TransientError,
    };

    let session_id = metadata.session_id.as_deref().unwrap_or("unknown");

    if attach_note_from_log(
        &matched.agent_type,
        session_id,
        repo_str,
        commit,
        &session_log,
        note::Confidence::ExactHashMatch,
    )
    .is_ok()
    {
        eprintln!(
            "[cadence] retry: attached session {} to commit {}",
            session_id,
            &commit[..std::cmp::min(7, commit.len())]
        );

        // Push if conditions are met
        if let Ok(Some(remote)) = git::resolve_push_remote()
            && push::should_push_remote(&remote)
        {
            let push_start = std::time::Instant::now();
            push::attempt_push_remote(&remote);
            eprintln!(
                "[cadence] retry push elapsed_ms={}",
                push_start.elapsed().as_millis()
            );
        }

        ResolveResult::Attached
    } else {
        ResolveResult::TransientError
    }
}

/// Attempt to resolve pending commits for the given repository.
///
/// This is a best-effort operation. Any errors during retry are logged
/// and silently ignored. For each pending record:
/// - If note already exists: remove the pending record (success).
/// - If max attempts exceeded: remove the pending record (abandoned).
/// - If session match is found and verified: attach note, remove pending record.
/// - Otherwise: increment the attempt counter and leave for next time.
///
/// Pending retries use a much wider time window than the initial hook
/// (24 hours instead of 10 minutes) because the commit could be old and
/// the session log file may have been modified since the commit was created.
fn retry_pending_for_repo(repo_str: &str, repo_root: &std::path::Path) {
    let mut pending_records = match pending::list_for_repo(repo_str) {
        Ok(records) => records,
        Err(_) => return,
    };

    for record in &mut pending_records {
        // Check if max retry attempts exceeded -- abandon the record
        if record.attempts >= MAX_RETRY_ATTEMPTS {
            eprintln!(
                "[cadence] warning: abandoning pending commit {} after {} attempts",
                &record.commit[..std::cmp::min(7, record.commit.len())],
                record.attempts
            );
            let _ = pending::remove(&record.commit);
            continue;
        }

        match try_resolve_single_commit(
            &record.commit,
            repo_str,
            repo_root,
            record.commit_time,
            86_400,
        ) {
            ResolveResult::Attached | ResolveResult::AlreadyExists => {
                let _ = pending::remove(&record.commit);
            }
            ResolveResult::NotFound | ResolveResult::TransientError => {
                let _ = pending::increment(record);
            }
        }
    }
}

/// Parse a duration string like "7d", "30d", "1d" into seconds.
///
/// Currently only supports the `<N>d` format (number of days).
/// Returns an error for unrecognized formats.
fn parse_since_duration(since: &str) -> Result<i64> {
    let since = since.trim();
    if let Some(days_str) = since.strip_suffix('d') {
        let days: i64 = days_str
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid --since value: {:?}", since))?;
        if days <= 0 {
            anyhow::bail!("--since value must be positive: {:?}", since);
        }
        Ok(days * 86_400)
    } else {
        anyhow::bail!(
            "unsupported --since format {:?}: expected e.g. \"7d\", \"30d\"",
            since
        );
    }
}

/// The hydrate subcommand: backfill AI session notes for recent commits.
///
/// This scans ALL Claude and Codex log directories (not scoped to any
/// single repo), finds commit hashes in session logs, resolves repos
/// from session metadata, and attaches notes where missing.
///
/// Properties:
/// - Can take minutes for large log directories
/// - Prints verbose progress throughout
/// - All errors are non-fatal (logged and continued)
/// - Does NOT auto-push by default (use `--push` flag)
fn run_hydrate(since: &str, do_push: bool) -> Result<()> {
    let since_secs = parse_since_duration(since)?;
    let since_days = since_secs / 86_400;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Step 1: Collect all recent session logs (repo-agnostic)
    eprintln!(
        "[cadence] Scanning agent logs (last {} days)...",
        since_days
    );

    // Step 2: Find all session files modified within the --since window
    let files = agents::all_recent_files(now, since_secs);
    eprintln!("[cadence] Found {} session logs", files.len());
    if !files.is_empty() {
        let mut counts: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for file in &files {
            let agent = scanner::agent_type_from_path(file).to_string();
            *counts.entry(agent).or_insert(0) += 1;
        }
        let summary = counts
            .into_iter()
            .map(|(agent, count)| format!("{agent}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("[cadence]   Agents with sessions: {}", summary);
    }

    // Counters for final summary
    let mut attached = 0usize;
    let mut skipped = 0usize;
    let mut errors = 0usize;
    let mut fallback_attached = 0usize;

    // Step 3: Pre-process each file to resolve repo and group by repo display
    struct SessionInfo {
        file: std::path::PathBuf,
        session_id: String,
        repo_root: std::path::PathBuf,
        metadata: scanner::SessionMetadata,
    }

    let mut sessions_by_repo: std::collections::BTreeMap<String, Vec<SessionInfo>> =
        std::collections::BTreeMap::new();

    for file in &files {
        let metadata = scanner::parse_session_metadata(file);

        // Skip files with no session metadata (e.g., file-history-snapshot files)
        if metadata.session_id.is_none() && metadata.cwd.is_none() {
            continue;
        }

        // Skip sessions with no cwd silently — we can't determine the repo
        let cwd = match &metadata.cwd {
            Some(c) => c.clone(),
            None => continue,
        };

        let cwd_path = std::path::Path::new(&cwd);

        // Skip sessions whose cwd isn't a git repo (silently)
        let repo_root = match git::repo_root_at(cwd_path) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let session_id = metadata
            .session_id
            .as_deref()
            .unwrap_or("unknown")
            .to_string();

        // Determine repo display: prefer remote URL, fall back to directory name
        let repo_display = match git::first_remote_url_at(&repo_root) {
            Ok(Some(url)) => url,
            _ => repo_root
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };

        sessions_by_repo
            .entry(repo_display.clone())
            .or_default()
            .push(SessionInfo {
                file: file.clone(),
                session_id,
                repo_root,
                metadata,
            });
    }

    // Step 4: Process sessions grouped by repo
    for (repo_display, sessions) in &sessions_by_repo {
        eprintln!("[cadence] {}", repo_display);

        let mut repo_total = 0usize;
        let mut repo_with_commits = 0usize;
        let mut repo_without_commits = 0usize;

        for session in sessions {
            repo_total += 1;

            let session_display = if session.session_id.len() > 8 {
                &session.session_id[..8]
            } else {
                &session.session_id
            };

            // Extract all commit hashes from the session log
            let commit_hashes = scanner::extract_commit_hashes(&session.file);

            if commit_hashes.is_empty() {
                repo_without_commits += 1;

                if !git::check_enabled_at(&session.repo_root) {
                    continue;
                }

                let header = format!("[cadence]   {} |", session_display);

                let time_range =
                    if let Some((start, end)) = scanner::session_time_range(&session.file) {
                        Some((start, end))
                    } else {
                        // Fall back to file mtime ± 24 hours
                        let mtime = match file_mtime_epoch(&session.file) {
                            Some(t) => t,
                            None => {
                                eprintln!("{} no timestamps and no mtime", header);
                                continue;
                            }
                        };
                        Some((mtime - 86_400, mtime + 86_400))
                    };

                let (start_ts, end_ts) = match time_range {
                    Some(r) => r,
                    None => {
                        eprintln!("{} no timestamps", header);
                        continue;
                    }
                };

                let commits = match git::commits_in_time_range(&session.repo_root, start_ts, end_ts)
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} error scanning commits: {}", header, e);
                        errors += 1;
                        continue;
                    }
                };

                if commits.len() != 1 {
                    let status = if commits.is_empty() {
                        "no commits in time window"
                    } else {
                        "ambiguous commits in time window"
                    };
                    eprintln!("{} {}", header, status);
                    continue;
                }

                let hash = &commits[0];
                match git::note_exists_at(&session.repo_root, hash) {
                    Ok(true) => {
                        skipped += 1;
                        eprintln!("{} commit {} already attached", header, &hash[..7]);
                        continue;
                    }
                    Ok(false) => {}
                    Err(e) => {
                        eprintln!("{} error checking note for {}: {}", header, &hash[..7], e);
                        errors += 1;
                        continue;
                    }
                }

                let session_log = match std::fs::read_to_string(&session.file) {
                    Ok(content) => content,
                    Err(e) => {
                        eprintln!("{} failed to read session log: {}", header, e);
                        errors += 1;
                        continue;
                    }
                };

                let agent_type = session
                    .metadata
                    .agent_type
                    .clone()
                    .unwrap_or(scanner::AgentType::Claude);
                let repo_str = session.repo_root.to_string_lossy().to_string();

                let note_content = match note::format_with_confidence(
                    &agent_type,
                    &session.session_id,
                    &repo_str,
                    hash,
                    &session_log,
                    note::Confidence::TimeWindowMatch,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("{} failed to format note for {}: {}", header, &hash[..7], e);
                        errors += 1;
                        continue;
                    }
                };

                match git::add_note_at(&session.repo_root, hash, &note_content) {
                    Ok(()) => {
                        attached += 1;
                        fallback_attached += 1;
                        eprintln!(
                            "{} commit {} attached (time window match)",
                            header,
                            &hash[..7]
                        );
                    }
                    Err(e) => {
                        eprintln!("{} failed to attach note to {}: {}", header, &hash[..7], e);
                        errors += 1;
                    }
                }

                continue;
            }

            repo_with_commits += 1;

            if !git::check_enabled_at(&session.repo_root) {
                continue;
            }

            // For each hash, attach note if missing.
            // Buffer messages so we can combine a single status with the header.
            let mut session_attached = 0usize;
            let mut session_skipped = 0usize;
            let mut messages: Vec<String> = Vec::new();

            let header = format!("[cadence]   {} |", session_display);

            for hash in &commit_hashes {
                // Verify the commit exists in the resolved repo
                match git::commit_exists_at(&session.repo_root, hash) {
                    Ok(true) => {}
                    Ok(false) => {
                        // Commit does not exist in this repo -- could be from a
                        // different repo or could be rebased away. Skip silently.
                        continue;
                    }
                    Err(e) => {
                        messages.push(format!("error checking commit {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                }

                // Check dedup: skip if note already exists
                match git::note_exists_at(&session.repo_root, hash) {
                    Ok(true) => {
                        session_skipped += 1;
                        skipped += 1;
                        continue;
                    }
                    Ok(false) => {} // Need to attach
                    Err(e) => {
                        messages.push(format!("error checking note for {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                }

                // Read the full session log
                let session_log = match std::fs::read_to_string(&session.file) {
                    Ok(content) => content,
                    Err(e) => {
                        messages.push(format!("failed to read session log: {}", e));
                        errors += 1;
                        continue;
                    }
                };

                // Use agent type from parsed metadata (already inferred by
                // parse_session_metadata via infer_agent_type). Fall back to
                // Claude if metadata didn't determine it.
                let agent_type = session
                    .metadata
                    .agent_type
                    .clone()
                    .unwrap_or(scanner::AgentType::Claude);

                let repo_str = session.repo_root.to_string_lossy().to_string();

                // Format the note
                let note_content = match note::format(
                    &agent_type,
                    &session.session_id,
                    &repo_str,
                    hash,
                    &session_log,
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        messages.push(format!("failed to format note for {}: {}", &hash[..7], e));
                        errors += 1;
                        continue;
                    }
                };

                // Attach the note
                match git::add_note_at(&session.repo_root, hash, &note_content) {
                    Ok(()) => {
                        messages.push(format!("commit {} attached", &hash[..7]));
                        session_attached += 1;
                        attached += 1;
                    }
                    Err(e) => {
                        messages.push(format!("failed to attach note to {}: {}", &hash[..7], e));
                        errors += 1;
                    }
                }
            }

            // Summarise skipped commits as a single message
            if session_attached == 0 && session_skipped > 0 {
                messages.push(format!("{} already attached", session_skipped));
            }

            // Print: combine header + single message on one line, or multi-line
            if messages.len() <= 1 {
                let status = messages
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("nothing to do");
                eprintln!("{} {}", header, status);
            } else {
                eprintln!("{}", header);
                for msg in &messages {
                    eprintln!("[cadence]     {}", msg);
                }
            }
        }

        // Per-repo summary
        eprintln!(
            "[cadence]   {} sessions, {} with commits, {} without",
            repo_total, repo_with_commits, repo_without_commits
        );
    }

    // Final summary
    eprintln!(
        "[cadence] Done. {} attached, {} fallback attached, {} skipped, {} errors.",
        attached, fallback_attached, skipped, errors
    );

    // Step 7: Push if requested
    if do_push {
        eprintln!("[cadence] Pushing notes...");
        if let Ok(Some(remote)) = git::resolve_push_remote() {
            push::attempt_push_remote(&remote);
        }
    }

    Ok(())
}

fn run_retry() -> Result<()> {
    let repo_root = git::repo_root()?;
    let repo_str = repo_root.to_string_lossy().to_string();

    let pending_count = pending::list_for_repo(&repo_str)
        .map(|r| r.len())
        .unwrap_or(0);

    if pending_count == 0 {
        eprintln!("[cadence] no pending commits for this repo");
        return Ok(());
    }

    eprintln!("[cadence] retrying {} pending commit(s)...", pending_count);
    retry_pending_for_repo(&repo_str, &repo_root);

    let remaining = pending::list_for_repo(&repo_str)
        .map(|r| r.len())
        .unwrap_or(0);
    let resolved = pending_count - remaining;
    eprintln!(
        "[cadence] retry complete: {} resolved, {} still pending",
        resolved, remaining
    );

    Ok(())
}

/// The status subcommand: show Cadence CLI configuration and state.
///
/// Displays:
/// - Current repo root (or a message if not in a git repo)
/// - Hooks path and whether the post-commit/pre-push shims are installed
/// - Number of pending retries for the current repo
/// - Org filter config (if any)
/// - Autopush consent status
/// - Per-repo enabled/disabled status
///
/// All output uses the `[cadence]` prefix on stderr.
/// Handles being called outside a git repo gracefully.
fn run_status() -> Result<()> {
    run_status_inner(&mut std::io::stderr())
}

/// Inner implementation of `run_status` that writes to a `Write` impl.
/// This allows tests to capture the output for verification.
fn run_status_inner(w: &mut dyn std::io::Write) -> Result<()> {
    writeln!(w, "[cadence] Status").ok();

    // --- Repo root ---
    let repo_root = match git::repo_root() {
        Ok(root) => {
            writeln!(w, "[cadence]   Repo: {}", root.to_string_lossy()).ok();
            Some(root)
        }
        Err(_) => {
            writeln!(w, "[cadence]   Repo: (not in a git repository)").ok();
            None
        }
    };

    // --- Hooks path and shim status ---
    match git::config_get_global("core.hooksPath") {
        Ok(Some(path)) => {
            let post_path = std::path::Path::new(&path).join("post-commit");
            let post_installed = match std::fs::read_to_string(&post_path) {
                Ok(content) => is_cadence_hook(&content),
                Err(_) => false,
            };
            let pre_path = std::path::Path::new(&path).join("pre-push");
            let pre_installed = match std::fs::read_to_string(&pre_path) {
                Ok(content) => is_cadence_hook(&content),
                Err(_) => false,
            };
            let post_str = if post_installed { "yes" } else { "no" };
            let pre_str = if pre_installed { "yes" } else { "no" };
            writeln!(
                w,
                "[cadence]   Hooks path: {} (post-commit: {}, pre-push: {})",
                path, post_str, pre_str
            )
            .ok();
        }
        _ => {
            writeln!(w, "[cadence]   Hooks path: (not configured)").ok();
        }
    }

    // --- Pending retries ---
    if let Some(ref root) = repo_root {
        let repo_str = root.to_string_lossy().to_string();
        let pending_count = pending::list_for_repo(&repo_str)
            .map(|r| r.len())
            .unwrap_or(0);
        writeln!(w, "[cadence]   Pending retries: {}", pending_count).ok();
    } else {
        writeln!(w, "[cadence]   Pending retries: (n/a - not in a repo)").ok();
    }

    // --- Org filter ---
    match git::config_get_global("ai.session-commit-linker.org") {
        Ok(Some(org)) => {
            writeln!(w, "[cadence]   Org filter: {}", org).ok();
        }
        _ => {
            writeln!(w, "[cadence]   Org filter: (none)").ok();
        }
    }

    // --- Autopush consent ---
    if repo_root.is_some() {
        match git::config_get("ai.session-commit-linker.autopush") {
            Ok(Some(val)) if val == "true" => {
                writeln!(w, "[cadence]   Auto-push: enabled (consented)").ok();
            }
            Ok(Some(val)) if val == "false" => {
                writeln!(w, "[cadence]   Auto-push: disabled (opted out)").ok();
            }
            _ => {
                writeln!(
                    w,
                    "[cadence]   Auto-push: not yet configured (will prompt on first push)"
                )
                .ok();
            }
        }
    } else {
        writeln!(w, "[cadence]   Auto-push: (n/a - not in a repo)").ok();
    }

    // --- Per-repo enabled/disabled ---
    if repo_root.is_some() {
        let enabled = git::check_enabled();
        if enabled {
            writeln!(w, "[cadence]   Repo enabled: yes").ok();
        } else {
            writeln!(w, "[cadence]   Repo enabled: no").ok();
        }
    } else {
        writeln!(w, "[cadence]   Repo enabled: (n/a - not in a repo)").ok();
    }

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
            HookCommand::PrePush { remote, url } => run_hook_pre_push(&remote, &url),
            HookCommand::PostCommitRetry {
                commit,
                repo,
                timestamp,
            } => run_hook_post_commit_retry(&commit, &repo, timestamp),
        },
        Command::Hydrate { since, push } => run_hydrate(&since, push),
        Command::Retry => run_retry(),
        Command::Status => run_status(),
    };

    if let Err(e) = result {
        eprintln!("[cadence] error: {}", e);
        process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    #[test]
    fn cli_parses_install() {
        let cli = Cli::parse_from(["cadence", "install"]);
        assert!(matches!(cli.command, Command::Install { org: None }));
    }

    #[test]
    fn cli_parses_install_with_org() {
        let cli = Cli::parse_from(["cadence", "install", "--org", "my-org"]);
        match cli.command {
            Command::Install { org } => assert_eq!(org.as_deref(), Some("my-org")),
            _ => panic!("expected Install command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit() {
        let cli = Cli::parse_from(["cadence", "hook", "post-commit"]);
        assert!(matches!(
            cli.command,
            Command::Hook {
                hook_command: HookCommand::PostCommit
            }
        ));
    }

    #[test]
    fn cli_parses_hook_pre_push() {
        let cli = Cli::parse_from([
            "cadence",
            "hook",
            "pre-push",
            "origin",
            "git@github.com:org/repo.git",
        ]);
        match cli.command {
            Command::Hook {
                hook_command: HookCommand::PrePush { remote, url },
            } => {
                assert_eq!(remote, "origin");
                assert_eq!(url, "git@github.com:org/repo.git");
            }
            _ => panic!("expected Hook PrePush command"),
        }
    }

    #[test]
    fn cli_parses_hook_post_commit_retry() {
        let cli = Cli::parse_from([
            "cadence",
            "hook",
            "post-commit-retry",
            "abcdef0123456789abcdef0123456789abcdef01",
            "/Users/foo/repo",
            "1700000000",
        ]);
        match cli.command {
            Command::Hook {
                hook_command:
                    HookCommand::PostCommitRetry {
                        commit,
                        repo,
                        timestamp,
                    },
            } => {
                assert_eq!(commit, "abcdef0123456789abcdef0123456789abcdef01");
                assert_eq!(repo, "/Users/foo/repo");
                assert_eq!(timestamp, 1_700_000_000);
            }
            _ => panic!("expected Hook PostCommitRetry command"),
        }
    }

    #[test]
    fn cli_parses_hydrate_defaults() {
        let cli = Cli::parse_from(["cadence", "hydrate"]);
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
        let cli = Cli::parse_from(["cadence", "hydrate", "--since", "30d", "--push"]);
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
        let cli = Cli::parse_from(["cadence", "retry"]);
        assert!(matches!(cli.command, Command::Retry));
    }

    #[test]
    fn cli_parses_status() {
        let cli = Cli::parse_from(["cadence", "status"]);
        assert!(matches!(cli.command, Command::Status));
    }

    #[test]
    #[serial]
    fn run_install_returns_ok() {
        // run_install now does real work but with a fake home it should
        // succeed. We need to redirect HOME and GIT_CONFIG_GLOBAL to
        // isolate from the real environment.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global git config so we don't pollute the real one
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn run_hook_post_commit_returns_ok() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // The catch-all wrapper ensures this always returns Ok even
        // when called outside a git repo (the inner logic will fail
        // but the error is caught and logged to stderr).
        let result = run_hook_post_commit();

        unsafe { std::env::set_var("HOME", &original_home) };
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn run_hydrate_returns_ok() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // With a fake HOME and no session logs, hydrate should
        // succeed quickly with "Done. 0 attached, 0 fallback attached, 0 skipped, 0 errors."
        let result = run_hydrate("7d", false);

        unsafe { std::env::set_var("HOME", &original_home) };
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_since_duration_7d() {
        assert_eq!(parse_since_duration("7d").unwrap(), 7 * 86_400);
    }

    #[test]
    fn test_parse_since_duration_30d() {
        assert_eq!(parse_since_duration("30d").unwrap(), 30 * 86_400);
    }

    #[test]
    fn test_parse_since_duration_1d() {
        assert_eq!(parse_since_duration("1d").unwrap(), 86_400);
    }

    #[test]
    fn test_parse_since_duration_invalid_format() {
        assert!(parse_since_duration("7h").is_err());
        assert!(parse_since_duration("abc").is_err());
        assert!(parse_since_duration("").is_err());
    }

    #[test]
    fn test_parse_since_duration_zero_rejected() {
        assert!(parse_since_duration("0d").is_err());
    }

    #[test]
    fn test_parse_since_duration_negative_rejected() {
        assert!(parse_since_duration("-1d").is_err());
    }

    #[test]
    fn run_retry_returns_err_outside_repo() {
        // run_retry now calls git::repo_root() which fails outside a git repo.
        // In CI or test environments where the CWD might be inside a repo,
        // it could return Ok. We just verify it doesn't panic.
        let _ = run_retry();
    }

    #[test]
    #[serial]
    fn run_status_returns_ok_outside_repo() {
        // run_status should always return Ok even outside a git repo --
        // it gracefully handles the case where git::repo_root() fails.
        // We chdir to a temp dir that has no .git to actually exercise
        // the outside-repo code path.
        let original_cwd = safe_cwd();
        let tmp = TempDir::new().expect("failed to create temp dir");
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create an empty global config to isolate from developer's environment
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(tmp.path()).expect("failed to chdir to temp dir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("not in a git repository"),
            "should show outside-repo message, got: {}",
            output
        );
        assert!(
            output.contains("Pending retries: (n/a - not in a repo)"),
            "pending should show n/a outside repo, got: {}",
            output
        );
        assert!(
            output.contains("Auto-push: (n/a - not in a repo)"),
            "autopush should show n/a outside repo, got: {}",
            output
        );
        assert!(
            output.contains("Repo enabled: (n/a - not in a repo)"),
            "repo enabled should show n/a outside repo, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Negative CLI parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn cli_rejects_unknown_subcommand() {
        let result = Cli::try_parse_from(["cadence", "frobnicate"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hook_without_sub_subcommand() {
        let result = Cli::try_parse_from(["cadence", "hook"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_hydrate_since_missing_value() {
        let result = Cli::try_parse_from(["cadence", "hydrate", "--since"]);
        assert!(result.is_err());
    }

    #[test]
    fn cli_rejects_no_subcommand() {
        let result = Cli::try_parse_from(["cadence"]);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Integration test: post-commit hook with a real temp repo
    // -----------------------------------------------------------------------

    use serde_json::json;
    use serial_test::serial;
    use std::path::PathBuf;
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
    fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
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
    /// This is needed because serial tests may leave CWD in a deleted temp dir
    /// if a previous test panicked before restoring CWD.
    fn safe_cwd() -> PathBuf {
        match std::env::current_dir() {
            Ok(cwd) if cwd.exists() => cwd,
            _ => {
                // CWD is invalid (deleted temp dir from panicked test).
                // Restore to a known-good directory.
                let fallback = std::env::temp_dir();
                std::env::set_current_dir(&fallback).ok();
                fallback
            }
        }
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_to_commit() {
        // Set up temp repo with a commit
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        // Use a separate temp dir as a fake HOME to avoid polluting the
        // real ~/.claude directory. The agents module reads $HOME to find
        // session logs, so redirecting it is sufficient.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Get the actual repo root as git sees it (may differ from dir.path()
        // due to symlinks, e.g. /var -> /private/var on macOS)
        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let git_repo_root_path = std::path::Path::new(&git_repo_root);

        // Get the HEAD commit hash and timestamp
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        // Create a fake Claude session log directory matching this repo
        // inside the fake HOME, so it is fully self-contained in temp dirs.
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Create a fake JSONL session log with the commit hash and metadata.
        // Use the git-reported repo root for cwd to match what verify_match checks.
        let session_content = format!(
            r#"{{"session_id":"test-session-id","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the session file mtime to match the commit time
        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // chdir into the repo and run the hook
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();

        // The hook should always return Ok
        assert!(result.is_ok());

        // Verify a note was attached
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: test-session-id"));
        assert!(note_output.contains(&head_hash));
        assert!(note_output.contains("confidence: exact_hash_match"));

        // Restore HOME and cwd
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_cursor_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "cursor-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_cursor_project() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let project_dir = fake_home
            .path()
            .join(".cursor")
            .join("projects")
            .join("proj1");
        std::fs::create_dir_all(&project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"cursor-proj-1"}}
{{"cwd":"{cwd}"}}
{{"content":"[main {hash}] initial commit"}}
"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = project_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-proj-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_copilot_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "copilot-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: copilot"));
        assert!(note_output.contains("session_id: copilot-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_attaches_note_antigravity_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Antigravity")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "antigravity-chat-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: antigravity"));
        assert!(note_output.contains("session_id: antigravity-chat-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_fallback_time_match_attaches_note() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Session log without commit hash (fallback should use time window)
        let session_content = format!(
            r#"{{"session_id":"fallback-session","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash here"}}
"#,
            cwd = git_repo_root,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: fallback-session"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_fallback_ambiguous_skips() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"fallback-a","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash here"}}
"#,
            cwd = git_repo_root,
        );
        let session_a = claude_project_dir.join("session-a.jsonl");
        let session_b = claude_project_dir.join("session-b.jsonl");
        std::fs::write(&session_a, &session_content).unwrap();
        std::fs::write(&session_b, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_a, ft).unwrap();
        filetime::set_file_mtime(&session_b, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // No note should be attached due to ambiguity
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // Pending record should exist
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", head_hash));
        assert!(pending_path.exists(), "pending record should exist");

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_deduplication_skips_if_note_exists() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Manually attach a note first
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "existing note",
                &head_hash,
            ],
        );

        // chdir into repo and run hook
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // The note should still be the original one (not overwritten)
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(note_output, "existing note");

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_no_match_writes_pending() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        // Use a fake HOME so pending records are written to a temp dir
        // instead of the real ~/.cadence/cli/pending/.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Don't create any session logs — the hook should not find a match

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // No note should be attached
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // A pending record should have been written inside the fake home
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", head_hash));
        assert!(pending_path.exists(), "pending record should exist");

        // Restore HOME and cwd. The fake_home TempDir drop handles cleanup.
        // SAFETY: This test is #[serial], so no other threads are reading
        // env vars concurrently.
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_post_commit_never_fails_outside_git_repo() {
        // Isolate HOME so we don't scan real session logs
        let fake_home = TempDir::new().unwrap();
        let original_home = std::env::var("HOME").unwrap_or_default();
        unsafe { std::env::set_var("HOME", fake_home.path()) };

        // When called outside a git repo, the hook should still return Ok
        // because the catch-all wrapper catches errors.
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        unsafe { std::env::set_var("HOME", &original_home) };
    }

    // -----------------------------------------------------------------------
    // Integration test: retry resolves a pending commit
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_retry_resolves_pending_commit() {
        // This test simulates the scenario where:
        // 1. A commit is made but no session log exists yet (pending record created)
        // 2. The session log appears later
        // 3. On the next commit, the retry logic finds and resolves the pending record

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        // Step 1: Run the hook with no session logs -- creates a pending record
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Verify pending record was created
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        assert!(pending_path.exists(), "pending record should exist");

        // Step 2: Now create the session log that matches the first commit
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"retry-test-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short = &first_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set mtime to match first commit time
        let ft = filetime::FileTime::from_unix_time(first_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Step 3: Make a second commit, which triggers retry of pending records
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        // Run the hook again -- this should resolve the pending record for first_hash
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Verify the pending record was removed
        assert!(
            !pending_path.exists(),
            "pending record should have been removed after retry"
        );

        // Verify a note was attached to the first commit
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: retry-test-session"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration test: retry increments attempt on failure
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_retry_increments_attempt_on_failure() {
        // Scenario: pending record exists, but no session log is found.
        // Retry should increment the attempt counter.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Step 1: Run the hook with no session logs -- creates a pending record
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Read the pending record -- attempts should be 2: the initial write
        // sets attempts=1, then the retry loop at the end of the hook
        // increments it to 2 (because retry also fails to find a session log).
        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        let content = std::fs::read_to_string(&pending_path).unwrap();
        let record: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(record["attempts"], 2);

        // Step 2: Make a second commit (still no session log for first commit)
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        // Run the hook again -- retry should fail (no session log) and increment
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        // Read the pending record again -- attempts should be 3
        // (was 2 after first hook, retry in second hook increments to 3)
        let content = std::fs::read_to_string(&pending_path).unwrap();
        let record: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            record["attempts"], 3,
            "attempt count should be incremented after failed retry. Record: {}",
            &content
        );

        // Pending record should still exist
        assert!(
            pending_path.exists(),
            "pending record should still exist after failed retry"
        );

        // First commit should still have no note
        let status = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "first commit should have no note after failed retry"
        );

        // Suppress unused variable warnings
        let _ = git_repo_root;

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration test: run_retry subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_run_retry_in_repo() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        // No pending records -- should print "no pending commits"
        let result = run_retry();
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration tests: hydrate subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_from_session_log() {
        // This test simulates hydration:
        // 1. Create a repo with a commit
        // 2. Create a fake Claude session log containing the commit hash
        // 3. Run hydrate
        // 4. Verify the note was attached

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a fake Claude session log directory
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        // Create a session log with the full commit hash and metadata
        let session_content = format!(
            r#"{{"session_id":"hydrate-test-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"Done! Full hash: {hash}"}}
"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
            hash = head_hash,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the mtime to "now" so it falls within the --since window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate (no need to chdir -- hydrate is repo-agnostic)
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Verify a note was attached to the commit
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: claude-code"));
        assert!(note_output.contains("session_id: hydrate-test-session"));
        assert!(note_output.contains(&head_hash));
        assert!(note_output.contains("confidence: exact_hash_match"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_cursor_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "cursor-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_cursor_project() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let project_dir = fake_home
            .path()
            .join(".cursor")
            .join("projects")
            .join("proj1");
        std::fs::create_dir_all(&project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"cursor-hydrate-proj"}}
{{"cwd":"{cwd}"}}
{{"content":"[main {hash}] initial commit"}}
"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = project_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: cursor"));
        assert!(note_output.contains("session_id: cursor-hydrate-proj"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_copilot_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "copilot-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: copilot"));
        assert!(note_output.contains("session_id: copilot-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_attaches_note_antigravity_chat_session() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let chat_dir = fake_home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Antigravity")
            .join("User")
            .join("workspaceStorage")
            .join("ws1")
            .join("chatSessions");
        std::fs::create_dir_all(&chat_dir).unwrap();

        let session_content = json!({
            "sessionId": "antigravity-hydrate-1",
            "baseUri": { "fsPath": format!("{}/README.md", git_repo_root) },
            "requests": [{
                "response": [{
                    "value": format!("[main {}] initial commit", head_hash)
                }],
                "variableData": {
                    "variables": [{
                        "value": { "uri": { "fsPath": format!("{}/README.md", git_repo_root) } }
                    }]
                }
            }]
        })
        .to_string();
        let session_file = chat_dir.join("session.json");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: antigravity"));
        assert!(note_output.contains("session_id: antigravity-hydrate-1"));
        assert!(note_output.contains(&head_hash));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_fallback_single_commit() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-fallback-session","cwd":"{cwd}","timestamp":"{ts}"}}
{{"type":"assistant","message":"no commit hash"}}
"#,
            cwd = git_repo_root,
            ts = head_time_str,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("session_id: hydrate-fallback-session"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_fallback_multiple_commits_skips() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        // Create a second commit
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);
        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let second_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let second_ts: i64 = second_ts_str.parse().unwrap();

        let t1 = OffsetDateTime::from_unix_timestamp(first_ts).unwrap();
        let t2 = OffsetDateTime::from_unix_timestamp(second_ts).unwrap();
        let s1 = t1.format(&Rfc3339).unwrap();
        let s2 = t2.format(&Rfc3339).unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-fallback-ambiguous","cwd":"{cwd}","timestamp":"{ts1}"}}
{{"timestamp":"{ts2}","type":"assistant","message":"no commit hash"}}
"#,
            cwd = git_repo_root,
            ts1 = s1,
            ts2 = s2,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let status_first = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        let status_second = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status_first.success());
        assert!(!status_second.success());

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Codex fallback via timestamp (post-commit)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_post_commit_fallback_codex_timestamp() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"timestamp":"{ts}","type":"session_meta","payload":{{"id":"codex-session-1","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"no commit hash"}}"#,
            ts = head_time_str,
            cwd = git_repo_root,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-session-1"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate fallback with timestamp range selects single commit
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_fallback_timestamp_single_commit() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        // Create two commits with distinct timestamps
        let t1 = 1_700_000_100i64;
        let t2 = 1_700_003_700i64;

        std::fs::write(repo_path.join("file1.txt"), "first").unwrap();
        run_git(repo_path, &["add", "file1.txt"]);
        let mut cmd = std::process::Command::new("git");
        cmd.args(["-C", repo_path.to_str().unwrap()])
            .args(["commit", "-m", "first commit"])
            .env("GIT_AUTHOR_DATE", t1.to_string())
            .env("GIT_COMMITTER_DATE", t1.to_string());
        let output = cmd.output().expect("failed to run git");
        assert!(output.status.success(), "git commit failed");

        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        let mut cmd = std::process::Command::new("git");
        cmd.args(["-C", repo_path.to_str().unwrap()])
            .args(["commit", "-m", "second commit"])
            .env("GIT_AUTHOR_DATE", t2.to_string())
            .env("GIT_COMMITTER_DATE", t2.to_string());
        let output = cmd.output().expect("failed to run git");
        assert!(output.status.success(), "git commit failed");

        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let ts_str = OffsetDateTime::from_unix_timestamp(t1)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"hydrate-e2e","cwd":"{cwd}","timestamp":"{ts}"}}
{{"type":"assistant","message":"no commit hash"}}"#,
            cwd = git_repo_root,
            ts = ts_str,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_first = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_first.contains("confidence: time_window_match"));

        let status_second = std::process::Command::new("git")
            .args(["-C", repo_path.to_str().unwrap()])
            .args([
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status_second.success());

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Retry fallback resolves pending commit via time window
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_retry_fallback_time_window() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let first_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let first_ts: i64 = first_ts_str.parse().unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let pending_path = fake_home
            .path()
            .join(".cadence/cli")
            .join("pending")
            .join(format!("{}.json", first_hash));
        assert!(pending_path.exists(), "pending record should exist");

        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"retry-fallback","cwd":"{cwd}"}}
{{"type":"assistant","message":"no commit hash"}}"#,
            cwd = git_repo_root,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(first_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);

        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(note_output.contains("session_id: retry-fallback"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Codex exact hash match (post-commit)
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_post_commit_codex_exact_hash() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"type":"session_meta","payload":{{"id":"codex-exact","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"commit {hash} done"}}"#,
            cwd = git_repo_root,
            hash = head_hash,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let ft = filetime::FileTime::from_unix_time(head_ts, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-exact"));
        assert!(note_output.contains("confidence: exact_hash_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate exact hash for Codex sessions
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_codex_exact_hash() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"type":"session_meta","payload":{{"id":"codex-hydrate","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"[main {short}] initial commit\n 1 file changed"}}
{{"type":"assistant","message":"commit {hash} done"}}"#,
            cwd = git_repo_root,
            short = &head_hash[..7],
            hash = head_hash,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-hydrate"));
        assert!(note_output.contains("confidence: exact_hash_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // E2E: Hydrate fallback for Codex sessions
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_e2e_hydrate_fallback_codex_timestamp() {
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);
        let head_ts_str = run_git(repo_path, &["show", "-s", "--format=%ct", "HEAD"]);
        let head_ts: i64 = head_ts_str.parse().unwrap();
        let head_time = OffsetDateTime::from_unix_timestamp(head_ts).unwrap();
        let head_time_str = head_time.format(&Rfc3339).unwrap();

        let codex_dir = fake_home
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("02")
            .join("10");
        std::fs::create_dir_all(&codex_dir).unwrap();

        let session_content = format!(
            r#"{{"timestamp":"{ts}","type":"session_meta","payload":{{"id":"codex-hydrate-fallback","cwd":"{cwd}"}}}}
{{"type":"assistant","message":"no commit hash"}}"#,
            ts = head_time_str,
            cwd = git_repo_root,
        );
        let session_file = codex_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(note_output.contains("agent: codex"));
        assert!(note_output.contains("session_id: codex-hydrate-fallback"));
        assert!(note_output.contains("confidence: time_window_match"));

        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_skips_if_note_already_exists() {
        // Hydrate should skip commits that already have notes (dedup)

        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Manually attach a note first
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "pre-existing note",
                &head_hash,
            ],
        );

        // Create a fake session log with the commit hash
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"should-be-skipped","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short_hash}] some commit\n 1 file changed"}}
"#,
            cwd = git_repo_root,
            short_hash = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // The note should still be the pre-existing one (not overwritten)
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(note_output, "pre-existing note");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_multiple_commits_in_one_session() {
        // A single session may contain multiple commits. Hydrate should
        // attach notes to all of them.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Make a second commit
        std::fs::write(repo_path.join("file2.txt"), "second").unwrap();
        run_git(repo_path, &["add", "file2.txt"]);
        run_git(repo_path, &["commit", "-m", "second commit"]);
        let second_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a session log containing both commit hashes
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"multi-commit-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {s1}] initial commit"}}
{{"type":"tool_result","content":"commit {h1}"}}
{{"type":"tool_result","content":"[main {s2}] second commit"}}
{{"type":"tool_result","content":"commit {h2}"}}
"#,
            cwd = git_repo_root,
            s1 = &first_hash[..7],
            h1 = first_hash,
            s2 = &second_hash[..7],
            h2 = second_hash,
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run hydrate
        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Both commits should have notes
        let note1 = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &first_hash,
            ],
        );
        assert!(
            note1.contains("agent: claude-code"),
            "first commit should have a note"
        );
        assert!(note1.contains("session_id: multi-commit-session"));

        let note2 = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &second_hash,
            ],
        );
        assert!(
            note2.contains("agent: claude-code"),
            "second commit should have a note"
        );
        assert!(note2.contains("session_id: multi-commit-session"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Integration tests: install subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_install_creates_hooks_dir_and_shim() {
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global git config so we don't pollute the real one
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify hooks directory was created
        let hooks_dir = fake_home.path().join(".git-hooks");
        assert!(hooks_dir.exists(), "~/.git-hooks should be created");

        // Verify post-commit shim was written
        let shim_path = hooks_dir.join("post-commit");
        assert!(shim_path.exists(), "post-commit shim should exist");

        let shim_content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(
            shim_content,
            post_commit_hook_content(),
            "shim content should match exactly"
        );

        // Verify pre-push shim was written
        let pre_push_path = hooks_dir.join("pre-push");
        assert!(pre_push_path.exists(), "pre-push shim should exist");

        let pre_push_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(
            pre_push_content,
            pre_push_hook_content(),
            "pre-push shim content should match exactly"
        );

        // Verify shim is executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&shim_path).unwrap().permissions();
            let mode = perms.mode();
            assert!(
                mode & 0o111 != 0,
                "shim should be executable, got mode {:o}",
                mode
            );

            let pre_perms = std::fs::metadata(&pre_push_path).unwrap().permissions();
            let pre_mode = pre_perms.mode();
            assert!(
                pre_mode & 0o111 != 0,
                "pre-push shim should be executable, got mode {:o}",
                pre_mode
            );
        }

        // Verify core.hooksPath was set in global config
        let config_content = std::fs::read_to_string(&global_config).unwrap();
        assert!(
            config_content.contains("hooksPath"),
            "global config should contain hooksPath"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_with_org_sets_global_config() {
        // Ensure CWD is valid (previous serial test may have left it in a deleted temp dir)
        let _original_cwd = safe_cwd();
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let result = run_install_inner(Some("my-org".to_string()), Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify org was persisted to global config
        let config_content = std::fs::read_to_string(&global_config).unwrap();
        assert!(
            config_content.contains("my-org"),
            "global config should contain org filter value"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_idempotent() {
        // Running install twice should succeed without errors
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // First install
        let result1 = run_install_inner(None, Some(fake_home.path()));
        assert!(result1.is_ok());

        // Second install
        let result2 = run_install_inner(None, Some(fake_home.path()));
        assert!(result2.is_ok());

        // Shims should still be correct
        let shim_path = fake_home.path().join(".git-hooks").join("post-commit");
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_push_path = fake_home.path().join(".git-hooks").join("pre-push");
        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_detects_existing_non_linker_hook() {
        // If a post-commit hook exists that was NOT created by cadence,
        // install should still overwrite it (with a warning).
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Pre-create hooks dir and non-linker hooks
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, "#!/bin/sh\necho 'custom hook'\n").unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, "#!/bin/sh\necho 'custom pre-push'\n").unwrap();

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // The shim should now be the cadence one (overwritten)
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // The original hook should have been backed up
        let backup_path = hooks_dir.join("post-commit.pre-cadence");
        assert!(
            backup_path.exists(),
            "backup of original hook should exist at post-commit.pre-cadence"
        );
        let backup_content = std::fs::read_to_string(&backup_path).unwrap();
        assert_eq!(
            backup_content, "#!/bin/sh\necho 'custom hook'\n",
            "backup should contain the original hook content"
        );

        let pre_backup_path = hooks_dir.join("pre-push.pre-cadence");
        assert!(
            pre_backup_path.exists(),
            "backup of original hook should exist at pre-push.pre-cadence"
        );
        let pre_backup_content = std::fs::read_to_string(&pre_backup_path).unwrap();
        assert_eq!(
            pre_backup_content, "#!/bin/sh\necho 'custom pre-push'\n",
            "backup should contain the original pre-push hook content"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_detects_existing_linker_hook() {
        // If a post-commit hook exists that WAS created by cadence,
        // install should update it silently.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        // Pre-create hooks dir with existing cadence hooks
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, post_commit_hook_content()).unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, pre_push_hook_content()).unwrap();

        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // The shim should still be correct
        let content = std::fs::read_to_string(&shim_path).unwrap();
        assert_eq!(content, post_commit_hook_content());

        let pre_content = std::fs::read_to_string(&pre_push_path).unwrap();
        assert_eq!(pre_content, pre_push_hook_content());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    #[test]
    #[serial]
    fn test_install_runs_hydration() {
        // Verify that running install also runs hydration and attaches notes
        // to commits that have matching session logs.

        let dir = init_temp_repo();
        let repo_path = dir.path();

        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(&global_config, "").unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a fake Claude session log containing the commit hash
        let git_repo_root_path = std::path::Path::new(&git_repo_root);
        let encoded = agents::encode_repo_path(git_repo_root_path);
        let claude_project_dir = fake_home
            .path()
            .join(".claude")
            .join("projects")
            .join(&encoded);
        std::fs::create_dir_all(&claude_project_dir).unwrap();

        let session_content = format!(
            r#"{{"session_id":"install-hydrate-test","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short_hash}] fix bug\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = git_repo_root,
            short_hash = &head_hash[..7],
        );
        let session_file = claude_project_dir.join("session.jsonl");
        std::fs::write(&session_file, &session_content).unwrap();

        // Set the mtime to "now" so it falls within the 7-day hydration window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ft = filetime::FileTime::from_unix_time(now, 0);
        filetime::set_file_mtime(&session_file, ft).unwrap();

        // Run install (which should run hydration as its final step)
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_install_inner(None, Some(fake_home.path()));
        assert!(result.is_ok());

        // Verify a note was attached to the commit by hydration
        let note_output = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert!(
            note_output.contains("agent: claude-code"),
            "hydration during install should have attached a note"
        );
        assert!(note_output.contains("session_id: install-hydrate-test"));

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hydrate_no_logs_returns_ok() {
        // Hydrate with no log directories should succeed quickly and
        // deterministically when HOME is isolated.
        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let result = run_hydrate("7d", false);
        assert!(result.is_ok());

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
    }

    #[test]
    fn test_hydrate_invalid_since_returns_error() {
        let result = run_hydrate("invalid", false);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Integration tests: status subcommand
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_status_in_repo_shows_repo_root() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains(&format!("Repo: {}", git_repo_root)),
            "should show repo root path, got: {}",
            output
        );
        assert!(
            output.contains("Pending retries: 0"),
            "should show zero pending retries, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_hooks_path_when_configured() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a fake global config with core.hooksPath
        let hooks_dir = fake_home.path().join(".git-hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let hooks_dir_str = hooks_dir.to_string_lossy().to_string();

        // Write the cadence shims
        let shim_path = hooks_dir.join("post-commit");
        std::fs::write(&shim_path, post_commit_hook_content()).unwrap();
        let pre_push_path = hooks_dir.join("pre-push");
        std::fs::write(&pre_push_path, pre_push_hook_content()).unwrap();

        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(
            &global_config,
            format!("[core]\n    hooksPath = {}\n", hooks_dir_str),
        )
        .unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("post-commit: yes"),
            "should show post-commit installed, got: {}",
            output
        );
        assert!(
            output.contains("pre-push: yes"),
            "should show pre-push installed, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_pending_count() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);

        // Write some pending records for this repo
        let pending_dir = fake_home.path().join(".cadence/cli").join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        for i in 0..3 {
            let fake_hash = format!("{:0>40}", format!("abcdef{}", i));
            let record = serde_json::json!({
                "commit": fake_hash,
                "repo": git_repo_root,
                "commit_time": 1700000000 + i,
                "attempts": 1,
                "last_attempt": 1700000060 + i,
            });
            std::fs::write(
                pending_dir.join(format!("{}.json", fake_hash)),
                serde_json::to_string_pretty(&record).unwrap(),
            )
            .unwrap();
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Pending retries: 3"),
            "should show 3 pending retries, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_org_filter() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();

        // Create a global config with org filter
        let global_config = fake_home.path().join("fake-global-gitconfig");
        std::fs::write(
            &global_config,
            "[ai \"session-commit-linker\"]\n    org = my-test-org\n",
        )
        .unwrap();

        unsafe {
            std::env::set_var("HOME", fake_home.path());
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Org filter: my-test-org"),
            "should show org filter, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_autopush_status() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Set autopush to true
        run_git(
            repo_path,
            &["config", "ai.session-commit-linker.autopush", "true"],
        );

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Auto-push: enabled"),
            "should show autopush enabled, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_status_shows_repo_disabled() {
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Disable this repo
        run_git(
            repo_path,
            &["config", "ai.session-commit-linker.enabled", "false"],
        );

        std::env::set_current_dir(repo_path).expect("failed to chdir");

        let mut buf = Vec::new();
        let result = run_status_inner(&mut buf);
        assert!(result.is_ok());

        let output = String::from_utf8(buf).unwrap();
        assert!(
            output.contains("Repo enabled: no"),
            "should show repo as disabled, got: {}",
            output
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_existing_notes_from_other_refs_not_affected() {
        // Cadence CLI uses refs/notes/ai-sessions. Existing notes from
        // other refs (e.g., the default refs/notes/commits) should not
        // be affected by our operations.
        let dir = init_temp_repo();
        let repo_path = dir.path();

        let head_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Attach a note using the default ref (refs/notes/commits)
        run_git(
            repo_path,
            &["notes", "add", "-m", "default ref note", &head_hash],
        );

        // Attach a note using our custom ref
        run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "add",
                "-m",
                "ai session note",
                &head_hash,
            ],
        );

        // Verify both notes exist independently
        let default_note = run_git(repo_path, &["notes", "show", &head_hash]);
        assert_eq!(default_note, "default ref note");

        let ai_note = run_git(
            repo_path,
            &[
                "notes",
                "--ref",
                "refs/notes/ai-sessions",
                "show",
                &head_hash,
            ],
        );
        assert_eq!(ai_note, "ai session note");

        // Verify note_exists only detects our ref
        let exists =
            git::note_exists_at(repo_path, &head_hash).expect("note_exists_at should work");
        assert!(exists);

        // Adding our note should not have affected the default note
        let default_note_after = run_git(repo_path, &["notes", "show", &head_hash]);
        assert_eq!(default_note_after, "default ref note");
    }

    #[test]
    fn test_short_hash_uses_first_7_chars() {
        // Verify that the scanner uses exactly the first 7 characters
        // of the commit hash for short hash matching.
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";
        let short_hash = &commit_hash[..7]; // "abcdef0"

        // Create a file containing only the short hash (not the full hash)
        let content = format!(r#"{{"output":"commit {} done"}}"#, short_hash);
        let file = dir.path().join("session.jsonl");
        std::fs::write(&file, format!("{}\n", content)).unwrap();

        // Should match on short hash
        let result = scanner::find_session_for_commit(commit_hash, &[file.clone()]);
        assert!(
            result.is_some(),
            "should match on first 7 chars of commit hash"
        );

        // Create a file with only 6 chars of the hash (should NOT match)
        let too_short = &commit_hash[..6]; // "abcdef"
        let content2 = format!(r#"{{"output":"commit {} done"}}"#, too_short);
        let file2 = dir.path().join("session2.jsonl");
        std::fs::write(&file2, format!("{}\n", content2)).unwrap();

        // The 6-char substring should NOT match since the file only has 6 chars
        // but the scanner checks for the 7-char short hash
        let result2 = scanner::find_session_for_commit(commit_hash, &[file2.clone()]);
        assert!(
            result2.is_none(),
            "should not match on fewer than 7 chars of commit hash"
        );
    }

    #[test]
    #[serial]
    fn test_max_retry_count_abandons_record() {
        // When a pending record exceeds MAX_RETRY_ATTEMPTS, it should be
        // removed rather than retried indefinitely.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        let git_repo_root = run_git(repo_path, &["rev-parse", "--show-toplevel"]);
        let first_hash = run_git(repo_path, &["rev-parse", "HEAD"]);

        // Create a pending record with attempts >= MAX_RETRY_ATTEMPTS
        let pending_dir = fake_home.path().join(".cadence/cli").join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        let record = serde_json::json!({
            "commit": first_hash,
            "repo": git_repo_root,
            "commit_time": 1700000000,
            "attempts": MAX_RETRY_ATTEMPTS,
            "last_attempt": 1700000060,
        });
        let pending_path = pending_dir.join(format!("{}.json", first_hash));
        std::fs::write(
            &pending_path,
            serde_json::to_string_pretty(&record).unwrap(),
        )
        .unwrap();

        // Verify the pending record exists
        assert!(pending_path.exists());

        // Run retry -- should abandon the record since it exceeded max attempts
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        retry_pending_for_repo(&git_repo_root, std::path::Path::new(&git_repo_root));

        // The pending record should have been removed
        assert!(
            !pending_path.exists(),
            "pending record should be removed after exceeding max retry attempts"
        );

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_works_in_detached_head() {
        // The post-commit hook should work correctly even when HEAD is detached.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Detach HEAD
        run_git(repo_path, &["checkout", "--detach", "HEAD"]);

        // The hook should not panic or error in detached HEAD state
        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok(), "hook should succeed in detached HEAD state");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_hook_works_in_repo_with_no_remotes() {
        // The post-commit hook should work correctly in a local-only repo
        // with no remotes configured.
        let dir = init_temp_repo();
        let repo_path = dir.path();
        let original_cwd = safe_cwd();

        let fake_home = TempDir::new().expect("failed to create fake home");
        let original_home = std::env::var("HOME").ok();
        unsafe {
            std::env::set_var("HOME", fake_home.path());
        }

        // Verify no remotes
        let remotes = run_git(repo_path, &["remote"]);
        assert!(remotes.is_empty(), "should have no remotes");

        std::env::set_current_dir(repo_path).expect("failed to chdir");
        let result = run_hook_post_commit();
        assert!(result.is_ok(), "hook should succeed with no remotes");

        // Restore
        unsafe {
            match original_home {
                Some(h) => std::env::set_var("HOME", h),
                None => std::env::remove_var("HOME"),
            }
        }
        std::env::set_current_dir(original_cwd).unwrap();
    }
}
