//! Git utility helpers.
//!
//! All functions shell out to `git` via `std::process::Command`.
//! The notes ref used throughout is `refs/notes/ai-sessions`.

use crate::output;
use anyhow::{Context, Result, bail};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The dedicated git notes ref for AI session data.
pub const NOTES_REF: &str = "refs/notes/ai-sessions";

/// Validate that a commit hash is a valid hex string of 7-40 characters.
///
/// This prevents flag injection (e.g., passing `--help` as a commit) and
/// ensures we only pass well-formed refs to git.
pub(crate) fn validate_commit_hash(commit: &str) -> Result<()> {
    let is_valid =
        commit.len() >= 7 && commit.len() <= 40 && commit.bytes().all(|b| b.is_ascii_hexdigit());
    if !is_valid {
        bail!(
            "invalid commit hash {:?}: must be 7-40 lowercase hex characters",
            commit
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Run a git command and return its stdout as a trimmed `String`.
/// Returns an error if the command exits with a non-zero status.
fn git_output(args: &[&str]) -> Result<String> {
    let output = run_git_output_at(None, args, &[])?;

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

fn git_output_in(repo: &Path, args: &[&str]) -> Result<String> {
    let output = run_git_output_at(Some(repo), args, &[])?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git {} failed: {}", args.join(" "), stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(stdout.trim().to_string())
}

pub(crate) fn run_git_output_at(
    repo: Option<&Path>,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<std::process::Output> {
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

    display_parts.extend(args.iter().map(|s| s.to_string()));
    if output::is_verbose() {
        output::detail(&display_parts.join(" "));
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.args(args).spawn().context("failed to execute git")?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let (tx, rx) = std::sync::mpsc::channel::<(Stream, Vec<u8>)>();
        if let Some(stdout) = stdout {
            let tx = tx.clone();
            std::thread::spawn(move || read_stream(Stream::Stdout, stdout, tx));
        }
        if let Some(stderr) = stderr {
            let tx = tx.clone();
            std::thread::spawn(move || read_stream(Stream::Stderr, stderr, tx));
        }
        drop(tx);

        let mut stdout_buf: Vec<u8> = Vec::new();
        let mut stderr_buf: Vec<u8> = Vec::new();
        let mut saw_stdout = false;
        let mut saw_stderr = false;

        while let Ok((stream, chunk)) = rx.recv() {
            match stream {
                Stream::Stdout => {
                    if !saw_stdout {
                        output::detail("stdout:");
                        saw_stdout = true;
                    }
                    stdout_buf.extend_from_slice(&chunk);
                    emit_stream_chunk(&chunk);
                }
                Stream::Stderr => {
                    if !saw_stderr {
                        output::detail("stderr:");
                        saw_stderr = true;
                    }
                    stderr_buf.extend_from_slice(&chunk);
                    emit_stream_chunk(&chunk);
                }
            }
        }

        let status = child.wait().context("failed to wait on git")?;
        return Ok(std::process::Output {
            status,
            stdout: stdout_buf,
            stderr: stderr_buf,
        });
    }

    let output = cmd.args(args).output().context("failed to execute git")?;
    Ok(output)
}

#[derive(Copy, Clone, Debug)]
enum Stream {
    Stdout,
    Stderr,
}

fn read_stream<R: std::io::Read>(
    stream: Stream,
    mut reader: R,
    tx: std::sync::mpsc::Sender<(Stream, Vec<u8>)>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let _ = tx.send((stream, buf[..n].to_vec()));
            }
            Err(_) => break,
        }
    }
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

/// Run a git command and return whether it succeeded (exit code 0).
/// Does not treat non-zero exit as an error — just returns `false`.
fn git_succeeds(args: &[&str]) -> Result<bool> {
    let output = run_git_output_at(None, args, &[])?;
    let status = output.status;
    Ok(status.success())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether Cadence CLI is enabled for the current repository.
///
/// Reads `git config ai.cadence.enabled`. If the value is exactly
/// `"false"`, returns `false` -- the caller should skip ALL processing
/// (session scanning, note attachment, pending records, push, retry).
/// Any other value (including unset) returns `true`.
///
/// This is placed in the `git` module (not `push`) because it gates
/// the entire hook lifecycle, not just the push decision.
pub fn check_enabled() -> bool {
    match config_get("ai.cadence.enabled") {
        Ok(Some(val)) => val != "false",
        // Unset or error: default to enabled
        _ => true,
    }
}

/// Check whether Cadence CLI is enabled for a specific repository directory.
///
/// This is the directory-parameterised version of [`check_enabled`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
///
/// Reads `git -C <repo> config ai.cadence.enabled`. If the value is exactly
/// `"false"`, returns `false`. Any other value (including unset) returns `true`.
pub(crate) fn check_enabled_at(repo: &Path) -> bool {
    let output =
        match run_git_output_at(Some(repo), &["config", "--get", "ai.cadence.enabled"], &[]) {
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
pub fn repo_root() -> Result<PathBuf> {
    let path = git_output(&["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(path))
}

/// Return the repository root for a given working directory.
///
/// Runs `git -C <dir> rev-parse --show-toplevel`. This handles the case
/// where `dir` is a subdirectory of the repo.
pub(crate) fn repo_root_at(dir: &Path) -> Result<PathBuf> {
    let output = run_git_output_at(Some(dir), &["rev-parse", "--show-toplevel"], &[])
        .context("failed to execute git rev-parse --show-toplevel")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git rev-parse --show-toplevel failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
    Ok(PathBuf::from(stdout.trim()))
}

/// Check whether an AI-session note already exists for the given commit,
/// in a specific repository directory.
///
/// This is the directory-parameterised version of [`note_exists`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
pub(crate) fn note_exists_at(repo: &Path, commit: &str) -> Result<bool> {
    validate_commit_hash(commit)?;
    let output = run_git_output_at(
        Some(repo),
        &["notes", "--ref", NOTES_REF, "show", "--", commit],
        &[],
    )
    .context("failed to execute git notes show")?;
    Ok(output.status.success())
}

/// Attach an AI-session note to a commit in a specific repository directory.
///
/// This is the directory-parameterised version of [`add_note`], for use
/// by commands that operate on repos other than the CWD (e.g., `hydrate`).
///
/// **Precondition:** Callers must check [`note_exists_at`] first and skip if
/// a note is already present.
pub(crate) fn add_note_at(repo: &Path, commit: &str, content: &str) -> Result<()> {
    validate_commit_hash(commit)?;

    // Write content to a temp file to avoid ARG_MAX limits on large notes.
    let mut tmp = tempfile::NamedTempFile::new().context("failed to create temp file for note")?;
    tmp.write_all(content.as_bytes())
        .context("failed to write note to temp file")?;
    tmp.flush().context("failed to flush note temp file")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();

    let output = run_git_output_at(
        Some(repo),
        &[
            "notes", "--ref", NOTES_REF, "add", "-F", &tmp_path, "--", commit,
        ],
        &[],
    )
    .context("failed to execute git notes add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git notes add failed: {}", stderr.trim());
    }
    Ok(())
}

/// Store arbitrary bytes as a git blob object and return its 40-char SHA-1 hash.
///
/// Uses `git hash-object -w --stdin` to write the blob to the object store.
pub fn store_blob(data: &[u8]) -> Result<String> {
    store_blob_at(None, data)
}

/// Store arbitrary bytes as a git blob in a specific repository.
pub fn store_blob_at(repo: Option<&Path>, data: &[u8]) -> Result<String> {
    let mut cmd = Command::new("git");
    if let Some(repo) = repo {
        cmd.args(["-C", &repo.to_string_lossy()]);
    }
    cmd.args(["hash-object", "-w", "--stdin"]);
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().context("failed to spawn git hash-object")?;
    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(data)
            .context("failed to write blob data to git hash-object stdin")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait for git hash-object")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git hash-object failed: {}", stderr.trim());
    }

    let sha = String::from_utf8(output.stdout)
        .context("git hash-object output was not valid UTF-8")?
        .trim()
        .to_string();

    if sha.len() != 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("git hash-object returned invalid SHA: {}", sha);
    }

    Ok(sha)
}

/// Read a git blob by its SHA and return the raw bytes.
///
/// Uses `git cat-file blob <sha>`.
pub fn read_blob(sha: &str) -> Result<Vec<u8>> {
    read_blob_at(None, sha)
}

/// Read a git blob by its SHA from a specific repository.
pub fn read_blob_at(repo: Option<&Path>, sha: &str) -> Result<Vec<u8>> {
    let output = run_git_output_at(repo, &["cat-file", "blob", sha], &[])
        .context("failed to execute git cat-file blob")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git cat-file blob failed: {}", stderr.trim());
    }

    Ok(output.stdout)
}

/// Check whether a commit exists in a given repository.
///
/// Runs `git -C <repo> cat-file -t -- <commit>` and checks for success.
/// The `--` separator prevents the commit argument from being interpreted
/// as a flag.
pub(crate) fn commit_exists_at(repo: &Path, commit: &str) -> Result<bool> {
    let output = run_git_output_at(Some(repo), &["cat-file", "-t", "--", commit], &[])
        .context("failed to execute git cat-file")?;
    Ok(output.status.success())
}

/// Return full commit hashes within the given time range for a repository.
///
/// Uses `git log --since=@<start> --until=@<end> --format=%H`.
pub(crate) fn commits_in_time_range(
    repo: &Path,
    start_ts: i64,
    end_ts: i64,
) -> Result<Vec<String>> {
    let (start, end) = if start_ts <= end_ts {
        (start_ts, end_ts)
    } else {
        (end_ts, start_ts)
    };

    let since = format!("@{}", start);
    let until = format!("@{}", end);

    let output = run_git_output_at(
        Some(repo),
        &["log", "--since", &since, "--until", &until, "--format=%H"],
        &[],
    )
    .context("failed to execute git log")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git log failed: {}", stderr.trim());
    }

    let stdout = String::from_utf8(output.stdout).context("git log output was not valid UTF-8")?;
    let mut commits = Vec::new();
    for line in stdout.lines() {
        let hash = line.trim();
        if hash.is_empty() {
            continue;
        }
        commits.push(hash.to_string());
    }
    Ok(commits)
}

/// Return the full 40-character SHA of HEAD.
pub fn head_hash() -> Result<String> {
    git_output(&["rev-parse", "HEAD"])
}

/// Return the commit timestamp of HEAD as a Unix epoch `i64`.
pub fn head_timestamp() -> Result<i64> {
    let ts_str = git_output(&["show", "-s", "--format=%ct", "HEAD"])?;
    ts_str
        .parse::<i64>()
        .context("failed to parse HEAD timestamp as i64")
}

/// Check whether an AI-session note already exists for the given commit.
pub fn note_exists(commit: &str) -> Result<bool> {
    validate_commit_hash(commit)?;
    git_succeeds(&["notes", "--ref", NOTES_REF, "show", "--", commit])
}

/// Attach an AI-session note to the given commit.
///
/// **Precondition:** Callers must check [`note_exists`] first and skip if a note
/// is already present. `git notes add` will fail if a note already exists for the
/// given commit. The PLAN.md deduplication rules require checking before attaching:
/// "if a note already exists, treat as success, do nothing."
pub fn add_note(commit: &str, content: &str) -> Result<()> {
    validate_commit_hash(commit)?;

    // Write content to a temp file to avoid ARG_MAX limits on large notes.
    let mut tmp = tempfile::NamedTempFile::new().context("failed to create temp file for note")?;
    tmp.write_all(content.as_bytes())
        .context("failed to write note to temp file")?;
    tmp.flush().context("failed to flush note temp file")?;
    let tmp_path = tmp.path().to_string_lossy().to_string();

    let output = run_git_output_at(
        None,
        &[
            "notes", "--ref", NOTES_REF, "add", "-F", &tmp_path, "--", commit,
        ],
        &[],
    )
    .context("failed to execute git notes add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git notes add failed: {}", stderr.trim());
    }
    Ok(())
}

/// A single `git log` entry annotated with whether it has a note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitNoteMarker {
    pub short: String,
    pub date: String,
    pub subject: String,
    pub has_note: bool,
}

/// Return `git log` entries annotated with note presence from the given notes ref.
///
/// This mirrors:
/// `git log --date=short --format='%H%x09%h%x09%ad%x09%s'`
/// plus a per-commit note existence check against `notes_ref`.
pub fn list_commits_with_note_markers(notes_ref: &str) -> Result<Vec<CommitNoteMarker>> {
    let log_output = run_git_output_at(
        None,
        &["log", "--date=short", "--format=%H%x09%h%x09%ad%x09%s"],
        &[],
    )
    .context("failed to execute git log")?;

    if !log_output.status.success() {
        let stderr = String::from_utf8_lossy(&log_output.stderr);
        bail!("git log failed: {}", stderr.trim());
    }

    let notes_output = run_git_output_at(None, &["notes", "--ref", notes_ref, "list"], &[])
        .context("failed to execute git notes list")?;

    if !notes_output.status.success() {
        let stderr = String::from_utf8_lossy(&notes_output.stderr);
        bail!(
            "git notes list failed for ref {:?}: {}",
            notes_ref,
            stderr.trim()
        );
    }

    let notes_stdout = String::from_utf8(notes_output.stdout)
        .context("git notes list output was not valid UTF-8")?;
    let noted_commit_ids = parse_noted_commit_ids(&notes_stdout);

    let log_stdout =
        String::from_utf8(log_output.stdout).context("git log output was not valid UTF-8")?;
    let mut entries = Vec::new();
    for line in log_stdout.lines() {
        if let Some((full, short, date, subject)) = parse_log_line(line) {
            entries.push(CommitNoteMarker {
                short,
                date,
                subject,
                has_note: noted_commit_ids.contains(full.as_str()),
            });
        }
    }

    Ok(entries)
}

fn parse_log_line(line: &str) -> Option<(String, String, String, String)> {
    let mut parts = line.splitn(4, '\t');
    let full = parts.next()?.to_string();
    let short = parts.next()?.to_string();
    let date = parts.next()?.to_string();
    let subject = parts.next().unwrap_or("").to_string();

    if full.is_empty() || short.is_empty() || date.is_empty() {
        return None;
    }

    Some((full, short, date, subject))
}

fn parse_noted_commit_ids(notes_list_stdout: &str) -> HashSet<String> {
    notes_list_stdout
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _note_object = parts.next()?;
            let commit_object = parts.next()?;
            Some(commit_object.to_string())
        })
        .collect()
}

/// Push the AI-session notes ref to the provided remote.
pub fn push_notes(remote: &str) -> Result<()> {
    push_notes_at(None, remote)
}

pub fn push_notes_at(repo: Option<&Path>, remote: &str) -> Result<()> {
    let output = run_git_output_at(
        repo,
        &["push", "--no-verify", remote, NOTES_REF],
        &[("GIT_TERMINAL_PROMPT", "0")],
    )
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
#[allow(dead_code)]
pub fn has_upstream() -> Result<bool> {
    match git_output(&["remote"]) {
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
pub fn resolve_push_remote() -> Result<Option<String>> {
    let output = run_git_output_at(None, &["symbolic-ref", "--quiet", "--short", "HEAD"], &[])
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
    if let Ok(Some(remote)) = config_get(&push_remote_key)
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    if let Ok(Some(remote)) = config_get("remote.pushDefault")
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let branch_remote_key = format!("branch.{}.remote", branch);
    if let Ok(Some(remote)) = config_get(&branch_remote_key)
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let remotes = match git_output(&["remote"]) {
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

/// Return the URL for a named remote (if any).
pub fn remote_url(remote: &str) -> Result<Option<String>> {
    let output = run_git_output_at(None, &["remote", "get-url", remote], &[])
        .context("failed to execute git remote get-url")?;

    if !output.status.success() {
        return Ok(None);
    }

    let url = String::from_utf8(output.stdout)
        .context("git remote get-url output was not valid UTF-8")?;
    Ok(Some(url.trim().to_string()))
}

/// Resolve the push remote for a specific repository.
pub fn resolve_push_remote_at(repo: &Path) -> Result<Option<String>> {
    let output = run_git_output_at(
        Some(repo),
        &["symbolic-ref", "--quiet", "--short", "HEAD"],
        &[],
    )
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
    if let Ok(Some(remote)) = config_get_at(repo, &push_remote_key)
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    if let Ok(Some(remote)) = config_get_at(repo, "remote.pushDefault")
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let branch_remote_key = format!("branch.{}.remote", branch);
    if let Ok(Some(remote)) = config_get_at(repo, &branch_remote_key)
        && !remote.is_empty()
        && remote != "."
    {
        return Ok(Some(remote));
    }

    let remotes = match git_output_in(repo, &["remote"]) {
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
pub(crate) fn first_remote_url_at(repo: &Path) -> Result<Option<String>> {
    let output =
        run_git_output_at(Some(repo), &["remote"], &[]).context("failed to execute git remote")?;

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
        .context("failed to execute git remote get-url")?;

    if !url_output.status.success() {
        return Ok(None);
    }

    let url = String::from_utf8(url_output.stdout)
        .context("git remote get-url output was not valid UTF-8")?;
    Ok(Some(url.trim().to_string()))
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
#[allow(dead_code)]
pub fn remote_orgs() -> Result<Vec<String>> {
    let remotes = git_output(&["remote"])?;
    let mut orgs = Vec::new();

    for remote_name in remotes.lines() {
        if remote_name.is_empty() {
            continue;
        }
        if let Ok(url) = git_output(&["remote", "get-url", remote_name])
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
pub fn remote_orgs_at(repo: &Path) -> Result<Vec<String>> {
    let remotes = git_output_in(repo, &["remote"])?;
    let mut orgs = Vec::new();

    for remote_name in remotes.lines() {
        if remote_name.is_empty() {
            continue;
        }
        if let Ok(url) = git_output_in(repo, &["remote", "get-url", remote_name])
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
pub fn config_get(key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(None, &["config", "--get", key], &[])
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
pub fn config_get_at(repo: &Path, key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(Some(repo), &["config", "--get", key], &[])
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

/// Read a git config value from global scope. Returns `Ok(None)` if the key is not set.
///
/// Uses `--global` flag to read only the global config, not repo-local.
/// This is used for settings like `ai.cadence.org` that are set at install time.
pub fn config_get_global(key: &str) -> Result<Option<String>> {
    let output = run_git_output_at(None, &["config", "--global", "--get", key], &[])
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
pub fn repo_matches_org_filter(repo: &Path) -> Result<bool> {
    let configured_org = match config_get_global("ai.cadence.org") {
        Ok(Some(org)) => org,
        _ => return Ok(true),
    };

    let remote_orgs = remote_orgs_at(repo)?;
    Ok(remote_orgs
        .iter()
        .any(|org| org.eq_ignore_ascii_case(&configured_org)))
}

/// Write a git config value (repo-local scope).
#[cfg(test)]
pub fn config_set(key: &str, value: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", key, value], &[])
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
pub fn config_set_global(key: &str, value: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", "--global", key, value], &[])
        .context("failed to execute git config --global set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config --global set failed: {}", stderr.trim());
    }
    Ok(())
}

/// Remove a git config key from global scope (`--global --unset`).
///
/// Returns `Ok(())` if the key was removed or was already absent.
/// Returns an error only on genuine git failures.
pub fn config_unset_global(key: &str) -> Result<()> {
    let output = run_git_output_at(None, &["config", "--global", "--unset", key], &[])
        .context("failed to execute git config --global --unset")?;

    if !output.status.success() {
        // Exit code 5 means the key was not set — not an error for us.
        let code = output.status.code().unwrap_or(-1);
        if code != 5 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "git config --global --unset {:?} failed (exit {}): {}",
                key,
                code,
                stderr.trim()
            );
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
    use std::process::Command;
    use tempfile::TempDir;

    /// Helper: create a temporary git repo with one commit.
    /// Returns the TempDir (which cleans up on drop) and sets the
    /// working directory for the test by returning a guard.
    ///
    /// Note: since we cannot change the process-wide CWD safely in
    /// parallel tests, all git commands in tests must use `-C <path>`.
    /// We provide a `git_in` helper for this.
    fn init_temp_repo() -> TempDir {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        // git init
        run_git(path, &["init"]);
        // Set required user config for commits
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        // Override hooksPath to prevent the global post-commit hook from firing
        run_git(path, &["config", "core.hooksPath", "/dev/null"]);
        // Create an initial commit
        std::fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        dir
    }

    /// Run a git command inside the given directory, panicking on failure.
    fn run_git(dir: &std::path::Path, args: &[&str]) -> String {
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

    /// Run one of our git module functions inside a specific directory
    /// by temporarily overriding GIT_DIR behaviour via `-C`.
    /// Since our public functions don't take a path arg (they rely on cwd),
    /// we use a wrapper approach: spawn a git command with `-C`.
    fn git_output_in(dir: &std::path::Path, args: &[&str]) -> Result<String> {
        let output = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .context("failed to execute git")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }

        let stdout = String::from_utf8(output.stdout).context("git output was not valid UTF-8")?;
        Ok(stdout.trim().to_string())
    }

    #[test]
    fn test_parse_log_line_valid() {
        let line = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\tabc1234\t2026-02-12\tsubject";
        let parsed = parse_log_line(line).expect("expected parsed log line");
        assert_eq!(parsed.0, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(parsed.1, "abc1234");
        assert_eq!(parsed.2, "2026-02-12");
        assert_eq!(parsed.3, "subject");
    }

    #[test]
    fn test_parse_log_line_invalid() {
        assert!(parse_log_line("bad-line").is_none());
        assert!(parse_log_line("\tabc1234\t2026-02-12\tsubject").is_none());
    }

    #[test]
    fn test_parse_noted_commit_ids_uses_second_column() {
        let input = "\
1111111111111111111111111111111111111111 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
2222222222222222222222222222222222222222 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
";
        let ids = parse_noted_commit_ids(input);
        assert!(ids.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        assert!(ids.contains("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));
        assert!(!ids.contains("1111111111111111111111111111111111111111"));
    }

    // -----------------------------------------------------------------------
    // repo_root — tested via direct git command in temp dir
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_root() {
        let dir = init_temp_repo();
        let root = git_output_in(dir.path(), &["rev-parse", "--show-toplevel"]).unwrap();
        let root_path = PathBuf::from(&root);
        // The root should be the temp dir (possibly canonicalized)
        assert!(root_path.exists());
        // The root should contain the README we created
        assert!(root_path.join("README.md").exists());
    }

    // -----------------------------------------------------------------------
    // head_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_hash() {
        let dir = init_temp_repo();
        let hash = git_output_in(dir.path(), &["rev-parse", "HEAD"]).unwrap();
        // Full SHA is 40 hex characters
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // head_timestamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_timestamp() {
        let dir = init_temp_repo();
        let ts_str = git_output_in(dir.path(), &["show", "-s", "--format=%ct", "HEAD"]).unwrap();
        let ts: i64 = ts_str.parse().unwrap();
        // Should be a reasonable Unix timestamp (after 2020)
        assert!(ts > 1_577_836_800);
    }

    // -----------------------------------------------------------------------
    // note_exists + add_note
    // -----------------------------------------------------------------------

    #[test]
    fn test_note_exists_false_then_true_after_add() {
        let dir = init_temp_repo();
        let path = dir.path();
        let hash = run_git(path, &["rev-parse", "HEAD"]);

        // No note yet
        let status = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["notes", "--ref", NOTES_REF, "show", &hash])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());

        // Add a note
        run_git(
            path,
            &[
                "notes",
                "--ref",
                NOTES_REF,
                "add",
                "-m",
                "test note content",
                &hash,
            ],
        );

        // Now note exists
        let status = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["notes", "--ref", NOTES_REF, "show", &hash])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());

        // Verify content
        let note_content =
            git_output_in(path, &["notes", "--ref", NOTES_REF, "show", &hash]).unwrap();
        assert_eq!(note_content, "test note content");
    }

    // -----------------------------------------------------------------------
    // has_upstream
    // -----------------------------------------------------------------------

    #[test]
    fn test_has_upstream_false_when_no_remote() {
        let dir = init_temp_repo();
        let remotes = git_output_in(dir.path(), &["remote"]).unwrap();
        assert!(remotes.is_empty());
    }

    #[test]
    fn test_has_upstream_true_when_remote_added() {
        let dir = init_temp_repo();
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        );
        let remotes = git_output_in(path, &["remote"]).unwrap();
        assert!(!remotes.is_empty());
    }

    // -----------------------------------------------------------------------
    // remote_org (via parse_org_from_url — pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_org_from_ssh_url() {
        let org = parse_org_from_url("git@github.com:my-org/my-repo.git");
        assert_eq!(org, Some("my-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_https_url() {
        let org = parse_org_from_url("https://github.com/other-org/some-repo.git");
        assert_eq!(org, Some("other-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_http_url() {
        let org = parse_org_from_url("http://github.com/http-org/repo.git");
        assert_eq!(org, Some("http-org".to_string()));
    }

    #[test]
    fn test_parse_org_from_unknown_url() {
        let org = parse_org_from_url("svn://example.com/repo");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_empty_url() {
        let org = parse_org_from_url("");
        assert_eq!(org, None);
    }

    // -----------------------------------------------------------------------
    // parse_org_from_url (integration test with temp repo)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_org_from_url_integration() {
        let dir = init_temp_repo();
        let path = dir.path();
        run_git(
            path,
            &[
                "remote",
                "add",
                "origin",
                "git@github.com:acme-corp/widgets.git",
            ],
        );
        let url = git_output_in(path, &["remote", "get-url", "origin"]).unwrap();
        let org = parse_org_from_url(&url);
        assert_eq!(org, Some("acme-corp".to_string()));
    }

    // -----------------------------------------------------------------------
    // config_get + config_set
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_get_missing_key() {
        let dir = init_temp_repo();
        let path = dir.path();
        let output = Command::new("git")
            .args(["-C", path.to_str().unwrap()])
            .args(["config", "--get", "ai.cadence.nonexistent"])
            .output()
            .unwrap();
        // Should exit non-zero (key not set)
        assert!(!output.status.success());
    }

    #[test]
    fn test_config_set_then_get() {
        let dir = init_temp_repo();
        let path = dir.path();

        // Set a config value
        run_git(path, &["config", "ai.cadence.enabled", "true"]);

        // Read it back
        let value = git_output_in(path, &["config", "--get", "ai.cadence.enabled"]).unwrap();
        assert_eq!(value, "true");
    }

    #[test]
    fn test_config_overwrite() {
        let dir = init_temp_repo();
        let path = dir.path();

        run_git(path, &["config", "ai.cadence.org", "first-org"]);
        run_git(path, &["config", "ai.cadence.org", "second-org"]);

        let value = git_output_in(path, &["config", "--get", "ai.cadence.org"]).unwrap();
        assert_eq!(value, "second-org");
    }

    // -----------------------------------------------------------------------
    // Multiple commits — verify head_hash changes
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_hash_changes_after_new_commit() {
        let dir = init_temp_repo();
        let path = dir.path();

        let hash1 = run_git(path, &["rev-parse", "HEAD"]);

        // Make another commit
        std::fs::write(path.join("file2.txt"), "content").unwrap();
        run_git(path, &["add", "file2.txt"]);
        run_git(path, &["commit", "-m", "second commit"]);

        let hash2 = run_git(path, &["rev-parse", "HEAD"]);

        assert_ne!(hash1, hash2);
        assert_eq!(hash2.len(), 40);
    }

    // -----------------------------------------------------------------------
    // validate_commit_hash
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_commit_hash_valid_short() {
        assert!(validate_commit_hash("abcdef0").is_ok());
    }

    #[test]
    fn test_validate_commit_hash_valid_full() {
        assert!(validate_commit_hash("abcdef0123456789abcdef0123456789abcdef01").is_ok());
    }

    #[test]
    fn test_validate_commit_hash_rejects_flag_injection() {
        assert!(validate_commit_hash("--help").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_too_short() {
        assert!(validate_commit_hash("abc").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_non_hex() {
        assert!(validate_commit_hash("ghijklm").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_empty() {
        assert!(validate_commit_hash("").is_err());
    }

    #[test]
    fn test_validate_commit_hash_rejects_too_long() {
        assert!(validate_commit_hash("a".repeat(41).as_str()).is_err());
    }

    // -----------------------------------------------------------------------
    // parse_org_from_url — edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_org_from_url_https_with_trailing_slash() {
        // Trailing slash after org — org segment should still parse
        let org = parse_org_from_url("https://github.com/org/");
        assert_eq!(org, Some("org".to_string()));
    }

    #[test]
    fn test_parse_org_from_url_https_host_only() {
        // No org segment after host
        let org = parse_org_from_url("https://github.com/");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_from_url_https_host_no_trailing_slash() {
        let org = parse_org_from_url("https://github.com");
        assert_eq!(org, None);
    }

    #[test]
    fn test_parse_org_from_url_ssh_nested_path() {
        // SSH with nested paths — org is the first segment after the colon
        let org = parse_org_from_url("git@github.com:org/sub/repo.git");
        assert_eq!(org, Some("org".to_string()));
    }

    // -----------------------------------------------------------------------
    // commits_in_time_range
    // -----------------------------------------------------------------------

    #[test]
    fn test_commits_in_time_range_includes_commit() {
        let dir = init_temp_repo();
        let path = dir.path();

        let hash = run_git(path, &["rev-parse", "HEAD"]);
        let ts_str = run_git(path, &["show", "-s", "--format=%ct", "HEAD"]);
        let ts: i64 = ts_str.parse().unwrap();

        let commits = commits_in_time_range(path, ts - 10, ts + 10).unwrap();
        assert!(commits.contains(&hash));
    }

    #[test]
    fn test_commits_in_time_range_empty_outside_window() {
        let dir = init_temp_repo();
        let path = dir.path();

        let ts_str = run_git(path, &["show", "-s", "--format=%ct", "HEAD"]);
        let ts: i64 = ts_str.parse().unwrap();

        let commits = commits_in_time_range(path, ts - 10_000, ts - 9_000).unwrap();
        assert!(commits.is_empty());
    }

    #[test]
    fn test_parse_org_from_url_https_with_port() {
        let org = parse_org_from_url("https://github.com:443/org/repo.git");
        // The host segment is "github.com:443", org is next path segment
        assert_eq!(org, Some("org".to_string()));
    }

    #[test]
    fn test_parse_org_from_url_https_with_auth() {
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
    fn enter_temp_repo() -> (TempDir, PathBuf) {
        let original_cwd = std::env::current_dir().expect("failed to get cwd");
        let dir = init_temp_repo();
        std::env::set_current_dir(dir.path()).expect("failed to chdir into temp repo");
        (dir, original_cwd)
    }

    #[test]
    #[serial]
    fn test_api_repo_root() {
        let (_dir, original_cwd) = enter_temp_repo();
        let root = repo_root().expect("repo_root failed");
        assert!(root.join("README.md").exists());
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_head_hash() {
        let (_dir, original_cwd) = enter_temp_repo();
        let hash = head_hash().expect("head_hash failed");
        assert_eq!(hash.len(), 40);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_head_timestamp() {
        let (_dir, original_cwd) = enter_temp_repo();
        let ts = head_timestamp().expect("head_timestamp failed");
        assert!(ts > 1_577_836_800); // After 2020
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_note_exists_and_add_note() {
        let (_dir, original_cwd) = enter_temp_repo();
        let hash = head_hash().expect("head_hash failed");

        // No note yet
        assert!(!note_exists(&hash).expect("note_exists failed"));

        // Add a note via the public API
        add_note(&hash, "test session data").expect("add_note failed");

        // Now it should exist
        assert!(note_exists(&hash).expect("note_exists failed after add"));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_has_upstream_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo();
        assert!(!has_upstream().expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_has_upstream_with_remote() {
        let (dir, original_cwd) = enter_temp_repo();
        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/test-org/test-repo.git",
            ],
        );
        assert!(has_upstream().expect("has_upstream failed"));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // resolve_push_remote
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_resolve_push_remote_prefers_branch_push_remote() {
        let (dir, original_cwd) = enter_temp_repo();
        let branch = run_git(dir.path(), &["symbolic-ref", "--short", "HEAD"]);

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/example/upstream.git",
            ],
        );
        run_git(
            dir.path(),
            &[
                "config",
                &format!("branch.{}.pushRemote", branch),
                "upstream",
            ],
        );

        let resolved = resolve_push_remote().expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("upstream".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_resolve_push_remote_uses_push_default() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "fork",
                "https://github.com/example/fork.git",
            ],
        );
        run_git(dir.path(), &["config", "remote.pushDefault", "fork"]);

        let resolved = resolve_push_remote().expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("fork".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_resolve_push_remote_uses_branch_remote() {
        let (dir, original_cwd) = enter_temp_repo();
        let branch = run_git(dir.path(), &["symbolic-ref", "--short", "HEAD"]);

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://github.com/example/origin.git",
            ],
        );
        run_git(
            dir.path(),
            &["config", &format!("branch.{}.remote", branch), "origin"],
        );

        let resolved = resolve_push_remote().expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("origin".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_resolve_push_remote_uses_single_remote_fallback() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(
            dir.path(),
            &[
                "remote",
                "add",
                "solo",
                "https://github.com/example/solo.git",
            ],
        );

        let resolved = resolve_push_remote().expect("resolve_push_remote failed");
        assert_eq!(resolved, Some("solo".to_string()));

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_resolve_push_remote_detached_head_returns_none() {
        let (dir, original_cwd) = enter_temp_repo();
        run_git(dir.path(), &["checkout", "--detach", "HEAD"]);

        let resolved = resolve_push_remote().expect("resolve_push_remote failed");
        assert_eq!(resolved, None);

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_config_get_missing() {
        let (_dir, original_cwd) = enter_temp_repo();
        let val = config_get("ai.cadence.nonexistent").expect("config_get failed");
        assert_eq!(val, None);
        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_api_config_set_then_get() {
        let (_dir, original_cwd) = enter_temp_repo();
        config_set("ai.cadence.enabled", "true").expect("config_set failed");
        let val = config_get("ai.cadence.enabled").expect("config_get failed");
        assert_eq!(val, Some("true".to_string()));
        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // check_enabled
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_check_enabled_default_true() {
        let (_dir, original_cwd) = enter_temp_repo();

        // No config set -- should default to enabled
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_explicitly_true() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.cadence.enabled", "true"]);
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_explicitly_false() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.cadence.enabled", "false"]);
        assert!(!check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_check_enabled_other_value_treated_as_true() {
        let (dir, original_cwd) = enter_temp_repo();

        run_git(dir.path(), &["config", "ai.cadence.enabled", "yes"]);
        assert!(check_enabled());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: detached HEAD
    // -----------------------------------------------------------------------

    #[test]
    fn test_head_hash_works_in_detached_head() {
        let dir = init_temp_repo();
        let path = dir.path();

        // Get the current HEAD hash, then detach HEAD
        let hash = run_git(path, &["rev-parse", "HEAD"]);
        run_git(path, &["checkout", "--detach", "HEAD"]);

        // `git rev-parse HEAD` should still return the same hash in detached state
        let detached_hash = git_output_in(path, &["rev-parse", "HEAD"]).unwrap();
        assert_eq!(hash, detached_hash);
        assert_eq!(detached_hash.len(), 40);
    }

    #[test]
    fn test_head_timestamp_works_in_detached_head() {
        let dir = init_temp_repo();
        let path = dir.path();

        // Get the timestamp before detaching
        let ts_before = git_output_in(path, &["show", "-s", "--format=%ct", "HEAD"]).unwrap();

        run_git(path, &["checkout", "--detach", "HEAD"]);

        // Timestamp should still be readable in detached state
        let ts_after = git_output_in(path, &["show", "-s", "--format=%ct", "HEAD"]).unwrap();
        assert_eq!(ts_before, ts_after);
    }

    #[test]
    fn test_note_operations_work_in_detached_head() {
        let dir = init_temp_repo();
        let path = dir.path();

        let hash = run_git(path, &["rev-parse", "HEAD"]);
        run_git(path, &["checkout", "--detach", "HEAD"]);

        // note_exists_at should work in detached HEAD
        let exists = note_exists_at(path, &hash).expect("note_exists_at failed in detached HEAD");
        assert!(!exists);

        // add_note_at should work in detached HEAD
        add_note_at(path, &hash, "test detached note")
            .expect("add_note_at failed in detached HEAD");

        // Verify the note was attached
        let exists = note_exists_at(path, &hash).expect("note_exists_at failed after add");
        assert!(exists);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: repo with no remotes
    // -----------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_push_notes_fails_gracefully_no_remote() {
        let (_dir, original_cwd) = enter_temp_repo();

        // push_notes should fail (no remote) but not panic
        let result = push_notes("origin");
        assert!(result.is_err());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    #[serial]
    fn test_remote_orgs_empty_when_no_remotes() {
        let (_dir, original_cwd) = enter_temp_repo();

        let orgs = remote_orgs().expect("remote_orgs failed");
        assert!(orgs.is_empty());

        std::env::set_current_dir(original_cwd).unwrap();
    }

    #[test]
    fn test_remote_orgs_at_collects_orgs() {
        let dir = init_temp_repo();
        let path = dir.path();

        run_git(
            path,
            &["remote", "add", "origin", "git@github.com:org-one/repo.git"],
        );
        run_git(
            path,
            &[
                "remote",
                "add",
                "upstream",
                "https://github.com/org-two/repo.git",
            ],
        );

        let orgs = remote_orgs_at(path).expect("remote_orgs_at failed");
        assert_eq!(orgs.len(), 2);
        assert!(orgs.contains(&"org-one".to_string()));
        assert!(orgs.contains(&"org-two".to_string()));
    }

    #[test]
    #[serial]
    fn test_repo_matches_org_filter() {
        let dir = init_temp_repo();
        let path = dir.path();

        run_git(
            path,
            &["remote", "add", "origin", "git@github.com:my-org/repo.git"],
        );

        let global_config = path.join("fake-global-gitconfig");
        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = my-org\n").unwrap();

        let original_global = std::env::var("GIT_CONFIG_GLOBAL").ok();
        unsafe {
            std::env::set_var("GIT_CONFIG_GLOBAL", &global_config);
        }

        let matches = repo_matches_org_filter(path).expect("repo_matches_org_filter failed");
        assert!(matches);

        std::fs::write(&global_config, "[ai \"cadence\"]\n    org = other-org\n").unwrap();
        let matches = repo_matches_org_filter(path).expect("repo_matches_org_filter failed");
        assert!(!matches);

        unsafe {
            match original_global {
                Some(g) => std::env::set_var("GIT_CONFIG_GLOBAL", g),
                None => std::env::remove_var("GIT_CONFIG_GLOBAL"),
            }
        }
    }

    // -----------------------------------------------------------------------
    // store_blob / read_blob
    // -----------------------------------------------------------------------

    #[test]
    fn test_store_and_read_blob_roundtrip() {
        let dir = init_temp_repo();
        let data = b"hello, this is a test blob";

        let sha = store_blob_at(Some(dir.path()), data).expect("store_blob_at failed");
        assert_eq!(sha.len(), 40);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));

        let read_back = read_blob_at(Some(dir.path()), &sha).expect("read_blob_at failed");
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_store_blob_binary_data() {
        let dir = init_temp_repo();
        // Binary data including null bytes
        let data: Vec<u8> = (0..=255).collect();

        let sha = store_blob_at(Some(dir.path()), &data).expect("store_blob_at failed");
        let read_back = read_blob_at(Some(dir.path()), &sha).expect("read_blob_at failed");
        assert_eq!(read_back, data);
    }

    #[test]
    fn test_store_blob_empty() {
        let dir = init_temp_repo();
        let sha = store_blob_at(Some(dir.path()), b"").expect("store_blob_at failed");
        let read_back = read_blob_at(Some(dir.path()), &sha).expect("read_blob_at failed");
        assert!(read_back.is_empty());
    }

    #[test]
    fn test_store_blob_deterministic() {
        let dir = init_temp_repo();
        let data = b"same content";

        let sha1 = store_blob_at(Some(dir.path()), data).expect("first store failed");
        let sha2 = store_blob_at(Some(dir.path()), data).expect("second store failed");
        assert_eq!(sha1, sha2, "same content should produce same SHA");
    }

    #[test]
    fn test_read_blob_nonexistent() {
        let dir = init_temp_repo();
        let result = read_blob_at(Some(dir.path()), "0000000000000000000000000000000000000000");
        assert!(result.is_err());
    }
}
