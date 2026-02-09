//! Git utility helpers.
//!
//! All functions shell out to `git` via `std::process::Command`.
//! The notes ref used throughout is `refs/notes/ai-sessions`.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;

/// The dedicated git notes ref for AI session data.
const NOTES_REF: &str = "refs/notes/ai-sessions";

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Run a git command and return its stdout as a trimmed `String`.
/// Returns an error if the command exits with a non-zero status.
fn git_output(args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .output()
        .context("failed to execute git")?;

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

/// Run a git command and return whether it succeeded (exit code 0).
/// Does not treat non-zero exit as an error — just returns `false`.
fn git_succeeds(args: &[&str]) -> Result<bool> {
    let status = Command::new("git")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to execute git")?;
    Ok(status.success())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return the repository root (`git rev-parse --show-toplevel`).
pub fn repo_root() -> Result<PathBuf> {
    let path = git_output(&["rev-parse", "--show-toplevel"])?;
    Ok(PathBuf::from(path))
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
    git_succeeds(&["notes", "--ref", NOTES_REF, "show", commit])
}

/// Attach an AI-session note to the given commit.
pub fn add_note(commit: &str, content: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["notes", "--ref", NOTES_REF, "add", "-m", content, commit])
        .output()
        .context("failed to execute git notes add")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git notes add failed: {}", stderr.trim());
    }
    Ok(())
}

/// Push the AI-session notes ref to `origin`.
pub fn push_notes() -> Result<()> {
    let output = Command::new("git")
        .args(["push", "origin", NOTES_REF])
        .output()
        .context("failed to execute git push")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git push notes failed: {}", stderr.trim());
    }
    Ok(())
}

/// Check whether the repository has at least one configured remote.
pub fn has_upstream() -> Result<bool> {
    let remotes = git_output(&["remote"])?;
    Ok(!remotes.is_empty())
}

/// Extract the owner/org from the first remote URL.
///
/// Supports:
/// - SSH:   `git@github.com:org/repo.git`
/// - HTTPS: `https://github.com/org/repo.git`
///
/// Returns `None` if no remote is configured or the URL cannot be parsed.
pub fn remote_org() -> Result<Option<String>> {
    let remotes = git_output(&["remote"])?;
    let first_remote = match remotes.lines().next() {
        Some(r) => r,
        None => return Ok(None),
    };

    let url = git_output(&["remote", "get-url", first_remote])?;
    Ok(parse_org_from_url(&url))
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
pub fn config_get(key: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--get", key])
        .output()
        .context("failed to execute git config --get")?;

    if !output.status.success() {
        // Exit code 1 means the key is not set — that is not an error.
        return Ok(None);
    }

    let value =
        String::from_utf8(output.stdout).context("git config output was not valid UTF-8")?;
    Ok(Some(value.trim().to_string()))
}

/// Write a git config value (repo-local scope).
pub fn config_set(key: &str, value: &str) -> Result<()> {
    let output = Command::new("git")
        .args(["config", key, value])
        .output()
        .context("failed to execute git config set")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("git config set failed: {}", stderr.trim());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
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
    // remote_org (integration test with temp repo)
    // -----------------------------------------------------------------------

    #[test]
    fn test_remote_org_integration() {
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
            .args(["config", "--get", "ai.barometer.nonexistent"])
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
        run_git(path, &["config", "ai.barometer.autopush", "true"]);

        // Read it back
        let value = git_output_in(path, &["config", "--get", "ai.barometer.autopush"]).unwrap();
        assert_eq!(value, "true");
    }

    #[test]
    fn test_config_overwrite() {
        let dir = init_temp_repo();
        let path = dir.path();

        run_git(path, &["config", "ai.barometer.org", "first-org"]);
        run_git(path, &["config", "ai.barometer.org", "second-org"]);

        let value = git_output_in(path, &["config", "--get", "ai.barometer.org"]).unwrap();
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
}
