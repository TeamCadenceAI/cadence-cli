//! Claude Code agent log discovery.
//!
//! Claude Code stores session logs under `~/.claude/projects/<encoded-path>/`.
//! The encoded path replaces `/` with `-` in the absolute repo path.
//! For example, a repo at `/Users/foo/bar` produces a directory named
//! `-Users-foo-bar` under `~/.claude/projects/`.

use std::path::{Path, PathBuf};

use super::{AgentExplorer, SessionLog, SessionSource, home_dir, recent_files_with_exts};
use crate::scanner::AgentType;
use async_trait::async_trait;

/// Return ALL directories under `~/.claude/projects/`.
///
/// Unlike `log_dirs`, this function is not scoped to a specific repository.
/// It returns every project directory, for use by the `backfill` command
/// which needs to scan all sessions regardless of repo.
///
/// Returns an empty `Vec` if:
/// - The home directory cannot be resolved
/// - `~/.claude/projects/` does not exist
pub async fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    all_log_dirs_in(&home).await
}

pub struct ClaudeExplorer;

#[async_trait]
impl AgentExplorer for ClaudeExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let dirs = all_log_dirs().await;
        recent_files_with_exts(&dirs, now, since_secs, &["jsonl"])
            .await
            .into_iter()
            .map(|file| SessionLog {
                agent_type: AgentType::Claude,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            })
            .collect()
    }
}

/// Internal: find ALL Claude log directories under a given home directory.
///
/// Separated from `all_log_dirs` for testability.
async fn all_log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let projects_dir = home.join(".claude").join("projects");
    let mut entries = match tokio::fs::read_dir(&projects_dir).await {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut dirs = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        }
    }

    dirs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // all_log_dirs_in
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_all_log_dirs_returns_all_directories() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&projects_dir).await.unwrap();

        // Create multiple project directories
        tokio::fs::create_dir(projects_dir.join("-Users-foo-bar"))
            .await
            .unwrap();
        tokio::fs::create_dir(projects_dir.join("-Users-baz-qux"))
            .await
            .unwrap();
        tokio::fs::create_dir(projects_dir.join("-home-user-project"))
            .await
            .unwrap();

        let result = all_log_dirs_in(home.path()).await;
        assert_eq!(result.len(), 3);
    }

    #[tokio::test]
    async fn test_all_log_dirs_returns_empty_when_no_projects_dir() {
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path()).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_all_log_dirs_ignores_files() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&projects_dir).await.unwrap();

        // Create a file (not a directory)
        tokio::fs::write(projects_dir.join("some-file"), "not a dir")
            .await
            .unwrap();
        // Create a directory
        tokio::fs::create_dir(projects_dir.join("-Users-foo-bar"))
            .await
            .unwrap();

        let result = all_log_dirs_in(home.path()).await;
        assert_eq!(result.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: missing ~/.claude/ directory
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_all_log_dirs_graceful_when_claude_dir_missing() {
        // Same for all_log_dirs: missing ~/.claude/ should not error.
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path()).await;
        assert!(result.is_empty());
    }
}
