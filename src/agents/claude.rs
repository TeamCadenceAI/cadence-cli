//! Claude Code agent log discovery.
//!
//! Claude Code stores session logs under `~/.claude/projects/<encoded-path>/`.
//! The encoded path replaces `/` with `-` in the absolute repo path.
//! For example, a repo at `/Users/foo/bar` produces a directory named
//! `-Users-foo-bar` under `~/.claude/projects/`.

use std::fs;
use std::path::{Path, PathBuf};

use super::home_dir;

/// Return ALL directories under `~/.claude/projects/`.
///
/// Unlike `log_dirs`, this function is not scoped to a specific repository.
/// It returns every project directory, for use by the `backfill` command
/// which needs to scan all sessions regardless of repo.
///
/// Returns an empty `Vec` if:
/// - The home directory cannot be resolved
/// - `~/.claude/projects/` does not exist
pub fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    all_log_dirs_in(&home)
}

/// Internal: find ALL Claude log directories under a given home directory.
///
/// Separated from `all_log_dirs` for testability.
fn all_log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let projects_dir = home.join(".claude").join("projects");
    let entries = match fs::read_dir(&projects_dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut dirs = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

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
    use std::fs;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // all_log_dirs_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_log_dirs_returns_all_directories() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create multiple project directories
        fs::create_dir(projects_dir.join("-Users-foo-bar")).unwrap();
        fs::create_dir(projects_dir.join("-Users-baz-qux")).unwrap();
        fs::create_dir(projects_dir.join("-home-user-project")).unwrap();

        let result = all_log_dirs_in(home.path());
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_all_log_dirs_returns_empty_when_no_projects_dir() {
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_all_log_dirs_ignores_files() {
        let home = TempDir::new().unwrap();
        let projects_dir = home.path().join(".claude").join("projects");
        fs::create_dir_all(&projects_dir).unwrap();

        // Create a file (not a directory)
        fs::write(projects_dir.join("some-file"), "not a dir").unwrap();
        // Create a directory
        fs::create_dir(projects_dir.join("-Users-foo-bar")).unwrap();

        let result = all_log_dirs_in(home.path());
        assert_eq!(result.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Phase 12 hardening: missing ~/.claude/ directory
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_log_dirs_graceful_when_claude_dir_missing() {
        // Same for all_log_dirs: missing ~/.claude/ should not error.
        let home = TempDir::new().unwrap();
        let result = all_log_dirs_in(home.path());
        assert!(result.is_empty());
    }
}
