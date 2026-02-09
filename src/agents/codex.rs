//! Codex agent log discovery.
//!
//! Codex stores session logs under `~/.codex/sessions/`.
//! Unlike Claude Code, Codex session directories are not scoped to a
//! specific repo path -- all sessions live in a flat directory.

use std::fs;
use std::path::{Path, PathBuf};

use super::home_dir;

/// Return ALL subdirectories under `~/.codex/sessions/`.
///
/// This function is identical to `log_dirs` for Codex (since Codex sessions
/// are already not scoped to a repo), but is provided for API symmetry with
/// `claude::all_log_dirs`. Used by the `hydrate` command.
pub fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Return all subdirectories under `~/.codex/sessions/`.
///
/// Codex does not encode the repo path into the directory name, so all
/// session directories are returned as candidates. The caller is responsible
/// for filtering by time window and content.
///
/// Returns an empty `Vec` if:
/// - The home directory cannot be resolved
/// - `~/.codex/sessions/` does not exist
///
/// The `_repo_path` parameter is accepted for API symmetry with
/// `claude::log_dirs` but is not used for filtering.
pub fn log_dirs(_repo_path: &Path) -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Internal: find Codex session directories under a given home directory.
///
/// Separated from `log_dirs` for testability -- tests pass a temp directory
/// instead of the real home, avoiding `unsafe` env var manipulation.
fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let sessions_dir = home.join(".codex").join("sessions");
    let entries = match fs::read_dir(&sessions_dir) {
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

    #[test]
    fn test_log_dirs_finds_session_directories() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();

        // Create session directories
        let session1 = sessions_dir.join("session-abc");
        let session2 = sessions_dir.join("session-def");
        fs::create_dir(&session1).unwrap();
        fs::create_dir(&session2).unwrap();

        let result = log_dirs_in(home.path());

        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_log_dirs_returns_empty_when_sessions_dir_missing() {
        let home = TempDir::new().unwrap();
        // Don't create .codex/sessions/

        let result = log_dirs_in(home.path());

        assert!(result.is_empty());
    }

    #[test]
    fn test_log_dirs_ignores_files() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();

        // Create a file (not a directory)
        fs::write(sessions_dir.join("not-a-dir.txt"), "content").unwrap();

        // Create an actual directory
        let session_dir = sessions_dir.join("real-session");
        fs::create_dir(&session_dir).unwrap();

        let result = log_dirs_in(home.path());

        assert_eq!(result.len(), 1);
        assert_eq!(result[0], session_dir);
    }

    #[test]
    fn test_log_dirs_returns_all_sessions() {
        // Codex log_dirs should return all session directories regardless
        // of content -- filtering happens later in candidate_files
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();

        fs::create_dir(sessions_dir.join("session-1")).unwrap();
        fs::create_dir(sessions_dir.join("session-2")).unwrap();
        fs::create_dir(sessions_dir.join("session-3")).unwrap();

        let result = log_dirs_in(home.path());

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_log_dirs_empty_sessions_directory() {
        let home = TempDir::new().unwrap();
        let sessions_dir = home.path().join(".codex").join("sessions");
        fs::create_dir_all(&sessions_dir).unwrap();
        // Sessions dir exists but is empty

        let result = log_dirs_in(home.path());

        assert!(result.is_empty());
    }
}
