//! Cursor agent log discovery.
//!
//! Cursor stores chat sessions in two places:
//! - VS Code style chatSessions:
//!   ~/Library/Application Support/Cursor/User/workspaceStorage/*/chatSessions/*.json
//! - Cursor projects:
//!   ~/.cursor/projects/<workspace-id>/*.{json,txt}

use std::fs;
use std::path::{Path, PathBuf};

use super::{find_chat_session_dirs, home_dir};

/// Return all Cursor log directories for use by the post-commit hook.
pub fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Return all Cursor log directories for hydrate (not repo-scoped).
pub fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs()
}

fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // VS Code style chatSessions.
    let ws_root = home
        .join("Library")
        .join("Application Support")
        .join("Cursor")
        .join("User")
        .join("workspaceStorage");
    dirs.extend(find_chat_session_dirs(&ws_root));

    // Cursor projects directory.
    let projects_dir = home.join(".cursor").join("projects");
    if let Ok(entries) = fs::read_dir(&projects_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                dirs.push(path);
            }
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
    fn test_cursor_log_dirs_collects_chat_sessions_and_projects() {
        let home = TempDir::new().unwrap();

        let ws_root = home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Cursor")
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        fs::create_dir_all(&ws_root).unwrap();

        let projects_dir = home.path().join(".cursor").join("projects").join("p1");
        fs::create_dir_all(&projects_dir).unwrap();

        let dirs = log_dirs_in(home.path());

        assert!(dirs.contains(&ws_root));
        assert!(dirs.contains(&projects_dir));
    }
}
