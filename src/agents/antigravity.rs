//! Antigravity log discovery (VS Code style workspace storage).
//!
//! Antigravity stores chat sessions under:
//! ~/Library/Application Support/Antigravity/User/workspaceStorage/*/chatSessions/*.json

use std::path::{Path, PathBuf};

use super::{find_chat_session_dirs, home_dir};

/// Return all Antigravity log directories for use by the post-commit hook.
pub fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home)
}

/// Return all Antigravity log directories for hydrate (not repo-scoped).
pub fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs()
}

fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let ws_root = home
        .join("Library")
        .join("Application Support")
        .join("Antigravity")
        .join("User")
        .join("workspaceStorage");
    find_chat_session_dirs(&ws_root)
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
    fn test_antigravity_log_dirs_collects_chat_sessions() {
        let home = TempDir::new().unwrap();
        let ws_root = home
            .path()
            .join("Library")
            .join("Application Support")
            .join("Antigravity")
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        fs::create_dir_all(&ws_root).unwrap();

        let dirs = log_dirs_in(home.path());
        assert_eq!(dirs, vec![ws_root]);
    }
}
