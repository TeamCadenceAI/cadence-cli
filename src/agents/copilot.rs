//! Copilot (VS Code chat sessions) log discovery.
//!
//! VS Code stores chat sessions under:
//! - macOS: ~/Library/Application Support/Code/User/workspaceStorage/*/chatSessions/*.json
//! - Linux: ~/.config/Code/User/workspaceStorage/*/chatSessions/*.json
//! - Windows: %APPDATA%\\Code\\User\\workspaceStorage\\*\\chatSessions\\*.json

use std::path::{Path, PathBuf};

use super::{app_config_dir_in, find_chat_session_dirs, home_dir};

/// Return all Copilot log directories for use by the post-commit hook.
pub async fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

/// Return all Copilot log directories for backfill (not repo-scoped).
pub async fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs().await
}

async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let ws_root = app_config_dir_in("Code", home)
        .join("User")
        .join("workspaceStorage");
    find_chat_session_dirs(&ws_root).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::app_config_dir_in;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_copilot_log_dirs_collects_chat_sessions() {
        let home = TempDir::new().unwrap();
        let ws_root = app_config_dir_in("Code", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        tokio::fs::create_dir_all(&ws_root).await.unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert_eq!(dirs, vec![ws_root]);
    }
}
