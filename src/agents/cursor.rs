//! Cursor agent log discovery.
//!
//! Cursor stores chat sessions in two places:
//! - VS Code style chatSessions:
//!   - macOS: ~/Library/Application Support/Cursor/User/workspaceStorage/*/chatSessions/*.json
//!   - Linux: ~/.config/Cursor/User/workspaceStorage/*/chatSessions/*.json
//!   - Windows: %APPDATA%\\Cursor\\User\\workspaceStorage\\*\\chatSessions\\*.json
//! - Cursor projects:
//!   ~/.cursor/projects/<workspace-id>/*.{json,txt}

use std::path::{Path, PathBuf};

use super::{
    AgentExplorer, SessionLog, SessionSource, app_config_dir_in, find_chat_session_dirs, home_dir,
    recent_files_with_exts,
};
use crate::scanner::AgentType;
use async_trait::async_trait;

const CURSOR_PROJECT_SKIP_DIRS: &[&str] = &["mcps"];

/// Return all Cursor log directories for use by the post-commit hook.
pub async fn log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

/// Return all Cursor log directories for backfill (not repo-scoped).
pub async fn all_log_dirs() -> Vec<PathBuf> {
    log_dirs().await
}

pub struct CursorExplorer;

#[async_trait]
impl AgentExplorer for CursorExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let dirs = all_log_dirs().await;
        recent_files_with_exts(&dirs, now, since_secs, &["json", "txt"])
            .await
            .into_iter()
            .map(|file| SessionLog {
                agent_type: AgentType::Cursor,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            })
            .collect()
    }
}

async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // VS Code style chatSessions.
    let ws_root = app_config_dir_in("Cursor", home)
        .join("User")
        .join("workspaceStorage");
    dirs.extend(find_chat_session_dirs(&ws_root).await);

    // Cursor projects directory (scan recursively for json/txt files).
    let projects_dir = home.join(".cursor").join("projects");
    collect_cursor_project_dirs(&projects_dir, &mut dirs).await;

    dirs
}

async fn collect_cursor_project_dirs(root: &Path, results: &mut Vec<PathBuf>) {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let mut entries = match tokio::fs::read_dir(&dir).await {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        let mut has_match = false;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            let file_type = match entry.file_type().await {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                    continue;
                };
                if CURSOR_PROJECT_SKIP_DIRS.contains(&name) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() && !has_match {
                let has_supported_ext =
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| {
                            ["json", "txt"]
                                .iter()
                                .any(|allowed| allowed.eq_ignore_ascii_case(ext))
                        });
                if has_supported_ext {
                    has_match = true;
                }
            }
        }

        if has_match {
            results.push(dir);
        }
    }
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
    async fn test_cursor_log_dirs_collects_chat_sessions_and_projects() {
        let home = TempDir::new().unwrap();

        let ws_root = app_config_dir_in("Cursor", home.path())
            .join("User")
            .join("workspaceStorage")
            .join("abc")
            .join("chatSessions");
        tokio::fs::create_dir_all(&ws_root).await.unwrap();

        let projects_dir = home.path().join(".cursor").join("projects").join("p1");
        tokio::fs::create_dir_all(&projects_dir).await.unwrap();
        tokio::fs::write(projects_dir.join("session.txt"), "content")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;

        assert!(dirs.contains(&ws_root));
        assert!(dirs.contains(&projects_dir));
    }

    #[tokio::test]
    async fn test_cursor_log_dirs_skips_mcps_project_metadata() {
        let home = TempDir::new().unwrap();
        let mcps_tools_dir = home
            .path()
            .join(".cursor")
            .join("projects")
            .join("p1")
            .join("mcps")
            .join("user-shadcn-ui")
            .join("tools");
        tokio::fs::create_dir_all(&mcps_tools_dir).await.unwrap();
        tokio::fs::write(mcps_tools_dir.join("get_component.json"), "{}")
            .await
            .unwrap();

        let real_project_dir = home.path().join(".cursor").join("projects").join("p2");
        tokio::fs::create_dir_all(&real_project_dir).await.unwrap();
        tokio::fs::write(real_project_dir.join("session.txt"), "content")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;

        assert!(dirs.contains(&real_project_dir));
        assert!(!dirs.contains(&mcps_tools_dir));
    }
}
