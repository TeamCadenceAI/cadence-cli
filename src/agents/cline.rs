//! Cline log discovery.
//!
//! Cline stores task/session artifacts under extension global storage and
//! backup folders.

use std::path::{Path, PathBuf};

use super::{
    AgentExplorer, SessionLog, SessionSource, app_config_dir_in, collect_dirs_with_exts, home_dir,
    recent_files_with_exts,
};
use crate::scanner::AgentType;
use async_trait::async_trait;

const CLINE_EXT_IDS: &[&str] = &["saoudrizwan.claude-dev", "cline.cline"];
const IDE_APPS: &[&str] = &["Code", "Cursor", "Windsurf", "VSCodium"];

pub async fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

pub struct ClineExplorer;

#[async_trait]
impl AgentExplorer for ClineExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let dirs = all_log_dirs().await;
        recent_files_with_exts(&dirs, now, since_secs, &["json"])
            .await
            .into_iter()
            .map(|file| SessionLog {
                agent_type: AgentType::Cline,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            })
            .collect()
    }
}

async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    for app in IDE_APPS {
        let global_storage = app_config_dir_in(app, home)
            .join("User")
            .join("globalStorage");
        for ext in CLINE_EXT_IDS {
            collect_dirs_with_exts(
                &global_storage.join(ext).join("tasks"),
                &mut dirs,
                &["json"],
            )
            .await;
        }
    }

    for backup in [
        home.join(".cline").join("task-history"),
        home.join(".cline").join("tasks"),
        home.join(".cline").join("data").join("tasks"),
    ] {
        collect_dirs_with_exts(&backup, &mut dirs, &["json"]).await;
    }

    dirs.sort();
    dirs.dedup();
    dirs
}
#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[tokio::test]
    async fn test_cline_log_dirs_collects_global_storage_and_backup_dirs() {
        let home = TempDir::new().unwrap();

        let task_dir = app_config_dir_in("Code", home.path())
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("tasks")
            .join("task-1");
        tokio::fs::create_dir_all(&task_dir).await.unwrap();
        tokio::fs::write(task_dir.join("task-1.json"), "{}")
            .await
            .unwrap();

        let backup_dir = home.path().join(".cline").join("task-history").join("abc");
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();
        tokio::fs::write(backup_dir.join("ui_messages.json"), "{}")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;

        assert!(dirs.contains(&task_dir));
        assert!(dirs.contains(&backup_dir));
    }

    #[tokio::test]
    async fn test_cline_log_dirs_ignores_non_json_files() {
        let home = TempDir::new().unwrap();

        let task_dir = app_config_dir_in("Code", home.path())
            .join("User")
            .join("globalStorage")
            .join("saoudrizwan.claude-dev")
            .join("tasks")
            .join("task-1");
        tokio::fs::create_dir_all(&task_dir).await.unwrap();
        tokio::fs::write(task_dir.join("note.txt"), "nope")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert!(!dirs.contains(&task_dir));
    }
}
