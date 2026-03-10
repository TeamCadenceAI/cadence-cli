//! Amp Code log discovery.
//!
//! Primary source:
//! - `~/.local/share/amp/threads/*.json`
//!
//! Fallback source (if no threads are found):
//! - `~/.amp/file-changes/**/*.{json,jsonl}`

use std::path::{Path, PathBuf};

use super::{
    AgentExplorer, SessionLog, SessionSource, collect_dirs_with_exts, home_dir,
    recent_files_with_exts,
};
use crate::scanner::AgentType;
use async_trait::async_trait;

pub async fn all_log_dirs() -> Vec<PathBuf> {
    let home = match home_dir() {
        Some(h) => h,
        None => return Vec::new(),
    };
    log_dirs_in(&home).await
}

pub struct AmpCodeExplorer;

#[async_trait]
impl AgentExplorer for AmpCodeExplorer {
    async fn discover_recent(&self, now: i64, since_secs: i64) -> Vec<SessionLog> {
        let dirs = all_log_dirs().await;
        recent_files_with_exts(&dirs, now, since_secs, &["json", "jsonl"])
            .await
            .into_iter()
            .map(|file| SessionLog {
                agent_type: AgentType::AmpCode,
                source: SessionSource::File(file.path),
                updated_at: Some(file.mtime_epoch),
            })
            .collect()
    }
}

async fn log_dirs_in(home: &Path) -> Vec<PathBuf> {
    let primary_threads = amp_state_dir_in(home).join("threads");
    let mut primary_dirs = Vec::new();
    collect_dirs_with_exts(&primary_threads, &mut primary_dirs, &["json"]).await;

    if !primary_dirs.is_empty() {
        primary_dirs.sort();
        primary_dirs.dedup();
        return primary_dirs;
    }

    let mut fallback_dirs = Vec::new();
    collect_dirs_with_exts(
        &home.join(".amp").join("file-changes"),
        &mut fallback_dirs,
        &["json", "jsonl"],
    )
    .await;
    fallback_dirs.sort();
    fallback_dirs.dedup();
    fallback_dirs
}

fn amp_state_dir_in(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join(".local").join("share").join("amp")
    } else if cfg!(target_os = "windows") {
        if let Ok(appdata) = std::env::var("APPDATA") {
            PathBuf::from(appdata).join("amp")
        } else {
            home.join("AppData").join("Roaming").join("amp")
        }
    } else {
        home.join(".local").join("share").join("amp")
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    #[tokio::test]
    async fn test_amp_log_dirs_prefers_threads_dir() {
        let home = TempDir::new().unwrap();
        let threads_dir = amp_state_dir_in(home.path()).join("threads");
        tokio::fs::create_dir_all(&threads_dir).await.unwrap();
        tokio::fs::write(threads_dir.join("thread-1.json"), "{}")
            .await
            .unwrap();

        let fallback_dir = home.path().join(".amp").join("file-changes").join("x");
        tokio::fs::create_dir_all(&fallback_dir).await.unwrap();
        tokio::fs::write(fallback_dir.join("x.json"), "{}")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert_eq!(dirs, vec![threads_dir]);
    }

    #[tokio::test]
    async fn test_amp_log_dirs_falls_back_when_threads_missing() {
        let home = TempDir::new().unwrap();
        let fallback_dir = home.path().join(".amp").join("file-changes").join("x");
        tokio::fs::create_dir_all(&fallback_dir).await.unwrap();
        tokio::fs::write(fallback_dir.join("x.jsonl"), "{}")
            .await
            .unwrap();

        let dirs = log_dirs_in(home.path()).await;
        assert_eq!(dirs, vec![fallback_dir]);
    }
}
