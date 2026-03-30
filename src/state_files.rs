use crate::config::CliConfig;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static WRITE_JSON_TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn cadence_dir() -> Result<PathBuf> {
    CliConfig::config_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine Cadence config directory"))
}

pub fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

pub async fn write_json_atomic<T: ?Sized + Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("path has no parent: {}", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("path has no filename: {}", path.display()))?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let tmp = parent.join(format!(
        ".{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        WRITE_JSON_TMP_COUNTER.fetch_add(1, Ordering::Relaxed),
    ));
    let payload = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    tokio::fs::write(&tmp, payload)
        .await
        .with_context(|| format!("failed to write temporary file {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[tokio::test]
    async fn write_json_atomic_handles_concurrent_writers_for_same_path() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("shared.json");
        let mut tasks = Vec::new();

        for value in 0..8 {
            let path = path.clone();
            tasks.push(tokio::spawn(async move {
                write_json_atomic(&path, &json!({ "value": value })).await
            }));
        }

        for task in tasks {
            task.await
                .expect("join concurrent writer")
                .expect("write shared json");
        }

        let parsed = serde_json::from_str::<serde_json::Value>(
            &tokio::fs::read_to_string(&path)
                .await
                .expect("read final shared json"),
        )
        .expect("parse final shared json");
        assert!(parsed.get("value").is_some(), "expected JSON payload");
    }
}
