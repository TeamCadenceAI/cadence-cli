use crate::config::CliConfig;
use anyhow::{Context, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};

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
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("failed to create directory {}", parent.display()))?;
    let tmp = path.with_extension("tmp");
    let payload = serde_json::to_vec_pretty(value).context("failed to serialize JSON")?;
    tokio::fs::write(&tmp, payload)
        .await
        .with_context(|| format!("failed to write temporary file {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;
    Ok(())
}
