//! Pending retry state for payload ref sync failures.
//!
//! Records are scoped by `(repo, remote)` and stored under:
//! `~/.cadence/cli/payload-pending/<repo-hash>--<remote>.json`

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_ATTEMPTS: u32 = 20;
const RETRY_DELAYS_SECS: &[i64] = &[0, 1, 2, 4, 8, 16, 32, 60, 120, 300];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadPendingRecord {
    pub repo: String,
    pub remote: String,
    pub attempts: u32,
    pub last_attempt: i64,
    pub last_error: String,
}

fn payload_pending_dir_in(home: &Path) -> Result<PathBuf> {
    let dir = home.join(".cadence/cli").join("payload-pending");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

fn payload_pending_dir() -> Result<PathBuf> {
    let home = crate::agents::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    payload_pending_dir_in(&home)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn record_filename(repo: &str, remote: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(repo.as_bytes());
    hasher.update(b"\n");
    hasher.update(remote.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{:x}", digest);
    format!("{}--{}.json", &hex[..16], remote)
}

fn record_path(dir: &Path, repo: &str, remote: &str) -> PathBuf {
    dir.join(record_filename(repo, remote))
}

fn write_record(dir: &Path, record: &PayloadPendingRecord) -> Result<()> {
    let path = record_path(dir, &record.repo, &record.remote);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(record)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

pub fn load(repo: &str, remote: &str) -> Result<Option<PayloadPendingRecord>> {
    let dir = payload_pending_dir()?;
    let path = record_path(&dir, repo, remote);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let record: PayloadPendingRecord = serde_json::from_str(&content)?;
    Ok(Some(record))
}

pub fn clear(repo: &str, remote: &str) -> Result<()> {
    let dir = payload_pending_dir()?;
    let path = record_path(&dir, repo, remote);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub fn record_failure(repo: &str, remote: &str, last_error: &str) -> Result<()> {
    let dir = payload_pending_dir()?;
    let now = now_unix();
    let mut record = load(repo, remote)?.unwrap_or(PayloadPendingRecord {
        repo: repo.to_string(),
        remote: remote.to_string(),
        attempts: 0,
        last_attempt: now,
        last_error: String::new(),
    });
    record.attempts = record.attempts.saturating_add(1);
    record.last_attempt = now;
    record.last_error = last_error.to_string();
    write_record(&dir, &record)
}

pub fn is_retry_due(record: &PayloadPendingRecord) -> bool {
    if record.attempts >= MAX_ATTEMPTS {
        return false;
    }
    let idx = std::cmp::min(record.attempts as usize, RETRY_DELAYS_SECS.len() - 1);
    let wait = RETRY_DELAYS_SECS[idx];
    now_unix() >= record.last_attempt + wait
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_filename_stable() {
        let a = record_filename("/tmp/repo", "origin");
        let b = record_filename("/tmp/repo", "origin");
        assert_eq!(a, b);
    }

    #[test]
    fn test_retry_due_initial_true() {
        let r = PayloadPendingRecord {
            repo: "r".into(),
            remote: "origin".into(),
            attempts: 0,
            last_attempt: 0,
            last_error: "e".into(),
        };
        assert!(is_retry_due(&r));
    }
}
