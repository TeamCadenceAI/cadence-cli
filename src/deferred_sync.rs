//! Deferred non-blocking Cadence session ref sync.
//!
//! This module provides:
//! - pending sync queue records
//! - robust per-job lock acquisition with stale/corrupt lock cleanup
//! - detached background worker spawning
//! - `cadence hook deferred-sync` execution entrypoint

use anyhow::{Context, Result};
use rand08::Rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::task::JoinSet;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{agents, git, push};

const DEFAULT_LOCK_MAX_AGE_SECS: i64 = 300;
const DEFAULT_LOG_RETENTION_DAYS: i64 = 7;
const DEFAULT_SYNC_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_TIME_BUDGET_MS: u64 = 8_000;
const REF_SYNC_JOB_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct SyncRunOptions {
    /// Optional repository path to sync. Uses current repo when unset.
    pub repo: Option<PathBuf>,
    /// Optional remote to sync. Resolves push remote when unset.
    pub remote: Option<String>,
    /// Process persisted pending jobs instead of creating an explicit one.
    pub all_pending: bool,
    /// Whether this invocation is running as a detached background worker.
    pub background: bool,
    /// Maximum number of pending jobs to process in this invocation.
    pub max_items: usize,
    /// Total runtime budget for this invocation in milliseconds.
    pub time_budget_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingSyncRecord {
    /// Canonical repo root path for the queued sync job.
    pub repo_root: String,
    /// Git remote name for this sync job.
    pub remote: String,
    /// RFC3339 enqueue timestamp.
    pub enqueued_at: String,
    /// RFC3339 update timestamp.
    pub updated_at: String,
    /// Number of failed attempts.
    pub attempt_count: u32,
    /// Earliest epoch second when this job can be retried.
    pub next_attempt_at_epoch: i64,
    /// Last sync error, if any.
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncLockRecord {
    pid: u32,
    created_at_epoch: i64,
    hostname: String,
    repo_root: String,
    remote: String,
    worker_id: String,
}

#[derive(Debug)]
struct SyncLockGuard {
    path: PathBuf,
}

impl Drop for SyncLockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Upsert a pending sync job for `(repo, remote)`.
///
/// If a record already exists, this refreshes `updated_at` and makes it
/// immediately eligible for retry.
pub async fn enqueue_pending_sync(repo_root: &Path, remote: &str) -> Result<()> {
    let repo_root_str = repo_root.to_string_lossy().to_string();
    let key = pending_key(&repo_root_str, remote);
    let now_epoch = now_epoch();
    let now = crate::note::now_rfc3339();
    let dir = pending_dir().await?;
    let path = dir.join(format!("{key}.json"));

    let mut record = if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => {
                serde_json::from_str::<PendingSyncRecord>(&content).unwrap_or(PendingSyncRecord {
                    repo_root: repo_root_str.clone(),
                    remote: remote.to_string(),
                    enqueued_at: now.clone(),
                    updated_at: now.clone(),
                    attempt_count: 0,
                    next_attempt_at_epoch: now_epoch,
                    last_error: None,
                })
            }
            Err(_) => PendingSyncRecord {
                repo_root: repo_root_str.clone(),
                remote: remote.to_string(),
                enqueued_at: now.clone(),
                updated_at: now.clone(),
                attempt_count: 0,
                next_attempt_at_epoch: now_epoch,
                last_error: None,
            },
        }
    } else {
        PendingSyncRecord {
            repo_root: repo_root_str.clone(),
            remote: remote.to_string(),
            enqueued_at: now.clone(),
            updated_at: now.clone(),
            attempt_count: 0,
            next_attempt_at_epoch: now_epoch,
            last_error: None,
        }
    };

    record.updated_at = now;
    if record.next_attempt_at_epoch > now_epoch {
        record.next_attempt_at_epoch = now_epoch;
    }
    write_json_atomic(&path, &record).await
}

/// Spawn a detached one-shot background worker that runs:
/// `cadence hook deferred-sync --background ...`
///
/// The worker is intentionally short-lived and relies on queue-based retries.
pub async fn spawn_background_sync(repo_root: &Path, remote: &str) -> Result<()> {
    let exe = std::env::current_exe().context("resolve current executable for background sync")?;
    let mut cmd = std::process::Command::new(exe);
    cmd.arg("hook")
        .arg("deferred-sync")
        .arg("--background")
        .arg("--repo")
        .arg(repo_root)
        .arg("--remote")
        .arg(remote)
        .arg("--max-items")
        .arg("1")
        .arg("--time-budget-ms")
        .arg(DEFAULT_TIME_BUDGET_MS.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    // Cross-platform detached one-shot worker.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let _child = cmd
        .spawn()
        .context("spawn detached background sync worker")?;
    Ok(())
}

pub async fn run_sync_command(opts: SyncRunOptions) -> Result<()> {
    run_startup_maintenance().await?;

    let jobs = collect_runnable_jobs(&opts).await?;
    execute_jobs_bounded(jobs, opts.background, opts.time_budget_ms).await
}

/// Run lock/log maintenance before processing jobs.
async fn run_startup_maintenance() -> Result<()> {
    sweep_stale_locks().await?;
    sweep_old_logs().await?;
    sweep_log_size().await
}

/// Resolve and cap runnable jobs for the current invocation.
async fn collect_runnable_jobs(opts: &SyncRunOptions) -> Result<Vec<PendingSyncRecord>> {
    let mut jobs = if opts.all_pending {
        load_pending_records().await?
    } else {
        build_explicit_jobs(opts.repo.as_deref(), opts.remote.as_deref()).await?
    };
    jobs.sort_by(|a, b| a.repo_root.cmp(&b.repo_root).then(a.remote.cmp(&b.remote)));
    if jobs.is_empty() {
        return Ok(jobs);
    }

    let now = now_epoch();
    jobs.retain(|j| j.next_attempt_at_epoch <= now);
    jobs.truncate(opts.max_items.max(1));
    Ok(jobs)
}

/// Execute jobs with bounded concurrency and a global time budget.
async fn execute_jobs_bounded(
    jobs: Vec<PendingSyncRecord>,
    background: bool,
    time_budget_ms: u64,
) -> Result<()> {
    if jobs.is_empty() {
        return Ok(());
    }
    let start = std::time::Instant::now();
    let mut set = JoinSet::new();
    let mut in_flight = 0usize;
    let mut idx = 0usize;
    while idx < jobs.len() || in_flight > 0 {
        while idx < jobs.len() && in_flight < REF_SYNC_JOB_CONCURRENCY {
            let job = jobs[idx].clone();
            set.spawn(async move { run_one_pending_job(job, background).await });
            idx += 1;
            in_flight += 1;
        }

        let Some(done) = set.join_next().await else {
            break;
        };
        in_flight -= 1;
        let _ = done?;
        if start.elapsed().as_millis() as u64 > time_budget_ms {
            break;
        }
    }
    Ok(())
}

async fn run_one_pending_job(job: PendingSyncRecord, background: bool) -> Result<()> {
    let worker_id = Uuid::new_v4().to_string();
    let _trace_guard = init_tracing_for_worker(&worker_id, &job, background).ok();
    info!(
        worker_id = %worker_id,
        repo_root = %job.repo_root,
        remote = %job.remote,
        attempt = job.attempt_count,
        "sync worker started"
    );

    let lock = match acquire_lock(&job.repo_root, &job.remote, &worker_id).await? {
        Some(lock) => lock,
        None => {
            info!("lock already held; skipping duplicate worker");
            return Ok(());
        }
    };
    let _lock = lock;

    let repo_path = PathBuf::from(&job.repo_root);
    let sync_timeout = Duration::from_millis(DEFAULT_SYNC_TIMEOUT_MS);
    let started = std::time::Instant::now();
    let sync_result = tokio::time::timeout(
        sync_timeout,
        push::sync_session_refs_for_remote_at(&repo_path, &job.remote),
    )
    .await;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    match sync_result {
        Ok(Ok(())) => {
            info!(
                duration_ms = elapsed_ms,
                result = "ok",
                "sync worker finished successfully"
            );
            clear_pending_record(&job.repo_root, &job.remote).await?;
        }
        Ok(Err(e)) => {
            warn!(
                duration_ms = elapsed_ms,
                result = "error",
                error = %e,
                "sync worker failed"
            );
            update_pending_retry(&job, format!("{e:#}")).await?;
        }
        Err(_) => {
            warn!(
                duration_ms = elapsed_ms,
                result = "timeout",
                "sync worker timed out"
            );
            update_pending_retry(&job, "sync timed out".to_string()).await?;
        }
    }

    Ok(())
}

fn pending_key(repo_root: &str, remote: &str) -> String {
    let joined = format!("{repo_root}::{remote}");
    let digest = sha2::Sha256::digest(joined.as_bytes());
    format!("{:x}", digest)[..24].to_string()
}

fn lock_key(repo_root: &str, remote: &str) -> String {
    pending_key(repo_root, remote)
}

fn host_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown-host".to_string())
}

fn now_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn lock_max_age_secs() -> i64 {
    std::env::var("CADENCE_SYNC_LOCK_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_LOCK_MAX_AGE_SECS)
}

fn log_retention_days() -> i64 {
    std::env::var("CADENCE_SYNC_LOG_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_LOG_RETENTION_DAYS)
}

fn max_log_bytes() -> Option<u64> {
    std::env::var("CADENCE_SYNC_MAX_LOG_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
}

fn is_pid_alive(pid: u32) -> bool {
    let mut system = System::new();
    system.refresh_processes();
    system.process(Pid::from_u32(pid)).is_some()
}

async fn acquire_lock(
    repo_root: &str,
    remote: &str,
    worker_id: &str,
) -> Result<Option<SyncLockGuard>> {
    let dir = lock_dir().await?;
    acquire_lock_in_dir(&dir, repo_root, remote, worker_id).await
}

/// Acquire a lock file for a specific `(repo, remote)` job.
///
/// Returns:
/// - `Some(guard)` when the caller now owns the lock.
/// - `None` when another healthy worker currently owns the lock.
async fn acquire_lock_in_dir(
    dir: &Path,
    repo_root: &str,
    remote: &str,
    worker_id: &str,
) -> Result<Option<SyncLockGuard>> {
    let key = lock_key(repo_root, remote);
    let lock_path = dir.join(format!("{key}.lock"));
    let record = SyncLockRecord {
        pid: std::process::id(),
        created_at_epoch: now_epoch(),
        hostname: host_name(),
        repo_root: repo_root.to_string(),
        remote: remote.to_string(),
        worker_id: worker_id.to_string(),
    };

    if try_create_lock(&lock_path, &record).await? {
        return Ok(Some(SyncLockGuard { path: lock_path }));
    }

    if !tokio::fs::try_exists(&lock_path).await.unwrap_or(false) {
        if try_create_lock(&lock_path, &record).await? {
            return Ok(Some(SyncLockGuard { path: lock_path }));
        }
        return Ok(None);
    }

    let existing = tokio::fs::read_to_string(&lock_path).await;
    let existing_content = match existing {
        Ok(c) => c,
        Err(_) => {
            let _ = tokio::fs::remove_file(&lock_path).await;
            if try_create_lock(&lock_path, &record).await? {
                return Ok(Some(SyncLockGuard { path: lock_path }));
            }
            return Ok(None);
        }
    };

    let parsed = serde_json::from_str::<SyncLockRecord>(&existing_content);
    let parsed = match parsed {
        Ok(v) => v,
        Err(_) => {
            quarantine_broken_lock(&lock_path).await?;
            if try_create_lock(&lock_path, &record).await? {
                return Ok(Some(SyncLockGuard { path: lock_path }));
            }
            return Ok(None);
        }
    };

    let age = now_epoch().saturating_sub(parsed.created_at_epoch);
    let stale = age > lock_max_age_secs();
    let alive = is_pid_alive(parsed.pid);
    if stale || !alive {
        let _ = tokio::fs::remove_file(&lock_path).await;
        if try_create_lock(&lock_path, &record).await? {
            return Ok(Some(SyncLockGuard { path: lock_path }));
        }
        return Ok(None);
    }

    Ok(None)
}

/// Try to atomically create a lock file. Returns `false` if it already exists.
async fn try_create_lock(path: &Path, lock: &SyncLockRecord) -> Result<bool> {
    let data = serde_json::to_vec_pretty(lock)?;
    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    let file = opts.open(path).await;
    let mut file = match file {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("create lock {}", path.display())),
    };
    tokio::io::AsyncWriteExt::write_all(&mut file, &data).await?;
    Ok(true)
}

/// Rename malformed lock files so operators can inspect them later.
async fn quarantine_broken_lock(path: &Path) -> Result<()> {
    let ts = now_epoch();
    let broken = path.with_extension(format!("broken.{ts}"));
    let _ = tokio::fs::rename(path, broken).await;
    Ok(())
}

/// Best-effort startup sweep to remove stale/dead/corrupt lock files.
async fn sweep_stale_locks() -> Result<()> {
    let dir = lock_dir().await?;
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("lock") {
            continue;
        }
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(_) => {
                let _ = tokio::fs::remove_file(&path).await;
                continue;
            }
        };
        let parsed = serde_json::from_str::<SyncLockRecord>(&content);
        let parsed = match parsed {
            Ok(p) => p,
            Err(_) => {
                quarantine_broken_lock(&path).await?;
                continue;
            }
        };
        let age = now_epoch().saturating_sub(parsed.created_at_epoch);
        if age > lock_max_age_secs() || !is_pid_alive(parsed.pid) {
            let _ = tokio::fs::remove_file(&path).await;
        }
    }
    Ok(())
}

fn pending_path_for(repo_root: &str, remote: &str, dir: &Path) -> PathBuf {
    dir.join(format!("{}.json", pending_key(repo_root, remote)))
}

async fn update_pending_retry(job: &PendingSyncRecord, error_message: String) -> Result<()> {
    let dir = pending_dir().await?;
    let path = pending_path_for(&job.repo_root, &job.remote, &dir);
    let mut next = job.clone();
    next.attempt_count = next.attempt_count.saturating_add(1);
    let jitter = rand08::thread_rng().gen_range(0..=500i64);
    let backoff_ms = ((1u64 << next.attempt_count.min(8)) * 1000).min(300_000);
    next.next_attempt_at_epoch = now_epoch() + ((backoff_ms as i64 + jitter) / 1000);
    next.last_error = Some(error_message);
    next.updated_at = crate::note::now_rfc3339();
    write_json_atomic(&path, &next).await
}

/// Remove a pending job after successful sync.
async fn clear_pending_record(repo_root: &str, remote: &str) -> Result<()> {
    let dir = pending_dir().await?;
    let path = pending_path_for(repo_root, remote, &dir);
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        let _ = tokio::fs::remove_file(path).await;
    }
    Ok(())
}

/// Load all pending sync records from disk.
async fn load_pending_records() -> Result<Vec<PendingSyncRecord>> {
    let dir = pending_dir().await?;
    let mut out = Vec::new();
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(v) => v,
        Err(_) => return Ok(out),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(_) => continue,
        };
        if let Ok(record) = serde_json::from_str::<PendingSyncRecord>(&content) {
            out.push(record);
        }
    }
    Ok(out)
}

/// Build a single explicit sync job and ensure it exists in the pending queue.
async fn build_explicit_jobs(
    repo: Option<&Path>,
    remote: Option<&str>,
) -> Result<Vec<PendingSyncRecord>> {
    let repo_root = match repo {
        Some(path) => git::repo_root_at(path)
            .await
            .unwrap_or_else(|_| path.to_path_buf()),
        None => git::repo_root().await?,
    };
    let remote = match remote {
        Some(r) => r.to_string(),
        None => git::resolve_push_remote_at(&repo_root)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "origin".to_string()),
    };
    enqueue_pending_sync(&repo_root, &remote).await?;
    let rec = PendingSyncRecord {
        repo_root: repo_root.to_string_lossy().to_string(),
        remote,
        enqueued_at: crate::note::now_rfc3339(),
        updated_at: crate::note::now_rfc3339(),
        attempt_count: 0,
        next_attempt_at_epoch: now_epoch(),
        last_error: None,
    };
    Ok(vec![rec])
}

fn sanitize_filename_part(v: &str) -> String {
    v.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn timestamp_for_filename() -> String {
    time::OffsetDateTime::now_utc()
        .format(
            &time::format_description::parse("[year][month][day]T[hour][minute][second]Z").unwrap(),
        )
        .unwrap_or_else(|_| now_epoch().to_string())
}

fn init_tracing_for_worker(
    worker_id: &str,
    job: &PendingSyncRecord,
    background: bool,
) -> Result<tracing::subscriber::DefaultGuard> {
    let dir = std::fs::create_dir_all(log_dir_blocking()?.as_path());
    if dir.is_err() {
        return Err(anyhow::anyhow!("failed to create sync log directory"));
    }
    let pid = std::process::id();
    let ts = timestamp_for_filename();
    let name = format!(
        "sync-{}-{}-{}.log",
        ts,
        sanitize_filename_part(worker_id),
        pid
    );
    let path = log_dir_blocking()?.join(name);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open sync log file {}", path.display()))?;
    writeln!(
        file,
        "start worker_id={} pid={} repo_root={} remote={} background={}",
        worker_id, pid, job.repo_root, job.remote, background
    )?;
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(file)
        .finish();
    Ok(tracing::subscriber::set_default(subscriber))
}

/// Delete old per-worker logs based on retention-days policy.
async fn sweep_old_logs() -> Result<()> {
    let dir = log_dir().await?;
    let retention = log_retention_days().max(1);
    let cutoff = now_epoch() - retention * 86_400;
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let epoch = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if epoch < cutoff {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
    Ok(())
}

/// Enforce an optional total-size cap for sync worker logs.
async fn sweep_log_size() -> Result<()> {
    let Some(max_bytes) = max_log_bytes() else {
        return Ok(());
    };
    let dir = log_dir().await?;
    let mut files = Vec::<(PathBuf, u64, i64)>::new();
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        files.push((path, meta.len(), modified));
    }
    let mut total: u64 = files.iter().map(|(_, len, _)| *len).sum();
    if total <= max_bytes {
        return Ok(());
    }
    files.sort_by_key(|(_, _, modified)| *modified);
    for (path, len, _) in files {
        if total <= max_bytes {
            break;
        }
        if tokio::fs::remove_file(&path).await.is_ok() {
            total = total.saturating_sub(len);
        }
    }
    Ok(())
}

/// Write JSON atomically via a temp file + rename.
async fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let data = serde_json::to_vec_pretty(value)?;
    tokio::fs::write(&tmp, data).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
}

async fn cadence_cli_dir() -> Result<PathBuf> {
    let home =
        agents::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve home directory"))?;
    let dir = home.join(".cadence").join("cli");
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir)
}

async fn pending_dir() -> Result<PathBuf> {
    let dir = cadence_cli_dir().await?.join("pending-sync");
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir)
}

async fn lock_dir() -> Result<PathBuf> {
    let dir = cadence_cli_dir().await?.join("locks");
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir)
}

fn log_dir_blocking() -> Result<PathBuf> {
    let home =
        agents::home_dir().ok_or_else(|| anyhow::anyhow!("cannot resolve home directory"))?;
    let dir = home.join(".cadence").join("cli").join("logs").join("sync");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

async fn log_dir() -> Result<PathBuf> {
    let dir = cadence_cli_dir().await?.join("logs").join("sync");
    tokio::fs::create_dir_all(&dir).await?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pending_key_is_stable() {
        let a = pending_key("/tmp/repo", "origin");
        let b = pending_key("/tmp/repo", "origin");
        assert_eq!(a, b);
    }

    #[test]
    fn sanitize_filename_part_rewrites_special_chars() {
        assert_eq!(sanitize_filename_part("abc/def:ghi"), "abc_def_ghi");
    }

    #[tokio::test]
    async fn lock_create_and_reacquire_after_drop() {
        let tmp = TempDir::new().unwrap();
        let lock1 = acquire_lock_in_dir(tmp.path(), "/tmp/repo", "origin", "worker-1")
            .await
            .unwrap();
        assert!(lock1.is_some());
        drop(lock1);
        let lock2 = acquire_lock_in_dir(tmp.path(), "/tmp/repo", "origin", "worker-2")
            .await
            .unwrap();
        assert!(lock2.is_some());
    }
}
