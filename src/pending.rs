//! Pending retry system.
//!
//! Manages pending records for commits that could not be resolved at
//! hook time. Each unresolved commit is stored as a JSON file in
//! `~/.ai-barometer/pending/<commit-hash>.json`. The retry system
//! attempts to re-resolve these records on subsequent commits.
//!
//! Writes are atomic: data is written to a temporary file first, then
//! renamed into place. This prevents partial reads from concurrent
//! commits.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A record for a commit that could not be resolved at hook time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRecord {
    /// Full commit hash.
    pub commit: String,
    /// Absolute path to the repository root.
    pub repo: String,
    /// Unix epoch timestamp of the commit.
    pub commit_time: i64,
    /// Number of resolution attempts so far.
    pub attempts: u32,
    /// Unix epoch timestamp of the last attempt.
    pub last_attempt: i64,
}

// ---------------------------------------------------------------------------
// Internal helper for testability
// ---------------------------------------------------------------------------

/// Return the pending directory rooted at the given home directory.
///
/// This is the internal implementation that accepts a home path, allowing
/// tests to use a temp directory instead of the real `$HOME`.
fn pending_dir_in(home: &Path) -> anyhow::Result<PathBuf> {
    let dir = home.join(".ai-barometer").join("pending");
    if !dir.exists() {
        std::fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Return the pending directory: `~/.ai-barometer/pending/`.
///
/// Creates the directory (and parents) if it does not exist.
pub fn pending_dir() -> anyhow::Result<PathBuf> {
    let home = crate::agents::home_dir()
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
    pending_dir_in(&home)
}

/// Write a pending record for a commit that could not be resolved.
///
/// Creates `<commit-hash>.json` in the pending directory. The write is
/// atomic: data is written to a temporary file (`<commit-hash>.json.tmp`)
/// first, then renamed into place. This prevents concurrent commits from
/// reading a half-written file.
pub fn write_pending(commit: &str, repo: &str, commit_time: i64) -> anyhow::Result<()> {
    let dir = pending_dir()?;
    write_pending_in(&dir, commit, repo, commit_time)
}

/// Internal implementation of `write_pending` that accepts the pending
/// directory, for testability.
fn write_pending_in(dir: &Path, commit: &str, repo: &str, commit_time: i64) -> anyhow::Result<()> {
    let now = current_unix_timestamp();

    let record = PendingRecord {
        commit: commit.to_string(),
        repo: repo.to_string(),
        commit_time,
        attempts: 1,
        last_attempt: now,
    };

    let json = serde_json::to_string_pretty(&record)?;
    let final_path = dir.join(format!("{}.json", commit));
    let tmp_path = dir.join(format!("{}.json.tmp", commit));

    // Atomic write: write to temp file, then rename
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, &final_path)?;

    Ok(())
}

/// List all pending records for a given repository.
///
/// Reads all `.json` files in the pending directory, deserializes them
/// as `PendingRecord`, and filters by repo path. Files that cannot be
/// read or parsed are silently skipped. Orphaned `.json.tmp` files
/// (left behind by crashed writes) are cleaned up automatically.
///
/// The `repo` parameter must be a canonical absolute path as returned by
/// `git rev-parse --show-toplevel`. Filtering uses exact string equality,
/// so paths with trailing slashes, symlinks, or other non-canonical
/// representations will not match records written with the canonical form.
pub fn list_for_repo(repo: &str) -> anyhow::Result<Vec<PendingRecord>> {
    let dir = match pending_dir() {
        Ok(d) => d,
        Err(_) => return Ok(Vec::new()),
    };

    list_for_repo_in(&dir, repo)
}

/// Internal implementation of `list_for_repo` that accepts the pending
/// directory, for testability.
fn list_for_repo_in(dir: &Path, repo: &str) -> anyhow::Result<Vec<PendingRecord>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            // Clean up orphaned .json.tmp files left behind by crashed writes.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".json.tmp"))
            {
                let _ = std::fs::remove_file(&path);
            }
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let record: PendingRecord = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if record.repo != repo {
            continue;
        }

        records.push(record);
    }

    Ok(records)
}

/// Increment the attempt counter on a pending record and rewrite it.
///
/// Bumps `attempts` by 1, updates `last_attempt` to the current time,
/// and atomically rewrites the file.
pub fn increment(record: &mut PendingRecord) -> anyhow::Result<()> {
    let dir = pending_dir()?;
    increment_in(&dir, record)
}

/// Internal implementation of `increment` that accepts the pending
/// directory, for testability.
fn increment_in(dir: &Path, record: &mut PendingRecord) -> anyhow::Result<()> {
    record.attempts += 1;
    record.last_attempt = current_unix_timestamp();

    let json = serde_json::to_string_pretty(record)?;
    let final_path = dir.join(format!("{}.json", record.commit));
    let tmp_path = dir.join(format!("{}.json.tmp", record.commit));

    // Atomic write: write to temp file, then rename
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, &final_path)?;

    Ok(())
}

/// Remove the pending record for a given commit.
///
/// Deletes `<commit-hash>.json` from the pending directory. Does nothing
/// if the file does not exist (idempotent).
pub fn remove(commit: &str) -> anyhow::Result<()> {
    let dir = pending_dir()?;
    remove_in(&dir, commit)
}

/// Internal implementation of `remove` that accepts the pending
/// directory, for testability.
fn remove_in(dir: &Path, commit: &str) -> anyhow::Result<()> {
    let path = dir.join(format!("{}.json", commit));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Get the current Unix timestamp in seconds.
fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -----------------------------------------------------------------------
    // PendingRecord struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_record_struct() {
        let record = PendingRecord {
            commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
            repo: "/Users/foo/bar".to_string(),
            commit_time: 1_700_000_000,
            attempts: 1,
            last_attempt: 1_700_000_060,
        };
        assert_eq!(record.commit, "abcdef0123456789abcdef0123456789abcdef01");
        assert_eq!(record.repo, "/Users/foo/bar");
        assert_eq!(record.attempts, 1);
    }

    // -----------------------------------------------------------------------
    // Serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_record_serialize_deserialize() {
        let record = PendingRecord {
            commit: "abcdef0123456789abcdef0123456789abcdef01".to_string(),
            repo: "/Users/foo/bar".to_string(),
            commit_time: 1_700_000_000,
            attempts: 3,
            last_attempt: 1_700_000_300,
        };

        let json = serde_json::to_string_pretty(&record).unwrap();
        let deserialized: PendingRecord = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.commit, record.commit);
        assert_eq!(deserialized.repo, record.repo);
        assert_eq!(deserialized.commit_time, record.commit_time);
        assert_eq!(deserialized.attempts, record.attempts);
        assert_eq!(deserialized.last_attempt, record.last_attempt);
    }

    // -----------------------------------------------------------------------
    // pending_dir_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_pending_dir_in_creates_directory() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        assert!(dir.exists());
        assert!(dir.ends_with(".ai-barometer/pending"));
    }

    #[test]
    fn test_pending_dir_in_idempotent() {
        let home = TempDir::new().unwrap();

        // Call twice -- should not error
        let dir1 = pending_dir_in(home.path()).unwrap();
        let dir2 = pending_dir_in(home.path()).unwrap();

        assert_eq!(dir1, dir2);
        assert!(dir1.exists());
    }

    // -----------------------------------------------------------------------
    // write_pending_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_pending_creates_json_file() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/Users/foo/bar", 1_700_000_000).unwrap();

        let file_path = dir.join(format!("{}.json", commit));
        assert!(file_path.exists());

        // Verify the contents
        let content = std::fs::read_to_string(&file_path).unwrap();
        let record: PendingRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.commit, commit);
        assert_eq!(record.repo, "/Users/foo/bar");
        assert_eq!(record.commit_time, 1_700_000_000);
        assert_eq!(record.attempts, 1);
        assert!(record.last_attempt > 0);
    }

    #[test]
    fn test_write_pending_no_temp_file_left() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();

        // The .tmp file should not exist after a successful write
        let tmp_path = dir.join(format!("{}.json.tmp", commit));
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_write_pending_overwrites_existing() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        // Write first time
        write_pending_in(&dir, commit, "/repo1", 1_700_000_000).unwrap();
        // Write second time with different repo
        write_pending_in(&dir, commit, "/repo2", 1_700_000_100).unwrap();

        let file_path = dir.join(format!("{}.json", commit));
        let content = std::fs::read_to_string(&file_path).unwrap();
        let record: PendingRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.repo, "/repo2");
        assert_eq!(record.commit_time, 1_700_000_100);
    }

    // -----------------------------------------------------------------------
    // list_for_repo_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_for_repo_empty_dir() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        let records = list_for_repo_in(&dir, "/Users/foo/bar").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_list_for_repo_filters_by_repo() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        // Write records for two different repos
        write_pending_in(
            &dir,
            "aaaaaaa0000000000000000000000000000000aa",
            "/repo/a",
            100,
        )
        .unwrap();
        write_pending_in(
            &dir,
            "bbbbbbb0000000000000000000000000000000bb",
            "/repo/b",
            200,
        )
        .unwrap();
        write_pending_in(
            &dir,
            "ccccccc0000000000000000000000000000000cc",
            "/repo/a",
            300,
        )
        .unwrap();

        let records_a = list_for_repo_in(&dir, "/repo/a").unwrap();
        assert_eq!(records_a.len(), 2);

        let records_b = list_for_repo_in(&dir, "/repo/b").unwrap();
        assert_eq!(records_b.len(), 1);
        assert_eq!(
            records_b[0].commit,
            "bbbbbbb0000000000000000000000000000000bb"
        );
    }

    #[test]
    fn test_list_for_repo_no_matching_repo() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        write_pending_in(
            &dir,
            "aaaaaaa0000000000000000000000000000000aa",
            "/repo/a",
            100,
        )
        .unwrap();

        let records = list_for_repo_in(&dir, "/repo/nonexistent").unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_list_for_repo_skips_non_json_files() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        // Write a valid record
        write_pending_in(
            &dir,
            "aaaaaaa0000000000000000000000000000000aa",
            "/repo",
            100,
        )
        .unwrap();

        // Write a non-json file
        std::fs::write(dir.join("notes.txt"), "not a record").unwrap();

        // Write a .json.tmp file (should be ignored and cleaned up)
        let tmp_path = dir.join("leftover.json.tmp");
        std::fs::write(&tmp_path, "{}").unwrap();

        let records = list_for_repo_in(&dir, "/repo").unwrap();
        assert_eq!(records.len(), 1);

        // The .json.tmp file should have been cleaned up
        assert!(
            !tmp_path.exists(),
            "orphaned .json.tmp file should be cleaned up"
        );

        // The .txt file should NOT be cleaned up (only .json.tmp files)
        assert!(dir.join("notes.txt").exists());
    }

    #[test]
    fn test_list_for_repo_cleans_up_orphaned_tmp_files() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        // Create multiple orphaned .json.tmp files
        let tmp1 = dir.join("abc1234.json.tmp");
        let tmp2 = dir.join("def5678.json.tmp");
        std::fs::write(&tmp1, r#"{"partial":"write"}"#).unwrap();
        std::fs::write(&tmp2, "corrupted data").unwrap();

        assert!(tmp1.exists());
        assert!(tmp2.exists());

        // Listing should clean them up
        let records = list_for_repo_in(&dir, "/repo").unwrap();
        assert!(records.is_empty());

        assert!(!tmp1.exists(), "first orphaned tmp should be removed");
        assert!(!tmp2.exists(), "second orphaned tmp should be removed");
    }

    #[test]
    fn test_list_for_repo_skips_invalid_json() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();

        // Write a valid record
        write_pending_in(
            &dir,
            "aaaaaaa0000000000000000000000000000000aa",
            "/repo",
            100,
        )
        .unwrap();

        // Write an invalid JSON file with .json extension
        std::fs::write(dir.join("corrupt.json"), "not valid json {{{{").unwrap();

        let records = list_for_repo_in(&dir, "/repo").unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_list_for_repo_nonexistent_dir() {
        let dir = PathBuf::from("/nonexistent/dir/that/does/not/exist");
        let records = list_for_repo_in(&dir, "/repo").unwrap();
        assert!(records.is_empty());
    }

    // -----------------------------------------------------------------------
    // increment_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_increment_bumps_attempts() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();

        // Read it back
        let file_path = dir.join(format!("{}.json", commit));
        let content = std::fs::read_to_string(&file_path).unwrap();
        let mut record: PendingRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(record.attempts, 1);

        let old_last_attempt = record.last_attempt;

        // Increment
        increment_in(&dir, &mut record).unwrap();

        assert_eq!(record.attempts, 2);
        assert!(record.last_attempt >= old_last_attempt);

        // Verify the file on disk was updated
        let content2 = std::fs::read_to_string(&file_path).unwrap();
        let record2: PendingRecord = serde_json::from_str(&content2).unwrap();
        assert_eq!(record2.attempts, 2);
    }

    #[test]
    fn test_increment_multiple_times() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();

        let file_path = dir.join(format!("{}.json", commit));
        let content = std::fs::read_to_string(&file_path).unwrap();
        let mut record: PendingRecord = serde_json::from_str(&content).unwrap();

        increment_in(&dir, &mut record).unwrap();
        increment_in(&dir, &mut record).unwrap();
        increment_in(&dir, &mut record).unwrap();

        assert_eq!(record.attempts, 4); // 1 initial + 3 increments

        // Verify disk
        let content2 = std::fs::read_to_string(&file_path).unwrap();
        let record2: PendingRecord = serde_json::from_str(&content2).unwrap();
        assert_eq!(record2.attempts, 4);
    }

    #[test]
    fn test_increment_on_nonexistent_file_creates_it() {
        // If the on-disk file was deleted (e.g. by a concurrent remove) but
        // the in-memory record is still being iterated, increment should
        // handle this gracefully by creating the file anew rather than
        // panicking.
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        // Create a record in memory without writing it to disk first
        let mut record = PendingRecord {
            commit: commit.to_string(),
            repo: "/repo".to_string(),
            commit_time: 1_700_000_000,
            attempts: 1,
            last_attempt: 1_700_000_000,
        };

        // The file does not exist on disk -- increment should still succeed
        let file_path = dir.join(format!("{}.json", commit));
        assert!(!file_path.exists());

        increment_in(&dir, &mut record).unwrap();

        // The in-memory record should be updated
        assert_eq!(record.attempts, 2);

        // A file should now exist on disk with the updated record
        assert!(file_path.exists());
        let content = std::fs::read_to_string(&file_path).unwrap();
        let disk_record: PendingRecord = serde_json::from_str(&content).unwrap();
        assert_eq!(disk_record.attempts, 2);
        assert_eq!(disk_record.commit, commit);
        assert_eq!(disk_record.repo, "/repo");
    }

    #[test]
    fn test_increment_preserves_other_fields() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/Users/foo/bar", 1_700_000_000).unwrap();

        let file_path = dir.join(format!("{}.json", commit));
        let content = std::fs::read_to_string(&file_path).unwrap();
        let mut record: PendingRecord = serde_json::from_str(&content).unwrap();

        increment_in(&dir, &mut record).unwrap();

        assert_eq!(record.commit, commit);
        assert_eq!(record.repo, "/Users/foo/bar");
        assert_eq!(record.commit_time, 1_700_000_000);
    }

    // -----------------------------------------------------------------------
    // remove_in
    // -----------------------------------------------------------------------

    #[test]
    fn test_remove_deletes_file() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();
        let file_path = dir.join(format!("{}.json", commit));
        assert!(file_path.exists());

        remove_in(&dir, commit).unwrap();
        assert!(!file_path.exists());
    }

    #[test]
    fn test_remove_idempotent() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        // Remove a file that was never written -- should not error
        remove_in(&dir, commit).unwrap();

        // Write and remove twice -- second remove should not error
        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();
        remove_in(&dir, commit).unwrap();
        remove_in(&dir, commit).unwrap();
    }

    #[test]
    fn test_remove_only_removes_target() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit_a = "aaaaaaa0000000000000000000000000000000aa";
        let commit_b = "bbbbbbb0000000000000000000000000000000bb";

        write_pending_in(&dir, commit_a, "/repo", 100).unwrap();
        write_pending_in(&dir, commit_b, "/repo", 200).unwrap();

        remove_in(&dir, commit_a).unwrap();

        // commit_a should be gone, commit_b should remain
        assert!(!dir.join(format!("{}.json", commit_a)).exists());
        assert!(dir.join(format!("{}.json", commit_b)).exists());
    }

    // -----------------------------------------------------------------------
    // Write + List + Remove roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_list_remove_roundtrip() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        // Write
        write_pending_in(&dir, commit, "/Users/foo/repo", 1_700_000_000).unwrap();

        // List
        let records = list_for_repo_in(&dir, "/Users/foo/repo").unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].commit, commit);
        assert_eq!(records[0].repo, "/Users/foo/repo");
        assert_eq!(records[0].commit_time, 1_700_000_000);
        assert_eq!(records[0].attempts, 1);

        // Remove
        remove_in(&dir, commit).unwrap();

        // List again -- should be empty
        let records = list_for_repo_in(&dir, "/Users/foo/repo").unwrap();
        assert!(records.is_empty());
    }

    // -----------------------------------------------------------------------
    // Write + Increment + List roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_write_increment_list_roundtrip() {
        let home = TempDir::new().unwrap();
        let dir = pending_dir_in(home.path()).unwrap();
        let commit = "abcdef0123456789abcdef0123456789abcdef01";

        write_pending_in(&dir, commit, "/repo", 1_700_000_000).unwrap();

        // Read and increment
        let mut records = list_for_repo_in(&dir, "/repo").unwrap();
        assert_eq!(records.len(), 1);
        increment_in(&dir, &mut records[0]).unwrap();

        // Re-read from disk
        let records2 = list_for_repo_in(&dir, "/repo").unwrap();
        assert_eq!(records2.len(), 1);
        assert_eq!(records2[0].attempts, 2);
    }

    // -----------------------------------------------------------------------
    // current_unix_timestamp
    // -----------------------------------------------------------------------

    #[test]
    fn test_current_unix_timestamp_is_reasonable() {
        let ts = current_unix_timestamp();
        // Should be after 2020-01-01
        assert!(ts > 1_577_836_800);
    }
}
