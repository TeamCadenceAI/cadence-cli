//! Session scanning and correlation.
//!
//! Scans candidate session log files (JSONL) to find commit hashes,
//! then parses minimal metadata and verifies the match against the
//! git repository.
//!
//! The core invariant: "If an AI agent created a commit, the commit hash
//! appears verbatim in the session log." This module implements that
//! search by streaming files line-by-line (never loading entire files
//! into memory) and doing substring matching for the full hash and
//! the short hash (first 7 characters).

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The type of AI agent that produced a session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentType {
    Claude,
    Codex,
    Cursor,
    Copilot,
    Antigravity,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Claude => write!(f, "claude-code"),
            AgentType::Codex => write!(f, "codex"),
            AgentType::Cursor => write!(f, "cursor"),
            AgentType::Copilot => write!(f, "copilot"),
            AgentType::Antigravity => write!(f, "antigravity"),
        }
    }
}

/// A successful match: a candidate file contains a commit hash.
#[derive(Debug, Clone)]
pub struct SessionMatch {
    /// Path to the session log file that contained the commit hash.
    pub file_path: PathBuf,
    /// The agent type, inferred from the file path.
    pub agent_type: AgentType,
}

/// Minimal metadata parsed from a session log file.
///
/// Not every field is guaranteed to be present -- session logs vary
/// in structure. Fields are `Option` to handle missing data gracefully.
#[derive(Debug, Clone, Default)]
pub struct SessionMetadata {
    /// The session ID (UUID or similar identifier).
    pub session_id: Option<String>,
    /// The working directory where the agent was running.
    pub cwd: Option<String>,
    /// The agent type, if determinable from the log content.
    pub agent_type: Option<AgentType>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Search candidate files for a line containing the given commit hash.
///
/// Streams each file line-by-line using `BufReader` to avoid loading
/// entire files into memory. Checks each line for:
/// - The full 40-character commit hash (substring match)
/// - The short hash (first 7 characters, substring match)
///
/// Returns `Some(SessionMatch)` on the first match found across all
/// candidate files. Returns `None` if no files contain the hash.
///
/// The agent type is inferred from the file path:
/// - If the path contains `.claude` -> Claude
/// - If the path contains `.codex` -> Codex
/// - Otherwise defaults to Claude (conservative fallback)
pub fn find_session_for_commit(
    commit_hash: &str,
    candidate_files: &[PathBuf],
) -> Option<SessionMatch> {
    // Reject invalid commit hashes: must be 7-40 hex characters.
    // An empty or short string would cause `line.contains("")` to return true
    // for every line, producing universal false positives. Non-hex strings
    // can never be valid commit hashes.
    if crate::git::validate_commit_hash(commit_hash).is_err() {
        return None;
    }

    let short_hash = &commit_hash[..7];

    for file_path in candidate_files {
        let file = match File::open(file_path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };

            // Check for full hash first (more specific), then short hash
            if line.contains(commit_hash) || line.contains(short_hash) {
                let agent_type = infer_agent_type(file_path);
                return Some(SessionMatch {
                    file_path: file_path.clone(),
                    agent_type,
                });
            }
        }
    }

    None
}

/// Parse minimal metadata from a session log file.
///
/// Reads the file line-by-line, attempting to parse each line as JSON
/// and extracting known fields:
/// - `session_id` (or `sessionId`)
/// - `cwd` (or `workdir`, `working_directory`)
/// - `type` field that may indicate the agent
///
/// This is best-effort: not every line will be valid JSON, and not
/// every JSON line will contain the fields we need. The function
/// accumulates fields across all lines, with first-value-wins semantics
/// (once a field is found, later occurrences are ignored).
pub fn parse_session_metadata(file: &Path) -> SessionMetadata {
    let mut metadata = SessionMetadata::default();

    let file_handle = match File::open(file) {
        Ok(f) => f,
        Err(_) => return metadata,
    };

    let reader = BufReader::new(file_handle);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Attempt to parse as JSON
        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Extract session_id (top-level or nested under payload for Codex)
        if metadata.session_id.is_none() {
            if let Some(id) = value
                .get("session_id")
                .or_else(|| value.get("sessionId"))
                .or_else(|| value.pointer("/payload/id"))
                .and_then(|v| v.as_str())
            {
                metadata.session_id = Some(id.to_string());
            }
        }

        // Extract cwd / workdir (top-level or nested under payload for Codex)
        if metadata.cwd.is_none() {
            if let Some(cwd) = value
                .get("cwd")
                .or_else(|| value.get("workdir"))
                .or_else(|| value.get("working_directory"))
                .or_else(|| value.pointer("/payload/cwd"))
                .and_then(|v| v.as_str())
            {
                metadata.cwd = Some(cwd.to_string());
            }
        }

        // If we have both fields, stop early
        if metadata.session_id.is_some() && metadata.cwd.is_some() {
            break;
        }
    }

    // Fallback: parse full JSON (chatSessions format).
    if metadata.session_id.is_none() || metadata.cwd.is_none() {
        if let Some(value) = read_json_value(file) {
            if metadata.session_id.is_none() {
                if let Some(id) = value.get("sessionId").and_then(|v| v.as_str()) {
                    metadata.session_id = Some(id.to_string());
                }
            }

            if metadata.cwd.is_none() {
                if let Some(path) = extract_cwd_from_value(&value) {
                    metadata.cwd = Some(path);
                }
            }
        }
    }

    // Infer agent type from file path
    metadata.agent_type = Some(infer_agent_type(file));

    metadata
}

/// Extract the session time range (start, end) from a session log file.
///
/// Scans each line as JSON and looks for known timestamp keys:
/// - Top-level: `timestamp`, `time`, `created_at`, `createdAt`
/// - Nested under `payload`: `timestamp`, `created_at`, `createdAt`
///
/// Parses RFC3339/ISO8601 timestamps and returns the min/max epoch seconds.
/// Returns `None` if no parseable timestamps are found.
pub fn session_time_range(file: &Path) -> Option<(i64, i64)> {
    let file_handle = File::open(file).ok()?;
    let reader = BufReader::new(file_handle);

    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let candidates = [
            value.get("timestamp"),
            value.get("time"),
            value.get("created_at"),
            value.get("createdAt"),
            value.get("creationDate"),
            value.get("lastMessageDate"),
            value.pointer("/payload/timestamp"),
            value.pointer("/payload/created_at"),
            value.pointer("/payload/createdAt"),
        ];

        for candidate in candidates.iter().flatten() {
            if let Some(ts) =
                parse_timestamp(candidate).or_else(|| parse_numeric_timestamp(candidate))
            {
                min_ts = Some(min_ts.map_or(ts, |min| min.min(ts)));
                max_ts = Some(max_ts.map_or(ts, |max| max.max(ts)));
            }
        }
    }

    if min_ts.is_none() || max_ts.is_none() {
        if let Some(value) = read_json_value(file) {
            let mut all = Vec::new();
            collect_timestamp_candidates(&value, &mut all);
            for candidate in all {
                if let Some(ts) =
                    parse_timestamp(&candidate).or_else(|| parse_numeric_timestamp(&candidate))
                {
                    min_ts = Some(min_ts.map_or(ts, |min| min.min(ts)));
                    max_ts = Some(max_ts.map_or(ts, |max| max.max(ts)));
                }
            }
        }
    }

    match (min_ts, max_ts) {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    }
}

/// Verify that a session match is valid for a given repository and commit.
///
/// Checks two conditions:
/// 1. The `cwd` from the session metadata resolves to the same git repo
///    root as the target repository.
/// 2. The commit exists in that repository.
///
/// Returns `false` if any check fails or if the cwd is not available
/// in the metadata.
pub fn verify_match(metadata: &SessionMetadata, repo_root: &Path, commit: &str) -> bool {
    // Validate commit hash before passing to git commands.
    if crate::git::validate_commit_hash(commit).is_err() {
        return false;
    }

    let cwd = match &metadata.cwd {
        Some(c) => c,
        None => return false,
    };

    let cwd_path = Path::new(cwd);

    // Check 1: cwd resolves to the same git repo root
    match crate::git::repo_root_at(cwd_path) {
        Ok(cwd_repo_root) => {
            // Canonicalize both paths for comparison to handle symlinks
            let canonical_repo = match repo_root.canonicalize() {
                Ok(p) => p,
                Err(_) => repo_root.to_path_buf(),
            };
            let canonical_cwd_repo = match cwd_repo_root.canonicalize() {
                Ok(p) => p,
                Err(_) => cwd_repo_root,
            };
            if canonical_repo != canonical_cwd_repo {
                return false;
            }
        }
        Err(_) => return false,
    }

    // Check 2: commit exists in the repo
    crate::git::commit_exists_at(repo_root, commit).unwrap_or_default()
}

/// Extract commit hashes from git commit confirmation output in a session log.
///
/// Looks specifically for the `[branch HASH]` pattern that git outputs when
/// a commit is created (e.g., `[main abcdef0] Fix bug`). This targets only
/// commits actually made during the session, avoiding false positives from
/// git log, git diff, UUIDs, and other hex strings.
///
/// Returns a deduplicated `Vec<String>` of extracted hashes (lowercased).
/// Returns an empty Vec on any I/O error.
pub fn extract_commit_hashes(file: &Path) -> Vec<String> {
    let file_handle = match File::open(file) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };

    let reader = BufReader::new(file_handle);
    let mut hashes = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        extract_hashes_from_line(&line, &mut hashes, &mut seen);
    }

    hashes
}

/// Extract commit hashes from `[branch HASH]` patterns in a single line.
///
/// Matches the git commit confirmation format: `[branch_name hash]` where
/// `branch_name` can contain word chars, `/`, `.`, and `-`, and `hash` is
/// 7-40 hex characters.
fn extract_hashes_from_line(
    line: &str,
    hashes: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    // Match `[branch hash]` pattern from git commit output.
    // The branch name can contain word chars, /, ., - (e.g., feature/foo-bar).
    // The hash is 7-40 hex characters.
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Look for '['
        if bytes[i] != b'[' {
            i += 1;
            continue;
        }
        i += 1; // skip '['

        // Parse branch name: [\w/.#-]+ (at least 1 char)
        let branch_start = i;
        while i < len
            && (bytes[i].is_ascii_alphanumeric()
                || bytes[i] == b'/'
                || bytes[i] == b'.'
                || bytes[i] == b'-'
                || bytes[i] == b'_'
                || bytes[i] == b'#')
        {
            i += 1;
        }
        if i == branch_start {
            // No branch name chars found
            continue;
        }

        // Expect a space between branch name and hash
        if i >= len || bytes[i] != b' ' {
            continue;
        }
        i += 1; // skip space

        // Parse hex hash: 7-40 hex chars
        let hash_start = i;
        while i < len && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let hash_len = i - hash_start;
        if !(7..=40).contains(&hash_len) {
            continue;
        }

        // Expect ']' after hash
        if i >= len || bytes[i] != b']' {
            continue;
        }

        let hash = line[hash_start..hash_start + hash_len].to_ascii_lowercase();
        if seen.insert(hash.clone()) {
            hashes.push(hash);
        }

        i += 1; // skip ']'
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Infer the agent type from a file path.
///
/// - If path contains `.claude` -> Claude
/// - If path contains `.codex` -> Codex
/// - Otherwise -> Claude (conservative default)
fn infer_agent_type(path: &Path) -> AgentType {
    let path_str = path.to_string_lossy();
    if path_str.contains(".codex") {
        AgentType::Codex
    } else if path_str.contains(".cursor") || path_str.contains("/Cursor/") {
        AgentType::Cursor
    } else if path_str.contains("/Antigravity/") {
        AgentType::Antigravity
    } else if path_str.contains("/Code/") {
        AgentType::Copilot
    } else {
        // Default to Claude -- `.claude` paths and unknown paths
        AgentType::Claude
    }
}

/// Parse a timestamp value into epoch seconds.
fn parse_timestamp(value: &serde_json::Value) -> Option<i64> {
    let s = value.as_str()?;
    let dt = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    Some(dt.unix_timestamp())
}

fn parse_numeric_timestamp(value: &serde_json::Value) -> Option<i64> {
    let num = value.as_i64()?;
    if num <= 0 {
        return None;
    }
    if num > 1_000_000_000_000 {
        Some(num / 1000)
    } else {
        Some(num)
    }
}

fn read_json_value(file: &Path) -> Option<serde_json::Value> {
    let content = std::fs::read_to_string(file).ok()?;
    serde_json::from_str(&content).ok()
}

fn extract_cwd_from_value(value: &serde_json::Value) -> Option<String> {
    if let Some(path) = value.pointer("/baseUri/fsPath").and_then(|v| v.as_str()) {
        return Some(normalize_cwd_path(path));
    }
    if let Some(path) = value.pointer("/baseUri/path").and_then(|v| v.as_str()) {
        return Some(normalize_cwd_path(path));
    }

    if let Some(requests) = value.get("requests").and_then(|v| v.as_array()) {
        for request in requests {
            if let Some(path) = request
                .pointer("/variableData/variables")
                .and_then(|v| v.as_array())
                .and_then(|vars| {
                    vars.iter().find_map(|var| {
                        var.pointer("/value/uri/fsPath")
                            .or_else(|| var.pointer("/value/uri/path"))
                            .and_then(|v| v.as_str())
                    })
                })
            {
                return Some(normalize_cwd_path(path));
            }

            if let Some(path) = request
                .pointer("/response")
                .and_then(|v| v.as_array())
                .and_then(|responses| {
                    responses.iter().find_map(|resp| {
                        resp.pointer("/baseUri/fsPath")
                            .or_else(|| resp.pointer("/baseUri/path"))
                            .and_then(|v| v.as_str())
                    })
                })
            {
                return Some(normalize_cwd_path(path));
            }
        }
    }

    None
}

fn normalize_cwd_path(path: &str) -> String {
    let trimmed = path.strip_prefix("file://").unwrap_or(path);
    let candidate = Path::new(trimmed);
    if looks_like_file(candidate) {
        candidate
            .parent()
            .unwrap_or(candidate)
            .to_string_lossy()
            .to_string()
    } else {
        candidate.to_string_lossy().to_string()
    }
}

fn looks_like_file(path: &Path) -> bool {
    if path.extension().is_some() {
        return true;
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        return name.contains('.');
    }
    false
}

fn collect_timestamp_candidates(value: &serde_json::Value, out: &mut Vec<serde_json::Value>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                match key.as_str() {
                    "timestamp" | "time" | "created_at" | "createdAt" | "creationDate"
                    | "lastMessageDate" => out.push(val.clone()),
                    _ => {}
                }
                collect_timestamp_candidates(val, out);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_timestamp_candidates(item, out);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    // -----------------------------------------------------------------------
    // Helper: create a temp file with given content
    // -----------------------------------------------------------------------

    fn write_temp_file(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, content).expect("failed to write temp file");
        path
    }

    // -----------------------------------------------------------------------
    // infer_agent_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_infer_agent_type_claude() {
        let path = Path::new("/Users/foo/.claude/projects/-Users-foo-bar/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    #[test]
    fn test_infer_agent_type_codex() {
        let path = Path::new("/Users/foo/.codex/sessions/abc123/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Codex);
    }

    #[test]
    fn test_infer_agent_type_cursor() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Cursor/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Cursor);
    }

    #[test]
    fn test_infer_agent_type_copilot() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Code/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Copilot);
    }

    #[test]
    fn test_infer_agent_type_antigravity() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Antigravity/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Antigravity);
    }

    #[test]
    fn test_infer_agent_type_unknown_defaults_to_claude() {
        let path = Path::new("/tmp/some/random/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    // -----------------------------------------------------------------------
    // AgentType display
    // -----------------------------------------------------------------------

    #[test]
    fn test_agent_type_display_claude() {
        assert_eq!(AgentType::Claude.to_string(), "claude-code");
    }

    #[test]
    fn test_agent_type_display_codex() {
        assert_eq!(AgentType::Codex.to_string(), "codex");
    }

    #[test]
    fn test_agent_type_display_cursor() {
        assert_eq!(AgentType::Cursor.to_string(), "cursor");
    }

    #[test]
    fn test_agent_type_display_copilot() {
        assert_eq!(AgentType::Copilot.to_string(), "copilot");
    }

    #[test]
    fn test_agent_type_display_antigravity() {
        assert_eq!(AgentType::Antigravity.to_string(), "antigravity");
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — full hash match
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_full_hash_match() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // Create a JSONL file with a line containing the full hash
        let content =
            format!(r#"{{"type":"tool_result","content":"Created commit {commit_hash}"}}"#,);
        let file = write_temp_file(
            dir.path(),
            "session.jsonl",
            &format!("{}\n{{\"type\":\"other\"}}\n", content),
        );

        let result = find_session_for_commit(commit_hash, &[file.clone()]);

        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.file_path, file);
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — short hash match
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_short_hash_match() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";
        let short_hash = &commit_hash[..7]; // "abcdef0"

        // Only the short hash appears in the line
        let content = format!(r#"{{"type":"tool_result","content":"Committed {short_hash}"}}"#,);
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let result = find_session_for_commit(commit_hash, &[file]);

        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.agent_type, AgentType::Claude);
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — no match
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_no_match() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // File with unrelated content
        let file = write_temp_file(
            dir.path(),
            "session.jsonl",
            "{\"type\":\"message\"}\n{\"type\":\"other\"}\n",
        );

        let result = find_session_for_commit(commit_hash, &[file]);

        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — stops on first match
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_stops_on_first_file_match() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // First file has the match
        let file1 = write_temp_file(
            dir.path(),
            "first.jsonl",
            &format!(r#"{{"content":"commit {commit_hash}"}}"#),
        );
        // Second file also has a match (should not be reached)
        let file2 = write_temp_file(
            dir.path(),
            "second.jsonl",
            &format!(r#"{{"content":"commit {commit_hash}"}}"#),
        );

        let result = find_session_for_commit(commit_hash, &[file1.clone(), file2]);

        assert!(result.is_some());
        assert_eq!(result.unwrap().file_path, file1);
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — multiple files, match in second
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_match_in_second_file() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // First file has no match
        let file1 = write_temp_file(
            dir.path(),
            "no-match.jsonl",
            "{\"type\":\"message\",\"content\":\"hello\"}\n",
        );
        // Second file has the match
        let file2 = write_temp_file(
            dir.path(),
            "has-match.jsonl",
            &format!(r#"{{"content":"Created commit {commit_hash}"}}"#),
        );

        let result = find_session_for_commit(commit_hash, &[file1, file2.clone()]);

        assert!(result.is_some());
        assert_eq!(result.unwrap().file_path, file2);
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — empty candidate list
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_empty_candidates() {
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";
        let result = find_session_for_commit(commit_hash, &[]);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — nonexistent file is skipped gracefully
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_nonexistent_file_skipped() {
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";
        let nonexistent = PathBuf::from("/nonexistent/file.jsonl");
        let result = find_session_for_commit(commit_hash, &[nonexistent]);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — agent type from path
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_agent_type_claude_from_path() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // Put the file under a .claude directory
        let claude_dir = dir.path().join(".claude").join("projects");
        fs::create_dir_all(&claude_dir).unwrap();
        let file = write_temp_file(
            &claude_dir,
            "session.jsonl",
            &format!(r#"{{"content":"{commit_hash}"}}"#),
        );

        let result = find_session_for_commit(commit_hash, &[file]);

        assert!(result.is_some());
        assert_eq!(result.unwrap().agent_type, AgentType::Claude);
    }

    #[test]
    fn test_find_session_agent_type_codex_from_path() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // Put the file under a .codex directory
        let codex_dir = dir.path().join(".codex").join("sessions");
        fs::create_dir_all(&codex_dir).unwrap();
        let file = write_temp_file(
            &codex_dir,
            "session.jsonl",
            &format!(r#"{{"content":"{commit_hash}"}}"#),
        );

        let result = find_session_for_commit(commit_hash, &[file]);

        assert!(result.is_some());
        assert_eq!(result.unwrap().agent_type, AgentType::Codex);
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — hash embedded in complex JSONL
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_hash_in_realistic_jsonl() {
        let dir = TempDir::new().unwrap();
        let commit_hash = "655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e";

        // Simulate realistic Claude Code JSONL output
        let content = format!(
            r#"{{"type":"assistant","message":"I'll commit this now"}}
{{"type":"tool_use","name":"Bash","input":{{"command":"git add . && git commit -m \"fix bug\""}}}}
{{"type":"tool_result","content":"[main {short_hash}] fix bug\n 1 file changed, 2 insertions(+)"}}
{{"type":"assistant","message":"Done! The commit has been created."}}
"#,
            short_hash = &commit_hash[..7],
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let result = find_session_for_commit(commit_hash, &[file]);

        assert!(result.is_some());
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — hash that partially matches but shouldn't
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_partial_hash_no_false_positive() {
        let dir = TempDir::new().unwrap();
        // Full hash starts with "abcdef0..."
        let commit_hash = "abcdef0123456789abcdef0123456789abcdef01";

        // File contains "abcdef" (6 chars -- shorter than 7-char short hash)
        // This should NOT match because we check for 7-char short hash
        let content = r#"{"content":"the string abcdef appears here"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let result = find_session_for_commit(commit_hash, &[file]);

        // "abcdef" is only 6 chars, our short hash is "abcdef0" (7 chars).
        // The line does not contain "abcdef0", so no match.
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // find_session_for_commit — short/empty hash rejected
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_session_empty_hash_returns_none() {
        let dir = TempDir::new().unwrap();
        // A file where every line would match an empty string
        let file = write_temp_file(
            dir.path(),
            "session.jsonl",
            "{\"type\":\"message\",\"content\":\"hello\"}\n",
        );

        let result = find_session_for_commit("", &[file]);
        assert!(result.is_none());
    }

    #[test]
    fn test_find_session_short_hash_returns_none() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(
            dir.path(),
            "session.jsonl",
            "{\"content\":\"abcdef something\"}\n",
        );

        // 6-char hash is too short, should be rejected
        let result = find_session_for_commit("abcdef", &[file]);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_session_id_and_cwd() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"session_id":"abc-123","cwd":"/Users/foo/bar"}
{"type":"message","content":"hello"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[test]
    fn test_parse_metadata_camel_case_session_id() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"sessionId":"def-456","cwd":"/Users/baz"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("def-456".to_string()));
    }

    #[test]
    fn test_parse_metadata_workdir_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"workdir":"/home/user/project"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.cwd, Some("/home/user/project".to_string()));
    }

    #[test]
    fn test_parse_metadata_working_directory_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"working_directory":"/opt/app"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.cwd, Some("/opt/app".to_string()));
    }

    #[test]
    fn test_parse_metadata_chat_session_json() {
        let dir = TempDir::new().unwrap();
        let content = r#"{
  "sessionId": "chat-123",
  "requests": [
    {
      "variableData": {
        "variables": [
          {
            "value": {
              "uri": {
                "fsPath": "/Users/foo/dev/my-repo/src/main.rs"
              }
            }
          }
        ]
      }
    }
  ]
}"#;
        let file = write_temp_file(dir.path(), "session.json", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("chat-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-repo/src".to_string()));
    }

    #[test]
    fn test_parse_metadata_fields_across_multiple_lines() {
        let dir = TempDir::new().unwrap();
        // session_id on one line, cwd on another
        let content = r#"{"session_id":"multi-line-id"}
{"type":"other"}
{"cwd":"/Users/foo/repo"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("multi-line-id".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/repo".to_string()));
    }

    #[test]
    fn test_parse_metadata_no_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no metadata here"}
{"type":"tool_result","content":"more stuff"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[test]
    fn test_parse_metadata_invalid_json_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let content = r#"this is not json
{"session_id":"valid-id"}
also not json {{{{
{"cwd":"/valid/path"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("valid-id".to_string()));
        assert_eq!(metadata.cwd, Some("/valid/path".to_string()));
    }

    #[test]
    fn test_parse_metadata_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(dir.path(), "empty.jsonl", "");

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[test]
    fn test_parse_metadata_nonexistent_file() {
        let path = Path::new("/nonexistent/file.jsonl");
        let metadata = parse_session_metadata(path);

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[test]
    fn test_parse_metadata_agent_type_from_claude_path() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude").join("projects");
        fs::create_dir_all(&claude_dir).unwrap();
        let file = write_temp_file(&claude_dir, "session.jsonl", "{}");

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.agent_type, Some(AgentType::Claude));
    }

    #[test]
    fn test_parse_metadata_agent_type_from_codex_path() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex").join("sessions");
        fs::create_dir_all(&codex_dir).unwrap();
        let file = write_temp_file(&codex_dir, "session.jsonl", "{}");

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.agent_type, Some(AgentType::Codex));
    }

    #[test]
    fn test_parse_metadata_first_value_wins() {
        let dir = TempDir::new().unwrap();
        // Two lines with session_id -- first should win
        let content = r#"{"session_id":"first-id"}
{"session_id":"second-id"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("first-id".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata — Codex format (nested under payload)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_codex_session_meta() {
        let dir = TempDir::new().unwrap();
        // Real Codex session_meta format: id and cwd nested under payload
        let content = r#"{"timestamp":"2026-02-10T01:52:21.832Z","type":"session_meta","payload":{"id":"019c453f-e731-7bd1-9d05-c571ec59ca6b","cwd":"/Users/foo/dev/my-project","originator":"codex_cli_rs","cli_version":"0.98.0"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(
            metadata.session_id,
            Some("019c453f-e731-7bd1-9d05-c571ec59ca6b".to_string())
        );
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-project".to_string()));
    }

    #[test]
    fn test_parse_metadata_codex_payload_id_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.id present, no cwd
        let content = r#"{"type":"session_meta","payload":{"id":"abc-123"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, None);
    }

    #[test]
    fn test_parse_metadata_codex_payload_cwd_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.cwd present, no id
        let content = r#"{"type":"session_meta","payload":{"cwd":"/Users/foo/bar"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[test]
    fn test_parse_metadata_top_level_takes_priority_over_payload() {
        let dir = TempDir::new().unwrap();
        // Both top-level and payload fields present -- top-level wins (first-value-wins)
        let content = r#"{"session_id":"top-level-id","cwd":"/top/level"}
{"type":"session_meta","payload":{"id":"payload-id","cwd":"/payload/path"}}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let metadata = parse_session_metadata(&file);

        assert_eq!(metadata.session_id, Some("top-level-id".to_string()));
        assert_eq!(metadata.cwd, Some("/top/level".to_string()));
    }

    // -----------------------------------------------------------------------
    // session_time_range
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_time_range_parses_rfc3339() {
        let dir = TempDir::new().unwrap();
        let t1 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let t2 = OffsetDateTime::from_unix_timestamp(1_700_000_120).unwrap();
        let s1 = t1.format(&Rfc3339).unwrap();
        let s2 = t2.format(&Rfc3339).unwrap();

        let content = format!(
            r#"{{"timestamp":"{s1}"}}
{{"payload":{{"createdAt":"{s2}"}}}}"#,
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let range = session_time_range(&file).unwrap();
        assert_eq!(range.0, t1.unix_timestamp());
        assert_eq!(range.1, t2.unix_timestamp());
    }

    #[test]
    fn test_session_time_range_numeric_ms() {
        let dir = TempDir::new().unwrap();
        let content = r#"{
  "creationDate": 1749509938455,
  "lastMessageDate": 1749509971642
}"#;
        let file = write_temp_file(dir.path(), "session.json", content);

        let range = session_time_range(&file).unwrap();
        assert_eq!(range.0, 1_749_509_938);
        assert_eq!(range.1, 1_749_509_971);
    }

    #[test]
    fn test_session_time_range_none_when_missing() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no timestamps"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let range = session_time_range(&file);
        assert!(range.is_none());
    }

    #[test]
    fn test_extract_commit_hashes_from_codex_function_call_output() {
        let dir = TempDir::new().unwrap();
        // Real Codex function_call_output format with git commit output
        let content = r#"{"timestamp":"2026-02-10T02:13:37.205Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_fEoWO6fq3tRI8VsBgjkdxRfp","output":"Chunk ID: f0cd33\nWall time: 0.0525 seconds\nProcess exited with code 0\nOriginal token count: 40\nOutput:\n[main df69283] Create detailed TODO plan\n 1 file changed, 229 insertions(+)\n create mode 100644 TODO.md\n"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "df69283");
    }

    // -----------------------------------------------------------------------
    // verify_match — requires real git repos, run serially
    // -----------------------------------------------------------------------

    /// Helper: create a temp git repo with one commit, return (TempDir, commit_hash).
    fn init_temp_repo() -> (TempDir, String) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
        // Override hooksPath to prevent the global post-commit hook from firing
        run_git(path, &["config", "core.hooksPath", "/dev/null"]);
        fs::write(path.join("README.md"), "hello").unwrap();
        run_git(path, &["add", "README.md"]);
        run_git(path, &["commit", "-m", "initial commit"]);

        let hash = run_git(path, &["rev-parse", "HEAD"]);
        (dir, hash)
    }

    fn run_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-C", dir.to_str().unwrap()])
            .args(args)
            .output()
            .expect("failed to run git");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!("git {:?} failed: {}", args, stderr);
        }
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    #[test]
    fn test_verify_match_same_repo() {
        let (dir, commit_hash) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            cwd: Some(dir.path().to_string_lossy().to_string()),
            agent_type: Some(AgentType::Claude),
        };

        assert!(verify_match(&metadata, &repo_root, &commit_hash));
    }

    #[test]
    fn test_verify_match_missing_cwd() {
        let (dir, commit_hash) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            cwd: None,
            agent_type: Some(AgentType::Claude),
        };

        assert!(!verify_match(&metadata, &repo_root, &commit_hash));
    }

    #[test]
    fn test_verify_match_different_repo() {
        let (dir1, commit_hash) = init_temp_repo();
        let (dir2, _) = init_temp_repo();

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            // cwd points to dir2 but we're checking against dir1
            cwd: Some(dir2.path().to_string_lossy().to_string()),
            agent_type: Some(AgentType::Claude),
        };

        assert!(!verify_match(
            &metadata,
            &dir1.path().to_path_buf(),
            &commit_hash
        ));
    }

    #[test]
    fn test_verify_match_nonexistent_cwd() {
        let (dir, commit_hash) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            cwd: Some("/nonexistent/path/that/does/not/exist".to_string()),
            agent_type: Some(AgentType::Claude),
        };

        assert!(!verify_match(&metadata, &repo_root, &commit_hash));
    }

    #[test]
    fn test_verify_match_nonexistent_commit() {
        let (dir, _) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();
        let fake_commit = "0000000000000000000000000000000000000000";

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            cwd: Some(dir.path().to_string_lossy().to_string()),
            agent_type: Some(AgentType::Claude),
        };

        assert!(!verify_match(&metadata, &repo_root, fake_commit));
    }

    #[test]
    fn test_verify_match_cwd_in_subdirectory() {
        let (dir, commit_hash) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();

        // Create a subdirectory inside the repo
        let subdir = dir.path().join("src");
        fs::create_dir(&subdir).unwrap();

        let metadata = SessionMetadata {
            session_id: Some("test-session".to_string()),
            // cwd is a subdirectory of the repo -- should still resolve to same repo root
            cwd: Some(subdir.to_string_lossy().to_string()),
            agent_type: Some(AgentType::Claude),
        };

        assert!(verify_match(&metadata, &repo_root, &commit_hash));
    }

    // -----------------------------------------------------------------------
    // extract_commit_hashes
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_commit_hashes_finds_short_hash() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[test]
    fn test_extract_commit_hashes_finds_full_hash() {
        let dir = TempDir::new().unwrap();
        let hash = "abcdef0123456789abcdef0123456789abcdef01";
        let content = format!(r#"{{"content":"[main {hash}] fix bug"}}"#);
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash);
    }

    #[test]
    fn test_extract_commit_hashes_finds_multiple() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] first commit"}
{"content":"[main 1234567] second commit"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"abcdef0".to_string()));
        assert!(hashes.contains(&"1234567".to_string()));
    }

    #[test]
    fn test_extract_commit_hashes_deduplicates() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] fix bug"}
{"content":"[main abcdef0] fix bug"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn test_extract_commit_hashes_no_hashes() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"hello world"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_ignores_bare_hex() {
        let dir = TempDir::new().unwrap();
        // Bare hex strings (e.g., from git log) should NOT be extracted
        let content = r#"{"content":"abcdef0 Fix something"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_ignores_diff_blob_hashes() {
        let dir = TempDir::new().unwrap();
        // Diff index lines should NOT match
        let content = r#"{"content":"index c84f8ba..b145f18 100644"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_ignores_too_short_hex() {
        let dir = TempDir::new().unwrap();
        // 6-char hash in bracket pattern -- below minimum
        let content = r#"{"content":"[main abcdef] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_uppercase_lowered() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main ABCDEF0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[test]
    fn test_extract_commit_hashes_feature_branch() {
        let dir = TempDir::new().unwrap();
        // Branch names with slashes and dashes
        let content = r#"{"content":"[feature/foo-bar abcdef0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[test]
    fn test_extract_commit_hashes_nonexistent_file() {
        let path = Path::new("/nonexistent/file.jsonl");
        let hashes = extract_commit_hashes(path);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(dir.path(), "empty.jsonl", "");

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_realistic_session_log() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"assistant","message":"I'll commit now"}
{"type":"tool_use","name":"Bash","input":{"command":"git commit -m fix"}}
{"type":"tool_result","content":"[main 655dd38] fix\n 1 file changed"}
{"type":"assistant","message":"Done! Commit 655dd38"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        // Should find 655dd38 from the [main 655dd38] pattern
        // but NOT from the bare "Commit 655dd38" mention
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "655dd38");
    }

    // -----------------------------------------------------------------------
    // End-to-end: find + parse + verify
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_to_end_find_parse_verify() {
        let (dir, commit_hash) = init_temp_repo();
        let repo_root = dir.path().to_path_buf();

        // Create a fake session log with the commit hash and metadata
        let log_dir = TempDir::new().unwrap();
        let claude_dir = log_dir.path().join(".claude").join("projects");
        fs::create_dir_all(&claude_dir).unwrap();

        let content = format!(
            r#"{{"session_id":"e2e-session","cwd":"{cwd}"}}
{{"type":"tool_result","content":"[main {short}] fix bug\n 1 file changed"}}
{{"type":"assistant","message":"Done"}}
"#,
            cwd = dir.path().to_string_lossy(),
            short = &commit_hash[..7],
        );
        let file = write_temp_file(&claude_dir, "session.jsonl", &content);

        // Step 1: Find the session
        let session_match = find_session_for_commit(&commit_hash, &[file.clone()]);
        assert!(session_match.is_some());
        let session_match = session_match.unwrap();
        assert_eq!(session_match.agent_type, AgentType::Claude);

        // Step 2: Parse metadata
        let metadata = parse_session_metadata(&file);
        assert_eq!(metadata.session_id, Some("e2e-session".to_string()));
        assert_eq!(metadata.cwd, Some(dir.path().to_string_lossy().to_string()));

        // Step 3: Verify
        assert!(verify_match(&metadata, &repo_root, &commit_hash));
    }
}
