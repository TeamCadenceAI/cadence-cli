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

use std::io::{BufRead, BufReader, Cursor};
use std::path::Path;
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
    Windsurf,
    Warp,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Claude => write!(f, "claude-code"),
            AgentType::Codex => write!(f, "codex"),
            AgentType::Cursor => write!(f, "cursor"),
            AgentType::Copilot => write!(f, "copilot"),
            AgentType::Antigravity => write!(f, "antigravity"),
            AgentType::Windsurf => write!(f, "windsurf"),
            AgentType::Warp => write!(f, "warp"),
        }
    }
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
pub async fn parse_session_metadata(file: &Path) -> SessionMetadata {
    let mut metadata = SessionMetadata::default();
    let content = match tokio::fs::read_to_string(file).await {
        Ok(c) => c,
        Err(_) => return metadata,
    };
    let reader = BufReader::new(Cursor::new(content.as_bytes()));
    metadata = parse_session_metadata_reader(reader, metadata);

    // Fallback: parse full JSON (chatSessions format).
    if (metadata.session_id.is_none() || metadata.cwd.is_none())
        && let Some(value) = read_json_value(file).await
    {
        apply_metadata_from_value(&mut metadata, &value);
    }

    // Infer agent type from file path
    metadata.agent_type = Some(infer_agent_type(file));

    metadata
}

/// Parse minimal metadata from a session log string.
pub fn parse_session_metadata_str(content: &str) -> SessionMetadata {
    let metadata = SessionMetadata::default();
    let metadata = parse_session_metadata_reader(BufReader::new(Cursor::new(content)), metadata);
    let mut metadata = metadata;

    if (metadata.session_id.is_none() || metadata.cwd.is_none())
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        apply_metadata_from_value(&mut metadata, &value);
    }

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
pub async fn session_time_range(file: &Path) -> Option<(i64, i64)> {
    let content = tokio::fs::read_to_string(file).await.ok()?;
    let reader = BufReader::new(Cursor::new(content.as_bytes()));
    let range = session_time_range_reader(reader);

    if range.is_none()
        && let Some(value) = read_json_value(file).await
    {
        return session_time_range_from_value(&value);
    }

    range
}

/// Extract the session time range (start, end) from a session log string.
pub fn session_time_range_str(content: &str) -> Option<(i64, i64)> {
    let reader = BufReader::new(Cursor::new(content));
    let range = session_time_range_reader(reader);

    if range.is_none()
        && let Ok(value) = serde_json::from_str::<serde_json::Value>(content)
    {
        return session_time_range_from_value(&value);
    }

    range
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
pub async fn extract_commit_hashes(file: &Path) -> Vec<String> {
    let content = match tokio::fs::read_to_string(file).await {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    extract_commit_hashes_reader(BufReader::new(Cursor::new(content.as_bytes())))
}

/// Extract commit hashes from session log content.
pub fn extract_commit_hashes_str(content: &str) -> Vec<String> {
    extract_commit_hashes_reader(BufReader::new(Cursor::new(content)))
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
    let path_str = path.to_string_lossy().replace('\\', "/");
    let path_lower = path_str.to_ascii_lowercase();
    if path_lower.contains(".codex") {
        AgentType::Codex
    } else if path_lower.contains(".cursor") || path_lower.contains("/cursor/") {
        AgentType::Cursor
    } else if path_lower.contains("/antigravity/")
        || path_lower.contains("/antigravity-api/")
        || path_lower.contains("/.cadence/cli/antigravity-api/")
    {
        AgentType::Antigravity
    } else if path_lower.contains("/.codeium/windsurf/")
        || path_lower.contains("/windsurf-api/")
        || path_lower.contains("/library/application support/windsurf/")
        || path_lower.contains("/.config/windsurf/")
        || path_lower.contains("/appdata/roaming/windsurf/")
        || path_lower.contains("/windsurf/user/workspacestorage/")
    {
        AgentType::Windsurf
    } else if path_lower.contains("warp.sqlite") || path_lower.contains("/warp/") {
        AgentType::Warp
    } else if path_lower.contains("/code/") {
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

async fn read_json_value(file: &Path) -> Option<serde_json::Value> {
    let content = tokio::fs::read_to_string(file).await.ok()?;
    serde_json::from_str(&content).ok()
}

fn parse_session_metadata_reader<R: BufRead>(
    reader: R,
    mut metadata: SessionMetadata,
) -> SessionMetadata {
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

        apply_metadata_from_value(&mut metadata, &value);

        // If we have both fields, stop early
        if metadata.session_id.is_some() && metadata.cwd.is_some() {
            break;
        }
    }

    metadata
}

fn apply_metadata_from_value(metadata: &mut SessionMetadata, value: &serde_json::Value) {
    // Extract session_id (top-level or nested under payload for Codex)
    if metadata.session_id.is_none()
        && let Some(id) = value
            .get("session_id")
            .or_else(|| value.get("sessionId"))
            .or_else(|| value.pointer("/payload/id"))
            .and_then(|v| v.as_str())
    {
        metadata.session_id = Some(id.to_string());
    }

    // Extract cwd / workdir (top-level or nested under payload for Codex)
    if metadata.cwd.is_none()
        && let Some(cwd) = value
            .get("cwd")
            .or_else(|| value.get("workdir"))
            .or_else(|| value.get("working_directory"))
            .or_else(|| value.pointer("/payload/cwd"))
            .and_then(|v| v.as_str())
    {
        metadata.cwd = Some(cwd.to_string());
    }

    if metadata.session_id.is_none()
        && let Some(id) = value.get("sessionId").and_then(|v| v.as_str())
    {
        metadata.session_id = Some(id.to_string());
    }

    if metadata.cwd.is_none()
        && let Some(path) = extract_cwd_from_value(value)
    {
        metadata.cwd = Some(path);
    }
}

fn session_time_range_reader<R: BufRead>(reader: R) -> Option<(i64, i64)> {
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

    match (min_ts, max_ts) {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    }
}

fn session_time_range_from_value(value: &serde_json::Value) -> Option<(i64, i64)> {
    let mut all = Vec::new();
    collect_timestamp_candidates(value, &mut all);
    let mut min_ts: Option<i64> = None;
    let mut max_ts: Option<i64> = None;
    for candidate in all {
        if let Some(ts) =
            parse_timestamp(&candidate).or_else(|| parse_numeric_timestamp(&candidate))
        {
            min_ts = Some(min_ts.map_or(ts, |min| min.min(ts)));
            max_ts = Some(max_ts.map_or(ts, |max| max.max(ts)));
        }
    }
    match (min_ts, max_ts) {
        (Some(min), Some(max)) => Some((min, max)),
        _ => None,
    }
}

fn extract_commit_hashes_reader<R: BufRead>(reader: R) -> Vec<String> {
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

    use tempfile::TempDir;
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    // -----------------------------------------------------------------------
    // Helper: create a temp file with given content
    // -----------------------------------------------------------------------

    async fn write_temp_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        tokio::fs::write(&path, content)
            .await
            .expect("failed to write temp file");
        path
    }

    // -----------------------------------------------------------------------
    // infer_agent_type
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_infer_agent_type_claude() {
        let path = Path::new("/Users/foo/.claude/projects/-Users-foo-bar/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    #[tokio::test]
    async fn test_infer_agent_type_codex() {
        let path = Path::new("/Users/foo/.codex/sessions/abc123/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Codex);
    }

    #[tokio::test]
    async fn test_infer_agent_type_cursor() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Cursor/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Cursor);
    }

    #[tokio::test]
    async fn test_infer_agent_type_copilot() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Code/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Copilot);
    }

    #[tokio::test]
    async fn test_infer_agent_type_antigravity() {
        let path = Path::new(
            "/Users/foo/Library/Application Support/Antigravity/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Antigravity);
    }

    #[tokio::test]
    async fn test_infer_agent_type_antigravity_api_cache() {
        let path = Path::new("/Users/foo/.cadence/cli/antigravity-api/abc.json");
        assert_eq!(infer_agent_type(path), AgentType::Antigravity);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf() {
        let path = Path::new("/Users/foo/.codeium/windsurf/cascade/abc.pb");
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_api_cache() {
        let path = Path::new("/Users/foo/.cadence/cli/windsurf-api/abc.json");
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_linux_workspace_storage() {
        let path = Path::new(
            "/home/foo/.config/Windsurf/User/workspaceStorage/x/chatSessions/session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[tokio::test]
    async fn test_infer_agent_type_windsurf_windows_workspace_storage() {
        let path = Path::new(
            "C:\\Users\\foo\\AppData\\Roaming\\Windsurf\\User\\workspaceStorage\\x\\chatSessions\\session.json",
        );
        assert_eq!(infer_agent_type(path), AgentType::Windsurf);
    }

    #[test]
    fn test_infer_agent_type_warp() {
        let path = Path::new(
            "/Users/foo/Library/Group Containers/2BBY89MBSN.dev.warp/Library/Application Support/dev.warp.Warp-Stable/warp.sqlite",
        );
        assert_eq!(infer_agent_type(path), AgentType::Warp);
    }

    #[tokio::test]
    async fn test_infer_agent_type_unknown_defaults_to_claude() {
        let path = Path::new("/tmp/some/random/session.jsonl");
        assert_eq!(infer_agent_type(path), AgentType::Claude);
    }

    // -----------------------------------------------------------------------
    // AgentType display
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_agent_type_display_claude() {
        assert_eq!(AgentType::Claude.to_string(), "claude-code");
    }

    #[tokio::test]
    async fn test_agent_type_display_codex() {
        assert_eq!(AgentType::Codex.to_string(), "codex");
    }

    #[tokio::test]
    async fn test_agent_type_display_cursor() {
        assert_eq!(AgentType::Cursor.to_string(), "cursor");
    }

    #[tokio::test]
    async fn test_agent_type_display_copilot() {
        assert_eq!(AgentType::Copilot.to_string(), "copilot");
    }

    #[tokio::test]
    async fn test_agent_type_display_antigravity() {
        assert_eq!(AgentType::Antigravity.to_string(), "antigravity");
    }

    #[tokio::test]
    async fn test_agent_type_display_windsurf() {
        assert_eq!(AgentType::Windsurf.to_string(), "windsurf");
    }

    #[test]
    fn test_agent_type_display_warp() {
        assert_eq!(AgentType::Warp.to_string(), "warp");
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_metadata_session_id_and_cwd() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"session_id":"abc-123","cwd":"/Users/foo/bar"}
{"type":"message","content":"hello"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_camel_case_session_id() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"sessionId":"def-456","cwd":"/Users/baz"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("def-456".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_workdir_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"workdir":"/home/user/project"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.cwd, Some("/home/user/project".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_working_directory_field() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"working_directory":"/opt/app"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.cwd, Some("/opt/app".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_chat_session_json() {
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
        let file = write_temp_file(dir.path(), "session.json", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("chat-123".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-repo/src".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_fields_across_multiple_lines() {
        let dir = TempDir::new().unwrap();
        // session_id on one line, cwd on another
        let content = r#"{"session_id":"multi-line-id"}
{"type":"other"}
{"cwd":"/Users/foo/repo"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("multi-line-id".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/repo".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_no_fields() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no metadata here"}
{"type":"tool_result","content":"more stuff"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_invalid_json_lines_skipped() {
        let dir = TempDir::new().unwrap();
        let content = r#"this is not json
{"session_id":"valid-id"}
also not json {{{{
{"cwd":"/valid/path"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("valid-id".to_string()));
        assert_eq!(metadata.cwd, Some("/valid/path".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(dir.path(), "empty.jsonl", "").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_nonexistent_file() {
        let path = Path::new("/nonexistent/file.jsonl");
        let metadata = parse_session_metadata(path).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_claude_path() {
        let dir = TempDir::new().unwrap();
        let claude_dir = dir.path().join(".claude").join("projects");
        tokio::fs::create_dir_all(&claude_dir).await.unwrap();
        let file = write_temp_file(&claude_dir, "session.jsonl", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::Claude));
    }

    #[tokio::test]
    async fn test_parse_metadata_agent_type_from_codex_path() {
        let dir = TempDir::new().unwrap();
        let codex_dir = dir.path().join(".codex").join("sessions");
        tokio::fs::create_dir_all(&codex_dir).await.unwrap();
        let file = write_temp_file(&codex_dir, "session.jsonl", "{}").await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.agent_type, Some(AgentType::Codex));
    }

    #[tokio::test]
    async fn test_parse_metadata_first_value_wins() {
        let dir = TempDir::new().unwrap();
        // Two lines with session_id -- first should win
        let content = r#"{"session_id":"first-id"}
{"session_id":"second-id"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("first-id".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata_str
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_str_extracts_fields() {
        let content = r#"{"session_id":"str-1","cwd":"/tmp/repo"}"#;
        let metadata = parse_session_metadata_str(content);
        assert_eq!(metadata.session_id, Some("str-1".to_string()));
        assert_eq!(metadata.cwd, Some("/tmp/repo".to_string()));
    }

    #[test]
    fn test_parse_metadata_str_falls_back_to_full_json() {
        let content = r#"{"sessionId":"chat-999","requests":[{"response":[{"baseUri":{"path":"file:///Users/foo/dev/repo"}}]}]}"#;
        let metadata = parse_session_metadata_str(content);
        assert_eq!(metadata.session_id, Some("chat-999".to_string()));
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/repo".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_session_metadata — Codex format (nested under payload)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_parse_metadata_codex_session_meta() {
        let dir = TempDir::new().unwrap();
        // Real Codex session_meta format: id and cwd nested under payload
        let content = r#"{"timestamp":"2026-02-10T01:52:21.832Z","type":"session_meta","payload":{"id":"019c453f-e731-7bd1-9d05-c571ec59ca6b","cwd":"/Users/foo/dev/my-project","originator":"codex_cli_rs","cli_version":"0.98.0"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(
            metadata.session_id,
            Some("019c453f-e731-7bd1-9d05-c571ec59ca6b".to_string())
        );
        assert_eq!(metadata.cwd, Some("/Users/foo/dev/my-project".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_codex_payload_id_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.id present, no cwd
        let content = r#"{"type":"session_meta","payload":{"id":"abc-123"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("abc-123".to_string()));
        assert_eq!(metadata.cwd, None);
    }

    #[tokio::test]
    async fn test_parse_metadata_codex_payload_cwd_only() {
        let dir = TempDir::new().unwrap();
        // Only payload.cwd present, no id
        let content = r#"{"type":"session_meta","payload":{"cwd":"/Users/foo/bar"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, None);
        assert_eq!(metadata.cwd, Some("/Users/foo/bar".to_string()));
    }

    #[tokio::test]
    async fn test_parse_metadata_top_level_takes_priority_over_payload() {
        let dir = TempDir::new().unwrap();
        // Both top-level and payload fields present -- top-level wins (first-value-wins)
        let content = r#"{"session_id":"top-level-id","cwd":"/top/level"}
{"type":"session_meta","payload":{"id":"payload-id","cwd":"/payload/path"}}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let metadata = parse_session_metadata(&file).await;

        assert_eq!(metadata.session_id, Some("top-level-id".to_string()));
        assert_eq!(metadata.cwd, Some("/top/level".to_string()));
    }

    // -----------------------------------------------------------------------
    // session_time_range
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_session_time_range_parses_rfc3339() {
        let dir = TempDir::new().unwrap();
        let t1 = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let t2 = OffsetDateTime::from_unix_timestamp(1_700_000_120).unwrap();
        let s1 = t1.format(&Rfc3339).unwrap();
        let s2 = t2.format(&Rfc3339).unwrap();

        let content = format!(
            r#"{{"timestamp":"{s1}"}}
{{"payload":{{"createdAt":"{s2}"}}}}"#,
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content).await;

        let range = session_time_range(&file).await.unwrap();
        assert_eq!(range.0, t1.unix_timestamp());
        assert_eq!(range.1, t2.unix_timestamp());
    }

    #[tokio::test]
    async fn test_session_time_range_numeric_ms() {
        let dir = TempDir::new().unwrap();
        let content = r#"{
  "creationDate": 1749509938455,
  "lastMessageDate": 1749509971642
}"#;
        let file = write_temp_file(dir.path(), "session.json", content).await;

        let range = session_time_range(&file).await.unwrap();
        assert_eq!(range.0, 1_749_509_938);
        assert_eq!(range.1, 1_749_509_971);
    }

    #[test]
    fn test_session_time_range_str_parses() {
        let content = r#"{"timestamp":"2026-02-10T01:52:21Z"}"#;
        let range = session_time_range_str(content).unwrap();
        assert_eq!(range.0, range.1);
    }

    #[tokio::test]
    async fn test_session_time_range_none_when_missing() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"no timestamps"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let range = session_time_range(&file).await;
        assert!(range.is_none());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_from_codex_function_call_output() {
        let dir = TempDir::new().unwrap();
        // Real Codex function_call_output format with git commit output
        let content = r#"{"timestamp":"2026-02-10T02:13:37.205Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_fEoWO6fq3tRI8VsBgjkdxRfp","output":"Chunk ID: f0cd33\nWall time: 0.0525 seconds\nProcess exited with code 0\nOriginal token count: 40\nOutput:\n[main df69283] Create detailed TODO plan\n 1 file changed, 229 insertions(+)\n create mode 100644 TODO.md\n"}}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "df69283");
    }

    // -----------------------------------------------------------------------
    // extract_commit_hashes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_extract_commit_hashes_finds_short_hash() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_finds_full_hash() {
        let dir = TempDir::new().unwrap();
        let hash = "abcdef0123456789abcdef0123456789abcdef01";
        let content = format!(r#"{{"content":"[main {hash}] fix bug"}}"#);
        let file = write_temp_file(dir.path(), "session.jsonl", &content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash);
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_finds_multiple() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] first commit"}
{"content":"[main 1234567] second commit"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&"abcdef0".to_string()));
        assert!(hashes.contains(&"1234567".to_string()));
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_deduplicates() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main abcdef0] fix bug"}
{"content":"[main abcdef0] fix bug"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_no_hashes() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"message","content":"hello world"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_ignores_bare_hex() {
        let dir = TempDir::new().unwrap();
        // Bare hex strings (e.g., from git log) should NOT be extracted
        let content = r#"{"content":"abcdef0 Fix something"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_ignores_diff_blob_hashes() {
        let dir = TempDir::new().unwrap();
        // Diff index lines should NOT match
        let content = r#"{"content":"index c84f8ba..b145f18 100644"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_ignores_too_short_hex() {
        let dir = TempDir::new().unwrap();
        // 6-char hash in bracket pattern -- below minimum
        let content = r#"{"content":"[main abcdef] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_uppercase_lowered() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"[main ABCDEF0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_feature_branch() {
        let dir = TempDir::new().unwrap();
        // Branch names with slashes and dashes
        let content = r#"{"content":"[feature/foo-bar abcdef0] fix bug"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0");
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_nonexistent_file() {
        let path = Path::new("/nonexistent/file.jsonl");
        let hashes = extract_commit_hashes(path).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_empty_file() {
        let dir = TempDir::new().unwrap();
        let file = write_temp_file(dir.path(), "empty.jsonl", "").await;

        let hashes = extract_commit_hashes(&file).await;
        assert!(hashes.is_empty());
    }

    #[tokio::test]
    async fn test_extract_commit_hashes_realistic_session_log() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"type":"assistant","message":"I'll commit now"}
{"type":"tool_use","name":"Bash","input":{"command":"git commit -m fix"}}
{"type":"tool_result","content":"[main 655dd38] fix\n 1 file changed"}
{"type":"assistant","message":"Done! Commit 655dd38"}
"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content).await;

        let hashes = extract_commit_hashes(&file).await;
        // Should find 655dd38 from the [main 655dd38] pattern
        // but NOT from the bare "Commit 655dd38" mention
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "655dd38");
    }

    #[test]
    fn test_extract_commit_hashes_str() {
        let content = r#"{"content":"[main abcdef0] fix bug"}"#;
        let hashes = extract_commit_hashes_str(content);
        assert_eq!(hashes, vec!["abcdef0".to_string()]);
    }
}
