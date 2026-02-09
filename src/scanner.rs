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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The type of AI agent that produced a session log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentType {
    Claude,
    Codex,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Claude => write!(f, "claude-code"),
            AgentType::Codex => write!(f, "codex"),
        }
    }
}

/// A successful match: a candidate file contains a commit hash.
#[derive(Debug, Clone)]
pub struct SessionMatch {
    /// Path to the session log file that contained the commit hash.
    pub file_path: PathBuf,
    /// The line from the file that contained the match.
    pub matched_line: String,
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
                    matched_line: line,
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

        // Extract session_id
        if metadata.session_id.is_none()
            && let Some(id) = value
                .get("session_id")
                .or_else(|| value.get("sessionId"))
                .and_then(|v| v.as_str())
        {
            metadata.session_id = Some(id.to_string());
        }

        // Extract cwd / workdir
        if metadata.cwd.is_none()
            && let Some(cwd) = value
                .get("cwd")
                .or_else(|| value.get("workdir"))
                .or_else(|| value.get("working_directory"))
                .and_then(|v| v.as_str())
        {
            metadata.cwd = Some(cwd.to_string());
        }

        // If we have both fields, stop early
        if metadata.session_id.is_some() && metadata.cwd.is_some() {
            break;
        }
    }

    // Infer agent type from file path
    metadata.agent_type = Some(infer_agent_type(file));

    metadata
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

/// Extract all potential 40-character hex commit hashes from a file.
///
/// Scans every line of the file for substrings that look like full Git commit
/// hashes: exactly 40 consecutive lowercase or uppercase hex characters.
/// A hex substring is only considered a match if it is not preceded or
/// followed by another hex character (i.e., it must be exactly 40 chars,
/// not embedded in a longer hex string).
///
/// Returns a deduplicated `Vec<String>` of extracted hashes (lowercased).
/// Returns an empty Vec on any I/O error.
///
/// This is used by the `hydrate` command, which needs to find ALL commit
/// hashes in a session log (not just check for a specific hash).
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

/// Extract 40-char hex strings from a single line.
///
/// Walks through the line looking for runs of hex digits. When a run of
/// exactly 40 is found (bounded by non-hex chars or string boundaries),
/// it is added to the results.
fn extract_hashes_from_line(
    line: &str,
    hashes: &mut Vec<String>,
    seen: &mut std::collections::HashSet<String>,
) {
    let bytes = line.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i].is_ascii_hexdigit() {
            let start = i;
            while i < len && bytes[i].is_ascii_hexdigit() {
                i += 1;
            }
            let run_len = i - start;
            if run_len == 40 {
                let hash = line[start..i].to_ascii_lowercase();
                if seen.insert(hash.clone()) {
                    hashes.push(hash);
                }
            }
        } else {
            i += 1;
        }
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
    } else {
        // Default to Claude -- `.claude` paths and unknown paths
        AgentType::Claude
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
        assert!(m.matched_line.contains(commit_hash));
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
        assert!(m.matched_line.contains(short_hash));
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
        let m = result.unwrap();
        assert!(m.matched_line.contains(&commit_hash[..7]));
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
    // verify_match — requires real git repos, run serially
    // -----------------------------------------------------------------------

    /// Helper: create a temp git repo with one commit, return (TempDir, commit_hash).
    fn init_temp_repo() -> (TempDir, String) {
        let dir = TempDir::new().expect("failed to create temp dir");
        let path = dir.path();

        run_git(path, &["init"]);
        run_git(path, &["config", "user.email", "test@test.com"]);
        run_git(path, &["config", "user.name", "Test User"]);
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
    fn test_extract_commit_hashes_finds_full_hash() {
        let dir = TempDir::new().unwrap();
        let hash = "abcdef0123456789abcdef0123456789abcdef01";
        let content = format!(r#"{{"content":"Created commit {hash}"}}"#);
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash);
    }

    #[test]
    fn test_extract_commit_hashes_finds_multiple() {
        let dir = TempDir::new().unwrap();
        let hash1 = "abcdef0123456789abcdef0123456789abcdef01";
        let hash2 = "1234567890abcdef1234567890abcdef12345678";
        let content = format!(
            r#"{{"content":"commit {hash1}"}}
{{"content":"commit {hash2}"}}
"#
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&hash1.to_string()));
        assert!(hashes.contains(&hash2.to_string()));
    }

    #[test]
    fn test_extract_commit_hashes_deduplicates() {
        let dir = TempDir::new().unwrap();
        let hash = "abcdef0123456789abcdef0123456789abcdef01";
        let content = format!(
            r#"{{"content":"commit {hash}"}}
{{"content":"again {hash}"}}
"#
        );
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
    fn test_extract_commit_hashes_ignores_short_hex() {
        let dir = TempDir::new().unwrap();
        // 7-char hex string -- should NOT be extracted (only 40-char)
        let content = r#"{"content":"short hash abcdef0"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_ignores_longer_hex() {
        let dir = TempDir::new().unwrap();
        // 41-char hex string -- should NOT be extracted
        let content = r#"{"content":"long hex abcdef0123456789abcdef0123456789abcdef012"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_extract_commit_hashes_uppercase_lowered() {
        let dir = TempDir::new().unwrap();
        let content = r#"{"content":"commit ABCDEF0123456789ABCDEF0123456789ABCDEF01"}"#;
        let file = write_temp_file(dir.path(), "session.jsonl", content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], "abcdef0123456789abcdef0123456789abcdef01");
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
        let hash = "655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e";
        let content = format!(
            r#"{{"type":"assistant","message":"I'll commit now"}}
{{"type":"tool_use","name":"Bash","input":{{"command":"git commit -m fix"}}}}
{{"type":"tool_result","content":"[main 655dd38] fix\n 1 file changed"}}
{{"type":"assistant","message":"Done! Commit {hash}"}}
"#
        );
        let file = write_temp_file(dir.path(), "session.jsonl", &content);

        let hashes = extract_commit_hashes(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash);
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
