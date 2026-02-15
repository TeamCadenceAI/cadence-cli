//! Note formatting for AI session data.
//!
//! Produces human-readable notes with a YAML-style header delimited by `---`
//! followed by the verbatim session log (JSONL) payload. The header contains
//! metadata fields: agent, session_id, user_email, repo, commit,
//! confidence, uploaded_data_sha256, and payload_sha256.

use crate::scanner::AgentType;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Confidence level of the match between session and commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    ExactHashMatch,
    TimeWindowMatch,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::ExactHashMatch => write!(f, "exact_hash_match"),
            Confidence::TimeWindowMatch => write!(f, "time_window_match"),
        }
    }
}

/// Produce a complete note with YAML-style header and verbatim session log.
///
/// The note format is:
/// ```text
/// ---
/// agent: claude-code | codex | cursor | copilot | antigravity
/// session_id: <uuid>
/// user_email: <onboarded email or unknown>
/// repo: <path>
/// commit: <full hash>
/// confidence: exact_hash_match
/// uploaded_data_sha256: <hash>
/// payload_sha256: <hash>
/// ---
/// <verbatim session log (JSONL)>
/// ```
///
/// The `confidence` field is always `exact_hash_match` for now.
/// The `payload_sha256` is computed from `session_log`.
///
/// The `commit` parameter is validated via [`crate::git::validate_commit_hash`]
/// and must be 7-40 hex characters. Returns an error if validation fails.
///
/// # Parsing caveat
///
/// The payload is appended verbatim after the closing `---` delimiter. If the
/// payload itself contains a line that is exactly `---\n`, a naive parser that
/// scans for `---` delimiters will misparse the note. Parsers should use
/// `splitn(3, "---\n")` (splitting on at most 3 occurrences) to correctly
/// separate the header from the payload, and verify integrity using the
/// `payload_sha256` field.
pub fn format(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    session_log: &str,
    user_email: Option<&str>,
) -> anyhow::Result<String> {
    format_with_confidence(
        agent,
        session_id,
        repo,
        commit,
        session_log,
        user_email,
        Confidence::ExactHashMatch,
    )
}

/// Produce a complete note with an explicit confidence value.
pub fn format_with_confidence(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    session_log: &str,
    user_email: Option<&str>,
    confidence: Confidence,
) -> anyhow::Result<String> {
    crate::git::validate_commit_hash(commit)?;
    let sha = payload_sha256(session_log);
    let email = user_email.unwrap_or("unknown");

    let mut note = String::new();
    note.push_str("---\n");
    note.push_str(&format!("agent: {}\n", agent));
    note.push_str(&format!("session_id: {}\n", session_id));
    note.push_str(&format!("user_email: {}\n", email));
    note.push_str(&format!("repo: {}\n", repo));
    note.push_str(&format!("commit: {}\n", commit));
    note.push_str(&format!("confidence: {}\n", confidence));
    note.push_str(&format!("payload_sha256: {}\n", sha));
    note.push_str("---\n");
    note.push_str(session_log);

    Ok(note)
}

/// Compute the SHA-256 hash of the session log payload.
///
/// Returns the hash as a lowercase hex string (64 characters).
pub fn payload_sha256(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // payload_sha256
    // -----------------------------------------------------------------------

    #[test]
    fn test_payload_sha256_known_input() {
        // SHA-256 of "hello" is well-known
        let hash = payload_sha256("hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_payload_sha256_empty_input() {
        // SHA-256 of empty string is well-known
        let hash = payload_sha256("");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_payload_sha256_produces_64_char_hex() {
        let hash = payload_sha256("some content");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_payload_sha256_multiline() {
        let content = "line one\nline two\nline three\n";
        let hash = payload_sha256(content);
        assert_eq!(hash.len(), 64);
        // Verify determinism
        assert_eq!(hash, payload_sha256(content));
    }

    // -----------------------------------------------------------------------
    // format — exact note structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_produces_correct_structure() {
        let session_id = "abc-123-def-456";
        let repo = "/Users/foo/dev/my-repo";
        let commit = "655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e";
        let session_log = r#"{"type":"message","content":"hello"}
{"type":"tool_result","content":"done"}
"#;

        let note = format(
            &AgentType::Claude,
            session_id,
            repo,
            commit,
            session_log,
            Some("dev@example.com"),
        )
        .unwrap();

        // Verify the note starts with ---
        assert!(note.starts_with("---\n"));

        // Split into header and payload
        let parts: Vec<&str> = note.splitn(3, "---\n").collect();
        assert_eq!(parts.len(), 3);

        // parts[0] is empty (before first ---)
        assert_eq!(parts[0], "");

        // parts[1] is the header content (between the two ---)
        let header = parts[1];
        assert!(header.contains("agent: claude-code\n"));
        assert!(header.contains("session_id: abc-123-def-456\n"));
        assert!(header.contains("user_email: dev@example.com\n"));
        assert!(header.contains("repo: /Users/foo/dev/my-repo\n"));
        assert!(header.contains("commit: 655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e\n"));
        assert!(header.contains("confidence: exact_hash_match\n"));

        // Verify the payload_sha256 in the header matches the actual SHA-256
        let expected_sha = payload_sha256(session_log);
        assert!(header.contains(&format!("uploaded_data_sha256: {}\n", expected_sha)));
        assert!(header.contains(&format!("payload_sha256: {}\n", expected_sha)));

        // parts[2] is the verbatim payload after the closing ---
        assert_eq!(parts[2], session_log);
    }

    #[test]
    fn test_format_header_field_order() {
        let note = format(
            &AgentType::Codex,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "payload",
            Some("user@example.com"),
        )
        .unwrap();

        // Extract lines between the two --- delimiters
        let lines: Vec<&str> = note.lines().collect();
        assert_eq!(lines[0], "---");
        assert!(lines[1].starts_with("agent: "));
        assert!(lines[2].starts_with("session_id: "));
        assert!(lines[3].starts_with("user_email: "));
        assert!(lines[4].starts_with("repo: "));
        assert!(lines[5].starts_with("commit: "));
        assert!(lines[6].starts_with("confidence: "));
        assert!(lines[7].starts_with("uploaded_data_sha256: "));
        assert!(lines[8].starts_with("payload_sha256: "));
        assert_eq!(lines[9], "---");
    }

    #[test]
    fn test_format_with_empty_payload() {
        let note = format(
            &AgentType::Claude,
            "empty-session",
            "/repo",
            "0000000000000000000000000000000000000000",
            "",
            None,
        )
        .unwrap();

        // Should still have the header
        assert!(note.starts_with("---\n"));
        assert!(note.contains("confidence: exact_hash_match\n"));

        // SHA-256 of empty string
        let empty_sha = payload_sha256("");
        assert!(note.contains(&format!("payload_sha256: {}\n", empty_sha)));

        // The note should end with the closing --- and nothing after it
        assert!(note.ends_with("---\n"));
    }

    #[test]
    fn test_format_with_multiline_payload() {
        let session_log = r#"{"line":1}
{"line":2}
{"line":3}
{"line":4}
{"line":5}
"#;
        let note = format(
            &AgentType::Claude,
            "multi",
            "/repo",
            "aabbccdd00112233",
            session_log,
            None,
        )
        .unwrap();

        // Payload should be verbatim after the closing ---
        let closing_marker = "---\n";
        let header_end = note.find(closing_marker).unwrap(); // first ---
        let payload_start_search = &note[header_end + closing_marker.len()..];
        let second_marker = payload_start_search.find(closing_marker).unwrap();
        let payload = &payload_start_search[second_marker + closing_marker.len()..];

        assert_eq!(payload, session_log);
    }

    #[test]
    fn test_format_payload_is_verbatim() {
        // Verify the session log is not modified in any way
        let session_log = "  leading spaces\ttabs\nnewlines\n\n  trailing spaces  \n";
        let note = format(
            &AgentType::Codex,
            "sid",
            "/repo",
            "aabbccdd00112233",
            session_log,
            None,
        )
        .unwrap();

        // The note should end with the verbatim session log
        assert!(note.ends_with(session_log));
    }

    #[test]
    fn test_format_codex_agent() {
        let note = format(
            &AgentType::Codex,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
            None,
        )
        .unwrap();
        assert!(note.contains("agent: codex\n"));
    }

    #[test]
    fn test_format_cursor_agent() {
        let note = format(
            &AgentType::Cursor,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
        )
        .unwrap();
        assert!(note.contains("agent: cursor\n"));
    }

    #[test]
    fn test_format_copilot_agent() {
        let note = format(
            &AgentType::Copilot,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
        )
        .unwrap();
        assert!(note.contains("agent: copilot\n"));
    }

    #[test]
    fn test_format_antigravity_agent() {
        let note = format(
            &AgentType::Antigravity,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
        )
        .unwrap();
        assert!(note.contains("agent: antigravity\n"));
    }

    #[test]
    fn test_format_sha256_matches_payload() {
        let session_log = "some session log content\nwith multiple lines\n";
        let note = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            session_log,
            None,
        )
        .unwrap();

        let expected_sha = payload_sha256(session_log);
        assert!(note.contains(&format!("payload_sha256: {}\n", expected_sha)));
    }

    // -----------------------------------------------------------------------
    // format — round-trip: payload extraction
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_roundtrip_payload_extraction() {
        let session_log = r#"{"session_id":"abc","cwd":"/foo"}
{"type":"tool_result","content":"[main 655dd38] fix\n 1 file changed"}
{"type":"assistant","message":"Done!"}
"#;
        let note = format(
            &AgentType::Claude,
            "abc",
            "/foo",
            "655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
            session_log,
            None,
        )
        .unwrap();

        // Split on "---\n" to extract payload
        let parts: Vec<&str> = note.splitn(3, "---\n").collect();
        assert_eq!(parts.len(), 3);
        let extracted_payload = parts[2];

        assert_eq!(extracted_payload, session_log);

        // Verify the SHA in the header matches the extracted payload
        let sha_from_extraction = payload_sha256(extracted_payload);
        assert!(parts[1].contains(&format!("payload_sha256: {}\n", sha_from_extraction)));
    }

    // -----------------------------------------------------------------------
    // format — payload containing `---` delimiter
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_payload_containing_delimiter() {
        // Payload that contains `---` on its own line — this is the edge case
        // where a naive parser scanning for `---` delimiters would misparse.
        let session_log = "line one\n---\nline two\n";
        let note = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            session_log,
            None,
        )
        .unwrap();

        // Using splitn(3, "---\n") should still correctly extract the payload,
        // because it splits on at most 3 occurrences: empty prefix, header, rest.
        let parts: Vec<&str> = note.splitn(3, "---\n").collect();
        assert_eq!(parts.len(), 3);
        let extracted_payload = parts[2];

        // The extracted payload must be identical to the original session log
        assert_eq!(extracted_payload, session_log);

        // Verify the SHA in the header matches the extracted payload
        let sha_from_extraction = payload_sha256(extracted_payload);
        assert!(parts[1].contains(&format!("payload_sha256: {}\n", sha_from_extraction)));
    }

    // -----------------------------------------------------------------------
    // format — commit hash validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_rejects_invalid_commit_hash() {
        let result = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "not-a-hash",
            "log",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_format_rejects_empty_commit_hash() {
        let result = format(&AgentType::Claude, "sid", "/repo", "", "log", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_rejects_short_commit_hash() {
        let result = format(&AgentType::Claude, "sid", "/repo", "abcdef", "log", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_with_time_window_confidence() {
        let note = format_with_confidence(
            &AgentType::Claude,
            "time-window-session",
            "/repo",
            "abcdef0123456789abcdef0123456789abcdef01",
            "payload",
            Confidence::TimeWindowMatch,
        )
        .unwrap();

        assert!(note.contains("confidence: time_window_match\n"));
    }
}
