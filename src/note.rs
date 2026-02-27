//! Note formatting for AI session data.
//!
//! Produces human-readable notes with a YAML-style header delimited by `---`
//! followed by the verbatim session log (JSONL) payload. The header contains
//! metadata fields: agent, session_id, repo, commit, confidence, and
//! payload_sha256.

use crate::scanner::AgentType;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Confidence level of the match between session and commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum Confidence {
    ExactHashMatch,
    TimeWindowMatch,
    ScoredMatch,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::ExactHashMatch => write!(f, "exact_hash_match"),
            Confidence::TimeWindowMatch => write!(f, "time_window_match"),
            Confidence::ScoredMatch => write!(f, "scored_match"),
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
/// repo: <path>
/// commit: <full hash>
/// confidence: exact_hash_match
/// session_start: 2025-01-15T10:30:00Z   (omitted when unknown)
/// payload_sha256: <hash>
/// ---
/// <verbatim session log (JSONL)>
/// ```
///
/// The `confidence` field is always `exact_hash_match` for now.
/// The `payload_sha256` is computed from `session_log`.
/// The `session_start` field is an RFC 3339 timestamp of when the session
/// began; it is omitted if not available.
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
#[cfg(test)]
pub fn format(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    session_log: &str,
    session_start: Option<i64>,
) -> anyhow::Result<String> {
    format_with_confidence(
        agent,
        session_id,
        repo,
        commit,
        session_log,
        Confidence::ExactHashMatch,
        session_start,
    )
}

/// Produce a complete note with an explicit confidence value.
#[cfg(test)]
pub fn format_with_confidence(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    session_log: &str,
    confidence: Confidence,
    session_start: Option<i64>,
) -> anyhow::Result<String> {
    crate::git::validate_commit_hash(commit)?;
    let sha = payload_sha256(session_log);

    let mut note = String::new();
    note.push_str("---\n");
    note.push_str(&format!("agent: {}\n", agent));
    note.push_str(&format!("session_id: {}\n", session_id));
    note.push_str(&format!("repo: {}\n", repo));
    note.push_str(&format!("commit: {}\n", commit));
    note.push_str(&format!("confidence: {}\n", confidence));
    if let Some(epoch) = session_start
        && let Ok(dt) = OffsetDateTime::from_unix_timestamp(epoch)
        && let Ok(formatted) = dt.format(&Rfc3339)
    {
        note.push_str(&format!("session_start: {}\n", formatted));
    }
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
// V2 pointer note format
// ---------------------------------------------------------------------------

/// Encoding applied to the payload blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PayloadEncoding {
    /// Raw JSONL, no compression, no encryption.
    Plain,
    /// Zstd-compressed, not encrypted.
    Zstd,
    /// PGP-encrypted (binary), not compressed.
    Pgp,
    /// Zstd-compressed then PGP-encrypted (binary).
    ZstdPgp,
}

impl std::fmt::Display for PayloadEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadEncoding::Plain => write!(f, "plain"),
            PayloadEncoding::Zstd => write!(f, "zstd"),
            PayloadEncoding::Pgp => write!(f, "pgp"),
            PayloadEncoding::ZstdPgp => write!(f, "zstd+pgp"),
        }
    }
}

/// Produce a v2 pointer note (no inline payload).
///
/// The note contains a YAML-style header referencing a git blob that holds
/// the (optionally compressed, optionally encrypted) session log. Multiple
/// commits from the same session share a single blob.
///
/// ```text
/// ---
/// cadence_version: 2
/// agent: claude-code
/// session_id: <uuid>
/// repo: <path>
/// commit: <full hash>
/// confidence: exact_hash_match | time_window_match
/// session_start: 2025-01-15T10:30:00Z
/// payload_blob: <40-char SHA-1 of the git blob>
/// payload_sha256: <hex SHA-256 of the uncompressed plaintext>
/// payload_encoding: zstd+pgp | zstd | pgp | plain
/// ---
/// ```
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub fn format_v2(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    confidence: Confidence,
    session_start: Option<i64>,
    payload_blob: &str,
    payload_sha256_hex: &str,
    payload_encoding: PayloadEncoding,
) -> anyhow::Result<String> {
    format_v2_with_match_details(
        agent,
        session_id,
        repo,
        commit,
        confidence,
        session_start,
        payload_blob,
        payload_sha256_hex,
        payload_encoding,
        None,
        None,
    )
}

/// Produce a v2 pointer note with optional scoring diagnostics.
#[allow(clippy::too_many_arguments)]
pub fn format_v2_with_match_details(
    agent: &AgentType,
    session_id: &str,
    repo: &str,
    commit: &str,
    confidence: Confidence,
    session_start: Option<i64>,
    payload_blob: &str,
    payload_sha256_hex: &str,
    payload_encoding: PayloadEncoding,
    match_score: Option<f64>,
    match_reasons: Option<&[String]>,
) -> anyhow::Result<String> {
    crate::git::validate_commit_hash(commit)?;

    let mut note = String::new();
    note.push_str("---\n");
    note.push_str("cadence_version: 2\n");
    note.push_str(&format!("agent: {}\n", agent));
    note.push_str(&format!("session_id: {}\n", session_id));
    note.push_str(&format!("repo: {}\n", repo));
    note.push_str(&format!("commit: {}\n", commit));
    note.push_str(&format!("confidence: {}\n", confidence));
    if let Some(epoch) = session_start
        && let Ok(dt) = OffsetDateTime::from_unix_timestamp(epoch)
        && let Ok(formatted) = dt.format(&Rfc3339)
    {
        note.push_str(&format!("session_start: {}\n", formatted));
    }
    note.push_str(&format!("payload_blob: {}\n", payload_blob));
    note.push_str(&format!("payload_sha256: {}\n", payload_sha256_hex));
    note.push_str(&format!("payload_encoding: {}\n", payload_encoding));
    if let Some(score) = match_score {
        note.push_str(&format!("match_score: {:.3}\n", score));
    }
    if let Some(reasons) = match_reasons
        && !reasons.is_empty()
    {
        note.push_str(&format!("match_reasons: {}\n", reasons.join(",")));
    }
    note.push_str("---\n");

    Ok(note)
}

/// Compress raw payload bytes with zstd (level 3).
pub fn compress_payload(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
        .map_err(|e| anyhow::anyhow!("zstd compression failed: {}", e))
}

/// Decompress zstd-compressed payload bytes.
#[cfg(test)]
pub fn decompress_payload(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    zstd::decode_all(std::io::Cursor::new(data))
        .map_err(|e| anyhow::anyhow!("zstd decompression failed: {}", e))
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
            None,
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
        assert!(header.contains("repo: /Users/foo/dev/my-repo\n"));
        assert!(header.contains("commit: 655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e\n"));
        assert!(header.contains("confidence: exact_hash_match\n"));

        // Verify the payload_sha256 in the header matches the actual SHA-256
        let expected_sha = payload_sha256(session_log);
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
            None,
        )
        .unwrap();

        // Extract lines between the two --- delimiters
        let lines: Vec<&str> = note.lines().collect();
        assert_eq!(lines[0], "---");
        assert!(lines[1].starts_with("agent: "));
        assert!(lines[2].starts_with("session_id: "));
        assert!(lines[3].starts_with("repo: "));
        assert!(lines[4].starts_with("commit: "));
        assert!(lines[5].starts_with("confidence: "));
        assert!(lines[6].starts_with("payload_sha256: "));
        assert_eq!(lines[7], "---");
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .unwrap();

        assert!(note.contains("confidence: time_window_match\n"));
    }

    // -----------------------------------------------------------------------
    // format — session_start
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_session_start_renders_rfc3339() {
        // 2023-11-14T22:13:20Z
        let epoch = 1_700_000_000_i64;
        let note = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
            Some(epoch),
        )
        .unwrap();

        assert!(note.contains("session_start: 2023-11-14T22:13:20Z\n"));
    }

    #[test]
    fn test_format_session_start_none_omits_field() {
        let note = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "log",
            None,
        )
        .unwrap();

        assert!(!note.contains("session_start:"));
    }

    #[test]
    fn test_format_session_start_field_order() {
        let epoch = 1_700_000_000_i64;
        let note = format(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            "payload",
            Some(epoch),
        )
        .unwrap();

        let lines: Vec<&str> = note.lines().collect();
        assert_eq!(lines[0], "---");
        assert!(lines[1].starts_with("agent: "));
        assert!(lines[2].starts_with("session_id: "));
        assert!(lines[3].starts_with("repo: "));
        assert!(lines[4].starts_with("commit: "));
        assert!(lines[5].starts_with("confidence: "));
        assert!(lines[6].starts_with("session_start: "));
        assert!(lines[7].starts_with("payload_sha256: "));
        assert_eq!(lines[8], "---");
    }

    // -----------------------------------------------------------------------
    // format_v2 — pointer note structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_v2_produces_correct_structure() {
        let note = format_v2(
            &AgentType::Claude,
            "abc-123",
            "/repo",
            "655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
            Confidence::ExactHashMatch,
            Some(1_700_000_000),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PayloadEncoding::ZstdPgp,
        )
        .unwrap();

        assert!(note.starts_with("---\n"));
        assert!(note.ends_with("---\n"));
        assert!(note.contains("cadence_version: 2\n"));
        assert!(note.contains("agent: claude-code\n"));
        assert!(note.contains("session_id: abc-123\n"));
        assert!(note.contains("repo: /repo\n"));
        assert!(note.contains("commit: 655dd38a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e\n"));
        assert!(note.contains("confidence: exact_hash_match\n"));
        assert!(note.contains("session_start: 2023-11-14T22:13:20Z\n"));
        assert!(note.contains("payload_blob: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"));
        assert!(note.contains(
            "payload_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        ));
        assert!(note.contains("payload_encoding: zstd+pgp\n"));
    }

    #[test]
    fn test_format_v2_field_order() {
        let note = format_v2(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            Confidence::ExactHashMatch,
            Some(1_700_000_000),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PayloadEncoding::Zstd,
        )
        .unwrap();

        let lines: Vec<&str> = note.lines().collect();
        assert_eq!(lines[0], "---");
        assert!(lines[1].starts_with("cadence_version: "));
        assert!(lines[2].starts_with("agent: "));
        assert!(lines[3].starts_with("session_id: "));
        assert!(lines[4].starts_with("repo: "));
        assert!(lines[5].starts_with("commit: "));
        assert!(lines[6].starts_with("confidence: "));
        assert!(lines[7].starts_with("session_start: "));
        assert!(lines[8].starts_with("payload_blob: "));
        assert!(lines[9].starts_with("payload_sha256: "));
        assert!(lines[10].starts_with("payload_encoding: "));
        assert_eq!(lines[11], "---");
    }

    #[test]
    fn test_format_v2_no_inline_payload() {
        let note = format_v2(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            Confidence::ExactHashMatch,
            None,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PayloadEncoding::Plain,
        )
        .unwrap();

        // Should end with closing --- and nothing after
        assert!(note.ends_with("---\n"));
        // Split: should have exactly empty prefix, header, empty suffix
        let parts: Vec<&str> = note.splitn(3, "---\n").collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2], ""); // no payload after closing ---
    }

    #[test]
    fn test_format_v2_no_session_start() {
        let note = format_v2(
            &AgentType::Claude,
            "sid",
            "/repo",
            "aabbccdd00112233",
            Confidence::TimeWindowMatch,
            None,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PayloadEncoding::Zstd,
        )
        .unwrap();

        assert!(!note.contains("session_start:"));
        assert!(note.contains("confidence: time_window_match\n"));
    }

    #[test]
    fn test_format_v2_all_encodings() {
        for (enc, label) in [
            (PayloadEncoding::Plain, "plain"),
            (PayloadEncoding::Zstd, "zstd"),
            (PayloadEncoding::Pgp, "pgp"),
            (PayloadEncoding::ZstdPgp, "zstd+pgp"),
        ] {
            let note = format_v2(
                &AgentType::Claude,
                "sid",
                "/repo",
                "aabbccdd00112233",
                Confidence::ExactHashMatch,
                None,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                enc,
            )
            .unwrap();
            assert!(
                note.contains(&format!("payload_encoding: {}\n", label)),
                "expected encoding label '{}' in note",
                label
            );
        }
    }

    #[test]
    fn test_format_v2_rejects_invalid_commit() {
        let result = format_v2(
            &AgentType::Claude,
            "sid",
            "/repo",
            "not-a-hash",
            Confidence::ExactHashMatch,
            None,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            PayloadEncoding::Plain,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // compress / decompress round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_compress_decompress_roundtrip() {
        let original =
            b"hello world, this is a test payload with some repetition repetition repetition";
        let compressed = compress_payload(original).unwrap();
        let decompressed = decompress_payload(&compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_compress_reduces_size_on_repetitive_data() {
        let data = "repetitive data\n".repeat(1000);
        let compressed = compress_payload(data.as_bytes()).unwrap();
        assert!(
            compressed.len() < data.len(),
            "compressed ({}) should be smaller than original ({})",
            compressed.len(),
            data.len()
        );
    }

    #[test]
    fn test_compress_empty() {
        let compressed = compress_payload(b"").unwrap();
        let decompressed = decompress_payload(&compressed).unwrap();
        assert!(decompressed.is_empty());
    }
}
