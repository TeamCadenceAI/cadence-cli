//! Canonical session storage models and serialization helpers.
//!
//! Session objects are the source of truth and contain both structured
//! frontmatter metadata and raw session content.

use crate::scanner::AgentType;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_uid: String,
    pub agent: String,
    pub session_id: String,
    pub repo_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_remote_url: Option<String>,
    pub git_ref: String,
    pub head_sha: String,
    pub committer_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_user_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_user_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_start: Option<i64>,
    pub content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub ingested_at: String,
    pub cli_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEnvelope {
    pub record: SessionRecord,
    pub session_content: String,
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

pub fn content_sha256(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub fn hash_key(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result)
}

pub fn compute_session_uid(
    agent: &AgentType,
    session_id: &str,
    repo_root: &str,
    session_start: Option<i64>,
    content_sha: &str,
) -> String {
    let key = format!(
        "{}|{}|{}|{}|{}",
        agent,
        session_id,
        repo_root,
        session_start.unwrap_or_default(),
        content_sha
    );
    hash_key(&key)
}

pub fn serialize_session_object(record: SessionRecord, session_content: String) -> Result<Vec<u8>> {
    let envelope = SessionEnvelope {
        record,
        session_content,
    };
    Ok(serde_json::to_vec(&envelope)?)
}

pub fn compress_bytes(data: &[u8]) -> Result<Vec<u8>> {
    Ok(zstd::encode_all(std::io::Cursor::new(data), 3)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record() -> SessionRecord {
        SessionRecord {
            session_uid: "uid-1".to_string(),
            agent: "codex".to_string(),
            session_id: "session-abc".to_string(),
            repo_root: "/tmp/repo".to_string(),
            repo_remote_url: None,
            git_ref: "refs/heads/main".to_string(),
            head_sha: "abc123".to_string(),
            committer_key_hash: "committer-hash".to_string(),
            git_user_email: Some("dev@example.com".to_string()),
            git_user_name: Some("Dev Name".to_string()),
            session_start: Some(1_700_000_000),
            content_sha256: "content-sha".to_string(),
            cwd: Some("/tmp/repo".to_string()),
            ingested_at: "2026-03-02T00:00:00Z".to_string(),
            cli_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn compute_session_uid_is_deterministic() {
        let content_sha = content_sha256("session content");
        let uid1 = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_000),
            &content_sha,
        );
        let uid2 = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_000),
            &content_sha,
        );
        assert_eq!(uid1, uid2);

        let uid_with_different_start = compute_session_uid(
            &AgentType::Codex,
            "session-abc",
            "/tmp/repo",
            Some(1_700_000_001),
            &content_sha,
        );
        assert_ne!(uid1, uid_with_different_start);
    }

    #[test]
    fn serialize_session_object_round_trips() {
        let record = sample_record();
        let bytes = serialize_session_object(record.clone(), "line1\nline2".to_string())
            .expect("serialize session object");
        let envelope: SessionEnvelope =
            serde_json::from_slice(&bytes).expect("deserialize session envelope");

        assert_eq!(envelope.record.session_uid, record.session_uid);
        assert_eq!(envelope.record.agent, record.agent);
        assert_eq!(envelope.record.session_id, record.session_id);
        assert_eq!(envelope.record.repo_root, record.repo_root);
        assert_eq!(envelope.record.content_sha256, record.content_sha256);
        assert_eq!(envelope.session_content, "line1\nline2");
    }

    #[test]
    fn serialize_session_object_omits_removed_legacy_keys() {
        let bytes = serialize_session_object(sample_record(), "line1\nline2".to_string())
            .expect("serialize session object");
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).expect("parse serialized session object");
        let record = value.get("record").expect("record object");

        assert!(record.get("session_end").is_none());
        assert!(record.get("observed_commits").is_none());
        assert!(record.get("time_window").is_none());
        assert!(record.get("match_signals").is_none());
    }

    #[test]
    fn deserialize_session_object_ignores_removed_legacy_keys() {
        let bytes = br#"{
            "record":{
                "session_uid":"uid-1",
                "agent":"codex",
                "session_id":"session-abc",
                "repo_root":"/tmp/repo",
                "repo_remote_url":null,
                "git_ref":"refs/heads/main",
                "head_sha":"abc123",
                "committer_key_hash":"committer-hash",
                "git_user_email":"dev@example.com",
                "git_user_name":"Dev Name",
                "session_start":1700000000,
                "session_end":1700000100,
                "content_sha256":"content-sha",
                "observed_commits":["abc123"],
                "time_window":{"start":1700000000,"end":1700000100},
                "cwd":"/tmp/repo",
                "match_signals":{
                    "confidence":"scored_match",
                    "score":0.9,
                    "reasons":["contains_commit_hash"]
                },
                "ingested_at":"2026-03-02T00:00:00Z",
                "cli_version":"1.0.0"
            },
            "session_content":"line1\nline2"
        }"#;

        let envelope: SessionEnvelope =
            serde_json::from_slice(bytes).expect("deserialize legacy session envelope");

        assert_eq!(envelope.record.session_uid, "uid-1");
        assert_eq!(envelope.record.session_id, "session-abc");
        assert_eq!(envelope.record.session_start, Some(1_700_000_000));
        assert_eq!(envelope.session_content, "line1\nline2");
    }
}
