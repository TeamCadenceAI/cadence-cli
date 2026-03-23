//! V2 session publication primitives.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalSessionKey {
    pub agent: String,
    pub agent_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationObservations {
    pub canonical_remote_url: String,
    pub remote_urls: Vec<String>,
    pub canonical_repo_root: String,
    pub worktree_roots: Vec<String>,
    pub cwd: Option<String>,
    pub git_ref: Option<String>,
    pub head_commit_sha: Option<String>,
    pub git_user_email: Option<String>,
    pub git_user_name: Option<String>,
    pub cli_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedPublication {
    pub logical_session: LogicalSessionKey,
    pub observations: PublicationObservations,
    pub raw_session_content: String,
    pub content_sha256: String,
    pub metadata_sha256: String,
    pub upload_sha256: String,
}

#[derive(Debug, Serialize)]
struct MaterialMetadataHashInput<'a> {
    canonical_remote_url: &'a str,
    remote_urls: &'a [String],
    canonical_repo_root: &'a str,
    worktree_roots: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    git_ref: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    head_commit_sha: Option<&'a str>,
}

pub fn content_sha256(content: &str) -> String {
    sha256_hex(content.as_bytes())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn metadata_sha256(observations: &PublicationObservations) -> Result<String> {
    let input = MaterialMetadataHashInput {
        canonical_remote_url: &observations.canonical_remote_url,
        remote_urls: &observations.remote_urls,
        canonical_repo_root: &observations.canonical_repo_root,
        worktree_roots: &observations.worktree_roots,
        git_ref: observations.git_ref.as_deref(),
        head_commit_sha: observations.head_commit_sha.as_deref(),
    };
    let bytes = serde_json::to_vec(&input)?;
    Ok(sha256_hex(&bytes))
}

pub fn prepare_publication(
    logical_session: LogicalSessionKey,
    observations: PublicationObservations,
    raw_session_content: String,
) -> Result<PreparedPublication> {
    let content_sha256 = content_sha256(&raw_session_content);
    let metadata_sha256 = metadata_sha256(&observations)?;
    let upload_sha256 = sha256_hex(raw_session_content.as_bytes());
    Ok(PreparedPublication {
        logical_session,
        observations,
        raw_session_content,
        content_sha256,
        metadata_sha256,
        upload_sha256,
    })
}

pub fn new_publish_uid() -> String {
    format!("pub_{}", Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_observations() -> PublicationObservations {
        PublicationObservations {
            canonical_remote_url: "git@github.com:TeamCadenceAI/cadence-cli.git".to_string(),
            remote_urls: vec![
                "git@github.com:TeamCadenceAI/cadence-cli.git".to_string(),
                "https://github.com/TeamCadenceAI/cadence-cli".to_string(),
            ],
            canonical_repo_root: "/tmp/cadence-cli".to_string(),
            worktree_roots: vec!["/tmp/cadence-cli".to_string()],
            cwd: Some("/tmp/cadence-cli".to_string()),
            git_ref: Some("refs/heads/main".to_string()),
            head_commit_sha: Some("8be58f2bfb86977bab1b6017702634506e85a8d4".to_string()),
            git_user_email: Some("dev@example.com".to_string()),
            git_user_name: Some("Dev".to_string()),
            cli_version: Some("2.0.6".to_string()),
        }
    }

    #[test]
    fn metadata_hash_ignores_cli_version() {
        let mut first = sample_observations();
        let mut second = sample_observations();
        second.cli_version = Some("9.9.9".to_string());
        first.cwd = None;
        second.cwd = Some("/some/other/cwd".to_string());

        assert_eq!(
            metadata_sha256(&first).unwrap(),
            metadata_sha256(&second).unwrap()
        );
    }

    #[test]
    fn metadata_hash_changes_for_head_or_ref_changes() {
        let mut observations = sample_observations();
        let first = metadata_sha256(&observations).unwrap();
        observations.head_commit_sha = Some("deadbeef".repeat(8));
        let second = metadata_sha256(&observations).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn publish_uid_has_expected_prefix() {
        assert!(new_publish_uid().starts_with("pub_"));
    }
}
