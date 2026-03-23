//! HTTP client for Cadence API endpoints used by the CLI.
//!
//! Includes:
//! - CLI auth exchange + revoke
//! - Backfill-complete reporting
//! - Direct session upload URL + confirmation

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{error::Error as _, time::Duration};

// ---------------------------------------------------------------------------
// Endpoint path constants
// ---------------------------------------------------------------------------

const AUTH_EXCHANGE_PATH: &str = "/api/auth/exchange";
const AUTH_REVOKE_PATH: &str = "/api/auth";
const BACKFILL_COMPLETE_PATH: &str = "/api/onboarding/backfill-complete";
const USER_ORGS_PATH: &str = "/api/user/orgs";
const SESSION_PUBLICATION_CREATE_PATH: &str = "/api/v2/session-publications";

// ---------------------------------------------------------------------------
// Response DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /api/auth/exchange`.
#[derive(Debug, Serialize)]
struct ExchangeRequest<'a> {
    code: &'a str,
}

/// Data payload from `POST /api/auth/exchange`.
#[derive(Debug, Clone, Deserialize)]
pub struct CliTokenExchangeResult {
    /// Bearer token used by the CLI for authenticated API calls.
    pub token: String,
    /// GitHub login associated with the authenticated user.
    pub login: String,
    /// RFC 3339 expiration timestamp for the token.
    pub expires_at: String,
}

/// Request body for `POST /api/onboarding/backfill-complete`.
#[derive(Debug, Clone, Serialize)]
pub struct BackfillCompleteRequest {
    /// Number of days covered by the backfill.
    pub window_days: i32,
    /// Number of sessions attached to repositories during backfill.
    pub notes_attached: i64,
    /// Number of sessions skipped during backfill processing.
    pub notes_skipped: i64,
    /// Human-readable issues encountered during backfill.
    pub issues: Vec<String>,
    /// Number of repositories scanned during backfill.
    pub repos_scanned: i32,
    /// RFC 3339 completion timestamp emitted by the CLI.
    pub finished_at: String,
    /// CLI version that reported the backfill completion.
    pub cli_version: String,
}

/// Data payload from `POST /api/onboarding/backfill-complete`.
#[derive(Debug, Clone, Deserialize)]
pub struct BackfillCompleteResponse {
    /// Whether the backend recorded the completion event.
    pub recorded: bool,
    /// Backend timestamp for the recorded completion.
    pub backfill_completed_at: String,
}

/// Minimal org info from `GET /api/user/orgs`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserOrgInfo {
    /// GitHub organization id for the account.
    pub github_org_id: i64,
    /// GitHub login for the org or personal account.
    pub github_org_login: String,
    /// Display name shown to the user, when available.
    pub display_name: Option<String>,
    /// Whether this record represents the user's personal account.
    pub is_personal: bool,
    /// Whether the org has completed onboarding.
    pub is_onboarded: bool,
    /// Whether the Cadence GitHub app is installed for the org.
    pub has_active_installation: bool,
    /// Cadence org id, if the org has been provisioned.
    pub org_id: Option<String>,
}

/// Response body from `GET /api/user/orgs`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UserOrgsResponse {
    /// Orgs visible to the authenticated CLI user.
    pub orgs: Vec<UserOrgInfo>,
}

/// Request body for `POST /api/v2/session-publications`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateSessionPublicationRequest {
    /// Agent family producing the session, such as `codex`.
    pub agent: String,
    /// Stable agent-native session identifier.
    pub agent_session_id: String,
    /// Idempotency key for this publication attempt.
    pub publish_uid: String,
    /// SHA-256 hash of the uploaded session content.
    pub upload_sha256: String,
    /// SHA-256 hash of material publication metadata.
    pub metadata_sha256: String,
    /// Canonical git remote URL selected for the session.
    pub canonical_remote_url: String,
    /// All observed remote URLs for the repository.
    pub remote_urls: Vec<String>,
    /// Canonical repository root associated with the session.
    pub canonical_repo_root: String,
    /// Repository and worktree roots observed for the session.
    pub worktree_roots: Vec<String>,
    /// Current working directory captured from the session, if any.
    pub cwd: Option<String>,
    /// Git ref associated with the upload, if available.
    pub git_ref: Option<String>,
    /// HEAD commit SHA associated with the upload, if available.
    pub head_commit_sha: Option<String>,
    /// Git user email configured for the repository, if available.
    pub git_user_email: Option<String>,
    /// Git user name configured for the repository, if available.
    pub git_user_name: Option<String>,
    /// CLI version that created the publication request.
    pub cli_version: Option<String>,
}

/// Response body from `POST /api/v2/session-publications`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CreateSessionPublicationResponse {
    /// Server-generated publication identifier.
    pub publication_id: String,
    /// Pre-signed upload URL for the raw session payload.
    pub upload_url: String,
    /// Resolved Cadence org id that owns the publication.
    pub org_id: String,
}

/// Response body from `POST /api/sessions/{uid}/confirm`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SessionUploadConfirmResponse {
    /// Publication status returned after upload confirmation.
    pub status: String,
}

/// Standard API response envelope used by backend endpoints.
#[derive(Debug, Deserialize)]
struct ApiResponseEnvelope<T> {
    data: T,
}

// ---------------------------------------------------------------------------
// Classified authenticated request errors
// ---------------------------------------------------------------------------

/// Classified failures for authenticated CLI requests.
#[derive(Debug)]
pub enum AuthenticatedRequestError {
    /// Authentication failed or the token has expired.
    Unauthorized,
    /// The request conflicted with current server state.
    Conflict(String),
    /// The target resource could not be found.
    NotFound,
    /// The server rejected semantically invalid input.
    Unprocessable(String),
    /// The server returned a 5xx response.
    Server(String),
    /// The server rejected the request as malformed.
    BadRequest(String),
    /// The request failed before receiving a response.
    Network(String),
    /// The server response could not be decoded.
    Parse(String),
    /// A non-standard failure occurred.
    Unexpected(String),
}

impl std::fmt::Display for AuthenticatedRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "unauthorized"),
            Self::Conflict(msg) => write!(f, "conflict: {msg}"),
            Self::NotFound => write!(f, "not_found"),
            Self::Unprocessable(msg) => write!(f, "unprocessable: {msg}"),
            Self::Server(msg) => write!(f, "server_error: {msg}"),
            Self::BadRequest(msg) => write!(f, "bad_request: {msg}"),
            Self::Network(msg) => write!(f, "network_error: {msg}"),
            Self::Parse(msg) => write!(f, "parse_error: {msg}"),
            Self::Unexpected(msg) => write!(f, "unexpected_error: {msg}"),
        }
    }
}

impl std::error::Error for AuthenticatedRequestError {}

// ---------------------------------------------------------------------------
// ApiClient
// ---------------------------------------------------------------------------

/// HTTP client for the Cadence API.
///
/// Wraps `reqwest::Client` with a normalized base URL.
#[derive(Debug)]
pub struct ApiClient {
    client: reqwest::Client,
    raw_client: reqwest::Client,
    base_url: String,
}

impl ApiClient {
    /// Create a new API client.
    ///
    /// `base_url` is trimmed and stripped of a trailing slash to prevent
    /// double-slash issues when joining endpoint paths.
    pub fn new(base_url: &str) -> Self {
        let normalized = base_url.trim().trim_end_matches('/').to_string();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::HeaderName::from_static("x-cadence-cli-version"),
            reqwest::header::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("build Cadence API HTTP client");
        let raw_client = reqwest::Client::builder()
            .build()
            .expect("build raw HTTP client");
        Self {
            client,
            raw_client,
            base_url: normalized,
        }
    }

    /// Exchange a short-lived CLI exchange code for a long-lived CLI JWT.
    pub async fn exchange_cli_code(
        &self,
        code: &str,
        timeout: Duration,
    ) -> Result<CliTokenExchangeResult> {
        let url = self.url(AUTH_EXCHANGE_PATH);
        let resp = self
            .client
            .post(&url)
            .timeout(timeout)
            .json(&ExchangeRequest { code })
            .send()
            .await
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp).await?;
        let envelope: ApiResponseEnvelope<CliTokenExchangeResult> =
            serde_json::from_str(&body).context("failed to parse auth exchange response")?;
        Ok(envelope.data)
    }

    /// Revoke a bearer token via `DELETE /api/auth`.
    pub async fn revoke_token(
        &self,
        token: &str,
        timeout: Duration,
    ) -> std::result::Result<(), AuthenticatedRequestError> {
        let url = self.url(AUTH_REVOKE_PATH);
        let resp = self
            .client
            .delete(&url)
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .map_err(map_network_error)?;

        if resp.status().is_success() {
            return Ok(());
        }

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(map_authenticated_http_error(status, &body))
    }

    /// Report backfill completion to onboarding state.
    pub async fn report_backfill_complete(
        &self,
        token: &str,
        report: &BackfillCompleteRequest,
        timeout: Duration,
    ) -> std::result::Result<BackfillCompleteResponse, AuthenticatedRequestError> {
        let url = self.url(BACKFILL_COMPLETE_PATH);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .timeout(timeout)
            .json(report)
            .send()
            .await
            .map_err(map_network_error)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp.text().await.map_err(map_network_error)?;
        let envelope: ApiResponseEnvelope<BackfillCompleteResponse> =
            serde_json::from_str(&body)
                .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))?;
        Ok(envelope.data)
    }

    /// List orgs accessible to the authenticated CLI user.
    pub async fn list_user_orgs(
        &self,
        token: &str,
        timeout: Duration,
    ) -> std::result::Result<UserOrgsResponse, AuthenticatedRequestError> {
        let url = self.url(USER_ORGS_PATH);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(token)
            .timeout(timeout)
            .send()
            .await
            .map_err(map_network_error)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp.text().await.map_err(map_network_error)?;
        let envelope: ApiResponseEnvelope<UserOrgsResponse> = serde_json::from_str(&body)
            .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))?;
        Ok(envelope.data)
    }

    /// Create or fetch a session publication.
    pub async fn create_session_publication(
        &self,
        token: &str,
        org_id: &str,
        request: &CreateSessionPublicationRequest,
        timeout: Duration,
    ) -> std::result::Result<CreateSessionPublicationResponse, AuthenticatedRequestError> {
        let url = self.url(SESSION_PUBLICATION_CREATE_PATH);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .header("x-org-id", org_id)
            .timeout(timeout)
            .json(request)
            .send()
            .await
            .map_err(map_network_error)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp.text().await.map_err(map_network_error)?;
        serde_json::from_str::<CreateSessionPublicationResponse>(&body)
            .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))
    }

    /// Upload session bytes to a presigned S3 URL.
    pub async fn upload_presigned(
        &self,
        upload_url: &str,
        content_type: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> std::result::Result<(), AuthenticatedRequestError> {
        let resp = tokio::time::timeout(
            timeout,
            self.raw_client
                .put(upload_url)
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(payload.to_vec())
                .send(),
        )
        .await
        .map_err(|_| {
            AuthenticatedRequestError::Network(format!(
                "presigned upload timed out after {:?} while sending {} bytes",
                timeout,
                payload.len()
            ))
        })?
        .map_err(map_network_error)?;

        if resp.status().is_success() {
            return Ok(());
        }

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(map_authenticated_http_error(status, &body))
    }

    /// Confirm that a previously-uploaded session blob is ready for ingestion.
    pub async fn confirm_session_upload(
        &self,
        token: &str,
        publication_id: &str,
        org_id: &str,
        timeout: Duration,
    ) -> std::result::Result<SessionUploadConfirmResponse, AuthenticatedRequestError> {
        let url = self.url(&format!(
            "/api/v2/session-publications/{publication_id}/confirm"
        ));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .header("x-org-id", org_id)
            .timeout(timeout)
            .send()
            .await
            .map_err(map_network_error)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp.text().await.map_err(map_network_error)?;
        serde_json::from_str::<SessionUploadConfirmResponse>(&body)
            .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build a full URL by joining the base URL with an endpoint path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

// ---------------------------------------------------------------------------
// HTTP error mapping (FR-8)
// ---------------------------------------------------------------------------

/// Read a response body and return it as a string, or map non-success status
/// codes to user-friendly errors.
async fn map_http_error(resp: reqwest::Response) -> Result<String> {
    let status = resp.status();
    if status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Ok(body);
    }

    let body = resp.text().await.unwrap_or_default();

    match status.as_u16() {
        401 => anyhow::bail!("Unauthorized: API credentials rejected."),
        400 => {
            let detail = extract_error_message(&body);
            anyhow::bail!("Bad request: {detail}");
        }
        404 => {
            let detail = extract_error_message(&body);
            anyhow::bail!("Not found: {detail}");
        }
        500..=599 => {
            let detail = extract_error_message(&body);
            anyhow::bail!("Server error: {detail}");
        }
        _ => {
            anyhow::bail!("Unexpected response (HTTP {status}): {body}");
        }
    }
}

fn map_authenticated_http_error(status: u16, body: &str) -> AuthenticatedRequestError {
    let detail = extract_error_message(body);
    match status {
        401 => AuthenticatedRequestError::Unauthorized,
        400 => AuthenticatedRequestError::BadRequest(detail),
        404 => AuthenticatedRequestError::NotFound,
        409 => AuthenticatedRequestError::Conflict(detail),
        422 => AuthenticatedRequestError::Unprocessable(detail),
        500..=599 => AuthenticatedRequestError::Server(detail),
        _ => AuthenticatedRequestError::Unexpected(format!("HTTP {status}: {detail}")),
    }
}

fn map_network_error(error: reqwest::Error) -> AuthenticatedRequestError {
    AuthenticatedRequestError::Network(format_network_error(&error))
}

fn format_network_error(error: &reqwest::Error) -> String {
    let mut message = if error.is_timeout() {
        format!("timeout: {error}")
    } else if error.is_connect() {
        format!("connect: {error}")
    } else {
        error.to_string()
    };

    let mut sources = Vec::new();
    let mut current = error.source();
    while let Some(source) = current {
        let detail = source.to_string();
        if !detail.is_empty() {
            sources.push(detail);
        }
        current = source.source();
    }

    if !sources.is_empty() {
        message.push_str("; cause: ");
        message.push_str(&sources.join(": "));
    }

    message
}

/// Try to extract a `message` or `error` field from a JSON error body.
/// Falls back to the raw body (truncated) if parsing fails.
fn extract_error_message(body: &str) -> String {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(body)
        && let Some(msg) = value.get("message").or(value.get("error"))
        && let Some(s) = msg.as_str()
    {
        return s.to_string();
    }

    if body.is_empty() {
        return "no details provided".to_string();
    }

    // Truncate large error bodies to prevent noisy output
    let trimmed = body.trim();
    if trimmed.len() > 200 {
        format!("{}...", &trimmed[..200])
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_joins_paths() {
        let client = ApiClient::new("https://api.example.com/");
        assert_eq!(
            client.url("/api/keys/public"),
            "https://api.example.com/api/keys/public"
        );
    }

    #[test]
    fn authenticated_error_maps_statuses() {
        assert!(matches!(
            map_authenticated_http_error(401, ""),
            AuthenticatedRequestError::Unauthorized
        ));
        assert!(matches!(
            map_authenticated_http_error(409, ""),
            AuthenticatedRequestError::Conflict(_)
        ));
        assert!(matches!(
            map_authenticated_http_error(422, ""),
            AuthenticatedRequestError::Unprocessable(_)
        ));
        assert!(matches!(
            map_authenticated_http_error(404, ""),
            AuthenticatedRequestError::NotFound
        ));
        assert!(matches!(
            map_authenticated_http_error(503, "{\"error\":\"bad\"}"),
            AuthenticatedRequestError::Server(_)
        ));
    }

    #[test]
    fn session_upload_request_serializes_upload_sha256_field() {
        let request = CreateSessionPublicationRequest {
            agent: "codex".to_string(),
            agent_session_id: "agent-session-1".to_string(),
            publish_uid: "pub-1".to_string(),
            upload_sha256: "upload-sha".to_string(),
            metadata_sha256: "metadata-sha".to_string(),
            canonical_remote_url: "git@github.com:team/repo.git".to_string(),
            remote_urls: vec!["git@github.com:team/repo.git".to_string()],
            canonical_repo_root: "/tmp/repo".to_string(),
            worktree_roots: vec!["/tmp/repo".to_string()],
            cwd: None,
            git_ref: Some("refs/heads/main".to_string()),
            head_commit_sha: Some("abc123".to_string()),
            git_user_email: None,
            git_user_name: None,
            cli_version: Some("1.0.0".to_string()),
        };

        let value = serde_json::to_value(&request).expect("serialize request");

        assert_eq!(value["upload_sha256"], "upload-sha");
        assert!(value.get("content_sha256").is_none());
    }
}
