//! HTTP client for Cadence API endpoints used by the CLI.
//!
//! Includes:
//! - Public key retrieval for encryption setup
//! - CLI auth exchange + revoke
//! - Backfill-complete reporting
//! - Direct session upload URL + confirmation

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Endpoint path constants
// ---------------------------------------------------------------------------

const KEYS_PUBLIC_PATH: &str = "/api/keys/public";
const AUTH_EXCHANGE_PATH: &str = "/api/auth/exchange";
const AUTH_REVOKE_PATH: &str = "/api/auth";
const BACKFILL_COMPLETE_PATH: &str = "/api/onboarding/backfill-complete";
const SESSION_UPLOAD_URL_PATH: &str = "/api/sessions/upload-url";

// ---------------------------------------------------------------------------
// Response DTOs
// ---------------------------------------------------------------------------

/// Response from `GET /api/keys/public`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ApiPublicKey {
    pub fingerprint: String,
    pub armored_public_key: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub rotated_at: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_string")]
    pub version: Option<String>,
}

/// Request body for `POST /api/auth/exchange`.
#[derive(Debug, Serialize)]
struct ExchangeRequest<'a> {
    code: &'a str,
}

/// Data payload from `POST /api/auth/exchange`.
#[derive(Debug, Clone, Deserialize)]
pub struct CliTokenExchangeResult {
    pub token: String,
    pub login: String,
    pub expires_at: String,
}

/// Request body for `POST /api/onboarding/backfill-complete`.
#[derive(Debug, Clone, Serialize)]
pub struct BackfillCompleteRequest {
    pub window_days: i32,
    pub notes_attached: i64,
    pub notes_skipped: i64,
    pub issues: Vec<String>,
    pub repos_scanned: i32,
    pub finished_at: String,
    pub cli_version: String,
}

/// Data payload from `POST /api/onboarding/backfill-complete`.
#[derive(Debug, Clone, Deserialize)]
pub struct BackfillCompleteResponse {
    pub recorded: bool,
    pub backfill_completed_at: String,
    #[allow(dead_code)]
    pub next_step: String,
}

/// Request body for `POST /api/sessions/upload-url`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionUploadUrlRequest {
    pub session_uid: String,
    pub agent: String,
    pub agent_session_id: String,
    pub repo_remote_url: String,
    pub branch_key: String,
    pub session_start: Option<i64>,
    pub content_sha256: String,
    pub git_user_email: Option<String>,
    pub git_user_name: Option<String>,
    pub cli_version: String,
    pub cwd: Option<String>,
    pub repo_root: String,
}

/// Response body from `POST /api/sessions/upload-url`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SessionUploadUrlResponse {
    pub upload_url: String,
    pub session_uid: String,
    pub org_id: String,
}

/// Response body from `POST /api/sessions/{uid}/confirm`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SessionUploadConfirmResponse {
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
    Unauthorized,
    Conflict(String),
    NotFound,
    Unprocessable(String),
    Server(String),
    BadRequest(String),
    Network(String),
    Parse(String),
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

    // -----------------------------------------------------------------------
    // Public endpoint methods
    // -----------------------------------------------------------------------

    /// Fetch the current API public key.
    pub async fn get_api_public_key(&self) -> Result<ApiPublicKey> {
        let url = self.url(KEYS_PUBLIC_PATH);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp).await?;
        let envelope: ApiResponseEnvelope<ApiPublicKey> =
            serde_json::from_str(&body).context("failed to parse api public key response")?;
        Ok(envelope.data)
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
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;

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
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;
        let envelope: ApiResponseEnvelope<BackfillCompleteResponse> =
            serde_json::from_str(&body)
                .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))?;
        Ok(envelope.data)
    }

    /// Request a presigned S3 upload URL for a session blob.
    pub async fn request_session_upload_url(
        &self,
        token: &str,
        request: &SessionUploadUrlRequest,
        timeout: Duration,
    ) -> std::result::Result<SessionUploadUrlResponse, AuthenticatedRequestError> {
        let url = self.url(SESSION_UPLOAD_URL_PATH);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .timeout(timeout)
            .json(request)
            .send()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;
        serde_json::from_str::<SessionUploadUrlResponse>(&body)
            .map_err(|e| AuthenticatedRequestError::Parse(e.to_string()))
    }

    /// Upload compressed session bytes to a presigned S3 URL.
    pub async fn upload_presigned(
        &self,
        upload_url: &str,
        payload: &[u8],
        timeout: Duration,
    ) -> std::result::Result<(), AuthenticatedRequestError> {
        let resp = self
            .raw_client
            .put(upload_url)
            .header(reqwest::header::CONTENT_TYPE, "application/zstd")
            .timeout(timeout)
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;

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
        session_uid: &str,
        org_id: &str,
        timeout: Duration,
    ) -> std::result::Result<SessionUploadConfirmResponse, AuthenticatedRequestError> {
        let url = self.url(&format!("/api/sessions/{session_uid}/confirm"));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(token)
            .header("x-org-id", org_id)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(map_authenticated_http_error(status, &body));
        }

        let body = resp
            .text()
            .await
            .map_err(|e| AuthenticatedRequestError::Network(e.to_string()))?;
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

fn deserialize_optional_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(s)) => Some(s),
        Some(serde_json::Value::Number(n)) => Some(n.to_string()),
        Some(serde_json::Value::Bool(b)) => Some(b.to_string()),
        Some(serde_json::Value::Null) | None => None,
        Some(other) => Some(other.to_string()),
    })
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
}
