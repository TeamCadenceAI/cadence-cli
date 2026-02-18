//! HTTP client for the AI Barometer API.
//!
//! Provides a thin wrapper around `reqwest::blocking::Client` for interacting
//! with key management endpoints. All methods return `anyhow::Result` and
//! translate HTTP errors into user-friendly messages per FR-8.

use anyhow::{Context, Result};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Endpoint path constants
// ---------------------------------------------------------------------------

const KEYS_PUBLIC_PATH: &str = "/api/keys/public";
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

/// Standard API response envelope used by current backend endpoints.
#[derive(Debug, Deserialize)]
struct ApiResponseEnvelope<T> {
    data: T,
}

// ---------------------------------------------------------------------------
// ApiClient
// ---------------------------------------------------------------------------

/// HTTP client for the AI Barometer API.
///
/// Wraps `reqwest::blocking::Client` with a normalized base URL.
pub struct ApiClient {
    client: reqwest::blocking::Client,
    base_url: String,
}

impl ApiClient {
    /// Create a new API client.
    ///
    /// `base_url` is trimmed and stripped of a trailing slash to prevent
    /// double-slash issues when joining endpoint paths.
    pub fn new(base_url: &str) -> Self {
        let normalized = base_url.trim().trim_end_matches('/').to_string();
        Self {
            client: reqwest::blocking::Client::new(),
            base_url: normalized,
        }
    }

    // -----------------------------------------------------------------------
    // Public endpoint methods
    // -----------------------------------------------------------------------

    /// Fetch the current API public key.
    pub fn get_api_public_key(&self) -> Result<ApiPublicKey> {
        let url = self.url(KEYS_PUBLIC_PATH);
        let resp = self
            .client
            .get(&url)
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp)?;
        let envelope: ApiResponseEnvelope<ApiPublicKey> =
            serde_json::from_str(&body).context("failed to parse api public key response")?;
        Ok(envelope.data)
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
/// codes to user-friendly error messages.
fn map_http_error(resp: reqwest::blocking::Response) -> Result<String> {
    let status = resp.status();
    if status.is_success() {
        let body = resp.text().unwrap_or_default();
        return Ok(body);
    }

    let body = resp.text().unwrap_or_default();

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
}
