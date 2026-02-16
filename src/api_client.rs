//! HTTP client for the AI Barometer API.
//!
//! Provides a thin wrapper around `reqwest::blocking::Client` for interacting
//! with key management and auth endpoints. All methods return `anyhow::Result`
//! and translate HTTP errors into user-friendly messages per FR-8.

// This module is a foundation for future auth/keys command specs. The public API
// will be consumed once those command handlers are added. Suppress dead_code until then.
#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Endpoint path constants
// ---------------------------------------------------------------------------

const KEYS_PATH: &str = "/api/keys";
const KEYS_TEST_PATH: &str = "/api/keys/test";
const AUTH_PATH: &str = "/api/auth";
const AUTH_EXCHANGE_PATH: &str = "/api/auth/exchange";

// ---------------------------------------------------------------------------
// Request DTOs
// ---------------------------------------------------------------------------

/// Request body for `POST /api/keys`.
#[derive(Serialize)]
struct PushKeyRequest<'a> {
    fingerprint: &'a str,
    armored_private_key: &'a str,
    test_encrypted_message: &'a str,
}

/// Request body for `POST /api/keys/test`.
#[derive(Serialize)]
struct TestKeyRequest<'a> {
    encrypted_message: &'a str,
}

/// Request body for `POST /api/auth/exchange`.
#[derive(Serialize)]
struct ExchangeCodeRequest<'a> {
    code: &'a str,
}

// ---------------------------------------------------------------------------
// Response DTOs
// ---------------------------------------------------------------------------

/// Response from `GET /api/keys` when an active key exists.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct KeyStatus {
    pub fingerprint: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Response from `POST /api/keys`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PushKeyResponse {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub superseded: Option<String>,
}

/// Response from `POST /api/keys/test`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TestKeyResponse {
    pub success: bool,
    #[serde(default, alias = "error")]
    pub message: Option<String>,
}

/// Response from `POST /api/auth/exchange`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ExchangeCodeResponse {
    pub token: String,
    #[serde(default)]
    pub login: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// Backward-compatible key status payloads.
///
/// Supports both:
/// - legacy flat payload: `{ "fingerprint": "...", "created_at": "..." }`
/// - current API payload: `{ "active_key": { ... } }`
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum KeyStatusPayload {
    Flat(KeyStatus),
    WithActiveKey {
        #[serde(default)]
        active_key: Option<KeyStatus>,
    },
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
/// Wraps `reqwest::blocking::Client` with a normalized base URL and optional
/// Bearer token. All auth-required endpoints verify the token is present before
/// sending; `exchange_code` is the sole unauthenticated endpoint.
pub struct ApiClient {
    client: reqwest::blocking::Client,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    /// Create a new API client.
    ///
    /// `base_url` is trimmed and stripped of a trailing slash to prevent
    /// double-slash issues when joining endpoint paths. `token` is optional —
    /// only `exchange_code` can be called without one.
    pub fn new(base_url: &str, token: Option<String>) -> Self {
        let normalized = base_url.trim().trim_end_matches('/').to_string();
        Self {
            client: reqwest::blocking::Client::new(),
            base_url: normalized,
            token,
        }
    }

    // -----------------------------------------------------------------------
    // Public endpoint methods
    // -----------------------------------------------------------------------

    /// Fetch the current active key status from the server.
    ///
    /// Returns `None` if no key is configured server-side (empty body or 404).
    pub fn get_key_status(&self) -> Result<Option<KeyStatus>> {
        let url = self.url(KEYS_PATH);
        let resp = self
            .auth_request(reqwest::Method::GET, &url)?
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }

        let body = map_http_error(resp)?;
        if body.is_empty() {
            return Ok(None);
        }

        let payload: KeyStatusPayload =
            parse_response_payload(&body, "failed to parse key status response")?;
        match payload {
            KeyStatusPayload::Flat(key) => Ok(Some(key)),
            KeyStatusPayload::WithActiveKey { active_key } => Ok(active_key),
        }
    }

    /// Push a GPG private key to the server.
    ///
    /// Automatically supersedes any previously active key.
    pub fn push_key(
        &self,
        fingerprint: &str,
        armored_private_key: &str,
        test_encrypted_message: &str,
    ) -> Result<PushKeyResponse> {
        let url = self.url(KEYS_PATH);
        let payload = PushKeyRequest {
            fingerprint,
            armored_private_key,
            test_encrypted_message,
        };
        let resp = self
            .auth_request(reqwest::Method::POST, &url)?
            .json(&payload)
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp)?;
        let parsed: PushKeyResponse =
            parse_response_payload(&body, "failed to parse push key response")?;
        Ok(parsed)
    }

    /// Test server-side decryption of an encrypted message.
    pub fn test_key(&self, encrypted_message: &str) -> Result<TestKeyResponse> {
        let url = self.url(KEYS_TEST_PATH);
        let payload = TestKeyRequest { encrypted_message };
        let resp = self
            .auth_request(reqwest::Method::POST, &url)?
            .json(&payload)
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp)?;
        let parsed: TestKeyResponse =
            parse_response_payload(&body, "failed to parse test key response")?;
        Ok(parsed)
    }

    /// Revoke the current authentication token.
    pub fn revoke_token(&self) -> Result<()> {
        let url = self.url(AUTH_PATH);
        let resp = self
            .auth_request(reqwest::Method::DELETE, &url)?
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NO_CONTENT || status.is_success() {
            return Ok(());
        }

        // Non-success — fall through to error mapping
        map_http_error(resp)?;
        Ok(())
    }

    /// Exchange an OAuth authorization code for an API token.
    ///
    /// This is the only endpoint that does **not** require a Bearer token.
    pub fn exchange_code(&self, code: &str) -> Result<ExchangeCodeResponse> {
        let url = self.url(AUTH_EXCHANGE_PATH);
        let payload = ExchangeCodeRequest { code };
        let resp = self
            .client
            .post(&url)
            .json(&payload)
            .send()
            .with_context(|| format!("failed to connect to API at {url}"))?;

        let body = map_http_error(resp)?;
        let parsed: ExchangeCodeResponse =
            parse_response_payload(&body, "failed to parse auth exchange response")?;
        Ok(parsed)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build a full URL by joining the base URL with an endpoint path.
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Build an authenticated request. Returns an error if no token is set.
    fn auth_request(
        &self,
        method: reqwest::Method,
        url: &str,
    ) -> Result<reqwest::blocking::RequestBuilder> {
        let token = self
            .token
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Not authenticated. Run `cadence auth login` first."))?;

        Ok(self
            .client
            .request(method, url)
            .header("Authorization", format!("Bearer {token}")))
    }
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
        401 => anyhow::bail!("Not authenticated. Run `cadence auth login` to sign in."),
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

/// Parse either an enveloped API response (`{"data": ...}`) or a legacy
/// direct payload (`{...}`) for backward compatibility.
fn parse_response_payload<T>(body: &str, context: &'static str) -> Result<T>
where
    T: DeserializeOwned,
{
    if let Ok(enveloped) = serde_json::from_str::<ApiResponseEnvelope<T>>(body) {
        return Ok(enveloped.data);
    }

    serde_json::from_str::<T>(body).context(context)
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A minimal HTTP mock server for testing.
    /// Binds to a random port, accepts one request, and responds with a
    /// pre-configured status and body.
    struct MockServer {
        addr: String,
        listener: TcpListener,
    }

    /// Captured request data from the mock server.
    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl CapturedRequest {
        fn header(&self, name: &str) -> Option<&str> {
            let lower = name.to_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| k.to_lowercase() == lower)
                .map(|(_, v)| v.as_str())
        }
    }

    impl MockServer {
        fn new() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            Self { addr, listener }
        }

        fn url(&self) -> &str {
            &self.addr
        }

        /// Accept one request and respond with the given status and body.
        /// Returns the captured request for assertion.
        fn respond(self, status: u16, body: &str) -> CapturedRequest {
            let (mut stream, _) = self.listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            // Read request line
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
            let method = parts.first().unwrap_or(&"").to_string();
            let path = parts.get(1).unwrap_or(&"").to_string();

            // Read headers
            let mut headers = Vec::new();
            let mut content_length: usize = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let trimmed = line.trim().to_string();
                if trimmed.is_empty() {
                    break;
                }
                if let Some((key, value)) = trimmed.split_once(':') {
                    let k = key.trim().to_string();
                    let v = value.trim().to_string();
                    if k.to_lowercase() == "content-length" {
                        content_length = v.parse().unwrap_or(0);
                    }
                    headers.push((k, v));
                }
            }

            // Read body
            let mut body_buf = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body_buf).unwrap();
            }
            let request_body = String::from_utf8_lossy(&body_buf).to_string();

            // Write response
            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();

            CapturedRequest {
                method,
                path,
                headers,
                body: request_body,
            }
        }
    }

    // -------------------------------------------------------------------
    // Constructor tests
    // -------------------------------------------------------------------

    #[test]
    fn test_constructor_stores_base_url_and_token() {
        let client = ApiClient::new("https://api.example.com", Some("tok_123".into()));
        assert_eq!(client.base_url, "https://api.example.com");
        assert_eq!(client.token, Some("tok_123".to_string()));
    }

    #[test]
    fn test_constructor_trims_base_url() {
        let client = ApiClient::new("  https://api.example.com  ", None);
        assert_eq!(client.base_url, "https://api.example.com");
    }

    #[test]
    fn test_constructor_strips_trailing_slash() {
        let client = ApiClient::new("https://api.example.com/", None);
        assert_eq!(client.base_url, "https://api.example.com");
    }

    #[test]
    fn test_constructor_strips_multiple_trailing_slashes() {
        let client = ApiClient::new("https://api.example.com///", None);
        assert_eq!(client.base_url, "https://api.example.com");
    }

    #[test]
    fn test_constructor_none_token() {
        let client = ApiClient::new("https://api.example.com", None);
        assert!(client.token.is_none());
    }

    // -------------------------------------------------------------------
    // URL building tests
    // -------------------------------------------------------------------

    #[test]
    fn test_url_join_no_trailing_slash() {
        let client = ApiClient::new("https://api.example.com", None);
        assert_eq!(client.url("/api/keys"), "https://api.example.com/api/keys");
    }

    #[test]
    fn test_url_join_with_trailing_slash_input() {
        let client = ApiClient::new("https://api.example.com/", None);
        assert_eq!(client.url("/api/keys"), "https://api.example.com/api/keys");
    }

    // -------------------------------------------------------------------
    // Auth header tests
    // -------------------------------------------------------------------

    #[test]
    fn test_auth_request_requires_token() {
        let client = ApiClient::new("https://api.example.com", None);
        let result = client.auth_request(reqwest::Method::GET, "https://api.example.com/api/keys");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Not authenticated"),
            "expected auth error, got: {msg}"
        );
    }

    #[test]
    fn test_auth_request_succeeds_with_token() {
        let client = ApiClient::new("https://api.example.com", Some("tok_123".into()));
        let result = client.auth_request(reqwest::Method::GET, "https://api.example.com/api/keys");
        assert!(result.is_ok());
    }

    // -------------------------------------------------------------------
    // get_key_status() tests
    // -------------------------------------------------------------------

    #[test]
    fn test_get_key_status_success() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"fingerprint":"ABCD1234","created_at":"2025-01-01T00:00:00Z"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.get_key_status().unwrap();
        let req = handle.join().unwrap();

        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/api/keys");
        assert!(
            req.header("Authorization")
                .unwrap()
                .starts_with("Bearer tok_abc")
        );

        let status = result.unwrap();
        assert_eq!(status.fingerprint, "ABCD1234");
        assert_eq!(status.created_at, Some("2025-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_get_key_status_success_enveloped_active_key() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"data":{"active_key":{"fingerprint":"ABCD1234","created_at":"2025-01-01T00:00:00Z"}}}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.get_key_status().unwrap();
        let _req = handle.join().unwrap();

        let status = result.unwrap();
        assert_eq!(status.fingerprint, "ABCD1234");
        assert_eq!(status.created_at, Some("2025-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_get_key_status_enveloped_no_active_key_returns_none() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"data":{"active_key":null}}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.get_key_status().unwrap();
        let _req = handle.join().unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_get_key_status_no_key_returns_none() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || server.respond(404, ""));

        let result = client.get_key_status().unwrap();
        let _req = handle.join().unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_get_key_status_empty_body_returns_none() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || server.respond(200, ""));

        let result = client.get_key_status().unwrap();
        let _req = handle.join().unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_get_key_status_requires_auth() {
        let client = ApiClient::new("https://api.example.com", None);
        let result = client.get_key_status();
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Not authenticated"),);
    }

    // -------------------------------------------------------------------
    // push_key() tests
    // -------------------------------------------------------------------

    #[test]
    fn test_push_key_success() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"message":"Key stored","superseded":"OLD_FP"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client
            .push_key("NEW_FP", "-----BEGIN PGP PRIVATE KEY-----", "encrypted_msg")
            .unwrap();
        let req = handle.join().unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/keys");
        assert!(req.header("Authorization").unwrap().starts_with("Bearer "));

        // Verify request body
        let sent: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(sent["fingerprint"], "NEW_FP");
        assert_eq!(
            sent["armored_private_key"],
            "-----BEGIN PGP PRIVATE KEY-----"
        );
        assert_eq!(sent["test_encrypted_message"], "encrypted_msg");

        assert_eq!(result.message, Some("Key stored".to_string()));
        assert_eq!(result.superseded, Some("OLD_FP".to_string()));
    }

    #[test]
    fn test_push_key_success_enveloped() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"data":{"id":"123e4567-e89b-12d3-a456-426614174000","fingerprint":"NEW_FP","created_at":"2025-01-01T00:00:00Z"}}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client
            .push_key("NEW_FP", "-----BEGIN PGP PRIVATE KEY-----", "encrypted_msg")
            .unwrap();
        let _req = handle.join().unwrap();

        assert!(result.message.is_none());
        assert!(result.superseded.is_none());
    }

    #[test]
    fn test_push_key_requires_auth() {
        let client = ApiClient::new("https://api.example.com", None);
        let result = client.push_key("FP", "key", "msg");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Not authenticated"),);
    }

    // -------------------------------------------------------------------
    // test_key() tests
    // -------------------------------------------------------------------

    #[test]
    fn test_test_key_success() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"success":true,"message":"Decryption verified"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.test_key("encrypted_data").unwrap();
        let req = handle.join().unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/keys/test");
        assert!(req.header("Authorization").unwrap().starts_with("Bearer "));

        let sent: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(sent["encrypted_message"], "encrypted_data");

        assert!(result.success);
        assert_eq!(result.message, Some("Decryption verified".to_string()));
    }

    #[test]
    fn test_test_key_failure_response() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"success":false,"message":"Decryption failed"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.test_key("bad_data").unwrap();
        let _req = handle.join().unwrap();

        assert!(!result.success);
        assert_eq!(result.message, Some("Decryption failed".to_string()));
    }

    #[test]
    fn test_test_key_failure_enveloped_with_error_field() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"data":{"success":false,"error":"Decryption failed"}}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.test_key("bad_data").unwrap();
        let _req = handle.join().unwrap();

        assert!(!result.success);
        assert_eq!(result.message, Some("Decryption failed".to_string()));
    }

    #[test]
    fn test_test_key_requires_auth() {
        let client = ApiClient::new("https://api.example.com", None);
        let result = client.test_key("encrypted");
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Not authenticated"),);
    }

    // -------------------------------------------------------------------
    // revoke_token() tests
    // -------------------------------------------------------------------

    #[test]
    fn test_revoke_token_success() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || server.respond(204, ""));

        let result = client.revoke_token();
        let req = handle.join().unwrap();

        assert!(result.is_ok());
        assert_eq!(req.method, "DELETE");
        assert_eq!(req.path, "/api/auth");
        assert!(req.header("Authorization").unwrap().starts_with("Bearer "));
    }

    #[test]
    fn test_revoke_token_requires_auth() {
        let client = ApiClient::new("https://api.example.com", None);
        let result = client.revoke_token();
        assert!(result.is_err());
        assert!(format!("{}", result.unwrap_err()).contains("Not authenticated"),);
    }

    // -------------------------------------------------------------------
    // exchange_code() tests
    // -------------------------------------------------------------------

    #[test]
    fn test_exchange_code_success() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, None);

        let body = r#"{"token":"tok_new","login":"octocat","expires_at":"2026-01-01T00:00:00Z"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.exchange_code("auth_code_123").unwrap();
        let req = handle.join().unwrap();

        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/auth/exchange");
        // exchange_code should NOT send an Authorization header
        assert!(req.header("Authorization").is_none());

        let sent: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(sent["code"], "auth_code_123");

        assert_eq!(result.token, "tok_new");
        assert_eq!(result.login, Some("octocat".to_string()));
        assert_eq!(result.expires_at, Some("2026-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn test_exchange_code_no_token_required() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, None);

        let body = r#"{"token":"tok_new"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.exchange_code("code");
        let _req = handle.join().unwrap();

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.token, "tok_new");
        assert!(resp.login.is_none());
        assert!(resp.expires_at.is_none());
    }

    #[test]
    fn test_exchange_code_success_enveloped() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, None);

        let body =
            r#"{"data":{"token":"tok_new","login":"octocat","expires_at":"2026-01-01T00:00:00Z"}}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.exchange_code("auth_code_123").unwrap();
        let _req = handle.join().unwrap();

        assert_eq!(result.token, "tok_new");
        assert_eq!(result.login, Some("octocat".to_string()));
        assert_eq!(result.expires_at, Some("2026-01-01T00:00:00Z".to_string()));
    }

    // -------------------------------------------------------------------
    // HTTP error mapping tests
    // -------------------------------------------------------------------

    #[test]
    fn test_error_401_not_authenticated() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_expired".into()));

        let handle =
            std::thread::spawn(move || server.respond(401, r#"{"message":"Unauthorized"}"#));

        let result = client.get_key_status();
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Not authenticated"),
            "expected 'Not authenticated', got: {msg}"
        );
    }

    #[test]
    fn test_error_400_includes_body_message() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || {
            server.respond(400, r#"{"message":"Invalid fingerprint format"}"#)
        });

        let result = client.push_key("bad", "key", "msg");
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Invalid fingerprint format"),
            "expected body message in error, got: {msg}"
        );
    }

    #[test]
    fn test_error_400_non_json_body() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || server.respond(400, "plain text error"));

        let result = client.push_key("fp", "key", "msg");
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Bad request"),
            "expected 'Bad request', got: {msg}"
        );
        assert!(
            msg.contains("plain text error"),
            "expected raw body in error, got: {msg}"
        );
    }

    #[test]
    fn test_error_400_empty_body() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle = std::thread::spawn(move || server.respond(400, ""));

        let result = client.push_key("fp", "key", "msg");
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("no details provided"),
            "expected 'no details provided', got: {msg}"
        );
    }

    #[test]
    fn test_error_500_server_error() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let handle =
            std::thread::spawn(move || server.respond(500, r#"{"message":"Internal failure"}"#));

        let result = client.get_key_status();
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Server error"),
            "expected 'Server error', got: {msg}"
        );
        assert!(
            msg.contains("Internal failure"),
            "expected body message, got: {msg}"
        );
    }

    #[test]
    fn test_error_exchange_400_bad_code() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, None);

        let handle = std::thread::spawn(move || {
            server.respond(400, r#"{"message":"Invalid or expired code"}"#)
        });

        let result = client.exchange_code("expired_code");
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("Invalid or expired code"),
            "expected code error, got: {msg}"
        );
    }

    // -------------------------------------------------------------------
    // extract_error_message() unit tests
    // -------------------------------------------------------------------

    #[test]
    fn test_extract_error_message_json_message_field() {
        let body = r#"{"message":"Something went wrong"}"#;
        assert_eq!(extract_error_message(body), "Something went wrong");
    }

    #[test]
    fn test_extract_error_message_json_error_field() {
        let body = r#"{"error":"Access denied"}"#;
        assert_eq!(extract_error_message(body), "Access denied");
    }

    #[test]
    fn test_extract_error_message_empty_body() {
        assert_eq!(extract_error_message(""), "no details provided");
    }

    #[test]
    fn test_extract_error_message_plain_text() {
        assert_eq!(extract_error_message("plain text"), "plain text");
    }

    #[test]
    fn test_extract_error_message_truncates_long_body() {
        let long = "x".repeat(300);
        let result = extract_error_message(&long);
        assert!(result.len() < 210);
        assert!(result.ends_with("..."));
    }

    // -------------------------------------------------------------------
    // Connection failure test
    // -------------------------------------------------------------------

    #[test]
    fn test_connection_refused() {
        // Use a port that is almost certainly not listening
        let client = ApiClient::new("http://127.0.0.1:1", Some("tok_abc".into()));
        let result = client.get_key_status();
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("failed to connect"),
            "expected connection error, got: {msg}"
        );
    }

    // -------------------------------------------------------------------
    // Revoke with 401 (already expired token)
    // -------------------------------------------------------------------

    #[test]
    fn test_revoke_token_401() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_expired".into()));

        let handle =
            std::thread::spawn(move || server.respond(401, r#"{"message":"Unauthorized"}"#));

        let result = client.revoke_token();
        let _req = handle.join().unwrap();

        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("Not authenticated"));
    }

    // -------------------------------------------------------------------
    // Key status with optional/missing fields
    // -------------------------------------------------------------------

    #[test]
    fn test_get_key_status_minimal_fields() {
        let server = MockServer::new();
        let url = server.url().to_string();
        let client = ApiClient::new(&url, Some("tok_abc".into()));

        let body = r#"{"fingerprint":"ABCD1234"}"#;
        let handle = std::thread::spawn(move || server.respond(200, body));

        let result = client.get_key_status().unwrap().unwrap();
        let _req = handle.join().unwrap();

        assert_eq!(result.fingerprint, "ABCD1234");
        assert!(result.created_at.is_none());
        assert!(result.expires_at.is_none());
    }
}
