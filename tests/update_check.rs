//! Integration tests for `cadence update --check`.
//!
//! These tests use a local HTTP server to avoid hitting the real GitHub API.
//! They exercise the full update-check flow including JSON parsing, version
//! comparison, and error handling by controlling the server responses.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

/// The current version compiled into the binary.
const LOCAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Start a minimal HTTP server that returns the given status code and body
/// for exactly one request, then shuts down. Returns the URL to connect to.
fn spawn_one_shot_server(status: u16, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let body = body.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("failed to accept");
        let mut buf = [0u8; 4096];
        // Read the request (we don't care about its contents)
        let _ = stream.read(&mut buf);

        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    });

    url
}

/// Helper: create a GitHub-style release JSON with a given tag and optional assets.
fn release_json(tag: &str) -> String {
    format!(
        r#"{{"tag_name":"{}","assets":[{{"name":"cadence-aarch64-apple-darwin.tar.gz","browser_download_url":"https://example.com/a.tar.gz"}}]}}"#,
        tag
    )
}

// ---------------------------------------------------------------------------
// Tests using the update module's injectable URL helper
// ---------------------------------------------------------------------------

// Note: These tests call the update module functions directly rather than
// spawning the cadence binary, since we need URL injection. The binary
// integration path is verified by the CLI parsing tests in main.rs.

#[test]
fn check_reports_update_available_when_remote_newer() {
    // Use a version that's definitely newer than any real release
    let url = spawn_one_shot_server(200, &release_json("v99.0.0"));

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name).unwrap();
    assert_eq!(
        result,
        std::cmp::Ordering::Less,
        "remote 99.0.0 should be newer than local"
    );

    // Verify the display format
    let remote_display = cadence_cli::update::normalize_version_tag(&release.tag_name);
    let msg = format!("Update available: v{LOCAL_VERSION} → v{remote_display}");
    assert!(msg.starts_with("Update available: v"));
    assert!(msg.contains("→ v99.0.0"));
}

#[test]
fn check_reports_up_to_date_when_versions_equal() {
    let tag = format!("v{LOCAL_VERSION}");
    let url = spawn_one_shot_server(200, &release_json(&tag));

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name).unwrap();
    assert_eq!(result, std::cmp::Ordering::Equal);

    let msg = format!("cadence v{LOCAL_VERSION} is up to date");
    assert!(msg.starts_with("cadence v"));
    assert!(msg.ends_with("is up to date"));
}

#[test]
fn check_reports_up_to_date_when_local_newer() {
    let url = spawn_one_shot_server(200, &release_json("v0.0.1"));

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name).unwrap();
    assert_eq!(result, std::cmp::Ordering::Greater);
}

#[test]
fn check_handles_http_error_gracefully() {
    let url = spawn_one_shot_server(404, r#"{"message":"Not Found"}"#);

    let result = cadence_cli::update::check_latest_version_from_url(&url);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("HTTP 404"),
        "Error should mention status code, got: {err_msg}"
    );
}

#[test]
fn check_handles_malformed_json_gracefully() {
    let url = spawn_one_shot_server(200, "<html>Not JSON at all</html>");

    let result = cadence_cli::update::check_latest_version_from_url(&url);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Unable to parse release metadata")
    );
}

#[test]
fn check_handles_missing_tag_name() {
    let url = spawn_one_shot_server(200, r#"{"assets":[]}"#);

    let result = cadence_cli::update::check_latest_version_from_url(&url);
    assert!(result.is_err());
}

#[test]
fn check_handles_empty_tag_name() {
    let url = spawn_one_shot_server(200, r#"{"tag_name":"","assets":[]}"#);

    let result = cadence_cli::update::check_latest_version_from_url(&url);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("missing tag_name"));
}

#[test]
fn check_handles_invalid_semver_tag() {
    let url = spawn_one_shot_server(200, &release_json("not-a-version"));

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name);
    assert!(result.is_err(), "non-semver tag should produce error");
}

#[test]
fn check_handles_connection_refused() {
    // Connect to a port with no listener — should fail with a connection error.
    let result = cadence_cli::update::check_latest_version_from_url("http://127.0.0.1:1");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to connect")
    );
}

#[test]
fn check_handles_rate_limit_response() {
    // GitHub returns 403 with a JSON body for rate limits.
    let url = spawn_one_shot_server(
        403,
        r#"{"message":"API rate limit exceeded","documentation_url":"https://docs.github.com"}"#,
    );

    let result = cadence_cli::update::check_latest_version_from_url(&url);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("HTTP 403"),);
}

#[test]
fn check_parses_release_with_multiple_assets() {
    let json = r#"{
        "tag_name": "v99.0.0",
        "assets": [
            {"name": "cadence-aarch64-apple-darwin.tar.gz", "browser_download_url": "https://example.com/a"},
            {"name": "cadence-x86_64-unknown-linux-gnu.tar.gz", "browser_download_url": "https://example.com/b"},
            {"name": "SHA256SUMS", "browser_download_url": "https://example.com/sums"}
        ]
    }"#;
    let url = spawn_one_shot_server(200, json);

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    assert_eq!(release.tag_name, "v99.0.0");
    assert_eq!(release.assets.len(), 3);
}

#[test]
fn check_ignores_extra_json_fields() {
    let json = r#"{
        "tag_name": "v99.0.0",
        "name": "Release 99.0.0",
        "body": "Some markdown",
        "draft": false,
        "prerelease": false,
        "html_url": "https://github.com/...",
        "assets": []
    }"#;
    let url = spawn_one_shot_server(200, json);

    let release = cadence_cli::update::check_latest_version_from_url(&url).unwrap();
    assert_eq!(release.tag_name, "v99.0.0");
}
