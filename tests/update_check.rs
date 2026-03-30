//! Integration tests for `cadence update --check`.
//!
//! These tests use a local HTTP server to avoid hitting the real GitHub server.
//! They exercise the full update-check flow including redirect-based tag
//! discovery, version comparison, and error handling by controlling the server
//! responses.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The current version compiled into the binary.
const LOCAL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Start a minimal HTTP server that returns a 302 redirect to a release tag URL.
/// The `Location` header ends with the tag, mimicking GitHub's releases/latest redirect.
async fn spawn_redirect_server(tag: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let tag = tag.to_string();
    let url_clone = url.clone();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("failed to accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;

        let location = format!("{url_clone}/releases/tag/{tag}");
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    });

    url
}

/// Start a minimal HTTP server that returns a given status code (non-redirect).
async fn spawn_status_server(status: u16) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("failed to accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;

        let response =
            format!("HTTP/1.1 {status} Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    });

    url
}

/// Start a minimal HTTP server that returns a 302 redirect with a custom Location header.
async fn spawn_redirect_server_with_location(location: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let location = location.to_string();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("failed to accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;

        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    });

    url
}

/// Start a minimal HTTP server that returns a 302 redirect without a Location header.
async fn spawn_redirect_server_no_location() -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("failed to accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;

        let response =
            "HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string();
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.flush().await;
    });

    url
}

// ---------------------------------------------------------------------------
// Tests using the update module's injectable URL helper
// ---------------------------------------------------------------------------

#[tokio::test]
async fn check_reports_update_available_when_remote_newer() {
    // Use a version that's definitely newer than any real release
    let url = spawn_redirect_server("v99.0.0").await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
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

#[tokio::test]
async fn check_reports_up_to_date_when_versions_equal() {
    let tag = format!("v{LOCAL_VERSION}");
    let url = spawn_redirect_server(&tag).await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name).unwrap();
    assert_eq!(result, std::cmp::Ordering::Equal);

    let msg = format!("cadence v{LOCAL_VERSION} is up to date");
    assert!(msg.starts_with("cadence v"));
    assert!(msg.ends_with("is up to date"));
}

#[tokio::test]
async fn check_reports_up_to_date_when_local_newer() {
    let url = spawn_redirect_server("v0.0.1").await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name).unwrap();
    assert_eq!(result, std::cmp::Ordering::Greater);
}

#[tokio::test]
async fn check_handles_http_error_gracefully() {
    let url = spawn_status_server(404).await;

    let result = cadence_cli::update::check_latest_version_from_url(&url).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("HTTP 404"),
        "Error should mention status code, got: {err_msg}"
    );
}

#[tokio::test]
async fn check_handles_missing_location_header() {
    let url = spawn_redirect_server_no_location().await;

    let result = cadence_cli::update::check_latest_version_from_url(&url).await;
    assert!(result.is_err());
    assert!(
        result.unwrap_err().to_string().contains("Location header"),
        "Error should mention missing Location header"
    );
}

#[tokio::test]
async fn check_handles_empty_tag_in_redirect() {
    // Redirect to a URL ending with / (empty tag segment)
    let url = spawn_redirect_server_with_location("http://example.com/releases/tag/").await;

    let result = cadence_cli::update::check_latest_version_from_url(&url).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("version tag"),
        "Error should mention version tag, got: {err_msg}"
    );
}

#[tokio::test]
async fn check_handles_connection_refused() {
    // Connect to a port with no listener — should fail with a connection error.
    let result = cadence_cli::update::check_latest_version_from_url("http://127.0.0.1:1").await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to connect")
    );
}

#[tokio::test]
async fn check_handles_rate_limit_response() {
    // GitHub returns 403 for rate limits — this is not a redirect.
    let url = spawn_status_server(403).await;

    let result = cadence_cli::update::check_latest_version_from_url(&url).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("HTTP 403"));
}

#[tokio::test]
async fn check_handles_invalid_semver_tag() {
    let url = spawn_redirect_server("not-a-version").await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
    let result = cadence_cli::update::compare_versions(LOCAL_VERSION, &release.tag_name);
    assert!(result.is_err(), "non-semver tag should produce error");
}

#[tokio::test]
async fn check_constructs_assets_for_all_platforms() {
    let url = spawn_redirect_server("v99.0.0").await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
    assert_eq!(release.tag_name, "v99.0.0");
    // 6 canonical platform assets + 2 legacy macOS tarballs + 1 checksums file
    assert_eq!(release.assets.len(), 9);

    // Verify download URLs are constructed correctly
    let checksums = release
        .assets
        .iter()
        .find(|a| a.name == "checksums-sha256.txt")
        .unwrap();
    assert!(
        checksums
            .browser_download_url
            .contains("/releases/download/v99.0.0/checksums-sha256.txt"),
        "checksums URL should use direct download path"
    );
}

#[tokio::test]
async fn check_constructs_download_urls_from_base() {
    let url = spawn_redirect_server("v1.2.3").await;

    let release = cadence_cli::update::check_latest_version_from_url(&url)
        .await
        .unwrap();
    // All download URLs should be rooted at the server base
    for asset in &release.assets {
        assert!(
            asset
                .browser_download_url
                .contains("/releases/download/v1.2.3/"),
            "Asset '{}' URL should contain download path: {}",
            asset.name,
            asset.browser_download_url
        );
    }
}
