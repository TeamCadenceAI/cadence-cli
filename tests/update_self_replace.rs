//! Integration tests for `cadence update` self-replace flow.
//!
//! These tests exercise artifact selection, checksum verification, archive
//! extraction, and the full update install flow using local HTTP servers
//! and temporary filesystem state. They avoid actually replacing the test
//! runner binary.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

/// Start a minimal single-request HTTP server.
fn spawn_one_shot_server(status: u16, body: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let body = body.to_string();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("failed to accept");
        let mut buf = [0u8; 4096];
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

// ---------------------------------------------------------------------------
// Artifact selection tests (via library)
// ---------------------------------------------------------------------------

#[test]
fn pick_artifact_for_all_release_targets() {
    use cadence_cli::update::{ReleaseAsset, pick_artifact_for_target};

    let assets: Vec<ReleaseAsset> = [
        "cadence-cli-aarch64-apple-darwin.tar.gz",
        "cadence-cli-x86_64-apple-darwin.tar.gz",
        "cadence-cli-x86_64-unknown-linux-gnu.tar.gz",
        "cadence-cli-aarch64-unknown-linux-gnu.tar.gz",
        "cadence-cli-x86_64-pc-windows-msvc.zip",
        "cadence-cli-aarch64-pc-windows-msvc.zip",
        "checksums-sha256.txt",
    ]
    .iter()
    .map(|name| ReleaseAsset {
        name: name.to_string(),
        browser_download_url: format!("https://example.com/{name}"),
    })
    .collect();

    // All supported targets should match exactly
    let targets = [
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    ];

    for target in &targets {
        let result = pick_artifact_for_target(&assets, target);
        assert!(
            result.is_ok(),
            "Should find artifact for target '{target}': {:?}",
            result.err()
        );
        let asset = result.unwrap();
        assert!(
            asset.name.contains(target),
            "Asset name '{}' should contain target '{target}'",
            asset.name
        );
    }
}

#[test]
fn pick_artifact_for_unknown_target_gives_clear_error() {
    use cadence_cli::update::{ReleaseAsset, pick_artifact_for_target};

    let assets = vec![ReleaseAsset {
        name: "cadence-cli-x86_64-unknown-linux-gnu.tar.gz".to_string(),
        browser_download_url: "https://example.com/linux.tar.gz".to_string(),
    }];

    let result = pick_artifact_for_target(&assets, "riscv64-unknown-linux-gnu");
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("riscv64-unknown-linux-gnu"));
    assert!(err.contains("Available assets"));
}

// ---------------------------------------------------------------------------
// Checksum integration tests
// ---------------------------------------------------------------------------

#[test]
fn checksum_round_trip_with_real_file() {
    use cadence_cli::update::{parse_checksums, sha256_file, verify_checksum};

    let tmp = tempfile::tempdir().unwrap();

    // Create a test file
    let test_file = tmp.path().join("test-binary.tar.gz");
    std::fs::write(&test_file, b"fake binary content for checksum test").unwrap();

    // Compute its hash
    let hash = sha256_file(&test_file).unwrap();

    // Create checksums content in GNU format
    let checksums_content = format!("{hash}  test-binary.tar.gz\n");

    // Parse and verify
    let checksums = parse_checksums(&checksums_content).unwrap();
    assert!(verify_checksum(&checksums, "test-binary.tar.gz", &test_file).is_ok());
}

#[test]
fn checksum_verification_rejects_tampered_file() {
    use cadence_cli::update::{parse_checksums, verify_checksum};

    let tmp = tempfile::tempdir().unwrap();

    // Create file
    let test_file = tmp.path().join("tampered.tar.gz");
    std::fs::write(&test_file, b"original content").unwrap();

    // Create checksums with a different hash (as if file was tampered after checksum generation)
    let checksums_content =
        "0000000000000000000000000000000000000000000000000000000000000000  tampered.tar.gz\n";
    let checksums = parse_checksums(checksums_content).unwrap();

    let result = verify_checksum(&checksums, "tampered.tar.gz", &test_file);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Checksum verification failed")
    );
}

#[test]
fn checksum_missing_entry_for_artifact() {
    use cadence_cli::update::{parse_checksums, verify_checksum};

    let tmp = tempfile::tempdir().unwrap();
    let test_file = tmp.path().join("missing.tar.gz");
    std::fs::write(&test_file, b"content").unwrap();

    let checksums_content =
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2  other-file.tar.gz\n";
    let checksums = parse_checksums(checksums_content).unwrap();

    let result = verify_checksum(&checksums, "missing.tar.gz", &test_file);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

// ---------------------------------------------------------------------------
// Archive extraction integration tests
// ---------------------------------------------------------------------------

#[test]
fn extract_tar_gz_integration() {
    use cadence_cli::update::extract_binary;

    let tmp = tempfile::tempdir().unwrap();

    // Build a tar.gz containing a "cadence" binary
    let archive_path = tmp.path().join("cadence-cli-test.tar.gz");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut tar_builder = tar::Builder::new(encoder);

        let content = b"#!/bin/sh\necho test binary\n";
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, "cadence", &content[..])
            .unwrap();
        tar_builder.finish().unwrap();
    }

    let extract_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&extract_dir).unwrap();

    let binary_path = extract_binary(&archive_path, &extract_dir).unwrap();
    assert!(binary_path.exists());
    assert_eq!(binary_path.file_name().unwrap(), "cadence");

    let content = std::fs::read_to_string(&binary_path).unwrap();
    assert!(content.contains("echo test binary"));
}

#[test]
fn extract_zip_integration() {
    use cadence_cli::update::extract_binary;

    let tmp = tempfile::tempdir().unwrap();

    let archive_path = tmp.path().join("cadence-cli-test.zip");
    {
        let file = std::fs::File::create(&archive_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_writer.start_file("cadence.exe", options).unwrap();
        zip_writer.write_all(b"MZ fake exe content").unwrap();
        zip_writer.finish().unwrap();
    }

    let extract_dir = tmp.path().join("extracted");
    std::fs::create_dir_all(&extract_dir).unwrap();

    let binary_path = extract_binary(&archive_path, &extract_dir).unwrap();
    assert!(binary_path.exists());
    assert_eq!(binary_path.file_name().unwrap(), "cadence.exe");
}

// ---------------------------------------------------------------------------
// Full update flow integration tests
// ---------------------------------------------------------------------------

#[test]
fn update_install_already_up_to_date() {
    use cadence_cli::update::{current_version, run_update_install_from_url};

    // Serve a release with the same version as the current binary
    let tag = format!("v{}", current_version());
    let json = format!(
        r#"{{"tag_name":"{tag}","assets":[
            {{"name":"cadence-cli-aarch64-apple-darwin.tar.gz","browser_download_url":"https://example.com/a.tar.gz"}},
            {{"name":"checksums-sha256.txt","browser_download_url":"https://example.com/checksums.txt"}}
        ]}}"#
    );

    let url = spawn_one_shot_server(200, &json);

    // Should succeed and indicate already up to date
    let result = run_update_install_from_url(&url, true);
    assert!(
        result.is_ok(),
        "should succeed when up to date: {:?}",
        result.err()
    );
}

#[test]
fn update_install_network_error() {
    use cadence_cli::update::run_update_install_from_url;

    // Connect to a port with no listener
    let result = run_update_install_from_url("http://127.0.0.1:1", true);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Failed to connect") || err.contains("Failed to check"),
        "error should mention connection failure: {err}"
    );
}

#[test]
fn update_install_missing_checksums_asset() {
    use cadence_cli::update::run_update_install_from_url;

    // Release with a newer version but no checksums file
    let target = cadence_cli::update::build_target();
    let artifact_name = cadence_cli::update::expected_artifact_name(target);

    let json = format!(
        r#"{{"tag_name":"v99.0.0","assets":[
            {{"name":"{artifact_name}","browser_download_url":"https://example.com/artifact"}}
        ]}}"#
    );

    let url = spawn_one_shot_server(200, &json);

    let result = run_update_install_from_url(&url, true);
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("checksums-sha256.txt")
    );
}

#[test]
fn update_install_missing_target_asset() {
    use cadence_cli::update::run_update_install_from_url;

    // Release with a newer version but wrong platform artifact
    let json = r#"{"tag_name":"v99.0.0","assets":[
        {"name":"cadence-cli-riscv64-unknown-linux-gnu.tar.gz","browser_download_url":"https://example.com/wrong"},
        {"name":"checksums-sha256.txt","browser_download_url":"https://example.com/checksums"}
    ]}"#;

    let url = spawn_one_shot_server(200, json);

    let result = run_update_install_from_url(&url, true);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("No release asset found"),
        "should report missing asset: {err}"
    );
}

#[test]
fn update_check_flag_still_works() {
    use cadence_cli::update::run_update;

    // --check mode should work (hits real API or fails gracefully)
    // We just verify it doesn't panic or try to install anything
    let result = run_update(true, false);
    assert!(
        result.is_ok(),
        "check mode should always succeed: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Confirm bypass tests
// ---------------------------------------------------------------------------

#[test]
fn confirm_update_yes_flag_bypasses_prompt() {
    let result = cadence_cli::update::confirm_update("0.2.1", "0.3.0", true, None).unwrap();
    assert!(result, "--yes should always confirm");
}

#[test]
fn confirm_update_with_auto_override() {
    let result = cadence_cli::update::confirm_update("0.2.1", "0.3.0", true, Some(true)).unwrap();
    assert!(result, "--yes with auto_update should confirm");
}

// ---------------------------------------------------------------------------
// Download helper tests
// ---------------------------------------------------------------------------

#[test]
fn download_to_file_success() {
    use cadence_cli::update::download_to_file;

    let body = b"file content for download test";
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/test-file.bin");

    let body_owned = body.to_vec();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("failed to accept");
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body_owned.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.write_all(&body_owned);
        let _ = stream.flush();
    });

    let tmp = tempfile::tempdir().unwrap();
    let result = download_to_file(&url, tmp.path(), "test-file.bin").unwrap();
    assert!(result.exists());
    assert_eq!(std::fs::read(&result).unwrap(), body);
}

#[test]
fn download_to_file_http_error() {
    use cadence_cli::update::download_to_file;

    let url = spawn_one_shot_server(500, "Internal Server Error");

    let tmp = tempfile::tempdir().unwrap();
    let result = download_to_file(
        &format!("{url}/artifact.tar.gz"),
        tmp.path(),
        "artifact.tar.gz",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("HTTP 500"));
}

#[test]
fn download_to_file_connection_refused() {
    use cadence_cli::update::download_to_file;

    let tmp = tempfile::tempdir().unwrap();
    let result = download_to_file("http://127.0.0.1:1/file.bin", tmp.path(), "file.bin");
    assert!(result.is_err());
}
