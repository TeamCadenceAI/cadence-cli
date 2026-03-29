use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const TEST_INSTALL_SENTINEL_ENV: &str = "CADENCE_TEST_INSTALL_SENTINEL_PATH";

async fn spawn_release_server(tag: &str, artifact_name: String, archive: Vec<u8>) -> String {
    let archive_hash = format!("{:x}", Sha256::digest(&archive));
    let checksums = format!("{archive_hash}  {artifact_name}\n");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind release server");
    let addr = listener.local_addr().expect("release server addr");
    let base_url = format!("http://{addr}");
    let latest_url = format!("{base_url}/releases/latest");

    let tag = tag.to_string();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(stream) => stream,
                Err(_) => break,
            };

            let mut buf = [0u8; 8192];
            let read = match stream.read(&mut buf).await {
                Ok(read) => read,
                Err(_) => continue,
            };
            if read == 0 {
                continue;
            }

            let request = String::from_utf8_lossy(&buf[..read]);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/");

            let response = match path {
                "/releases/latest" => format!(
                    "HTTP/1.1 302 Found\r\nLocation: {base_url}/releases/tag/{tag}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .into_bytes(),
                p if p == format!("/releases/download/{tag}/{artifact_name}") => {
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        archive.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(&archive);
                    response
                }
                p if p == format!("/releases/download/{tag}/checksums-sha256.txt") => {
                    let mut response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        checksums.len()
                    )
                    .into_bytes();
                    response.extend_from_slice(checksums.as_bytes());
                    response
                }
                _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec(),
            };

            let _ = stream.write_all(&response).await;
            let _ = stream.flush().await;
        }
    });

    latest_url
}

fn cadence_binary_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "cadence.exe"
    } else {
        "cadence"
    }
}

fn updater_binary_name(target: &str) -> &'static str {
    if target.contains("windows") {
        "cadence-updater.exe"
    } else {
        "cadence-updater"
    }
}

fn build_release_archive(target: &str, cadence_bin: &Path, updater_bin: &Path) -> Vec<u8> {
    let cadence_name = cadence_binary_name(target);
    let updater_name = updater_binary_name(target);
    let cadence_bytes = std::fs::read(cadence_bin).expect("read cadence binary");
    let updater_bytes = std::fs::read(updater_bin).expect("read updater binary");

    if cadence_cli::update::archive_extension_for_target(target) == ".tar.gz" {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar_builder = tar::Builder::new(encoder);

        let mut cadence_header = tar::Header::new_gnu();
        cadence_header.set_size(cadence_bytes.len() as u64);
        cadence_header.set_mode(0o755);
        cadence_header.set_cksum();
        tar_builder
            .append_data(&mut cadence_header, cadence_name, &cadence_bytes[..])
            .expect("append cadence binary");

        let mut updater_header = tar::Header::new_gnu();
        updater_header.set_size(updater_bytes.len() as u64);
        updater_header.set_mode(0o755);
        updater_header.set_cksum();
        tar_builder
            .append_data(&mut updater_header, updater_name, &updater_bytes[..])
            .expect("append updater binary");

        let encoder = tar_builder.into_inner().expect("finish tar builder");
        return encoder.finish().expect("finish tar gzip");
    }

    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file(cadence_name, options)
        .expect("start cadence zip entry");
    zip.write_all(&cadence_bytes)
        .expect("write cadence zip entry");
    zip.start_file(updater_name, options)
        .expect("start updater zip entry");
    zip.write_all(&updater_bytes)
        .expect("write updater zip entry");
    zip.finish().expect("finish zip archive").into_inner()
}

async fn wait_for_file(path: &Path) {
    for _ in 0..100 {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {}", path.display());
}

#[tokio::test]
async fn update_hands_off_to_helper_and_runs_bootstrap() {
    let target = cadence_cli::update::build_target();
    let artifact_name = cadence_cli::update::expected_artifact_name(target);
    let cadence_bin = PathBuf::from(env!("CARGO_BIN_EXE_cadence"));
    let updater_bin = PathBuf::from(env!("CARGO_BIN_EXE_cadence-updater"));
    let archive = build_release_archive(target, &cadence_bin, &updater_bin);
    let release_url = spawn_release_server("v99.9.9", artifact_name.clone(), archive).await;

    let home = tempfile::tempdir().expect("temp home");
    let install_dir = home.path().join("install");
    tokio::fs::create_dir_all(&install_dir)
        .await
        .expect("create install dir");
    let cadence_state_dir = home.path().join(".cadence").join("cli");
    tokio::fs::create_dir_all(&cadence_state_dir)
        .await
        .expect("create cadence state dir");
    tokio::fs::write(
        cadence_state_dir.join("last-version-bootstrap"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .await
    .expect("write bootstrap marker");
    tokio::fs::write(
        cadence_state_dir.join("last-version-recovery-backfill"),
        format!("{}\n", env!("CARGO_PKG_VERSION")),
    )
    .await
    .expect("write recovery marker");

    let installed_cadence = install_dir.join(cadence_binary_name(target));
    tokio::fs::copy(&cadence_bin, &installed_cadence)
        .await
        .expect("copy cadence binary");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&installed_cadence, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("chmod installed cadence");
    }

    let sentinel_path = home.path().join("install-sentinel.json");
    let output = tokio::process::Command::new(&installed_cadence)
        .arg("update")
        .arg("--yes")
        .env("HOME", home.path())
        .env(TEST_INSTALL_SENTINEL_ENV, &sentinel_path)
        .env("CADENCE_TEST_RELEASE_URL", &release_url)
        .env("CADENCE_NO_UPDATE_CHECK", "1")
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("XDG_RUNTIME_DIR", home.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run cadence update");

    assert!(
        output.status.success(),
        "update command failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    wait_for_file(&sentinel_path).await;

    let sentinel: serde_json::Value = serde_json::from_str(
        &tokio::fs::read_to_string(&sentinel_path)
            .await
            .expect("read install sentinel"),
    )
    .expect("parse install sentinel");
    assert_eq!(
        sentinel
            .get("preserve_disable_state")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert_eq!(
        sentinel
            .get("passive_version_check_disabled")
            .and_then(serde_json::Value::as_bool),
        Some(true)
    );

    let updater_state_path = home
        .path()
        .join(".cadence")
        .join("cli")
        .join("updater-state.json");
    wait_for_file(&updater_state_path).await;
    let updater_state: serde_json::Value = serde_json::from_str(
        &tokio::fs::read_to_string(&updater_state_path)
            .await
            .expect("read updater state"),
    )
    .expect("parse updater state");
    assert_eq!(
        updater_state
            .get("last_installed_version")
            .and_then(serde_json::Value::as_str),
        Some("99.9.9")
    );
    assert_eq!(
        updater_state
            .get("consecutive_failures")
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cadence-updater")
            || String::from_utf8_lossy(&output.stdout).contains("cadence-updater"),
        "expected helper handoff messaging, stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        stderr
    );
}
