//! Shared HTTP transport helpers for production CLI network traffic.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;

/// Optional PEM bundle used to add corporate/intermediate roots for CLI HTTPS traffic.
pub const CA_BUNDLE_ENV_VAR: &str = "CADENCE_CA_BUNDLE";

/// Build a reqwest client with the shared Cadence trust configuration.
pub async fn build_client(
    builder: reqwest::ClientBuilder,
    description: &str,
) -> Result<reqwest::Client> {
    configure_client_builder(builder)
        .await?
        .build()
        .with_context(|| format!("failed to build {description}"))
}

/// Detect common enterprise TLS interception failures and return help text.
pub fn tls_failure_help(err: &anyhow::Error) -> Option<String> {
    if !error_chain_looks_like_unknown_issuer(err) {
        return None;
    }

    Some(format!(
        "TLS certificate verification failed. Cadence trusts native OS roots by default. If your network intercepts HTTPS, trust the corporate CA in your OS or set `{CA_BUNDLE_ENV_VAR}` or `SSL_CERT_FILE` to a PEM bundle."
    ))
}

async fn configure_client_builder(
    mut builder: reqwest::ClientBuilder,
) -> Result<reqwest::ClientBuilder> {
    for cert in load_extra_root_certificates().await? {
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder)
}

async fn load_extra_root_certificates() -> Result<Vec<reqwest::Certificate>> {
    let Some(path) = configured_ca_bundle_path() else {
        return Ok(Vec::new());
    };

    let pem_bundle = tokio::fs::read(&path).await.with_context(|| {
        format!(
            "failed to read `{CA_BUNDLE_ENV_VAR}` bundle {}",
            path.display()
        )
    })?;
    let certs = reqwest::Certificate::from_pem_bundle(&pem_bundle).with_context(|| {
        format!(
            "failed to parse PEM certificates from `{CA_BUNDLE_ENV_VAR}` bundle {}",
            path.display()
        )
    })?;

    if certs.is_empty() {
        bail!(
            "`{CA_BUNDLE_ENV_VAR}` bundle {} did not contain any certificates",
            path.display()
        );
    }

    Ok(certs)
}

fn configured_ca_bundle_path() -> Option<PathBuf> {
    let value = std::env::var(CA_BUNDLE_ENV_VAR).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

fn error_chain_looks_like_unknown_issuer(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let lower = cause.to_string().to_ascii_lowercase();
        lower.contains("unknownissuer")
            || lower.contains("unknown issuer")
            || lower.contains("unable to get local issuer")
            || lower.contains("self signed certificate")
            || lower.contains("certificate verify failed")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use serial_test::serial;
    use tempfile::TempDir;

    const TEST_PEM_BUNDLE: &[u8] = br#"
-----BEGIN CERTIFICATE-----
MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
YyRIHN8wfdVoOw==
-----END CERTIFICATE-----

-----BEGIN CERTIFICATE-----
MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5
MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
Um9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
Q0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi
9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83Bk
M6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB
/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WB
MAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlw
CkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW
1KyLa2tJElMzrdfkviT8tQp21KW8EA==
-----END CERTIFICATE-----
"#;

    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var(key).ok(),
            }
        }

        fn set_str(&self, value: &str) {
            unsafe { std::env::set_var(self.key, value) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[tokio::test]
    #[serial]
    async fn build_client_without_ca_bundle_succeeds() {
        let guard = EnvGuard::new(CA_BUNDLE_ENV_VAR);
        guard.set_str("   ");

        build_client(reqwest::Client::builder(), "test client")
            .await
            .expect("client without ca bundle");
    }

    #[tokio::test]
    #[serial]
    async fn build_client_with_missing_ca_bundle_fails() {
        let guard = EnvGuard::new(CA_BUNDLE_ENV_VAR);
        guard.set_str("/tmp/cadence-missing-ca-bundle.pem");

        let err = build_client(reqwest::Client::builder(), "test client")
            .await
            .expect_err("missing bundle should fail");
        let rendered = format!("{err:#}");

        assert!(rendered.contains(CA_BUNDLE_ENV_VAR));
        assert!(rendered.contains("failed to read"));
    }

    #[tokio::test]
    #[serial]
    async fn build_client_with_valid_ca_bundle_succeeds() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("bundle.pem");
        tokio::fs::write(&path, TEST_PEM_BUNDLE)
            .await
            .expect("write pem bundle");

        let guard = EnvGuard::new(CA_BUNDLE_ENV_VAR);
        guard.set_str(path.to_string_lossy().as_ref());

        build_client(reqwest::Client::builder(), "test client")
            .await
            .expect("client with ca bundle");
    }

    #[test]
    fn tls_failure_help_detects_unknown_issuer() {
        let err = anyhow!("invalid peer certificate: UnknownIssuer");
        let help = tls_failure_help(&err).expect("unknown issuer help");

        assert!(help.contains(CA_BUNDLE_ENV_VAR));
        assert!(help.contains("SSL_CERT_FILE"));
    }

    #[test]
    fn tls_failure_help_ignores_non_tls_errors() {
        let err = anyhow!("timeout while connecting to API");
        assert!(tls_failure_help(&err).is_none());
    }
}
