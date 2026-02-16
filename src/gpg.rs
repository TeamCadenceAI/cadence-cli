//! GPG encryption and decryption for AI session notes.
//!
//! Provides functions to encrypt/decrypt note content using the system `gpg`
//! binary. Encryption is optional: if a GPG recipient is configured in global
//! git config (`ai.cadence.gpg.recipient`), notes are encrypted
//! before being attached as git notes. Both plaintext and encrypted notes are
//! supported for backward compatibility.

use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::git;

/// Filename for the cached armored public key used by rpgp note encryption.
const PUBLIC_KEY_CACHE_FILENAME: &str = "public_key.asc";

/// The PGP ASCII armor header used to detect encrypted content.
#[allow(dead_code)]
const PGP_ARMOR_HEADER: &str = "-----BEGIN PGP MESSAGE-----";

/// The git config key for the GPG recipient.
pub const GPG_RECIPIENT_KEY: &str = "ai.cadence.gpg.recipient";

/// The git config key for the GPG public key source (path or URL).
pub const GPG_PUBLIC_KEY_SOURCE_KEY: &str = "ai.cadence.gpg.publicKeySource";

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Spawn `gpg` with the given args, write `input` to stdin, and return stdout
/// as a `String`. Returns an error if gpg exits non-zero or stdout is not
/// valid UTF-8.
fn run_gpg_with_input(args: &[&str], input: &str) -> Result<String> {
    let mut child = Command::new("gpg")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("gpg: failed to spawn gpg binary")?;

    // Write input to stdin. Take the handle first so it's dropped (closed)
    // before we wait, avoiding a deadlock.
    {
        let stdin = child
            .stdin
            .as_mut()
            .context("gpg: failed to open stdin pipe")?;
        stdin
            .write_all(input.as_bytes())
            .context("gpg: failed to write to stdin")?;
    }

    let output = child
        .wait_with_output()
        .context("gpg: failed to read command output")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        bail!("gpg failed (exit {}): {}", code, stderr.trim());
    }

    String::from_utf8(output.stdout).context("gpg: output was not valid UTF-8")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check if the `gpg` binary is available in PATH.
///
/// Runs `gpg --version` with suppressed I/O and returns `true` if the
/// command exits successfully. Returns `false` if gpg is missing or fails.
#[allow(dead_code)]
pub fn gpg_available() -> bool {
    Command::new("gpg")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read the configured GPG recipient from **global** git config.
///
/// Reads `ai.cadence.gpg.recipient`. Returns `Ok(None)` if the
/// key is not set or is blank/whitespace-only. Propagates real git errors.
///
/// Uses global scope only (not merged repo+global) so that behavior is
/// deterministic with the installer/setup flow.
pub fn get_recipient() -> Result<Option<String>> {
    let value = git::config_get_global(GPG_RECIPIENT_KEY)?;
    match value {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
        _ => Ok(None),
    }
}

/// Encrypt plaintext using GPG public-key encryption.
///
/// Spawns `gpg --batch --yes --encrypt --armor -r <recipient>`, pipes
/// `plaintext` to stdin, and returns the ASCII-armored ciphertext from stdout.
///
/// Returns an error if:
/// - The recipient is blank.
/// - The `gpg` binary cannot be spawned.
/// - `gpg` exits with a non-zero status.
/// - The output is not valid UTF-8.
pub fn encrypt_to_recipient(plaintext: &str, recipient: &str) -> Result<String> {
    let trimmed = recipient.trim();
    if trimmed.is_empty() {
        bail!("gpg encrypt: recipient must not be blank");
    }

    run_gpg_with_input(
        &["--batch", "--yes", "--encrypt", "--armor", "-r", trimmed],
        plaintext,
    )
    .context("gpg encrypt failed")
}

/// Encrypt plaintext using an armored private key via pure-Rust OpenPGP.
///
/// This is used for API challenge/test payloads so the ciphertext format
/// matches what the backend's OpenPGP parser supports.
pub fn encrypt_to_armored_private_key(
    plaintext: &str,
    armored_private_key: &str,
) -> Result<String> {
    use pgp::ArmorOptions;
    use pgp::composed::{Deserializable, Message, SignedSecretKey};
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    let trimmed = armored_private_key.trim();
    if trimmed.is_empty() {
        bail!("gpg encrypt: private key material must not be blank");
    }

    let (signed_key, _headers) =
        SignedSecretKey::from_string(trimmed).context("rpgp encrypt failed: key parse error")?;

    let enc_subkey = signed_key
        .secret_subkeys
        .first()
        .ok_or_else(|| anyhow::anyhow!("rpgp encrypt failed: no encryption subkey found"))?;

    let literal = pgp::packet::LiteralData::from_bytes((&[]).into(), plaintext.as_bytes());
    let message = Message::Literal(literal);

    let mut rng = rand08::thread_rng();
    let encrypted = message
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[enc_subkey])
        .context("rpgp encrypt failed: encryption error")?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .context("rpgp encrypt failed: armored serialization error")
}

/// Decrypt an ASCII-armored PGP message.
///
/// Spawns `gpg --batch --yes --decrypt`, pipes `ciphertext` to stdin, and
/// returns the decrypted plaintext from stdout.
///
/// Returns an error if:
/// - The `gpg` binary cannot be spawned.
/// - `gpg` exits with a non-zero status (e.g., missing private key).
/// - The output is not valid UTF-8.
#[allow(dead_code)]
pub fn decrypt(ciphertext: &str) -> Result<String> {
    run_gpg_with_input(&["--batch", "--yes", "--decrypt"], ciphertext).context("gpg decrypt failed")
}

/// Check if a string is a PGP-encrypted message.
///
/// Returns `true` if the content, after stripping leading whitespace, starts
/// with the PGP ASCII armor header `-----BEGIN PGP MESSAGE-----`.
///
/// This only checks the beginning of the content to avoid false positives
/// from text that happens to contain the header string mid-body.
#[allow(dead_code)]
pub fn is_encrypted(content: &str) -> bool {
    content.trim_start().starts_with(PGP_ARMOR_HEADER)
}

/// Import a GPG key from a file path (or any locator `gpg --import` supports).
///
/// Runs `gpg --batch --yes --import <source>`. The source is trimmed; blank
/// or whitespace-only input is rejected before spawning. On failure the
/// stderr output from gpg is included in the error context.
pub fn import_key(source: &str) -> Result<()> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        bail!("gpg import: source path must not be blank");
    }

    let output = Command::new("gpg")
        .args(["--batch", "--yes", "--import", trimmed])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("gpg: failed to spawn gpg binary for import")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code().unwrap_or(-1);
        bail!("gpg --import failed (exit {}): {}", code, stderr.trim());
    }

    Ok(())
}

/// Export the ASCII-armored private key for a given key identifier.
///
/// Runs `gpg --batch --yes --armor --export-secret-keys <key_identifier>` and
/// returns the armored private key block as a `String`.
///
/// Returns an error if:
/// - The key identifier is blank.
/// - The `gpg` binary cannot be spawned.
/// - `gpg` exits with a non-zero status (key not found, passphrase required, etc.).
/// - The export output is empty (key has no secret component).
/// - The output is not valid UTF-8.
pub fn export_secret_key(key_identifier: &str) -> Result<String> {
    let trimmed = key_identifier.trim();
    if trimmed.is_empty() {
        bail!("gpg export: key identifier must not be blank");
    }

    let output = Command::new("gpg")
        .args([
            "--batch",
            "--yes",
            "--armor",
            "--export-secret-keys",
            trimmed,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("gpg: failed to spawn gpg binary")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let lower = stderr.to_lowercase();
        if lower.contains("no secret key")
            || lower.contains("secret key not available")
            || lower.contains("not found")
        {
            bail!("Key not found in local GPG keyring: {trimmed}");
        }
        if lower.contains("passphrase") || lower.contains("pinentry") || lower.contains("agent") {
            bail!("Key requires a passphrase — export without passphrase and try again: {trimmed}");
        }
        let code = output.status.code().unwrap_or(-1);
        bail!(
            "gpg --export-secret-keys failed (exit {code}): {}",
            stderr.trim()
        );
    }

    let armored =
        String::from_utf8(output.stdout).context("gpg: export output was not valid UTF-8")?;

    // gpg may exit 0 but produce empty output when the key has no secret component
    if armored.trim().is_empty() {
        bail!("Key not found in local GPG keyring: {trimmed}");
    }

    Ok(armored)
}

/// Extract the fingerprint for a given key identifier.
///
/// Runs `gpg --batch --with-colons --fingerprint <key_identifier>` and parses
/// the first `fpr:` line to extract the fingerprint.
///
/// Returns an error if:
/// - The key identifier is blank.
/// - The `gpg` binary cannot be spawned.
/// - `gpg` exits with a non-zero status.
/// - No `fpr:` line is found in the output.
pub fn get_fingerprint(key_identifier: &str) -> Result<String> {
    let trimmed = key_identifier.trim();
    if trimmed.is_empty() {
        bail!("gpg fingerprint: key identifier must not be blank");
    }

    let output = Command::new("gpg")
        .args(["--batch", "--with-colons", "--fingerprint", trimmed])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("gpg: failed to spawn gpg binary")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lower = stderr.to_lowercase();
        if lower.contains("not found") || lower.contains("no public key") {
            bail!("Key not found in local GPG keyring: {trimmed}");
        }
        let code = output.status.code().unwrap_or(-1);
        bail!("gpg --fingerprint failed (exit {code}): {}", stderr.trim());
    }

    let stdout =
        String::from_utf8(output.stdout).context("gpg: fingerprint output was not valid UTF-8")?;

    parse_fingerprint_from_colons(&stdout)
        .ok_or_else(|| anyhow::anyhow!("Invalid key format: no fingerprint found for {trimmed}"))
}

/// Parse the first fingerprint from `gpg --with-colons` output.
///
/// Looks for a line starting with `fpr:` and extracts the fingerprint field
/// (field index 9, zero-based). Returns `None` if no valid fingerprint is found.
fn parse_fingerprint_from_colons(output: &str) -> Option<String> {
    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&"fpr") {
            // The fingerprint is in field index 9
            if let Some(fpr) = fields.get(9) {
                let fpr = fpr.trim();
                if !fpr.is_empty() {
                    return Some(fpr.to_string());
                }
            }
        }
    }
    None
}

/// Return the path to the cached public key file: `$HOME/.cadence/cli/public_key.asc`.
///
/// Returns `None` if `$HOME` cannot be determined.
pub fn public_key_cache_path() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(|h| {
        PathBuf::from(h)
            .join(".cadence")
            .join("cli")
            .join(PUBLIC_KEY_CACHE_FILENAME)
    })
}

/// Load the cached armored public key from disk.
///
/// Returns `Ok(Some(key))` if the cache file exists and is non-empty,
/// `Ok(None)` if the file is missing or empty, and `Err` on I/O errors
/// other than file-not-found.
pub fn load_cached_public_key() -> Result<Option<String>> {
    let path = match public_key_cache_path() {
        Some(p) => p,
        None => return Ok(None),
    };
    match std::fs::read_to_string(&path) {
        Ok(contents) if contents.trim().is_empty() => Ok(None),
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e)
            .with_context(|| format!("failed to read cached public key at {}", path.display())),
    }
}

/// Extract an armored public key from an armored private key.
///
/// Parses the `SignedSecretKey`, converts it to a `SignedPublicKey`, and
/// serializes the result as an ASCII-armored string.
pub fn extract_public_key_armored(armored_private_key: &str) -> Result<String> {
    use pgp::ArmorOptions;
    use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};

    let trimmed = armored_private_key.trim();
    if trimmed.is_empty() {
        bail!("extract public key: private key material must not be blank");
    }

    let (secret_key, _headers) =
        SignedSecretKey::from_string(trimmed).context("extract public key: key parse error")?;

    let public_key: SignedPublicKey = secret_key.into();

    // Verify the public key has at least one subkey
    if public_key.public_subkeys.is_empty() {
        bail!("extract public key: no public subkeys found");
    }

    public_key
        .to_armored_string(ArmorOptions::default())
        .context("extract public key: armored serialization error")
}

/// Save an armored public key to the cache file.
///
/// Creates parent directories if needed. Overwrites any existing cache file.
pub fn save_public_key_cache(armored_public_key: &str) -> Result<()> {
    let path = public_key_cache_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine cache path: $HOME is not set"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory at {}", parent.display()))?;
    }
    std::fs::write(&path, armored_public_key)
        .with_context(|| format!("failed to write cached public key at {}", path.display()))?;
    Ok(())
}

/// Encrypt plaintext using an armored public key via pure-Rust OpenPGP (rpgp).
///
/// Parses the `SignedPublicKey`, selects the first public subkey, and encrypts
/// the plaintext using SEIPDv1 (the same format the server's rpgp decryption expects).
pub fn encrypt_to_public_key(plaintext: &str, armored_public_key: &str) -> Result<String> {
    use pgp::ArmorOptions;
    use pgp::composed::{Deserializable, Message, SignedPublicKey};
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    let trimmed = armored_public_key.trim();
    if trimmed.is_empty() {
        bail!("rpgp encrypt: public key material must not be blank");
    }

    let (public_key, _headers) = SignedPublicKey::from_string(trimmed)
        .context("rpgp encrypt failed: public key parse error")?;

    let enc_subkey = public_key
        .public_subkeys
        .first()
        .ok_or_else(|| anyhow::anyhow!("rpgp encrypt failed: no encryption subkey found"))?;

    let literal = pgp::packet::LiteralData::from_bytes((&[]).into(), plaintext.as_bytes());
    let message = Message::Literal(literal);

    let mut rng = rand08::thread_rng();
    let encrypted = message
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[enc_subkey])
        .context("rpgp encrypt failed: encryption error")?;

    encrypted
        .to_armored_string(ArmorOptions::default())
        .context("rpgp encrypt failed: armored serialization error")
}

/// Check if a key for the given recipient exists in the GPG keyring.
///
/// Runs `gpg --batch --list-keys <recipient>` and returns `true` if the
/// command succeeds. Returns `false` if the key is not found, gpg is
/// missing, or any error occurs.
#[allow(dead_code)]
pub fn key_exists(recipient: &str) -> bool {
    let trimmed = recipient.trim();
    if trimmed.is_empty() {
        return false;
    }

    Command::new("gpg")
        .args(["--batch", "--list-keys", trimmed])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::path::PathBuf;
    use tempfile::TempDir;

    // -------------------------------------------------------------------
    // Helpers for env var management (unsafe in Rust 2024 edition)
    // -------------------------------------------------------------------

    /// Save, set, and restore an environment variable around a closure.
    /// Uses `unsafe` as required by Rust 2024 edition for `set_var`/`remove_var`.
    fn with_env<F, R>(key: &str, value: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let orig = std::env::var(key).ok();
        unsafe { std::env::set_var(key, value) };
        let result = f();
        unsafe {
            match orig {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        result
    }

    // -------------------------------------------------------------------
    // Unit tests: is_encrypted (pure logic, no external dependencies)
    // -------------------------------------------------------------------

    #[test]
    fn test_is_encrypted_valid_pgp_message() {
        let content = "-----BEGIN PGP MESSAGE-----\n\nsome data\n-----END PGP MESSAGE-----\n";
        assert!(is_encrypted(content));
    }

    #[test]
    fn test_is_encrypted_with_leading_whitespace() {
        let content = "  \n\t-----BEGIN PGP MESSAGE-----\ndata\n";
        assert!(is_encrypted(content));
    }

    #[test]
    fn test_is_encrypted_with_leading_newlines() {
        let content = "\n\n-----BEGIN PGP MESSAGE-----\ndata\n";
        assert!(is_encrypted(content));
    }

    #[test]
    fn test_is_encrypted_plaintext() {
        assert!(!is_encrypted("this is just plain text"));
    }

    #[test]
    fn test_is_encrypted_empty_string() {
        assert!(!is_encrypted(""));
    }

    #[test]
    fn test_is_encrypted_header_mid_body() {
        // Header in the middle should NOT classify as encrypted
        let content = "some preamble text\n-----BEGIN PGP MESSAGE-----\ndata\n";
        assert!(!is_encrypted(content));
    }

    #[test]
    fn test_is_encrypted_partial_header() {
        assert!(!is_encrypted("-----BEGIN PGP"));
    }

    #[test]
    fn test_is_encrypted_different_pgp_type() {
        // Public key block is not an encrypted message
        assert!(!is_encrypted("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"));
    }

    #[test]
    fn test_is_encrypted_just_header() {
        assert!(is_encrypted("-----BEGIN PGP MESSAGE-----"));
    }

    // -------------------------------------------------------------------
    // Unit tests: gpg_available (system-dependent but safe)
    // -------------------------------------------------------------------

    #[test]
    fn test_gpg_available_returns_bool() {
        // We can't control whether gpg is installed, but we can verify
        // the function returns without panicking.
        let _result = gpg_available();
    }

    // -------------------------------------------------------------------
    // Unit tests: get_recipient (requires isolated git config)
    // -------------------------------------------------------------------

    /// Create a temporary directory with an empty git config file.
    fn setup_isolated_git_config(dir: &TempDir) -> PathBuf {
        let config_path = dir.path().join(".gitconfig");
        std::fs::write(&config_path, "").unwrap();
        config_path
    }

    #[test]
    #[serial]
    fn test_get_recipient_unset() {
        let dir = TempDir::new().unwrap();
        let config_path = setup_isolated_git_config(&dir);

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            get_recipient()
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_get_recipient_set() {
        let dir = TempDir::new().unwrap();
        let config_path = setup_isolated_git_config(&dir);

        // Write a recipient value
        std::process::Command::new("git")
            .args([
                "config",
                "--file",
                config_path.to_str().unwrap(),
                GPG_RECIPIENT_KEY,
                "test@example.com",
            ])
            .output()
            .unwrap();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            get_recipient()
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("test@example.com".to_string()));
    }

    #[test]
    #[serial]
    fn test_get_recipient_blank_value() {
        let dir = TempDir::new().unwrap();
        let config_path = setup_isolated_git_config(&dir);

        // Write a blank recipient value
        std::process::Command::new("git")
            .args([
                "config",
                "--file",
                config_path.to_str().unwrap(),
                GPG_RECIPIENT_KEY,
                "   ",
            ])
            .output()
            .unwrap();

        let result = with_env("GIT_CONFIG_GLOBAL", config_path.to_str().unwrap(), || {
            get_recipient()
        });

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    // -------------------------------------------------------------------
    // Unit tests: encrypt_to_recipient error cases (no gpg needed)
    // -------------------------------------------------------------------

    #[test]
    fn test_encrypt_blank_recipient_fails() {
        let result = encrypt_to_recipient("hello", "");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("recipient must not be blank"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_encrypt_whitespace_recipient_fails() {
        let result = encrypt_to_recipient("hello", "   ");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("recipient must not be blank"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_encrypt_to_armored_private_key_blank_key_fails() {
        let result = encrypt_to_armored_private_key("hello", "");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("private key material must not be blank"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn test_encrypt_to_armored_private_key_invalid_key_fails() {
        let result = encrypt_to_armored_private_key("hello", "not a valid key");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("rpgp encrypt failed"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    #[serial]
    fn test_encrypt_to_armored_private_key_roundtrip() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let plaintext = "rpgp-compatibility-test";
        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            let armored = export_secret_key(&email)?;
            let ciphertext = encrypt_to_armored_private_key(plaintext, &armored)?;
            assert!(is_encrypted(&ciphertext));

            let decrypted = decrypt(&ciphertext)?;
            assert_eq!(decrypted.trim(), plaintext);
            Ok::<(), anyhow::Error>(())
        });

        result.unwrap();
    }

    // -------------------------------------------------------------------
    // Unit tests: key_exists edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_key_exists_empty_recipient() {
        assert!(!key_exists(""));
    }

    #[test]
    fn test_key_exists_whitespace_recipient() {
        assert!(!key_exists("   "));
    }

    #[test]
    #[cfg(not(windows))]
    fn test_key_exists_nonexistent_returns_false() {
        // Unless the test machine happens to have this key, this should be false.
        // If gpg is missing, also returns false.
        assert!(!key_exists(
            "definitely-not-a-real-key-id-12345@nowhere.invalid"
        ));
    }

    // -------------------------------------------------------------------
    // Integration tests: gated on gpg availability
    // -------------------------------------------------------------------

    /// Set up a temporary GPG home directory with a test keypair.
    /// Returns (TempDir, email) — TempDir must be kept alive for the
    /// duration of the test.
    fn setup_test_gpg_keyring() -> Option<(TempDir, String)> {
        if !gpg_available() {
            return None;
        }

        let dir = TempDir::new().unwrap();
        let gnupghome = dir.path();
        let email = "test-gpg@cadence.test";

        // Set restrictive permissions on the gnupg directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(gnupghome, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        // Generate a test key using batch mode
        let key_params = format!(
            "%no-protection\nKey-Type: RSA\nKey-Length: 2048\nSubkey-Type: RSA\nSubkey-Length: 2048\nName-Real: Test User\nName-Email: {}\nExpire-Date: 0\n%commit\n",
            email
        );

        let output = Command::new("gpg")
            .args(["--batch", "--gen-key"])
            .env("GNUPGHOME", gnupghome)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child
                    .stdin
                    .as_mut()
                    .unwrap()
                    .write_all(key_params.as_bytes())
                    .unwrap();
                child.wait_with_output()
            });

        match output {
            Ok(o) if o.status.success() => Some((dir, email.to_string())),
            _ => None,
        }
    }

    /// Helper to create an empty GNUPGHOME with correct permissions.
    fn empty_gnupghome() -> TempDir {
        let dir = TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    #[test]
    #[serial]
    fn test_encrypt_decrypt_roundtrip() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let plaintext = "Hello, this is a secret note!\nLine 2.";
        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            let ciphertext = encrypt_to_recipient(plaintext, &email)?;

            assert!(
                is_encrypted(&ciphertext),
                "encrypted output should start with PGP armor header"
            );
            assert!(
                ciphertext.contains("-----END PGP MESSAGE-----"),
                "encrypted output should contain PGP armor footer"
            );

            let decrypted = decrypt(&ciphertext)?;
            assert_eq!(
                decrypted.trim(),
                plaintext,
                "decrypted text should match original plaintext"
            );
            Ok::<(), anyhow::Error>(())
        });

        result.unwrap();
    }

    #[test]
    #[serial]
    fn test_encrypt_invalid_recipient_fails() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let result = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            encrypt_to_recipient("test data", "nonexistent@invalid.test")
        });

        assert!(
            result.is_err(),
            "encrypt with invalid recipient should fail"
        );
    }

    #[test]
    #[serial]
    fn test_encrypt_empty_plaintext() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            encrypt_to_recipient("", &email)
        });

        // GPG should still produce an armored payload for empty input
        match result {
            Ok(ciphertext) => assert!(is_encrypted(&ciphertext)),
            Err(e) => panic!("encrypt empty plaintext should succeed: {e}"),
        }
    }

    #[test]
    #[serial]
    fn test_decrypt_invalid_ciphertext_fails() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let result = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            decrypt("this is not valid ciphertext")
        });

        assert!(result.is_err(), "decrypt of invalid ciphertext should fail");
    }

    #[test]
    #[serial]
    fn test_key_exists_with_valid_key() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let exists = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            key_exists(&email)
        });

        assert!(
            exists,
            "key_exists should return true for generated test key"
        );
    }

    #[test]
    #[serial]
    fn test_key_exists_with_empty_keyring() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let exists = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            key_exists("nobody@example.com")
        });

        assert!(!exists, "key_exists should return false for empty keyring");
    }

    // -------------------------------------------------------------------
    // Unit tests: import_key edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_import_key_blank_source() {
        let result = import_key("");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("source path must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_import_key_whitespace_source() {
        let result = import_key("   \t  ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("source path must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_import_key_invalid_source() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let result = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            import_key("/nonexistent/path/to/key.asc")
        });

        assert!(result.is_err(), "import from nonexistent path should fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("gpg --import failed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_import_key_valid_file() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        // Export the public key to a temp file
        let export_output = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            Command::new("gpg")
                .args(["--batch", "--armor", "--export", &email])
                .output()
        });
        let export_output = export_output.expect("failed to run gpg --export");
        assert!(
            export_output.status.success(),
            "gpg --export failed: {}",
            String::from_utf8_lossy(&export_output.stderr)
        );
        assert!(
            !export_output.stdout.is_empty(),
            "exported key should not be empty"
        );

        // Write exported key to a temp file
        let key_dir = TempDir::new().unwrap();
        let key_path = key_dir.path().join("test-key.asc");
        std::fs::write(&key_path, &export_output.stdout).unwrap();

        // Import into a fresh keyring
        let import_home = empty_gnupghome();
        let result = with_env("GNUPGHOME", import_home.path().to_str().unwrap(), || {
            import_key(key_path.to_str().unwrap())
        });

        assert!(
            result.is_ok(),
            "import_key should succeed: {:?}",
            result.err()
        );

        // Verify the key is now in the new keyring
        let exists = with_env("GNUPGHOME", import_home.path().to_str().unwrap(), || {
            key_exists(&email)
        });
        assert!(exists, "imported key should be found in keyring");
    }

    // -------------------------------------------------------------------
    // Unit tests: export_secret_key
    // -------------------------------------------------------------------

    #[test]
    fn test_export_secret_key_blank_identifier() {
        let result = export_secret_key("");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("key identifier must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_export_secret_key_whitespace_identifier() {
        let result = export_secret_key("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("key identifier must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_export_secret_key_unknown_key() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let result = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            export_secret_key("nonexistent-key-id@invalid.test")
        });

        assert!(result.is_err(), "export of unknown key should fail");
        let msg = result.unwrap_err().to_string();
        // On Windows the gpg-agent in an empty temp GNUPGHOME may emit
        // passphrase/pinentry errors before reporting the key as missing,
        // so we accept that error variant too.
        assert!(
            msg.contains("Key not found")
                || msg.contains("gpg --export-secret-keys failed")
                || msg.contains("Key requires a passphrase"),
            "expected key-not-found error, got: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_export_secret_key_success() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            export_secret_key(&email)
        });

        assert!(result.is_ok(), "export should succeed: {:?}", result.err());
        let armored = result.unwrap();
        assert!(
            armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            "exported key should contain PGP private key header, got: {}",
            &armored[..armored.len().min(200)]
        );
    }

    // -------------------------------------------------------------------
    // Unit tests: get_fingerprint
    // -------------------------------------------------------------------

    #[test]
    fn test_get_fingerprint_blank_identifier() {
        let result = get_fingerprint("");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("key identifier must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_get_fingerprint_whitespace_identifier() {
        let result = get_fingerprint("   ");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("key identifier must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_get_fingerprint_unknown_key() {
        if !gpg_available() {
            eprintln!("skipping test: gpg not available");
            return;
        }

        let dir = empty_gnupghome();
        let result = with_env("GNUPGHOME", dir.path().to_str().unwrap(), || {
            get_fingerprint("nonexistent-key-id@invalid.test")
        });

        assert!(result.is_err(), "fingerprint of unknown key should fail");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Key not found") || msg.contains("gpg --fingerprint failed"),
            "expected key-not-found error, got: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_get_fingerprint_success() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            get_fingerprint(&email)
        });

        assert!(
            result.is_ok(),
            "fingerprint should succeed: {:?}",
            result.err()
        );
        let fpr = result.unwrap();
        assert!(!fpr.is_empty(), "fingerprint should not be empty");
        // GPG fingerprints are 40 hex characters
        assert!(
            fpr.len() == 40 && fpr.chars().all(|c| c.is_ascii_hexdigit()),
            "fingerprint should be 40 hex chars, got: {fpr}"
        );
    }

    // -------------------------------------------------------------------
    // Unit tests: parse_fingerprint_from_colons (pure logic)
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_fingerprint_valid() {
        let output = "tru::1:1234567890:\npub:u:2048:1:ABCDEF1234567890:1234567890:::-:::scESC::::::23::0:\nfpr:::::::::ABCDEF1234567890ABCDEF1234567890ABCDEF12:";
        let fpr = parse_fingerprint_from_colons(output);
        assert_eq!(
            fpr,
            Some("ABCDEF1234567890ABCDEF1234567890ABCDEF12".to_string())
        );
    }

    #[test]
    fn test_parse_fingerprint_multiple_fpr_lines_returns_first() {
        let output = "fpr:::::::::AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555:\nfpr:::::::::1111222233334444555566667777888899990000:";
        let fpr = parse_fingerprint_from_colons(output);
        assert_eq!(
            fpr,
            Some("AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555".to_string())
        );
    }

    #[test]
    fn test_parse_fingerprint_no_fpr_line() {
        let output = "pub:u:2048:1:ABCDEF:1234567890:::-:::scESC:\nuid:u::::1234567890::HASH::Test User <test@test>:";
        let fpr = parse_fingerprint_from_colons(output);
        assert!(fpr.is_none());
    }

    #[test]
    fn test_parse_fingerprint_empty_fpr_field() {
        let output = "fpr::::::::::";
        let fpr = parse_fingerprint_from_colons(output);
        assert!(fpr.is_none());
    }

    #[test]
    fn test_parse_fingerprint_empty_output() {
        let fpr = parse_fingerprint_from_colons("");
        assert!(fpr.is_none());
    }

    #[test]
    fn test_parse_fingerprint_whitespace_fpr_field() {
        let output = "fpr:::::::::   :";
        let fpr = parse_fingerprint_from_colons(output);
        assert!(fpr.is_none());
    }

    #[test]
    fn test_parse_fingerprint_short_fpr_line() {
        // Not enough fields
        let output = "fpr::::";
        let fpr = parse_fingerprint_from_colons(output);
        assert!(fpr.is_none());
    }

    // -------------------------------------------------------------------
    // Unit tests: public key cache path
    // -------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_public_key_cache_path_uses_home() {
        let path = with_env("HOME", "/tmp/fake-home", || public_key_cache_path());
        assert_eq!(
            path,
            Some(PathBuf::from("/tmp/fake-home/.cadence/cli/public_key.asc"))
        );
    }

    #[test]
    #[serial]
    fn test_public_key_cache_path_returns_none_when_home_missing() {
        let orig = std::env::var("HOME").ok();
        unsafe { std::env::remove_var("HOME") };
        let path = public_key_cache_path();
        unsafe {
            match orig {
                Some(v) => std::env::set_var("HOME", v),
                None => {}
            }
        }
        assert!(path.is_none());
    }

    // -------------------------------------------------------------------
    // Unit tests: load_cached_public_key
    // -------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_load_cached_public_key_missing_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = with_env("HOME", dir.path().to_str().unwrap(), || {
            load_cached_public_key()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_load_cached_public_key_empty_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache_dir = dir.path().join(".cadence").join("cli");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join("public_key.asc"), "").unwrap();

        let result = with_env("HOME", dir.path().to_str().unwrap(), || {
            load_cached_public_key()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_load_cached_public_key_whitespace_file_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache_dir = dir.path().join(".cadence").join("cli");
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join("public_key.asc"), "   \n  ").unwrap();

        let result = with_env("HOME", dir.path().to_str().unwrap(), || {
            load_cached_public_key()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }

    // -------------------------------------------------------------------
    // Unit tests: save_public_key_cache + load roundtrip
    // -------------------------------------------------------------------

    #[test]
    #[serial]
    fn test_save_and_load_public_key_cache_roundtrip() {
        let dir = TempDir::new().unwrap();
        let key_data = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nfake-key-data\n-----END PGP PUBLIC KEY BLOCK-----";

        let result = with_env("HOME", dir.path().to_str().unwrap(), || {
            save_public_key_cache(key_data)?;
            load_cached_public_key()
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some(key_data.to_string()));
    }

    #[test]
    #[serial]
    fn test_save_public_key_cache_creates_dirs() {
        let dir = TempDir::new().unwrap();
        let key_data = "test-key";

        let result = with_env("HOME", dir.path().to_str().unwrap(), || {
            save_public_key_cache(key_data)
        });
        assert!(result.is_ok());
        assert!(
            dir.path()
                .join(".cadence")
                .join("cli")
                .join("public_key.asc")
                .exists()
        );
    }

    // -------------------------------------------------------------------
    // Unit tests: extract_public_key_armored
    // -------------------------------------------------------------------

    #[test]
    fn test_extract_public_key_blank_input_fails() {
        let result = extract_public_key_armored("");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("private key material must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_extract_public_key_invalid_input_fails() {
        let result = extract_public_key_armored("not a valid key");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("key parse error"), "unexpected error: {msg}");
    }

    #[test]
    #[serial]
    fn test_extract_public_key_from_generated_keypair() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            let armored_private = export_secret_key(&email)?;
            let armored_public = extract_public_key_armored(&armored_private)?;
            assert!(
                armored_public.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
                "should contain public key header"
            );
            Ok::<(), anyhow::Error>(())
        });

        result.unwrap();
    }

    // -------------------------------------------------------------------
    // Unit tests: encrypt_to_public_key
    // -------------------------------------------------------------------

    #[test]
    fn test_encrypt_to_public_key_blank_key_fails() {
        let result = encrypt_to_public_key("hello", "");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("public key material must not be blank"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_encrypt_to_public_key_invalid_key_fails() {
        let result = encrypt_to_public_key("hello", "not a valid key");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("rpgp encrypt failed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_encrypt_to_public_key_roundtrip() {
        let Some((gpg_home, email)) = setup_test_gpg_keyring() else {
            eprintln!("skipping test: gpg not available or key generation failed");
            return;
        };

        let plaintext = "rpgp-public-key-encrypt-test";
        let result = with_env("GNUPGHOME", gpg_home.path().to_str().unwrap(), || {
            let armored_private = export_secret_key(&email)?;
            let armored_public = extract_public_key_armored(&armored_private)?;
            let ciphertext = encrypt_to_public_key(plaintext, &armored_public)?;
            assert!(is_encrypted(&ciphertext));

            // Decrypt with gpg CLI (which has the private key in the test keyring)
            let decrypted = decrypt(&ciphertext)?;
            assert_eq!(decrypted.trim(), plaintext);
            Ok::<(), anyhow::Error>(())
        });

        result.unwrap();
    }
}
