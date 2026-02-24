use anyhow::{Context, Result, bail};
use pgp::ArmorOptions;
use pgp::KeyType;
use pgp::composed::key::{SecretKeyParamsBuilder, SubkeyParamsBuilder};
use pgp::composed::{Deserializable, Message, SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::PublicKeyTrait;
use std::path::{Path, PathBuf};

use crate::agents;
use crate::git;

/// Filename for the cached armored public key for the local user.
const USER_PUBLIC_KEY_CACHE_FILENAME: &str = "user_public_key.asc";

/// Filename for the cached armored private key for the local user.
const USER_PRIVATE_KEY_CACHE_FILENAME: &str = "user_private_key.asc";

/// Filename for the cached armored public key for the API recipient.
const API_PUBLIC_KEY_CACHE_FILENAME: &str = "api_public_key.asc";

/// Filename for the cached API public key metadata.
const API_PUBLIC_KEY_META_FILENAME: &str = "api_public_key.json";

/// The git config key for the local user key fingerprint.
pub const USER_FINGERPRINT_KEY: &str = "ai.cadence.keys.userFingerprint";

/// The git config key for the API public key fingerprint.
pub const API_FINGERPRINT_KEY: &str = "ai.cadence.keys.apiFingerprint";

/// Metadata stored alongside the cached API public key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ApiPublicKeyMetadata {
    pub fingerprint: String,
    pub fetched_at: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub rotated_at: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

fn cache_dir() -> Option<PathBuf> {
    agents::home_dir().map(|home| home.join(".cadence").join("cli"))
}

fn read_optional_file(path: Option<PathBuf>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(contents) if contents.trim().is_empty() => Ok(None),
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn write_cache_file(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory at {}", parent.display()))?;
    }
    std::fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn fingerprint_to_string(fingerprint: &pgp::types::Fingerprint) -> String {
    format!("{:?}", fingerprint)
}

/// Read the configured local user fingerprint from **global** git config.
///
/// Reads `ai.cadence.keys.userFingerprint`. Returns `Ok(None)` if the
/// key is not set or is blank/whitespace-only. Propagates real git errors.
pub fn get_user_fingerprint() -> Result<Option<String>> {
    let value = git::config_get_global(USER_FINGERPRINT_KEY)?;
    match value {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
        _ => Ok(None),
    }
}

/// Read the configured API fingerprint from **global** git config.
pub fn get_api_fingerprint() -> Result<Option<String>> {
    let value = git::config_get_global(API_FINGERPRINT_KEY)?;
    match value {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
        _ => Ok(None),
    }
}

/// Return the path to the cached public key file: `$HOME/.cadence/cli/user_public_key.asc`.
///
/// Returns `None` if the home directory cannot be determined.
pub fn user_public_key_cache_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(USER_PUBLIC_KEY_CACHE_FILENAME))
}

/// Return the path to the cached private key file: `$HOME/.cadence/cli/user_private_key.asc`.
pub fn user_private_key_cache_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(USER_PRIVATE_KEY_CACHE_FILENAME))
}

/// Return the path to the cached API public key file: `$HOME/.cadence/cli/api_public_key.asc`.
pub fn api_public_key_cache_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(API_PUBLIC_KEY_CACHE_FILENAME))
}

/// Return the path to the cached API public key metadata file.
pub fn api_public_key_meta_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(API_PUBLIC_KEY_META_FILENAME))
}

/// Load the cached armored public key for the local user.
pub fn load_cached_user_public_key() -> Result<Option<String>> {
    read_optional_file(user_public_key_cache_path())
}

/// Load the cached armored private key for the local user.
pub fn load_cached_user_private_key() -> Result<Option<String>> {
    read_optional_file(user_private_key_cache_path())
}

/// Load the cached armored public key for the API recipient.
pub fn load_cached_api_public_key() -> Result<Option<String>> {
    read_optional_file(api_public_key_cache_path())
}

/// Save armored public + private keys to cache, enforcing private key permissions.
pub fn save_user_keys(armored_public_key: &str, armored_private_key: &str) -> Result<()> {
    let public_path = user_public_key_cache_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine cache path: $HOME is not set"))?;
    let private_path = user_private_key_cache_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine cache path: $HOME is not set"))?;

    write_cache_file(&public_path, armored_public_key)?;
    write_cache_file(&private_path, armored_private_key)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&private_path, perms);
    }

    Ok(())
}

/// Load cached API public key metadata.
pub fn load_api_public_key_metadata() -> Result<Option<ApiPublicKeyMetadata>> {
    let path = api_public_key_meta_path();
    let Some(path) = path else {
        return Ok(None);
    };
    match std::fs::read_to_string(&path) {
        Ok(contents) if contents.trim().is_empty() => Ok(None),
        Ok(contents) => {
            let parsed: ApiPublicKeyMetadata =
                serde_json::from_str(&contents).with_context(|| {
                    format!("failed to parse api key metadata at {}", path.display())
                })?;
            Ok(Some(parsed))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => {
            Err(e).with_context(|| format!("failed to read api key metadata at {}", path.display()))
        }
    }
}

/// Save API public key and metadata to cache.
pub fn save_api_public_key_cache(
    armored_public_key: &str,
    metadata: &ApiPublicKeyMetadata,
) -> Result<()> {
    let key_path = api_public_key_cache_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine cache path: $HOME is not set"))?;
    let meta_path = api_public_key_meta_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine cache path: $HOME is not set"))?;
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cache directory at {}", parent.display()))?;
    }
    std::fs::write(&key_path, armored_public_key).with_context(|| {
        format!(
            "failed to write cached api public key at {}",
            key_path.display()
        )
    })?;
    let meta =
        serde_json::to_string_pretty(metadata).context("failed to serialize api key metadata")?;
    std::fs::write(&meta_path, meta).with_context(|| {
        format!(
            "failed to write api key metadata at {}",
            meta_path.display()
        )
    })?;
    Ok(())
}

/// Determine whether API public key cache is stale.
pub fn api_public_key_cache_stale(metadata: &ApiPublicKeyMetadata, max_age_days: i64) -> bool {
    use time::format_description::well_known::Rfc3339;
    let Ok(fetched_at) = time::OffsetDateTime::parse(&metadata.fetched_at, &Rfc3339) else {
        return true;
    };
    let now = time::OffsetDateTime::now_utc();
    let age = now - fetched_at;
    age.whole_days() >= max_age_days
}

/// Generate a new OpenPGP keypair for the user identity.
pub fn generate_user_keypair(identity: &str, passphrase: &str) -> Result<(String, String, String)> {
    if passphrase.trim().is_empty() {
        bail!("passphrase must not be blank");
    }

    let key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(2048))
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(identity.to_string())
        .passphrase(Some(passphrase.into()))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::Rsa(2048))
                .can_encrypt(true)
                .passphrase(Some(passphrase.into()))
                .build()
                .context("failed to build encryption subkey")?,
        )
        .build()
        .context("failed to build key parameters")?;

    let mut rng = rand08::thread_rng();
    let secret_key = key_params
        .generate(&mut rng)
        .context("failed to generate secret key")?;

    let signed_secret_key = secret_key
        .sign(&mut rng, || passphrase.into())
        .context("failed to sign secret key")?;

    let armored_private = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .context("failed to armor private key")?;

    let public_key: SignedPublicKey = signed_secret_key.into();
    let armored_public = public_key
        .to_armored_string(ArmorOptions::default())
        .context("failed to armor public key")?;

    let fingerprint = fingerprint_to_string(&public_key.fingerprint());

    Ok((armored_public, armored_private, fingerprint))
}

/// Derive the fingerprint for an armored public key.
pub fn fingerprint_from_public_key(armored_public_key: &str) -> Result<String> {
    let trimmed = armored_public_key.trim();
    if trimmed.is_empty() {
        bail!("public key material must not be blank");
    }

    let (public_key, _headers) =
        SignedPublicKey::from_string(trimmed).context("failed to parse public key")?;

    Ok(fingerprint_to_string(&public_key.fingerprint()))
}

/// Encrypt binary data to multiple armored public keys, returning raw bytes (not armored).
///
/// Same as [`encrypt_to_public_keys`] but operates on `&[u8]` input and returns
/// `Vec<u8>` output (binary PGP packets). This avoids the ~33% overhead of
/// ASCII armor for large payloads stored as git blobs.
pub fn encrypt_to_public_keys_binary(
    data: &[u8],
    armored_public_keys: &[String],
) -> Result<Vec<u8>> {
    if armored_public_keys.is_empty() {
        bail!("rpgp encrypt: at least one public key is required");
    }

    let mut public_keys: Vec<SignedPublicKey> = Vec::new();

    for armored in armored_public_keys {
        let trimmed = armored.trim();
        if trimmed.is_empty() {
            bail!("rpgp encrypt: public key material must not be blank");
        }
        let (public_key, _headers) = SignedPublicKey::from_string(trimmed)
            .context("rpgp encrypt failed: public key parse error")?;
        public_keys.push(public_key);
    }

    let mut enc_subkeys: Vec<&pgp::composed::SignedPublicSubKey> = Vec::new();
    for public_key in &public_keys {
        let enc_subkey = public_key
            .public_subkeys
            .first()
            .ok_or_else(|| anyhow::anyhow!("rpgp encrypt failed: no encryption subkey found"))?;
        enc_subkeys.push(enc_subkey);
    }

    let literal = pgp::packet::LiteralData::from_bytes((&[]).into(), data);
    let message = Message::Literal(literal);

    let mut rng = rand08::thread_rng();
    let encrypted = message
        .encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &enc_subkeys)
        .context("rpgp encrypt failed: encryption error")?;

    encrypted
        .to_bytes()
        .context("rpgp encrypt failed: binary serialization error")
}
