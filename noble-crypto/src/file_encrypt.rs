// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! At-rest file encryption for sensitive key material.
//!
//! Provides casual-exposure reduction: prevents keys from being readable in
//! backups, logs, or accidental file copies.  In **automatic** mode the
//! encryption key is derivable from source code + the per-installation
//! `.chain_meta` file.  Primary protection remains Unix file permissions
//! (0o600).
//!
//! In **manual** mode the `.chain_meta` file itself is encrypted with a
//! password the operator provides on every startup, making the key material
//! unrecoverable without the password.
//!
//! # Noble envelope wire format
//!
//! ```text
//! Offset  Size   Field
//! 0       4      MAGIC: b"NBLE" (0x4E424C45)
//! 4       1      VERSION: 0x01
//! 5       12     NONCE: random AES-GCM nonce
//! 17      N+16   CIPHERTEXT: AES-256-GCM(plaintext) with 16-byte auth tag
//! ```
//!
//! Detection: first 4 bytes == `b"NBLE"` means Noble envelope.  Anything
//! else is legacy plaintext (backward compatible).
//!
//! # Locked chain_meta wire format (manual mode)
//!
//! ```text
//! Offset  Size   Field
//! 0       4      MAGIC: b"NBLK" (0x4E424C4B) — "Noble BLocK"
//! 4       1      VERSION: 0x01
//! 5       16     ARGON2_SALT: random salt for Argon2id
//! 21      12     AES_NONCE: AES-256-GCM nonce
//! 33      48     CIPHERTEXT: AES-256-GCM(chain_meta_32_bytes) + 16-byte tag
//! ```
//!
//! Total: 81 bytes. Detection: first 4 bytes == `b"NBLK"`.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, AeadCore, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::CryptoError;

// ---------------------------------------------------------------------------
// Noble envelope constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a Noble-encrypted file.
const MAGIC: [u8; 4] = *b"NBLE";

/// Current envelope version.
const VERSION: u8 = 0x01;

/// Size of header (magic + version).
const HEADER_LEN: usize = 4 + 1; // 5

/// AES-GCM nonce length.
const NONCE_LEN: usize = 12;

/// AES-GCM auth tag length (appended by aes-gcm crate).
const TAG_LEN: usize = 16;

/// Minimum valid envelope: header + nonce + tag (zero-length plaintext).
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

// ---------------------------------------------------------------------------
// Locked chain_meta constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a password-locked chain_meta file.
const LOCKED_MAGIC: [u8; 4] = *b"NBLK";

/// Argon2id salt length.
const ARGON2_SALT_LEN: usize = 16;

/// Expected locked file size: magic(4) + version(1) + salt(16) + nonce(12) + ciphertext(32+16).
const LOCKED_CHAIN_META_LEN: usize = 4 + 1 + ARGON2_SALT_LEN + NONCE_LEN + 32 + TAG_LEN;

// ---------------------------------------------------------------------------
// Obfuscated hardcoded key material
// ---------------------------------------------------------------------------
//
// The actual IKM (`b"noble-at-rest-v1-2026"`, 21 bytes) is XOR-masked at
// compile time so that `strings` on the binary cannot trivially reveal it.
// Assembled at runtime via XOR.

/// Random mask — looks like garbage bytes in the binary.
const MASK: [u8; 21] = [
    0xA3, 0x17, 0xF9, 0x4B, 0xD2, 0x8E, 0x55, 0xC1, 0x6A, 0x3F, 0xB8,
    0x07, 0xE4, 0x92, 0x1D, 0xAC, 0x73, 0xDF, 0x46, 0x5B, 0x80,
];

/// `IKM[i] ^ MASK[i]` — also looks like garbage bytes.
const MASKED_KEY: [u8; 21] = [
    0xCD, 0x78, 0x9B, 0x27, 0xB7, 0xA3, 0x34, 0xB5, 0x47, 0x4D, 0xDD,
    0x74, 0x90, 0xBF, 0x6B, 0x9D, 0x5E, 0xED, 0x76, 0x69, 0xB6,
];

/// HKDF info string — domain separation for file encryption keys.
const HKDF_INFO: &[u8] = b"noble-file-enc-v1";

/// Historical IKM constants for graceful key rotation.
/// Each entry is (MASK, MASKED_KEY) from a previous release.
/// When decryption with the current IKM fails (AES-GCM auth error),
/// these are tried in order from newest to oldest.
///
/// ## How to rotate the IKM
/// 1. Move current MASK + MASKED_KEY into LEGACY_KEYS (append at front)
/// 2. Choose a new IKM string (e.g. `b"noble-at-rest-v2-2027"`)
/// 3. Generate a new random MASK (21 bytes)
/// 4. Compute new MASKED_KEY = new_ikm XOR new_mask
/// 5. Replace MASK and MASKED_KEY constants
/// 6. Bump HKDF_INFO to `b"noble-file-enc-v2"` (optional domain separation)
/// 7. All existing encrypted files will auto-migrate on next node startup
const LEGACY_KEYS: &[([u8; 21], [u8; 21])] = &[
    // (Currently empty — v1 is the first and only IKM.
    //  When v2 ships, the v1 MASK/MASKED_KEY move here.)
];

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Recover the 21-byte IKM from the obfuscated constants.
fn deobfuscate_ikm() -> [u8; 21] {
    let mut ikm = [0u8; 21];
    for i in 0..21 {
        ikm[i] = MASKED_KEY[i] ^ MASK[i];
    }
    ikm
}

/// Derive a 32-byte AES-256 key from an arbitrary IKM and per-installation
/// entropy (`.chain_meta`).
fn derive_file_key_with_ikm(chain_meta: &[u8; 32], ikm: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(chain_meta), ikm);
    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut key)
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
    key
}

/// Derive the 32-byte AES-256 key from the hardcoded IKM and per-installation
/// entropy (`.chain_meta`).
fn derive_file_key(chain_meta: &[u8; 32]) -> [u8; 32] {
    let mut ikm = deobfuscate_ikm();
    let key = derive_file_key_with_ikm(chain_meta, &ikm);
    ikm.zeroize();
    key
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Derive a 32-byte wallet encryption key from the per-installation
/// `.chain_meta` entropy.
///
/// Uses HKDF-SHA256 with a wallet-specific info string for domain
/// separation from file encryption keys.  The result is hex-encoded by
/// the caller to produce a 64-char passphrase (well above the keystore's
/// 12-char minimum).
pub fn derive_wallet_key(chain_meta: &[u8; 32]) -> [u8; 32] {
    let mut ikm = deobfuscate_ikm();
    let hk = Hkdf::<Sha256>::new(Some(chain_meta), &ikm);
    ikm.zeroize();
    let mut key = [0u8; 32];
    hk.expand(b"noble-wallet-enc-v1", &mut key)
        .expect("HKDF-SHA256 expand to 32 bytes cannot fail");
    key
}

/// Returns `true` if `data` starts with the Noble envelope magic header.
pub fn is_noble_envelope(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && data[..4] == MAGIC
}

/// Returns `true` if `data` starts with the locked chain_meta magic header.
pub fn is_locked_chain_meta(data: &[u8]) -> bool {
    data.len() >= 5 && data[..4] == LOCKED_MAGIC
}

/// Encrypt `plaintext` into a Noble envelope.
///
/// The caller must supply the 32-byte per-installation entropy loaded from
/// `.chain_meta`.
pub fn encrypt_file_data(
    plaintext: &[u8],
    chain_meta: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    let mut key_bytes = derive_file_key(chain_meta);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("AES key init: {e}")))?;
    key_bytes.zeroize();

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::SigningFailed(format!("AES-GCM encrypt: {e}")))?;

    // Assemble envelope: MAGIC || VERSION || NONCE || CIPHERTEXT
    let mut envelope = Vec::with_capacity(HEADER_LEN + NONCE_LEN + ciphertext.len());
    envelope.extend_from_slice(&MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(nonce.as_slice());
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// Decrypt a Noble envelope back to plaintext.
///
/// Returns `Err` if the envelope is malformed, the version is unsupported,
/// or the authentication tag is invalid.
pub fn decrypt_file_data(
    envelope: &[u8],
    chain_meta: &[u8; 32],
) -> Result<Vec<u8>, CryptoError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(CryptoError::InvalidKey(format!(
            "Noble envelope too short: {} bytes (min {})",
            envelope.len(),
            MIN_ENVELOPE_LEN
        )));
    }

    if envelope[..4] != MAGIC {
        return Err(CryptoError::InvalidKey(
            "not a Noble envelope (bad magic)".into(),
        ));
    }

    let version = envelope[4];
    if version != VERSION {
        return Err(CryptoError::InvalidKey(format!(
            "unsupported Noble envelope version: {version:#04x}"
        )));
    }

    let nonce_bytes = &envelope[HEADER_LEN..HEADER_LEN + NONCE_LEN];
    let ciphertext = &envelope[HEADER_LEN + NONCE_LEN..];

    let mut key_bytes = derive_file_key(chain_meta);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| CryptoError::InvalidKey(format!("AES key init: {e}")))?;
    key_bytes.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::VerificationFailed("Noble envelope: AES-GCM auth failed".into()))
}

/// Decrypt a Noble envelope, falling back to legacy IKMs if the current
/// key fails AES-GCM authentication.
///
/// Returns `(plaintext, migrated)` where `migrated` is `true` when a
/// legacy key succeeded. The caller should re-encrypt and overwrite the
/// file to complete the migration.
pub fn decrypt_file_data_with_migration(
    envelope: &[u8],
    chain_meta: &[u8; 32],
) -> Result<(Vec<u8>, bool), CryptoError> {
    // 1. Try current key
    match decrypt_file_data(envelope, chain_meta) {
        Ok(pt) => return Ok((pt, false)),
        Err(CryptoError::VerificationFailed(_)) => { /* try legacy */ }
        Err(e) => return Err(e), // structural error — not recoverable
    }

    // 2. Parse envelope fields once (already validated by decrypt_file_data attempt above)
    let nonce = Nonce::from_slice(&envelope[HEADER_LEN..HEADER_LEN + NONCE_LEN]);
    let ciphertext = &envelope[HEADER_LEN + NONCE_LEN..];

    // 3. Try each legacy IKM (newest first)
    for (mask, masked) in LEGACY_KEYS {
        let mut ikm = [0u8; 21];
        for i in 0..21 {
            ikm[i] = mask[i] ^ masked[i];
        }
        let mut key = derive_file_key_with_ikm(chain_meta, &ikm);
        ikm.zeroize();

        if let Ok(cipher) = Aes256Gcm::new_from_slice(&key) {
            key.zeroize();
            if let Ok(pt) = cipher.decrypt(nonce, ciphertext) {
                return Ok((pt, true));
            }
        } else {
            key.zeroize();
        }
    }

    Err(CryptoError::VerificationFailed(
        "Noble envelope: AES-GCM auth failed with current and all legacy keys".into(),
    ))
}

// ---------------------------------------------------------------------------
// Locked chain_meta (password-protected)
// ---------------------------------------------------------------------------

/// Wrap 32-byte chain_meta with a password using Argon2id + AES-256-GCM.
pub fn lock_chain_meta(
    chain_meta: &[u8; 32],
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use argon2::Argon2;
    use rand::RngCore;

    let mut argon2_salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut argon2_salt);

    // Derive 32-byte key from password
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), &argon2_salt, &mut key)
        .map_err(|e| format!("Argon2id key derivation failed: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES key init: {e}"))?;
    key.zeroize();

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, chain_meta.as_slice())
        .map_err(|e| format!("AES-GCM encrypt: {e}"))?;

    // Assemble: LOCKED_MAGIC || VERSION || ARGON2_SALT || NONCE || CIPHERTEXT
    let mut locked = Vec::with_capacity(LOCKED_CHAIN_META_LEN);
    locked.extend_from_slice(&LOCKED_MAGIC);
    locked.push(0x01);
    locked.extend_from_slice(&argon2_salt);
    locked.extend_from_slice(nonce.as_slice());
    locked.extend_from_slice(&ciphertext);

    Ok(locked)
}

/// Unwrap locked chain_meta with password.
pub fn unlock_chain_meta(
    locked: &[u8],
    password: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    use argon2::Argon2;

    if locked.len() < LOCKED_CHAIN_META_LEN {
        return Err(format!(
            "locked chain_meta too short: {} bytes (expected {})",
            locked.len(),
            LOCKED_CHAIN_META_LEN
        )
        .into());
    }

    if locked[..4] != LOCKED_MAGIC {
        return Err("not a locked chain_meta (bad magic)".into());
    }

    if locked[4] != 0x01 {
        return Err(format!("unsupported locked chain_meta version: {:#04x}", locked[4]).into());
    }

    let argon2_salt = &locked[5..5 + ARGON2_SALT_LEN];
    let nonce_bytes = &locked[5 + ARGON2_SALT_LEN..5 + ARGON2_SALT_LEN + NONCE_LEN];
    let ciphertext = &locked[5 + ARGON2_SALT_LEN + NONCE_LEN..];

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), argon2_salt, &mut key)
        .map_err(|e| format!("Argon2id key derivation failed: {e}"))?;

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("AES key init: {e}"))?;
    key.zeroize();

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "wrong password or corrupt locked chain_meta")?;

    let arr: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| "decrypted chain_meta is not 32 bytes")?;

    Ok(arr)
}

/// Load the per-installation `.chain_meta` entropy file (load only, never creates).
///
/// Returns an error if the file does not exist. Use `create_chain_meta()` to
/// generate a new file during first-time setup.
pub fn load_chain_meta(
    data_dir: &std::path::Path,
    encryption_mode: &str,
    password: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join(".chain_meta");
    if !path.exists() {
        return Err(
            ".chain_meta not found. Run noble-tool setup to initialize.".into(),
        );
    }

    let bytes = std::fs::read(&path)?;

    if is_locked_chain_meta(&bytes) {
        if encryption_mode == "automatic" {
            return Err(
                "chain_meta is password-locked but encryption_mode is 'automatic'. \
                 Change to 'manual' mode or delete .chain_meta to reset."
                    .into(),
            );
        }
        let pw = password.ok_or(
            "encryption_mode is 'manual' but no password provided. \
             Set NOBLE_ENCRYPTION_PASSWORD or use the unlock page.",
        )?;
        if pw.is_empty() {
            return Err("encryption password must not be empty".into());
        }
        return unlock_chain_meta(&bytes, pw);
    }

    // Raw 32-byte format
    if bytes.len() != 32 {
        return Err(format!(
            "corrupt .chain_meta: expected 32 bytes, got {}",
            bytes.len()
        )
        .into());
    }
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "corrupt .chain_meta: expected exactly 32 bytes")?;

    // Auto-migrate from raw to locked if mode changed to manual
    if encryption_mode == "manual" {
        let pw = password.ok_or("encryption_mode is 'manual' but no password provided")?;
        if pw.is_empty() {
            return Err("encryption password must not be empty".into());
        }
        let locked = lock_chain_meta(&arr, pw)?;
        write_atomic(&path, &locked)?;
    }

    Ok(arr)
}

/// Create a new per-installation `.chain_meta` entropy file (create only, never overwrites).
///
/// Returns an error if the file already exists. Use `load_chain_meta()` to load
/// an existing file.
pub fn create_chain_meta(
    data_dir: &std::path::Path,
    encryption_mode: &str,
    password: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join(".chain_meta");

    if path.exists() {
        return Err(
            ".chain_meta already exists. Use load_chain_meta() instead.".into(),
        );
    }

    use rand::RngCore;
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let to_write = if encryption_mode == "manual" {
        let pw = password.ok_or("encryption_mode is 'manual' but no password provided")?;
        if pw.is_empty() {
            return Err("encryption password must not be empty".into());
        }
        lock_chain_meta(&entropy, pw)?
    } else {
        entropy.to_vec()
    };

    write_atomic(&path, &to_write)?;
    Ok(entropy)
}

/// Delete the `.chain_meta` file. Returns Ok even if the file does not exist.
pub fn destroy_chain_meta(
    data_dir: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join(".chain_meta");
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Load or create the per-installation `.chain_meta` entropy file.
///
/// Supports two modes:
/// - `"automatic"` (default): raw 32-byte file, no password needed.
/// - `"manual"`: password-protected NBLK envelope; requires `password`.
///
/// Handles migration between modes transparently.
pub fn load_or_create_chain_meta(
    data_dir: &std::path::Path,
    encryption_mode: &str,
    password: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    load_or_create_chain_meta_with_keystore(data_dir, encryption_mode, password, None)
}

/// Same as [`load_or_create_chain_meta`] but accepts an optional keystore path.
///
/// If `.chain_meta` does not exist and `keystore_path` points to a directory
/// with existing encrypted key files, this function **refuses to create new
/// entropy** and returns an error. Creating new chain_meta when encrypted
/// keys exist would orphan the keystore (keys encrypted with the old entropy
/// become permanently undecryptable).
pub fn load_or_create_chain_meta_with_keystore(
    data_dir: &std::path::Path,
    encryption_mode: &str,
    password: Option<&str>,
    keystore_path: Option<&std::path::Path>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    // Ensure data_dir exists (tests may use ephemeral paths).
    std::fs::create_dir_all(data_dir)?;

    let path = data_dir.join(".chain_meta");

    if path.exists() {
        let bytes = std::fs::read(&path)?;

        if is_locked_chain_meta(&bytes) {
            // Locked (NBLK) format
            if encryption_mode == "automatic" {
                return Err(
                    "chain_meta is password-locked but encryption_mode is 'automatic'. \
                     Change to 'manual' mode or delete .chain_meta to reset."
                        .into(),
                );
            }
            let pw = password.ok_or(
                "encryption_mode is 'manual' but no password provided. \
                 Set NOBLE_ENCRYPTION_PASSWORD or use the unlock page.",
            )?;
            if pw.is_empty() {
                return Err("encryption password must not be empty".into());
            }
            return unlock_chain_meta(&bytes, pw);
        }

        // Raw 32-byte format
        if bytes.len() != 32 {
            return Err(format!(
                "corrupt .chain_meta: expected 32 bytes, got {}",
                bytes.len()
            )
            .into());
        }
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "corrupt .chain_meta: expected exactly 32 bytes")?;

        // Auto-migrate from raw to locked if mode changed to manual
        if encryption_mode == "manual" {
            let pw = password.ok_or("encryption_mode is 'manual' but no password provided")?;
            if pw.is_empty() {
                return Err("encryption password must not be empty".into());
            }
            let locked = lock_chain_meta(&arr, pw)?;
            write_atomic(&path, &locked)?;
        }

        Ok(arr)
    } else {
        // SAFETY CHECK: refuse to create new chain_meta if an existing
        // keystore has encrypted key files. New random entropy would orphan
        // all keys encrypted with the old chain_meta.
        if let Some(ks_path) = keystore_path {
            if ks_path.is_dir() {
                let has_keys = std::fs::read_dir(ks_path)
                    .map(|entries| entries.filter_map(|e| e.ok()).any(|e| {
                        e.path().extension().map(|ext| ext == "json").unwrap_or(false)
                    }))
                    .unwrap_or(false);
                if has_keys {
                    return Err(
                        "FATAL: .chain_meta is missing but keystore contains encrypted keys. \
                         Creating new entropy would orphan all existing keys. \
                         Either restore the original .chain_meta file from backup, \
                         or delete the keystore directory and re-import your mnemonic."
                            .into(),
                    );
                }
            }
        }

        // Generate new chain_meta
        use rand::RngCore;
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);

        let to_write = if encryption_mode == "manual" {
            let pw = password.ok_or("encryption_mode is 'manual' but no password provided")?;
            if pw.is_empty() {
                return Err("encryption password must not be empty".into());
            }
            lock_chain_meta(&salt, pw)?
        } else {
            salt.to_vec()
        };

        write_atomic(&path, &to_write)?;
        Ok(salt)
    }
}

/// Check the status of the `.chain_meta` file in a data directory.
///
/// Returns `(exists, is_locked)`:
/// - `(false, false)` — no `.chain_meta` file found
/// - `(true, false)` — raw 32-byte automatic mode
/// - `(true, true)` — password-protected NBLK format (manual mode)
pub fn chain_meta_status(data_dir: &std::path::Path) -> (bool, bool) {
    let path = data_dir.join(".chain_meta");
    match std::fs::read(&path) {
        Ok(bytes) => (true, is_locked_chain_meta(&bytes)),
        Err(_) => (false, false),
    }
}

/// Switch the on-disk encryption mode of `.chain_meta`.
///
/// The in-memory `chain_meta` (32-byte entropy) never changes — only the
/// on-disk format is converted between raw bytes (automatic) and
/// password-locked NBLK envelope (manual).
///
/// - `automatic → manual`: requires `new_password`
/// - `manual → automatic`: requires `current_password` (verified against file)
/// - Same mode → no-op Ok
pub fn switch_encryption_mode(
    data_dir: &std::path::Path,
    chain_meta: &[u8; 32],
    new_mode: &str,
    current_password: Option<&str>,
    new_password: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = data_dir.join(".chain_meta");
    if !path.exists() {
        return Err("no .chain_meta file found in data directory".into());
    }

    let file_bytes = std::fs::read(&path)?;
    let currently_locked = is_locked_chain_meta(&file_bytes);
    let current_mode = if currently_locked { "manual" } else { "automatic" };

    // Same mode → no-op
    if current_mode == new_mode {
        return Ok(());
    }

    match new_mode {
        "manual" => {
            // automatic → manual: lock with new_password
            let pw = new_password.ok_or("new_password is required when switching to manual mode")?;
            if pw.is_empty() {
                return Err("new_password must not be empty".into());
            }
            let locked = lock_chain_meta(chain_meta, pw)?;
            write_atomic(&path, &locked)?;
        }
        "automatic" => {
            // manual → automatic: verify current_password, write raw bytes
            let pw = current_password
                .ok_or("current_password is required when switching from manual mode")?;
            let unlocked = unlock_chain_meta(&file_bytes, pw)?;
            // Verify the unlocked chain_meta matches the in-memory value
            if unlocked != *chain_meta {
                return Err("unlocked chain_meta does not match in-memory chain_meta".into());
            }
            write_atomic(&path, chain_meta)?;
        }
        _ => {
            return Err(format!("invalid encryption mode: '{new_mode}' (expected 'automatic' or 'manual')").into());
        }
    }

    Ok(())
}

/// Atomic write helper: write to .tmp, set permissions, rename.
fn write_atomic(
    path: &std::path::Path,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            &tmp_path,
            std::fs::Permissions::from_mode(0o600),
        );
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_chain_meta() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn derive_wallet_key_deterministic_and_distinct() {
        let meta = test_chain_meta();
        let k1 = derive_wallet_key(&meta);
        let k2 = derive_wallet_key(&meta);
        assert_eq!(k1, k2, "same chain_meta must produce same wallet key");

        // Wallet key must differ from file-encryption key (domain separation)
        let file_key = derive_file_key(&meta);
        assert_ne!(k1, file_key, "wallet key must differ from file key");

        // Different chain_meta produces different wallet key
        let other_meta = [0x99u8; 32];
        let k3 = derive_wallet_key(&other_meta);
        assert_ne!(k1, k3, "different chain_meta must produce different wallet key");

        // hex-encoded length is 64 chars (well above 12-char minimum)
        assert_eq!(hex::encode(k1).len(), 64);
    }

    #[test]
    fn obfuscation_recovers_correct_ikm() {
        let ikm = deobfuscate_ikm();
        assert_eq!(&ikm, b"noble-at-rest-v1-2026");
    }

    #[test]
    fn roundtrip_encrypt_decrypt() {
        let meta = test_chain_meta();
        let plaintext = b"secret validator key material";
        let envelope = encrypt_file_data(plaintext, &meta).unwrap();

        assert!(is_noble_envelope(&envelope));
        assert_eq!(&envelope[..4], b"NBLE");
        assert_eq!(envelope[4], 0x01);

        let decrypted = decrypt_file_data(&envelope, &meta).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn roundtrip_empty_plaintext() {
        let meta = test_chain_meta();
        let envelope = encrypt_file_data(b"", &meta).unwrap();
        let decrypted = decrypt_file_data(&envelope, &meta).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn different_chain_meta_fails_decrypt() {
        let meta1 = [0x01u8; 32];
        let meta2 = [0x02u8; 32];
        let envelope = encrypt_file_data(b"data", &meta1).unwrap();

        let result = decrypt_file_data(&envelope, &meta2);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let meta = test_chain_meta();
        let mut envelope = encrypt_file_data(b"data", &meta).unwrap();
        // Flip a byte in the ciphertext region
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;

        let result = decrypt_file_data(&envelope, &meta);
        assert!(result.is_err());
    }

    #[test]
    fn not_noble_envelope_detection() {
        assert!(!is_noble_envelope(b""));
        assert!(!is_noble_envelope(b"NB"));
        assert!(!is_noble_envelope(b"-----BEGIN PRIVATE KEY-----"));
        assert!(!is_noble_envelope(&[0x01; 33])); // raw validator key
    }

    #[test]
    fn too_short_envelope_rejected() {
        let meta = test_chain_meta();
        let short = b"NBLE\x01short";
        let result = decrypt_file_data(short, &meta);
        assert!(result.is_err());
    }

    #[test]
    fn bad_version_rejected() {
        let meta = test_chain_meta();
        let mut envelope = encrypt_file_data(b"data", &meta).unwrap();
        envelope[4] = 0xFF; // bad version
        let result = decrypt_file_data(&envelope, &meta);
        assert!(result.is_err());
    }

    #[test]
    fn chain_meta_roundtrip_via_tempdir() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_chain_meta_{}",
            std::process::id()
        ));
        let _ = std::fs::create_dir_all(&dir);

        let meta1 = load_or_create_chain_meta(&dir, "automatic", None).unwrap();
        assert_eq!(meta1.len(), 32);

        // Second call returns the same bytes
        let meta2 = load_or_create_chain_meta(&dir, "automatic", None).unwrap();
        assert_eq!(meta1, meta2);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_encryption_uses_unique_nonce() {
        let meta = test_chain_meta();
        let e1 = encrypt_file_data(b"same", &meta).unwrap();
        let e2 = encrypt_file_data(b"same", &meta).unwrap();
        // Nonce region: bytes 5..17
        assert_ne!(&e1[5..17], &e2[5..17]);
        // Both decrypt correctly
        assert_eq!(decrypt_file_data(&e1, &meta).unwrap(), b"same");
        assert_eq!(decrypt_file_data(&e2, &meta).unwrap(), b"same");
    }

    // --- Locked chain_meta tests ---

    #[test]
    fn lock_unlock_chain_meta_roundtrip() {
        let meta = [0xAAu8; 32];
        let locked = lock_chain_meta(&meta, "test-password").unwrap();

        assert!(is_locked_chain_meta(&locked));
        assert_eq!(locked.len(), LOCKED_CHAIN_META_LEN);
        assert_eq!(&locked[..4], b"NBLK");

        let unlocked = unlock_chain_meta(&locked, "test-password").unwrap();
        assert_eq!(unlocked, meta);
    }

    #[test]
    fn lock_wrong_password_fails() {
        let meta = [0xBBu8; 32];
        let locked = lock_chain_meta(&meta, "correct").unwrap();
        let result = unlock_chain_meta(&locked, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn locked_chain_meta_detection() {
        assert!(!is_locked_chain_meta(b""));
        assert!(!is_locked_chain_meta(b"NBLE"));
        assert!(is_locked_chain_meta(b"NBLK\x01"));
    }

    #[test]
    fn chain_meta_manual_mode_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_manual_meta_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // Create in manual mode
        let meta1 = load_or_create_chain_meta(&dir, "manual", Some("pw123")).unwrap();
        assert_eq!(meta1.len(), 32);

        // File should be locked
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert!(is_locked_chain_meta(&file_data));

        // Read back in manual mode
        let meta2 = load_or_create_chain_meta(&dir, "manual", Some("pw123")).unwrap();
        assert_eq!(meta1, meta2);

        // Wrong password fails
        let bad = load_or_create_chain_meta(&dir, "manual", Some("wrong"));
        assert!(bad.is_err());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_meta_auto_to_manual_migration() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_migrate_meta_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // Create in automatic mode (raw 32 bytes)
        let meta1 = load_or_create_chain_meta(&dir, "automatic", None).unwrap();
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert_eq!(file_data.len(), 32, "automatic mode should be raw 32 bytes");

        // Switch to manual mode — should auto-migrate
        let meta2 = load_or_create_chain_meta(&dir, "manual", Some("migrate-pw")).unwrap();
        assert_eq!(meta1, meta2, "chain_meta should be the same after migration");

        // File should now be locked
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert!(is_locked_chain_meta(&file_data), "should be locked after migration");

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- IKM migration tests ---

    #[test]
    fn current_key_no_migration() {
        let meta = test_chain_meta();
        let envelope = encrypt_file_data(b"test-data", &meta).unwrap();
        let (pt, migrated) = decrypt_file_data_with_migration(&envelope, &meta).unwrap();
        assert_eq!(pt, b"test-data");
        assert!(!migrated, "current key should not trigger migration");
    }

    #[test]
    fn empty_legacy_keys_behaves_like_normal() {
        // With LEGACY_KEYS empty, migration-aware decrypt should behave like normal
        let meta = test_chain_meta();
        let envelope = encrypt_file_data(b"payload", &meta).unwrap();
        let (pt, migrated) = decrypt_file_data_with_migration(&envelope, &meta).unwrap();
        assert_eq!(pt, b"payload");
        assert!(!migrated);

        // Wrong chain_meta should still fail
        let bad_meta = [0x99u8; 32];
        let result = decrypt_file_data_with_migration(&envelope, &bad_meta);
        assert!(result.is_err());
    }

    #[test]
    fn garbage_envelope_not_recovered() {
        let meta = test_chain_meta();
        // Valid header but random ciphertext
        let mut garbage = Vec::new();
        garbage.extend_from_slice(b"NBLE\x01");
        garbage.extend_from_slice(&[0xAA; NONCE_LEN]); // fake nonce
        garbage.extend_from_slice(&[0xBB; 48]); // fake ciphertext+tag
        let result = decrypt_file_data_with_migration(&garbage, &meta);
        assert!(result.is_err());
    }

    // --- Encryption mode switch tests ---

    #[test]
    fn switch_auto_to_manual() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_switch_a2m_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Create raw chain_meta
        let meta = [0xCCu8; 32];
        std::fs::write(dir.join(".chain_meta"), &meta).unwrap();

        switch_encryption_mode(&dir, &meta, "manual", None, Some("pw123")).unwrap();

        // File should now be locked
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert!(is_locked_chain_meta(&file_data));

        // Unlock and verify same entropy
        let unlocked = unlock_chain_meta(&file_data, "pw123").unwrap();
        assert_eq!(unlocked, meta);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_manual_to_auto() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_switch_m2a_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Create locked chain_meta
        let meta = [0xDDu8; 32];
        let locked = lock_chain_meta(&meta, "secret").unwrap();
        std::fs::write(dir.join(".chain_meta"), &locked).unwrap();

        switch_encryption_mode(&dir, &meta, "automatic", Some("secret"), None).unwrap();

        // File should now be raw 32 bytes
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert_eq!(file_data.len(), 32);
        assert!(!is_locked_chain_meta(&file_data));
        assert_eq!(file_data, meta);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_manual_wrong_password() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_switch_badpw_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        let meta = [0xEEu8; 32];
        let locked = lock_chain_meta(&meta, "correct").unwrap();
        std::fs::write(dir.join(".chain_meta"), &locked).unwrap();

        let result = switch_encryption_mode(&dir, &meta, "automatic", Some("wrong"), None);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_switch_rt_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        let meta = [0x55u8; 32];
        std::fs::write(dir.join(".chain_meta"), &meta).unwrap();

        // auto → manual
        switch_encryption_mode(&dir, &meta, "manual", None, Some("roundtrip")).unwrap();
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert!(is_locked_chain_meta(&file_data));

        // manual → auto
        switch_encryption_mode(&dir, &meta, "automatic", Some("roundtrip"), None).unwrap();
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert_eq!(file_data.len(), 32);
        assert_eq!(file_data, meta);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn switch_same_mode_noop() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_switch_noop_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        let meta = [0x77u8; 32];
        std::fs::write(dir.join(".chain_meta"), &meta).unwrap();

        // auto → auto is a no-op
        switch_encryption_mode(&dir, &meta, "automatic", None, None).unwrap();
        let file_data = std::fs::read(dir.join(".chain_meta")).unwrap();
        assert_eq!(file_data.len(), 32);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chain_meta_status_checks() {
        let dir = std::env::temp_dir().join(format!(
            "noble_test_status_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);

        // Non-existent
        let (exists, locked) = chain_meta_status(&dir);
        assert!(!exists);
        assert!(!locked);

        // Raw 32 bytes
        let meta = [0x99u8; 32];
        std::fs::write(dir.join(".chain_meta"), &meta).unwrap();
        let (exists, locked) = chain_meta_status(&dir);
        assert!(exists);
        assert!(!locked);

        // Locked NBLK
        let locked_data = lock_chain_meta(&meta, "test").unwrap();
        std::fs::write(dir.join(".chain_meta"), &locked_data).unwrap();
        let (exists, locked) = chain_meta_status(&dir);
        assert!(exists);
        assert!(locked);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_key_migration_roundtrip() {
        // Simulate encrypting with a "legacy" IKM by manually constructing
        // an envelope using a different IKM, then verify that the migration
        // function can decrypt it when we temporarily populate LEGACY_KEYS.
        //
        // Since LEGACY_KEYS is a static const, we test the internal logic
        // by directly using derive_file_key_with_ikm.
        let meta = test_chain_meta();
        let legacy_ikm = b"noble-at-rest-LEGACY!";

        // Encrypt with legacy key
        let mut legacy_key = derive_file_key_with_ikm(&meta, legacy_ikm);
        let cipher = Aes256Gcm::new_from_slice(&legacy_key).unwrap();
        legacy_key.zeroize();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, b"migrated-data".as_slice()).unwrap();

        let mut envelope = Vec::new();
        envelope.extend_from_slice(&MAGIC);
        envelope.push(VERSION);
        envelope.extend_from_slice(nonce.as_slice());
        envelope.extend_from_slice(&ciphertext);

        // Current key should fail
        let result = decrypt_file_data(&envelope, &meta);
        assert!(result.is_err(), "current key should fail for legacy-encrypted data");

        // Migration-aware should also fail because LEGACY_KEYS is empty
        let result = decrypt_file_data_with_migration(&envelope, &meta);
        assert!(result.is_err(), "should fail when legacy key not in registry");
    }
}
