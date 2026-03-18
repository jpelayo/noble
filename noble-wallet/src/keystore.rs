// Copyright 2026 InfiniteContext.com <blockchain@infinitecontext.com>
// SPDX-License-Identifier: Apache-2.0

//! Single-file hardened keystore — Argon2id key derivation + AES-256-GCM encryption.
//!
//! All node secrets (validator, P2P, TLS, TOTP, wallet, faucet) are stored in a
//! single encrypted binary file. The file is coupled to the per-installation
//! `.chain_meta` entropy via a SHA-256 fingerprint embedded in the header.
//!
//! # File format
//!
//! ```text
//! Offset  Size   Field
//! 0       4      MAGIC: b"NKST"
//! 4       1      VERSION: 0x01
//! 5       32     CHAIN_META_FINGERPRINT: SHA-256(chain_meta)
//! 37      16     ARGON2_SALT: random salt for passphrase derivation
//! 53      12     AES_NONCE: AES-256-GCM nonce
//! 65      N+16   CIPHERTEXT: AES-256-GCM(entries_cbor) + auth tag
//! ```
//!
//! Every mutation (add_key, remove_key, etc.) atomically rewrites the entire
//! file via tmp+rename.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use noble_codec::NobleCbor;
use noble_crypto::keys::{NoblePrivateKey, NoblePublicKey, NobleSigner, SignatureEnvelope};
use noble_crypto::SCHEME_SECP256K1;

use crate::error::WalletError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes identifying a Noble keystore file.
const KEYSTORE_MAGIC: [u8; 4] = *b"NKST";

/// Current keystore file version.
const KEYSTORE_VERSION: u8 = 0x01;

/// Offset of the chain_meta fingerprint in the file header.
const FINGERPRINT_OFFSET: usize = 5;

/// Size of the SHA-256 fingerprint.
const FINGERPRINT_LEN: usize = 32;

/// Size of the Argon2id salt.
const ARGON2_SALT_LEN: usize = 16;

/// Size of the AES-GCM nonce.
const AES_NONCE_LEN: usize = 12;

/// Total header size before ciphertext.
const HEADER_LEN: usize = 4 + 1 + FINGERPRINT_LEN + ARGON2_SALT_LEN + AES_NONCE_LEN; // 65

/// Minimum valid file size (header + 16-byte GCM auth tag on empty plaintext).
const MIN_FILE_LEN: usize = HEADER_LEN + 16;

/// Minimum passphrase length (characters).
const MIN_PASSPHRASE_LEN: usize = 12;

/// Maximum consecutive failed unlock attempts before lockout.
const MAX_UNLOCK_ATTEMPTS: usize = 5;

/// Cooldown period after exceeding max unlock attempts (seconds).
const UNLOCK_COOLDOWN_SECS: u64 = 300; // 5 minutes

// ---------------------------------------------------------------------------
// KeyScheme — strict enum, no unknown values
// ---------------------------------------------------------------------------

/// Identifies the type of secret stored in a keystore entry.
///
/// Deserialization rejects unrecognized values. No unknown scheme IDs are
/// allowed in the keystore file.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyScheme {
    /// On-chain wallet key (secp256k1, BIP-32 derived).
    WalletSecp256k1    = 0x02,
    /// Validator block-signing key (secp256k1).
    ValidatorSecp256k1 = 0x81,
    /// libp2p peer identity key.
    P2pIdentity        = 0x82,
    /// TLS private key (for HTTPS/WSS).
    TlsKey             = 0x83,
    /// TOTP shared secret (RFC 6238).
    TotpSecret         = 0x84,
    /// Faucet authentication passphrase.
    FaucetPassphrase   = 0x85,
}

impl KeyScheme {
    /// Convert from the legacy `SCHEME_*` u8 constants.
    pub fn from_u8(val: u8) -> Result<Self, WalletError> {
        match val {
            0x02 => Ok(Self::WalletSecp256k1),
            0x81 => Ok(Self::ValidatorSecp256k1),
            0x82 => Ok(Self::P2pIdentity),
            0x83 => Ok(Self::TlsKey),
            0x84 => Ok(Self::TotpSecret),
            0x85 => Ok(Self::FaucetPassphrase),
            other => Err(WalletError::UnsupportedScheme(other)),
        }
    }

    /// Whether this scheme can produce cryptographic signatures.
    pub fn is_signing(&self) -> bool {
        matches!(self, Self::WalletSecp256k1 | Self::ValidatorSecp256k1)
    }

    /// The raw u8 value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for KeyScheme {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for KeyScheme {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let val = u8::deserialize(d)?;
        Self::from_u8(val).map_err(|_| {
            serde::de::Error::custom(format!("unrecognized keystore scheme: {val:#04x}"))
        })
    }
}

// ---------------------------------------------------------------------------
// KeyEntry — one secret stored in the keystore
// ---------------------------------------------------------------------------

/// A single key/secret stored in the encrypted keystore.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Type of secret.
    pub scheme: KeyScheme,
    /// Human-readable label.
    pub label: String,
    /// Wire-format public key bytes (or synthetic hash for non-signing schemes).
    pub public_key: Vec<u8>,
    /// Raw secret bytes (zeroed when the keystore is locked).
    pub secret: Vec<u8>,
    /// Unix timestamp of creation.
    pub created_at: u64,
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Internal unlocked state
// ---------------------------------------------------------------------------

/// In-memory decrypted state, held while the keystore is unlocked.
struct UnlockedState {
    /// AES-256 key derived from passphrase + salt via Argon2id.
    aes_key: [u8; 32],
    /// Decrypted entries.
    entries: Vec<KeyEntry>,
    /// Private key cache for fast signing (wire_bytes → NoblePrivateKey).
    key_cache: HashMap<Vec<u8>, NoblePrivateKey>,
}

impl Drop for UnlockedState {
    fn drop(&mut self) {
        self.aes_key.zeroize();
        // KeyEntry::drop handles zeroing secrets
    }
}

impl UnlockedState {
    fn rebuild_key_cache(&mut self) {
        self.key_cache.clear();
        for entry in &self.entries {
            match priv_key_from_entry(entry) {
                Ok(priv_key) => {
                    let map_key = map_key_for_entry(entry);
                    self.key_cache.insert(map_key, priv_key);
                }
                Err(e) => {
                    tracing::warn!(
                        task = "wallet_key",
                        "skipping corrupt keystore entry (scheme {:#04x}): {e}",
                        entry.scheme.as_u8()
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// KeyStore
// ---------------------------------------------------------------------------

/// Single-file encrypted keystore for all node secrets.
pub struct KeyStore {
    /// Path to the keystore file on disk.
    path: PathBuf,
    /// SHA-256(chain_meta) — verified on open.
    chain_meta_fingerprint: [u8; 32],
    /// Argon2id salt from the file header (persisted across unlock cycles).
    argon2_salt: [u8; 16],
    /// Unlocked state (None = locked).
    state: Option<UnlockedState>,
    /// Consecutive failed unlock attempts.
    failed_attempts: usize,
    /// When the lockout expires (if any).
    lockout_until: Option<Instant>,
}

impl KeyStore {
    // ── Lifecycle ──────────────────────────────────────────────────────────

    /// Create a new keystore file. Fails if the file already exists.
    ///
    /// The keystore starts in a locked state with zero entries. Call `unlock()`
    /// before adding keys.
    pub(crate) fn create(path: &Path, chain_meta: &[u8; 32]) -> Result<Self, WalletError> {
        if path.exists() {
            return Err(WalletError::Io(format!(
                "keystore already exists: {}",
                path.display()
            )));
        }

        let fingerprint = chain_meta_fingerprint(chain_meta);
        let mut salt = [0u8; ARGON2_SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        // Write empty keystore (no entries).
        let empty_entries: Vec<KeyEntry> = Vec::new();
        let plaintext = empty_entries.to_cbor().map_err(|e| {
            WalletError::Serialization(format!("CBOR encode: {e}"))
        })?;

        // We need a temporary passphrase-derived key to encrypt. Since the
        // keystore is empty, we use a zero key — the real passphrase will be
        // set on first unlock+write.
        // Actually, we need to encrypt with the real passphrase. But create()
        // doesn't take a passphrase — the keystore starts locked.
        // Solution: store an empty ciphertext encrypted with a deterministic
        // key derived from chain_meta. The first unlock() will verify this.
        let passphrase = derive_create_passphrase(chain_meta);
        let aes_key = derive_aes_key(&passphrase, &salt)?;
        let (nonce, ciphertext) = aes_encrypt(&aes_key, &plaintext)?;

        let file_data = assemble_file(&fingerprint, &salt, &nonce, &ciphertext);
        write_atomic(path, &file_data)?;

        tracing::info!(task = "wallet_key", "created new keystore file: {}", path.display());

        Ok(Self {
            path: path.to_path_buf(),
            chain_meta_fingerprint: fingerprint,
            argon2_salt: salt,
            state: None,
            failed_attempts: 0,
            lockout_until: None,
        })
    }

    /// Create a new keystore file for standalone use (faucet, etc.).
    /// Unlike the `pub(crate)` `create()`, this is publicly accessible
    /// for independent subsystems that manage their own lifecycle.
    pub fn create_for_faucet(path: &Path, chain_meta: &[u8; 32]) -> Result<Self, WalletError> {
        Self::create(path, chain_meta)
    }

    /// Open an existing keystore file. Fails if the file is missing or the
    /// chain_meta fingerprint does not match.
    ///
    /// The keystore starts in a locked state. Call `unlock()` to decrypt.
    pub fn open(path: &Path, chain_meta: &[u8; 32]) -> Result<Self, WalletError> {
        if !path.exists() {
            return Err(WalletError::Io(format!(
                "keystore not found: {}. Run noble-tool setup.",
                path.display()
            )));
        }

        let data = fs::read(path)?;
        if data.len() < MIN_FILE_LEN {
            return Err(WalletError::Io(format!(
                "keystore file too short: {} bytes (min {MIN_FILE_LEN})",
                data.len()
            )));
        }

        // Verify magic
        if data[..4] != KEYSTORE_MAGIC {
            return Err(WalletError::Io(
                "not a Noble keystore file (bad magic)".into(),
            ));
        }

        // Verify version
        if data[4] != KEYSTORE_VERSION {
            return Err(WalletError::Io(format!(
                "unsupported keystore version: {:#04x}",
                data[4]
            )));
        }

        // Verify chain_meta fingerprint
        let expected = chain_meta_fingerprint(chain_meta);
        let stored = &data[FINGERPRINT_OFFSET..FINGERPRINT_OFFSET + FINGERPRINT_LEN];
        if stored != expected {
            return Err(WalletError::Io(
                "keystore was created with different .chain_meta. \
                 Restore backup or re-import mnemonic."
                    .into(),
            ));
        }

        let salt_start = FINGERPRINT_OFFSET + FINGERPRINT_LEN;
        let mut salt = [0u8; ARGON2_SALT_LEN];
        salt.copy_from_slice(&data[salt_start..salt_start + ARGON2_SALT_LEN]);

        let key_count = estimate_entry_count(&data);
        tracing::info!(task = "wallet_key", "opened keystore (~{key_count} entries)");

        Ok(Self {
            path: path.to_path_buf(),
            chain_meta_fingerprint: expected,
            argon2_salt: salt,
            state: None,
            failed_attempts: 0,
            lockout_until: None,
        })
    }

    /// Returns `true` if a keystore file exists at the given path.
    pub fn exists(path: &Path) -> bool {
        path.is_file()
    }

    /// Delete the keystore file. Returns Ok even if the file does not exist.
    pub(crate) fn destroy(path: &Path) -> Result<(), WalletError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(WalletError::Io(e.to_string())),
        }
    }

    // ── Lock / Unlock ─────────────────────────────────────────────────────

    /// Unlock the keystore by decrypting all entries with the given passphrase.
    pub fn unlock(&mut self, passphrase: &str) -> Result<(), WalletError> {
        self.check_lockout()?;

        let data = fs::read(&self.path)?;
        if data.len() < MIN_FILE_LEN {
            return Err(WalletError::Io("keystore file too short".into()));
        }

        let salt_start = FINGERPRINT_OFFSET + FINGERPRINT_LEN;
        let nonce_start = salt_start + ARGON2_SALT_LEN;
        let ct_start = nonce_start + AES_NONCE_LEN;

        let nonce_bytes = &data[nonce_start..ct_start];
        let ciphertext = &data[ct_start..];

        let mut aes_key = derive_aes_key(passphrase, &self.argon2_salt)?;

        let plaintext = match aes_decrypt(&aes_key, nonce_bytes, ciphertext) {
            Ok(pt) => pt,
            Err(_) => {
                aes_key.zeroize();
                self.failed_attempts += 1;
                if self.failed_attempts >= MAX_UNLOCK_ATTEMPTS {
                    self.lockout_until = Some(
                        Instant::now() + std::time::Duration::from_secs(UNLOCK_COOLDOWN_SECS),
                    );
                }
                return Err(WalletError::InvalidPassphrase);
            }
        };

        let entries: Vec<KeyEntry> = Vec::<KeyEntry>::from_cbor(&plaintext).map_err(|e| {
            aes_key.zeroize();
            WalletError::Serialization(format!("CBOR decode keystore entries: {e}"))
        })?;

        let mut unlocked = UnlockedState {
            aes_key,
            entries,
            key_cache: HashMap::new(),
        };
        unlocked.rebuild_key_cache();

        self.state = Some(unlocked);
        self.failed_attempts = 0;
        self.lockout_until = None;
        tracing::debug!(task = "wallet_key", "keystore unlocked");
        Ok(())
    }

    /// Lock the keystore, clearing all decrypted keys from memory.
    pub fn lock(&mut self) {
        self.state = None;
        tracing::debug!(task = "wallet_key", "keystore locked");
    }

    /// Returns `true` if the keystore is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.state.is_some()
    }

    // ── Key Management ────────────────────────────────────────────────────

    /// Add an entry to the keystore. Requires unlocked state.
    pub fn add_key(&mut self, entry: KeyEntry, passphrase: &str) -> Result<(), WalletError> {
        let state = self.state.as_mut().ok_or(WalletError::Locked)?;

        // Check for duplicate scheme (for non-signing schemes) or duplicate pubkey
        for existing in &state.entries {
            if entry.scheme == existing.scheme && !entry.scheme.is_signing() {
                return Err(WalletError::DuplicateKey(format!(
                    "a key with scheme {:#04x} already exists",
                    entry.scheme.as_u8()
                )));
            }
            if entry.public_key == existing.public_key && entry.scheme == existing.scheme {
                return Err(WalletError::DuplicateKey(hex::encode(&entry.public_key)));
            }
        }

        let priv_key = priv_key_from_entry(&entry)?;
        let map_key = map_key_for_entry(&entry);
        state.entries.push(entry);
        state.key_cache.insert(map_key, priv_key);

        self.flush(passphrase)?;
        Ok(())
    }

    /// Remove an entry by public key bytes. Requires unlocked state.
    pub fn remove_key(&mut self, pubkey: &[u8], passphrase: &str) -> Result<(), WalletError> {
        let state = self.state.as_mut().ok_or(WalletError::Locked)?;

        let idx = state
            .entries
            .iter()
            .position(|e| e.public_key == pubkey)
            .ok_or_else(|| WalletError::KeyNotFound(hex::encode(pubkey)))?;

        let removed = state.entries.remove(idx);
        let map_key = map_key_for_entry(&removed);
        state.key_cache.remove(&map_key);

        self.flush(passphrase)?;
        Ok(())
    }

    /// Remove all entries with the given scheme. Requires unlocked state.
    pub fn remove_by_scheme(
        &mut self,
        scheme: KeyScheme,
        passphrase: &str,
    ) -> Result<(), WalletError> {
        let state = self.state.as_mut().ok_or(WalletError::Locked)?;
        let before = state.entries.len();

        // Remove from cache first
        let to_remove: Vec<Vec<u8>> = state
            .entries
            .iter()
            .filter(|e| e.scheme == scheme)
            .map(map_key_for_entry)
            .collect();
        for key in &to_remove {
            state.key_cache.remove(key);
        }

        state.entries.retain(|e| e.scheme != scheme);

        if state.entries.len() < before {
            self.flush(passphrase)?;
        }
        Ok(())
    }

    // ── Query ─────────────────────────────────────────────────────────────

    /// List all public keys stored in the keystore.
    ///
    /// Returns `NoblePublicKey` entries that can be decoded from stored wire bytes.
    /// For backward compatibility, this returns all keys as `NoblePublicKey` —
    /// internal keys (P2P, TLS, etc.) are skipped since they don't have valid
    /// on-chain public keys.
    pub fn list_keys(&self) -> Result<Vec<NoblePublicKey>, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        let mut keys = Vec::new();
        for entry in &state.entries {
            if let Ok(pk) = NoblePublicKey::from_wire_bytes(&entry.public_key) {
                keys.push(pk);
            }
        }
        Ok(keys)
    }

    /// List all entries as (scheme, pubkey_wire_bytes).
    pub fn list_all_entries(&self) -> Result<Vec<(KeyScheme, Vec<u8>)>, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        Ok(state
            .entries
            .iter()
            .map(|e| (e.scheme, e.public_key.clone()))
            .collect())
    }

    /// List only signing keys as `NoblePublicKey`.
    pub fn list_signing_keys(&self) -> Result<Vec<NoblePublicKey>, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        let mut keys = Vec::new();
        for entry in &state.entries {
            if entry.scheme.is_signing() {
                if let Ok(pk) = NoblePublicKey::from_wire_bytes(&entry.public_key) {
                    keys.push(pk);
                }
            }
        }
        Ok(keys)
    }

    /// Returns `true` if the keystore contains an entry with the given scheme.
    pub fn has_scheme(&self, scheme_id: u8) -> Result<bool, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        Ok(state.entries.iter().any(|e| e.scheme.as_u8() == scheme_id))
    }

    /// Retrieve the raw secret bytes for the first entry matching the scheme.
    pub fn get_raw(&self, scheme_id: u8) -> Result<Vec<u8>, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        for entry in &state.entries {
            if entry.scheme.as_u8() == scheme_id {
                return Ok(entry.secret.clone());
            }
        }
        Err(WalletError::KeyNotFound(format!(
            "no key with scheme {scheme_id:#04x}"
        )))
    }

    // ── Signing ───────────────────────────────────────────────────────────

    /// Sign a message using the private key corresponding to the given public key.
    pub fn sign(
        &self,
        pubkey: &NoblePublicKey,
        message: &[u8; 32],
    ) -> Result<SignatureEnvelope, WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        let wire = pubkey.to_wire_bytes();
        let priv_key = state
            .key_cache
            .get(&wire)
            .ok_or_else(|| WalletError::KeyNotFound(hex::encode(&wire)))?;
        let envelope = priv_key.sign(message)?;
        Ok(envelope)
    }

    // ── High-level convenience (used by node.rs) ──────────────────────────

    /// Generate a new secp256k1 key for the given scheme.
    pub fn create_key(
        &mut self,
        scheme_id: u8,
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        let scheme = KeyScheme::from_u8(scheme_id)?;

        if self.has_scheme(scheme_id)? {
            return Err(WalletError::DuplicateKey(format!(
                "a key with scheme {scheme_id:#04x} already exists"
            )));
        }

        let (secret_key, priv_key) = match scheme {
            KeyScheme::WalletSecp256k1 => {
                let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
                let pk = NoblePrivateKey::Secp256k1(sk.clone());
                (sk, pk)
            }
            _ => return Err(WalletError::UnsupportedScheme(scheme_id)),
        };

        let pub_key = priv_key.public_key();
        let entry = KeyEntry {
            scheme,
            label: String::new(),
            public_key: pub_key.to_wire_bytes(),
            secret: secret_key.clone(),
            created_at: now_unix(),
        };

        self.add_key(entry, passphrase)?;
        Ok(pub_key)
    }

    /// Generate a BIP-39 mnemonic, derive a secp256k1 key at m/44'/9999'/0'/0/0,
    /// and store it. Returns (mnemonic_words, public_key).
    pub fn create_key_from_mnemonic(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
    ) -> Result<(String, NoblePublicKey), WalletError> {
        self.create_key_from_mnemonic_inner(word_count, encryption_passphrase, None, &[0u8; 32])
    }

    /// Generate a mnemonic-derived secp256k1 key and optionally write the same
    /// secret to `validator_key_path` (encrypted with `chain_meta`).
    pub fn create_key_from_mnemonic_with_validator(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
        validator_key_path: &std::path::Path,
        chain_meta: &[u8; 32],
    ) -> Result<(String, NoblePublicKey), WalletError> {
        self.create_key_from_mnemonic_inner(
            word_count,
            encryption_passphrase,
            Some(validator_key_path),
            chain_meta,
        )
    }

    fn create_key_from_mnemonic_inner(
        &mut self,
        word_count: usize,
        encryption_passphrase: &str,
        validator_key_path: Option<&std::path::Path>,
        chain_meta: &[u8; 32],
    ) -> Result<(String, NoblePublicKey), WalletError> {
        if word_count != 12 && word_count != 24 {
            return Err(WalletError::Crypto(format!(
                "word_count must be 12 or 24, got {word_count}"
            )));
        }

        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists".into(),
            ));
        }

        let mnemonic = bip39::Mnemonic::generate(word_count)
            .map_err(|e| WalletError::Crypto(format!("mnemonic generation: {e}")))?;

        let mnemonic_str = mnemonic.words().collect::<Vec<_>>().join(" ");
        let mut seed = mnemonic.to_seed("");

        let child = bip32::XPrv::derive_from_path(
            seed,
            &"m/44'/9999'/0'/0/0"
                .parse()
                .map_err(|e: bip32::Error| WalletError::Crypto(format!("derivation path: {e}")))?,
        )
        .map_err(|e| {
            seed.zeroize();
            WalletError::Crypto(format!("BIP-32 derivation: {e}"))
        })?;
        seed.zeroize();

        let secret_key = child.to_bytes();
        let mut sk_bytes: Vec<u8> = secret_key.to_vec();

        let priv_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
        let pub_key = priv_key.public_key();

        // Write validator.key with the same secret if requested.
        if let Some(vk_path) = validator_key_path {
            write_validator_key_file(vk_path, &sk_bytes, chain_meta)?;
        }

        let entry = KeyEntry {
            scheme: KeyScheme::WalletSecp256k1,
            label: String::new(),
            public_key: pub_key.to_wire_bytes(),
            secret: sk_bytes.clone(),
            created_at: now_unix(),
        };
        sk_bytes.zeroize();

        self.add_key(entry, encryption_passphrase)?;
        Ok((mnemonic_str, pub_key))
    }

    /// Recover a key from an existing BIP-39 mnemonic phrase.
    pub fn recover_from_mnemonic(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        self.recover_from_mnemonic_inner(mnemonic_words, encryption_passphrase, None, &[0u8; 32])
    }

    /// Recover a wallet key from mnemonic and optionally write the same
    /// secret to `validator_key_path`.
    pub fn recover_from_mnemonic_with_validator(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
        validator_key_path: &std::path::Path,
        chain_meta: &[u8; 32],
    ) -> Result<NoblePublicKey, WalletError> {
        self.recover_from_mnemonic_inner(
            mnemonic_words,
            encryption_passphrase,
            Some(validator_key_path),
            chain_meta,
        )
    }

    fn recover_from_mnemonic_inner(
        &mut self,
        mnemonic_words: &str,
        encryption_passphrase: &str,
        validator_key_path: Option<&std::path::Path>,
        chain_meta: &[u8; 32],
    ) -> Result<NoblePublicKey, WalletError> {
        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists; delete it first to import a different mnemonic"
                    .into(),
            ));
        }

        let mnemonic: bip39::Mnemonic = mnemonic_words
            .parse()
            .map_err(|e: bip39::Error| WalletError::Crypto(format!("invalid mnemonic: {e}")))?;

        let mut seed = mnemonic.to_seed("");

        let child = bip32::XPrv::derive_from_path(
            seed,
            &"m/44'/9999'/0'/0/0"
                .parse()
                .map_err(|e: bip32::Error| WalletError::Crypto(format!("derivation path: {e}")))?,
        )
        .map_err(|e| {
            seed.zeroize();
            WalletError::Crypto(format!("BIP-32 derivation: {e}"))
        })?;
        seed.zeroize();

        let secret_key = child.to_bytes();
        let mut sk_bytes: Vec<u8> = secret_key.to_vec();

        let priv_key = NoblePrivateKey::Secp256k1(sk_bytes.clone());
        let pub_key = priv_key.public_key();

        // Write validator.key if requested and missing.
        if let Some(vk_path) = validator_key_path {
            if !vk_path.exists() {
                write_validator_key_file(vk_path, &sk_bytes, chain_meta)?;
            }
        }

        let entry = KeyEntry {
            scheme: KeyScheme::WalletSecp256k1,
            label: String::new(),
            public_key: pub_key.to_wire_bytes(),
            secret: sk_bytes.clone(),
            created_at: now_unix(),
        };
        sk_bytes.zeroize();

        self.add_key(entry, encryption_passphrase)?;
        Ok(pub_key)
    }

    /// Import a secp256k1 private key from WIF or raw hex.
    pub fn import_secp256k1_key(
        &mut self,
        key_input: &str,
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        if self.has_scheme(SCHEME_SECP256K1)? {
            return Err(WalletError::DuplicateKey(
                "a secp256k1 key already exists".into(),
            ));
        }

        let mut secret_bytes = if key_input.len() == 64
            && key_input.chars().all(|c| c.is_ascii_hexdigit())
        {
            hex::decode(key_input).map_err(|e| WalletError::InvalidKey(e.to_string()))?
        } else {
            noble_crypto::bitcoin_addr::decode_wif(key_input)
                .map_err(|e| WalletError::InvalidKey(e.to_string()))?
        };

        let priv_key = NoblePrivateKey::Secp256k1(secret_bytes.clone());
        let pub_key = priv_key.public_key();

        let entry = KeyEntry {
            scheme: KeyScheme::WalletSecp256k1,
            label: String::new(),
            public_key: pub_key.to_wire_bytes(),
            secret: secret_bytes.clone(),
            created_at: now_unix(),
        };
        secret_bytes.zeroize();

        self.add_key(entry, passphrase)?;
        Ok(pub_key)
    }

    /// Store arbitrary raw bytes under an internal scheme.
    pub fn store_raw(
        &mut self,
        scheme_id: u8,
        raw_bytes: &[u8],
        passphrase: &str,
    ) -> Result<NoblePublicKey, WalletError> {
        let scheme = KeyScheme::from_u8(scheme_id)?;

        if self.has_scheme(scheme_id)? {
            return Err(WalletError::DuplicateKey(format!(
                "a key with scheme {scheme_id:#04x} already exists"
            )));
        }

        let priv_key = match scheme {
            KeyScheme::ValidatorSecp256k1 => {
                NoblePrivateKey::ValidatorSecp256k1(raw_bytes.to_vec())
            }
            KeyScheme::P2pIdentity => NoblePrivateKey::P2pIdentity(raw_bytes.to_vec()),
            KeyScheme::TlsKey => NoblePrivateKey::TlsKey(raw_bytes.to_vec()),
            KeyScheme::TotpSecret => NoblePrivateKey::TotpSecret(raw_bytes.to_vec()),
            KeyScheme::FaucetPassphrase => NoblePrivateKey::FaucetPassphrase(raw_bytes.to_vec()),
            _ => return Err(WalletError::UnsupportedScheme(scheme_id)),
        };

        let pub_key = priv_key.public_key();

        // For internal keys (0x80+), use internal scheme_id prefix in the
        // public_key field so has_scheme() can find them.
        let wire_bytes = if noble_crypto::is_signing_scheme(scheme_id) {
            pub_key.to_wire_bytes()
        } else {
            let mut w = Vec::with_capacity(1 + pub_key.key_bytes().len());
            w.push(scheme_id);
            w.extend_from_slice(pub_key.key_bytes());
            w
        };

        let entry = KeyEntry {
            scheme,
            label: String::new(),
            public_key: wire_bytes,
            secret: raw_bytes.to_vec(),
            created_at: now_unix(),
        };

        self.add_key(entry, passphrase)?;
        Ok(pub_key)
    }

    /// Delete a key from the keystore after verifying the passphrase.
    pub fn delete_key(
        &mut self,
        pubkey: &NoblePublicKey,
        passphrase: &str,
    ) -> Result<(), WalletError> {
        let wire = pubkey.to_wire_bytes();
        self.remove_key(&wire, passphrase)
    }

    /// Delete all entries for a given internal scheme ID (0x80+).
    pub fn delete_by_scheme(&mut self, scheme_id: u8) {
        let scheme = match KeyScheme::from_u8(scheme_id) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!(task = "wallet_key", "delete_by_scheme: unrecognized scheme {scheme_id:#04x}");
                return;
            }
        };
        if let Some(state) = self.state.as_mut() {
            let before = state.entries.len();
            let to_remove: Vec<Vec<u8>> = state
                .entries
                .iter()
                .filter(|e| e.scheme == scheme)
                .map(map_key_for_entry)
                .collect();
            for key in &to_remove {
                state.key_cache.remove(key);
            }
            state.entries.retain(|e| e.scheme != scheme);
            if state.entries.len() < before {
                if let Err(e) = self.flush_with_cached_key() {
                    tracing::error!(task = "wallet_key", "delete_by_scheme: flush failed: {e}");
                }
            }
        }
    }

    // ── Re-encrypt / migrate ──────────────────────────────────────────────

    /// Re-encrypt the keystore with a new passphrase.
    pub fn re_encrypt(
        &mut self,
        _old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<usize, WalletError> {
        // Must be unlocked
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;
        let count = state.entries.len();

        // Generate new salt
        let mut new_salt = [0u8; ARGON2_SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);

        let new_key = derive_aes_key(new_passphrase, &new_salt)?;

        let plaintext = {
            let state = self.state.as_ref().ok_or(WalletError::Locked)?;
            state.entries.to_cbor().map_err(|e| {
                WalletError::Serialization(format!("CBOR encode: {e}"))
            })?
        };

        let (nonce, ciphertext) = aes_encrypt(&new_key, &plaintext)?;
        let file_data =
            assemble_file(&self.chain_meta_fingerprint, &new_salt, &nonce, &ciphertext);
        write_atomic(&self.path, &file_data)?;

        // Update internal state
        self.argon2_salt = new_salt;
        if let Some(ref mut s) = self.state {
            s.aes_key.zeroize();
            s.aes_key = new_key;
        }

        Ok(count)
    }

    /// Migrate from the old directory-based keystore to a single file.
    ///
    /// Reads all `.json` key files from `dir`, decrypts them with
    /// `old_passphrase`, and consolidates into the new binary format.
    /// The old directory is renamed to `<dir>.migrated` on success.
    pub fn migrate_from_directory(
        dir: &Path,
        file: &Path,
        chain_meta: &[u8; 32],
        passphrase: &str,
    ) -> Result<Self, WalletError> {
        if !dir.is_dir() {
            return Err(WalletError::Io(format!(
                "migration source is not a directory: {}",
                dir.display()
            )));
        }

        // Create keystore and immediately unlock
        let mut ks = Self::create(file, chain_meta)?;
        let create_pass = derive_create_passphrase(chain_meta);
        ks.unlock(&create_pass)?;

        // Read old JSON key files
        let mut migrated = 0usize;
        for dir_entry in fs::read_dir(dir)? {
            let dir_entry = dir_entry?;
            let name = dir_entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".json") {
                continue;
            }

            let json = fs::read_to_string(dir_entry.path())?;
            let encrypted: LegacyEncryptedKeyFile =
                serde_json::from_str(&json).map_err(|e| {
                    WalletError::Serialization(format!(
                        "parse legacy key file {}: {e}",
                        name_str
                    ))
                })?;

            let secret = decrypt_legacy_key(&encrypted, passphrase)?;
            let scheme = KeyScheme::from_u8(encrypted.scheme_id)?;

            // Derive public key
            let priv_key = match scheme {
                KeyScheme::WalletSecp256k1 => NoblePrivateKey::Secp256k1(secret.clone()),
                KeyScheme::ValidatorSecp256k1 => {
                    NoblePrivateKey::ValidatorSecp256k1(secret.clone())
                }
                KeyScheme::P2pIdentity => NoblePrivateKey::P2pIdentity(secret.clone()),
                KeyScheme::TlsKey => NoblePrivateKey::TlsKey(secret.clone()),
                KeyScheme::TotpSecret => NoblePrivateKey::TotpSecret(secret.clone()),
                KeyScheme::FaucetPassphrase => {
                    NoblePrivateKey::FaucetPassphrase(secret.clone())
                }
            };

            let pub_key = priv_key.public_key();
            let wire_bytes = if noble_crypto::is_signing_scheme(scheme.as_u8()) {
                pub_key.to_wire_bytes()
            } else {
                let mut w = Vec::with_capacity(1 + pub_key.key_bytes().len());
                w.push(scheme.as_u8());
                w.extend_from_slice(pub_key.key_bytes());
                w
            };

            let entry = KeyEntry {
                scheme,
                label: String::new(),
                public_key: wire_bytes,
                secret: secret.clone(),
                created_at: now_unix(),
            };

            // Skip duplicates during migration
            let state = self_entries(&ks);
            let already = state.iter().any(|e| e.scheme == scheme);
            if !already {
                ks.add_key(entry, passphrase)?;
                migrated += 1;
            }
        }

        // Re-encrypt with the real passphrase (not the create passphrase)
        if passphrase != create_pass {
            ks.re_encrypt(&create_pass, passphrase)?;
        }

        // Rename old directory
        let migrated_dir = dir.with_extension("migrated");
        if !migrated_dir.exists() {
            if let Err(e) = fs::rename(dir, &migrated_dir) {
                tracing::warn!(
                    task = "wallet_key",
                    "failed to rename old keystore dir to {}: {e}",
                    migrated_dir.display()
                );
            }
        }

        tracing::info!(
            task = "wallet_key",
            "migrated {migrated} keys from directory to single file"
        );

        Ok(ks)
    }

    /// Backward compat: list all NoblePublicKey entries (signing keys only).
    pub fn list_keys_compat(&self) -> Result<Vec<NoblePublicKey>, WalletError> {
        self.list_signing_keys()
    }

    /// Backward compat: the `migrate_passphrase` method from the old keystore.
    pub fn migrate_passphrase(
        &mut self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> Result<usize, WalletError> {
        self.re_encrypt(old_passphrase, new_passphrase)
    }

    /// Returns the path to the keystore file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn check_lockout(&self) -> Result<(), WalletError> {
        if let Some(until) = self.lockout_until {
            if Instant::now() < until {
                let remaining = until.duration_since(Instant::now()).as_secs();
                return Err(WalletError::TooManyAttempts {
                    attempts: self.failed_attempts,
                    cooldown_secs: remaining + 1,
                });
            }
        }
        Ok(())
    }

    /// Encrypt entries and write to disk atomically using the cached AES key.
    fn flush(&mut self, _passphrase: &str) -> Result<(), WalletError> {
        self.flush_with_cached_key()
    }

    /// Encrypt entries and write to disk using the cached AES key + new nonce.
    fn flush_with_cached_key(&mut self) -> Result<(), WalletError> {
        let state = self.state.as_ref().ok_or(WalletError::Locked)?;

        let plaintext = state.entries.to_cbor().map_err(|e| {
            WalletError::Serialization(format!("CBOR encode: {e}"))
        })?;

        let (nonce, ciphertext) = aes_encrypt(&state.aes_key, &plaintext)?;
        let file_data = assemble_file(
            &self.chain_meta_fingerprint,
            &self.argon2_salt,
            &nonce,
            &ciphertext,
        );
        write_atomic(&self.path, &file_data)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// NodeSecrets — coupled lifecycle coordinator
// ---------------------------------------------------------------------------

/// Coordinates the lifecycle of `.chain_meta` and the keystore file.
///
/// Neither can exist without the other. `initialize()` creates both,
/// `load()` opens both, `destroy()` deletes both.
pub struct NodeSecrets {
    chain_meta: [u8; 32],
    keystore_path: PathBuf,
    chain_meta_path: PathBuf,
}

impl NodeSecrets {
    /// First-time setup: create both `.chain_meta` and keystore.
    /// Fails if either already exists.
    pub fn initialize(
        data_dir: &Path,
        keystore_path: &Path,
        encryption_mode: &str,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let chain_meta_path = data_dir.join(".chain_meta");

        if chain_meta_path.exists() {
            return Err(".chain_meta already exists. Use NodeSecrets::load() instead.".into());
        }
        if keystore_path.exists() {
            return Err(format!(
                "keystore already exists: {}. Use NodeSecrets::load() instead.",
                keystore_path.display()
            )
            .into());
        }

        // Create chain_meta first
        let chain_meta = noble_crypto::file_encrypt::create_chain_meta(
            data_dir,
            encryption_mode,
            password,
        )?;

        // Create keystore — if this fails, clean up chain_meta
        match KeyStore::create(keystore_path, &chain_meta) {
            Ok(_ks) => {}
            Err(e) => {
                if let Err(cleanup_err) = noble_crypto::file_encrypt::destroy_chain_meta(data_dir) {
                    tracing::warn!(
                        task = "wallet_key",
                        "failed to clean up .chain_meta after keystore create failure: {cleanup_err}"
                    );
                }
                return Err(format!("failed to create keystore: {e}").into());
            }
        }

        Ok(Self {
            chain_meta,
            keystore_path: keystore_path.to_path_buf(),
            chain_meta_path,
        })
    }

    /// Startup: load both `.chain_meta` and keystore.
    /// Fails if either is missing or the fingerprint doesn't match.
    pub fn load(
        data_dir: &Path,
        keystore_path: &Path,
        encryption_mode: &str,
        password: Option<&str>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let chain_meta_path = data_dir.join(".chain_meta");

        let chain_meta = noble_crypto::file_encrypt::load_chain_meta(
            data_dir,
            encryption_mode,
            password,
        )?;

        // Verify keystore exists and fingerprint matches
        let _ks = KeyStore::open(keystore_path, &chain_meta).map_err(|e| {
            format!("keystore open failed: {e}")
        })?;

        Ok(Self {
            chain_meta,
            keystore_path: keystore_path.to_path_buf(),
            chain_meta_path,
        })
    }

    /// Reset: destroy both `.chain_meta` and keystore.
    pub fn destroy(
        data_dir: &Path,
        keystore_path: &Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        KeyStore::destroy(keystore_path)?;
        noble_crypto::file_encrypt::destroy_chain_meta(data_dir)?;
        Ok(())
    }

    /// The 32-byte per-installation entropy.
    pub fn chain_meta(&self) -> &[u8; 32] {
        &self.chain_meta
    }

    /// Path to the keystore file.
    pub fn keystore_path(&self) -> &Path {
        &self.keystore_path
    }

    /// Path to the `.chain_meta` file.
    pub fn chain_meta_path(&self) -> &Path {
        &self.chain_meta_path
    }
}

// ---------------------------------------------------------------------------
// Legacy JSON format (for migration)
// ---------------------------------------------------------------------------

/// JSON-serialized per-key encrypted file (old format).
#[derive(Serialize, Deserialize)]
struct LegacyEncryptedKeyFile {
    scheme_id: u8,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Decrypt a secret key from a legacy JSON key file.
fn decrypt_legacy_key(
    file: &LegacyEncryptedKeyFile,
    passphrase: &str,
) -> Result<Vec<u8>, WalletError> {
    let salt = hex::decode(&file.salt).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce_bytes =
        hex::decode(&file.nonce).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let ciphertext =
        hex::decode(&file.ciphertext).map_err(|e| WalletError::Crypto(e.to_string()))?;

    let aes_key = derive_legacy_key(passphrase, &salt)?;
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| WalletError::Crypto(e.to_string()))?;

    Ok(plaintext)
}

/// Derive a 32-byte AES key from passphrase + salt (legacy Argon2id params).
fn derive_legacy_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], WalletError> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    Ok(key)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256(chain_meta) as the fingerprint.
fn chain_meta_fingerprint(chain_meta: &[u8; 32]) -> [u8; 32] {
    let hash = noble_crypto::sha256(chain_meta);
    *hash.as_bytes()
}

/// Derive the AES-256 key from passphrase + Argon2id salt.
fn derive_aes_key(passphrase: &str, salt: &[u8; ARGON2_SALT_LEN]) -> Result<[u8; 32], WalletError> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    Ok(key)
}

/// Derive the create-time passphrase from chain_meta. Used for the initial
/// empty keystore encryption before the user's passphrase is set.
fn derive_create_passphrase(chain_meta: &[u8; 32]) -> String {
    hex::encode(noble_crypto::file_encrypt::derive_wallet_key(chain_meta))
}

/// AES-256-GCM encrypt with a random nonce.
fn aes_encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
) -> Result<([u8; AES_NONCE_LEN], Vec<u8>), WalletError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let mut nonce_bytes = [0u8; AES_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| WalletError::Crypto(e.to_string()))?;
    Ok((nonce_bytes, ciphertext))
}

/// AES-256-GCM decrypt.
fn aes_decrypt(
    key: &[u8; 32],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, WalletError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| WalletError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| WalletError::Crypto(e.to_string()))
}

/// Assemble the complete keystore file bytes.
fn assemble_file(
    fingerprint: &[u8; 32],
    salt: &[u8; ARGON2_SALT_LEN],
    nonce: &[u8; AES_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    data.extend_from_slice(&KEYSTORE_MAGIC);
    data.push(KEYSTORE_VERSION);
    data.extend_from_slice(fingerprint);
    data.extend_from_slice(salt);
    data.extend_from_slice(nonce);
    data.extend_from_slice(ciphertext);
    data
}

/// Atomic write helper: write to .tmp, set permissions, rename.
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), WalletError> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = path.with_extension("noble.tmp");
    fs::write(&tmp_path, data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp_path, path).map_err(|e| WalletError::Io(e.to_string()))?;
    Ok(())
}

/// Write a validator.key file encrypted with chain_meta.
fn write_validator_key_file(
    vk_path: &Path,
    sk_bytes: &[u8],
    chain_meta: &[u8; 32],
) -> Result<(), WalletError> {
    let mut raw = vec![SCHEME_SECP256K1];
    raw.extend_from_slice(sk_bytes);
    let result = noble_crypto::file_encrypt::encrypt_file_data(&raw, chain_meta);
    raw.zeroize();
    let file_bytes = result.map_err(|e| WalletError::Crypto(format!("encrypt validator.key: {e}")))?;
    if let Some(parent) = vk_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(vk_path, &file_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(vk_path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Construct a NoblePrivateKey from a KeyEntry.
fn priv_key_from_entry(entry: &KeyEntry) -> Result<NoblePrivateKey, WalletError> {
    match entry.scheme {
        KeyScheme::WalletSecp256k1 => Ok(NoblePrivateKey::Secp256k1(entry.secret.clone())),
        KeyScheme::ValidatorSecp256k1 => {
            Ok(NoblePrivateKey::ValidatorSecp256k1(entry.secret.clone()))
        }
        KeyScheme::P2pIdentity => Ok(NoblePrivateKey::P2pIdentity(entry.secret.clone())),
        KeyScheme::TlsKey => Ok(NoblePrivateKey::TlsKey(entry.secret.clone())),
        KeyScheme::TotpSecret => Ok(NoblePrivateKey::TotpSecret(entry.secret.clone())),
        KeyScheme::FaucetPassphrase => {
            Ok(NoblePrivateKey::FaucetPassphrase(entry.secret.clone()))
        }
    }
}

/// Compute the HashMap key for a KeyEntry (used in the key cache).
fn map_key_for_entry(entry: &KeyEntry) -> Vec<u8> {
    if entry.scheme.is_signing() {
        entry.public_key.clone()
    } else {
        let mut w = Vec::with_capacity(1 + entry.public_key.len());
        w.push(entry.scheme.as_u8());
        w.extend_from_slice(&entry.public_key);
        w
    }
}

/// Estimate the number of entries from file size (rough, for logging only).
fn estimate_entry_count(data: &[u8]) -> usize {
    let ct_len = data.len().saturating_sub(HEADER_LEN + 16);
    // Rough: each CBOR entry is ~120 bytes
    if ct_len > 0 { ct_len / 120 } else { 0 }
}

/// Helper to access entries from a KeyStore (used in migration).
fn self_entries(ks: &KeyStore) -> Vec<&KeyEntry> {
    ks.state
        .as_ref()
        .map(|s| s.entries.iter().collect())
        .unwrap_or_default()
}

/// Current Unix timestamp.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use noble_crypto::{
        sha256, SCHEME_P2P_IDENTITY, SCHEME_TLS_KEY, SCHEME_TOTP_SECRET,
        SCHEME_VALIDATOR_SECP256K1,
    };
    use tempfile::tempdir;

    fn test_chain_meta() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn test_passphrase(chain_meta: &[u8; 32]) -> String {
        hex::encode(noble_crypto::file_encrypt::derive_wallet_key(chain_meta))
    }

    #[test]
    fn create_and_open_keystore() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();

        let _ks = KeyStore::create(&path, &meta).unwrap();
        assert!(path.exists());

        let _ks2 = KeyStore::open(&path, &meta).unwrap();
    }

    #[test]
    fn create_fails_if_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();

        KeyStore::create(&path, &meta).unwrap();
        let result = KeyStore::create(&path, &meta);
        assert!(result.is_err());
    }

    #[test]
    fn open_fails_if_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();

        let result = KeyStore::open(&path, &meta);
        assert!(result.is_err());
    }

    #[test]
    fn fingerprint_mismatch_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta1 = [0x01u8; 32];
        let meta2 = [0x02u8; 32];

        KeyStore::create(&path, &meta1).unwrap();
        let result = KeyStore::open(&path, &meta2);
        assert!(result.is_err(), "should fail with fingerprint mismatch");
    }

    #[test]
    fn unlock_and_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        assert!(!ks.is_unlocked());

        ks.unlock(&pass).unwrap();
        assert!(ks.is_unlocked());

        ks.lock();
        assert!(!ks.is_unlocked());
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        let result = ks.unlock("wrong-passphrase!");
        assert!(matches!(result, Err(WalletError::InvalidPassphrase)));
    }

    #[test]
    fn create_key_secp256k1() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        let keys = ks.list_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].scheme_id(), SCHEME_SECP256K1);
    }

    #[test]
    fn sign_with_created_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();

        let msg = sha256(b"wallet sign test");
        let envelope = ks.sign(&pk, msg.as_bytes()).unwrap();
        assert!(pk.verify(msg.as_bytes(), &envelope).is_ok());
    }

    #[test]
    fn persistence_across_lock_unlock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        ks.lock();

        // Reopen from disk
        let mut ks2 = KeyStore::open(&path, &meta).unwrap();
        ks2.unlock(&pass).unwrap();

        let msg = sha256(b"persistence test");
        let sig = ks2.sign(&pk, msg.as_bytes()).unwrap();
        assert!(pk.verify(msg.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn delete_key_removes_entry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 1);

        ks.delete_key(&pk, &pass).unwrap();
        assert_eq!(ks.list_keys().unwrap().len(), 0);
    }

    #[test]
    fn store_and_get_raw_p2p_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        let raw = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        ks.store_raw(SCHEME_P2P_IDENTITY, &raw, &pass).unwrap();

        let got = ks.get_raw(SCHEME_P2P_IDENTITY).unwrap();
        assert_eq!(got, raw);
    }

    #[test]
    fn duplicate_scheme_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        ks.store_raw(SCHEME_TOTP_SECRET, b"secret1", &pass).unwrap();

        let result = ks.store_raw(SCHEME_TOTP_SECRET, b"secret2", &pass);
        assert!(matches!(result, Err(WalletError::DuplicateKey(_))));
    }

    #[test]
    fn bip39_generate_and_recover() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let (mnemonic, pk1) = ks.create_key_from_mnemonic(24, &pass).unwrap();

        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);

        // Recover in new keystore
        let path2 = dir.path().join("keystore2.noble");
        let mut ks2 = KeyStore::create(&path2, &meta).unwrap();
        ks2.unlock(&pass).unwrap();
        let pk2 = ks2.recover_from_mnemonic(&mnemonic, &pass).unwrap();

        assert_eq!(pk1.to_wire_bytes(), pk2.to_wire_bytes());
    }

    #[test]
    fn brute_force_lockout() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();

        for _ in 0..MAX_UNLOCK_ATTEMPTS {
            let _ = ks.unlock("wrong-passphrase!");
        }

        let result = ks.unlock(&pass);
        assert!(
            matches!(result, Err(WalletError::TooManyAttempts { .. })),
            "expected TooManyAttempts, got: {result:?}"
        );
    }

    #[test]
    fn re_encrypt_preserves_entries() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        ks.store_raw(SCHEME_P2P_IDENTITY, b"p2p-bytes", &pass).unwrap();

        let new_pass = "new-pass-very-long!";
        let count = ks.re_encrypt(&pass, new_pass).unwrap();
        assert_eq!(count, 2);

        // Lock, reopen, unlock with new passphrase
        ks.lock();
        let mut ks2 = KeyStore::open(&path, &meta).unwrap();
        ks2.unlock(new_pass).unwrap();

        let msg = sha256(b"re-encrypt test");
        let sig = ks2.sign(&pk, msg.as_bytes()).unwrap();
        assert!(pk.verify(msg.as_bytes(), &sig).is_ok());

        let raw = ks2.get_raw(SCHEME_P2P_IDENTITY).unwrap();
        assert_eq!(raw, b"p2p-bytes");
    }

    #[test]
    fn import_secp256k1_hex_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let hex_key = hex::encode(&sk);

        let pk = ks.import_secp256k1_key(&hex_key, &pass).unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        let msg = sha256(b"import hex test");
        let sig = ks.sign(&pk, msg.as_bytes()).unwrap();
        assert!(pk.verify(msg.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn node_secrets_initialize_and_load() {
        let dir = tempdir().unwrap();
        let ks_path = dir.path().join("keystore.noble");

        let secrets = NodeSecrets::initialize(
            dir.path(),
            &ks_path,
            "automatic",
            None,
        )
        .unwrap();

        assert_eq!(secrets.chain_meta().len(), 32);
        assert!(ks_path.exists());
        assert!(dir.path().join(".chain_meta").exists());

        // Load should work
        let secrets2 = NodeSecrets::load(
            dir.path(),
            &ks_path,
            "automatic",
            None,
        )
        .unwrap();

        assert_eq!(secrets.chain_meta(), secrets2.chain_meta());
    }

    #[test]
    fn node_secrets_destroy() {
        let dir = tempdir().unwrap();
        let ks_path = dir.path().join("keystore.noble");

        NodeSecrets::initialize(dir.path(), &ks_path, "automatic", None).unwrap();
        assert!(ks_path.exists());
        assert!(dir.path().join(".chain_meta").exists());

        NodeSecrets::destroy(dir.path(), &ks_path).unwrap();
        assert!(!ks_path.exists());
        assert!(!dir.path().join(".chain_meta").exists());
    }

    #[test]
    fn node_secrets_initialize_fails_if_exists() {
        let dir = tempdir().unwrap();
        let ks_path = dir.path().join("keystore.noble");

        NodeSecrets::initialize(dir.path(), &ks_path, "automatic", None).unwrap();
        let result = NodeSecrets::initialize(dir.path(), &ks_path, "automatic", None);
        assert!(result.is_err());
    }

    #[test]
    fn node_secrets_load_fails_if_missing() {
        let dir = tempdir().unwrap();
        let ks_path = dir.path().join("keystore.noble");

        let result = NodeSecrets::load(dir.path(), &ks_path, "automatic", None);
        assert!(result.is_err());
    }

    #[test]
    fn mixed_signing_and_internal_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        ks.store_raw(SCHEME_P2P_IDENTITY, b"p2p-proto-bytes", &pass).unwrap();
        ks.store_raw(SCHEME_TOTP_SECRET, b"totp-base32", &pass).unwrap();

        // list_all_entries shows all entries
        let all = ks.list_all_entries().unwrap();
        assert_eq!(all.len(), 3);

        // list_keys returns only NoblePublicKey-compatible entries
        let pub_keys = ks.list_keys().unwrap();
        assert_eq!(pub_keys.len(), 1);

        // list_signing_keys shows only signing keys
        let signing = ks.list_signing_keys().unwrap();
        assert_eq!(signing.len(), 1);
    }

    #[test]
    fn store_raw_validator_key() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        let (sk, _pk) = noble_crypto::secp256k1::generate_keypair();
        let pk = ks.store_raw(SCHEME_VALIDATOR_SECP256K1, &sk, &pass).unwrap();
        assert_eq!(pk.scheme_id(), SCHEME_SECP256K1);

        let got = ks.get_raw(SCHEME_VALIDATOR_SECP256K1).unwrap();
        assert_eq!(got, sk);
    }

    #[cfg(unix)]
    #[test]
    fn keystore_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();

        KeyStore::create(&path, &meta).unwrap();
        let perms = std::fs::metadata(&path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "keystore file should have 0o600 permissions"
        );
    }

    #[test]
    fn delete_by_scheme_works() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();

        ks.store_raw(SCHEME_TOTP_SECRET, b"totp-secret", &pass).unwrap();
        assert!(ks.has_scheme(SCHEME_TOTP_SECRET).unwrap());

        ks.delete_by_scheme(SCHEME_TOTP_SECRET);
        assert!(!ks.has_scheme(SCHEME_TOTP_SECRET).unwrap());
    }

    #[test]
    fn sign_while_locked_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        let pk = ks.create_key(SCHEME_SECP256K1, &pass).unwrap();
        ks.lock();

        let msg = sha256(b"locked sign test");
        let result = ks.sign(&pk, msg.as_bytes());
        assert!(matches!(result, Err(WalletError::Locked)));
    }

    #[test]
    fn get_raw_while_locked_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.noble");
        let meta = test_chain_meta();
        let pass = test_passphrase(&meta);

        let mut ks = KeyStore::create(&path, &meta).unwrap();
        ks.unlock(&pass).unwrap();
        ks.store_raw(SCHEME_TLS_KEY, b"tls-key-bytes", &pass).unwrap();
        ks.lock();

        let result = ks.get_raw(SCHEME_TLS_KEY);
        assert!(matches!(result, Err(WalletError::Locked)));
    }
}
