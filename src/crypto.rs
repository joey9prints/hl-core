// crypto.rs
// All cryptographic primitives for Human Layer.
// Shared by every platform so they all encrypt identically. `MasterKey::from_bytes`
// and `SubKey::from_bytes` let a raw 32-byte root key (on iOS, the Keychain DEK)
// drive the same HKDF/AEAD path a passphrase-derived master key would.
//
// Design choices:
//   - Argon2id (m=64MB, t=3, p=4) for passphrase → 32-byte master key.
//   - XChaCha20-Poly1305 AEAD (192-bit random nonce).
//   - HKDF-SHA256 for per-purpose subkeys from the master/root key.
//   - All in-memory keys zeroized on drop.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crate::error::{Error, Result};

/// 32-byte master/root key. Zeroized on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    /// Wrap a raw 32-byte root key (e.g. the iOS Keychain DEK) as a MasterKey.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        MasterKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derive a purpose-specific subkey via HKDF.
    /// `purpose` is a domain separator like b"entries/v1" or b"hl-entry/wrap/v1".
    pub fn subkey(&self, purpose: &[u8]) -> SubKey {
        let hk = Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        hk.expand(purpose, &mut out)
            .expect("32 bytes is always within HKDF expand limit");
        SubKey(out)
    }
}

#[derive(Clone, ZeroizeOnDrop)]
pub struct SubKey([u8; 32]);

impl SubKey {
    /// Wrap a raw 32-byte key (e.g. a per-entry content key) as a SubKey.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SubKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// On-disk parameters for re-deriving the master key from the passphrase.
/// Lives in vault.json; safe to store in plaintext. Only present for
/// passphrase-mode vaults (desktop / post-enrollment); DEK-mode vaults omit it.
#[derive(Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algo: String,     // "argon2id"
    pub version: u32,     // 0x13
    pub m_cost: u32,      // memory KiB
    pub t_cost: u32,      // iterations
    pub p_cost: u32,      // lanes
    pub salt_b64: String, // base64-encoded 16-byte salt
}

impl KdfParams {
    /// Production defaults: 64 MiB, 3 passes, 4 lanes.
    pub fn new_default() -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            algo: "argon2id".into(),
            version: 0x13,
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt_b64: base64_encode(&salt),
        }
    }
}

/// Derive the master key from a passphrase using Argon2id.
pub fn derive_master_key(passphrase: &str, params: &KdfParams) -> Result<MasterKey> {
    if params.algo != "argon2id" {
        return Err(Error::Crypto(format!("unknown KDF: {}", params.algo)));
    }
    let salt = base64_decode(&params.salt_b64)?;
    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| Error::Crypto(format!("argon2 derive: {e}")))?;
    Ok(MasterKey(key))
}

/// AEAD-encrypt a plaintext under a subkey.
/// On-disk blob: [24-byte nonce][ciphertext + 16-byte tag].
pub fn seal(key: &SubKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| Error::Crypto(format!("seal: {e}")))?;
    let mut out = Vec::with_capacity(nonce.len() + ct.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// AEAD-decrypt. Errors on tag mismatch (any tampering).
pub fn open(key: &SubKey, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 24 + 16 {
        return Err(Error::Crypto("ciphertext too short".into()));
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(&blob[..24]);
    let pt = cipher
        .decrypt(
            nonce,
            chacha20poly1305::aead::Payload {
                msg: &blob[24..],
                aad,
            },
        )
        .map_err(|_| {
            Error::Crypto("decryption failed (wrong key, or file tampered with)".into())
        })?;
    Ok(pt)
}

pub fn base64_encode(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD.encode(b)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
    STANDARD_NO_PAD
        .decode(s.trim())
        .map_err(|e| Error::Crypto(format!("base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_seals_and_unseals() {
        let params = KdfParams::new_default();
        let mk = derive_master_key("test-passphrase", &params).unwrap();
        let sub = mk.subkey(b"entries/v1");
        let pt = b"test plaintext one";
        let aad = b"entry-id:abc123";
        let ct = seal(&sub, pt, aad).unwrap();
        let recovered = open(&sub, &ct, aad).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn raw_root_key_matches_derived_path() {
        // A DEK (raw bytes) drives the same subkey/AEAD path as a passphrase key.
        let dek = [7u8; 32];
        let root = MasterKey::from_bytes(dek);
        let sub = root.subkey(b"hl-entry/wrap/v1");
        let ct = seal(&sub, b"test content key", b"aad").unwrap();
        assert_eq!(open(&sub, &ct, b"aad").unwrap(), b"test content key");
    }

    #[test]
    fn aad_tamper_fails() {
        let mk = derive_master_key("test-passphrase", &KdfParams::new_default()).unwrap();
        let sub = mk.subkey(b"entries/v1");
        let ct = seal(&sub, b"test plaintext", b"id:1").unwrap();
        assert!(open(&sub, &ct, b"id:2").is_err());
    }
}
