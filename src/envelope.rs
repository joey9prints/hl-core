//! The per-entry envelope.
//!
//! Each record is sealed under its own random **content key (CEK)**; that CEK is
//! then **wrapped** by a KEK derived from the vault's *root* key — a device keystore
//! DEK, or a passphrase-derived master key. Re-keying therefore only re-wraps the
//! CEK and rewrites the header's `key` label: the payload bytes never change, no
//! content is re-encrypted, and the old root can be discarded. See `reseal_key`.
//!
//! Wire layout (self-describing; lengths explicit so the AEAD sizes can evolve):
//! ```text
//! [u32-LE header_len][header JSON][u32-LE wrap_len][wrapped_cek][payload]
//! ```
//!
//! # Version 2: the header is authenticated
//!
//! The header is plaintext, because a keyless listing and a keyless sync depend on
//! reading it. In **v1** it was also unauthenticated apart from the fields that
//! happened to appear in an AAD (`id`, and `key` for the wrap), which meant `date`
//! and `created` could be edited undetectably — and `created` is exactly what sync
//! reconciles on. See FORMAT.md §11.
//!
//! **v2 binds the stored header bytes, verbatim, into the AAD of the wrapped content
//! key.** Change any byte of the header and the CEK no longer unwraps, so the record
//! does not open at all. The header is authenticated through the content key rather
//! than directly, which is what keeps re-keying free: `reseal_key` recomputes the
//! wrap AAD from the *new* header and re-wraps 32 bytes, and the payload — whose own
//! AAD holds only the domain context and the id — is never touched.
//!
//! AADs, verbatim:
//! ```text
//! v2 payload : "entries/v2|payload|<id>"
//! v2 wrap    : "entries/v2|wrap|<id>|"  ++ <the exact stored header bytes>
//! v1 payload : "hl-entry/v1|payload|<id>"                          (read-only)
//! v1 wrap    : "hl-entry/v1|wrap|<id>|<key label>"                 (read-only)
//! ```
//!
//! Writers emit v2 only. Readers accept v1 and v2; `migrate_v1_to_v2` upgrades a v1
//! file in place, which does re-encrypt the payload because the payload AAD changed.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, MasterKey, SubKey};
use crate::error::{Error, Result};

/// The envelope version every writer emits.
pub const ENVELOPE_VERSION: u32 = 2;

/// HKDF purpose that turns the root key into the key-wrapping KEK. Unchanged in v2:
/// the KEK derivation is not what was weak, and keeping it lets a v1 and a v2 record
/// coexist under one root.
const WRAP_PURPOSE: &[u8] = b"hl-entry/wrap/v1";
/// Header `key` label for a vault sealed under the device Keychain DEK.
pub const KEY_LABEL_DEK: &str = "dek:v1";
/// Header `key` label for a vault sealed under the passphrase-derived master.
pub const KEY_LABEL_MASTER: &str = "master:v1";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EnvelopeHeader {
    pub v: u32,          // ENVELOPE_VERSION for anything newly written
    pub fmt: String,     // "hl-entry"
    pub aead: String,    // "xchacha20poly1305"
    pub id: String,      // record id (binds the payload AAD)
    pub date: String,    // YYYY-MM-DD (cheap listing without decrypt)
    pub key: String,     // which root wrapped the CEK: KEY_LABEL_DEK | KEY_LABEL_MASTER
    pub created: String, // ISO 8601
}

impl EnvelopeHeader {
    pub fn new(
        id: impl Into<String>,
        date: impl Into<String>,
        key: impl Into<String>,
        created: impl Into<String>,
    ) -> Self {
        EnvelopeHeader {
            v: ENVELOPE_VERSION,
            fmt: "hl-entry".into(),
            aead: "xchacha20poly1305".into(),
            id: id.into(),
            date: date.into(),
            key: key.into(),
            created: created.into(),
        }
    }
}

fn wrap_kek(root: &MasterKey) -> SubKey {
    root.subkey(WRAP_PURPOSE)
}
/// Reject a version this build does not know rather than guessing at its AADs.
fn check_version(v: u32) -> Result<()> {
    match v {
        1 | 2 => Ok(()),
        other => Err(Error::Format(format!(
            "unsupported envelope version {other} (this build reads v1 and v2)"
        ))),
    }
}

fn payload_aad(version: u32, id: &str) -> Vec<u8> {
    match version {
        1 => format!("hl-entry/v1|payload|{id}").into_bytes(),
        _ => format!("entries/v2|payload|{id}").into_bytes(),
    }
}

/// v2 appends the stored header bytes verbatim, so no header field can change
/// without the content key failing to unwrap. v1 bound only the id and key label.
fn wrap_aad(version: u32, id: &str, key_label: &str, header_bytes: &[u8]) -> Vec<u8> {
    match version {
        1 => format!("hl-entry/v1|wrap|{id}|{key_label}").into_bytes(),
        _ => {
            let mut aad = format!("entries/v2|wrap|{id}|").into_bytes();
            aad.extend_from_slice(header_bytes);
            aad
        }
    }
}

/// Seal `plaintext` into an envelope: a fresh CEK encrypts the payload; the CEK is
/// wrapped by the root's KEK, authenticated (in v2) under the stored header bytes.
pub fn seal_envelope(
    root: &MasterKey,
    header: &EnvelopeHeader,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    check_version(header.v)?;
    // Serialize the header FIRST: in v2 its exact bytes are the wrap AAD, so the
    // bytes that get authenticated must be the bytes that get stored.
    let hjson = serde_json::to_vec(header)?;
    // Zeroizing so the CEK is wiped on Drop — on the `?` error paths below too,
    // not only the happy path where a manual zeroize would have run.
    let mut cek = Zeroizing::new([0u8; 32]);
    crypto_fill(&mut cek);
    let payload = crypto::seal(
        &SubKey::from_bytes(*cek),
        plaintext,
        &payload_aad(header.v, &header.id),
    )?;
    let wrapped = crypto::seal(
        &wrap_kek(root),
        &cek[..],
        &wrap_aad(header.v, &header.id, &header.key, &hjson),
    )?;
    Ok(encode(&hjson, &wrapped, &payload))
}

/// Open an envelope: unwrap the CEK with the root's KEK, then decrypt the payload.
///
/// In v2 the unwrap is authenticated under the stored header bytes, so a single
/// altered header byte fails here and the record does not open at all.
pub fn open_envelope(root: &MasterKey, bytes: &[u8]) -> Result<(EnvelopeHeader, Vec<u8>)> {
    let d = decode(bytes)?;
    let header = d.header;
    check_version(header.v)?;
    // Zeroizing wraps both the unwrapped Vec and the fixed array, so every return
    // path (including the length-check error and a failed payload open) wipes them.
    let cek = Zeroizing::new(crypto::open(
        &wrap_kek(root),
        &d.wrapped,
        &wrap_aad(header.v, &header.id, &header.key, &d.header_bytes),
    )?);
    if cek.len() != 32 {
        return Err(Error::Format(
            "unwrapped content key is not 32 bytes".into(),
        ));
    }
    let mut cek_arr = Zeroizing::new([0u8; 32]);
    cek_arr.copy_from_slice(&cek[..]);
    let pt = crypto::open(
        &SubKey::from_bytes(*cek_arr),
        &d.payload,
        &payload_aad(header.v, &header.id),
    );
    Ok((header, pt?))
}

/// Read only the header (no key needed) — for cheap listing (id + date).
pub fn read_header(bytes: &[u8]) -> Result<EnvelopeHeader> {
    Ok(decode(bytes)?.header)
}

/// Structural check with no key: the envelope parses, its version is known, and its
/// declared lengths are consistent with the file. This is everything a keyless
/// reader can say about a file; it is emphatically NOT integrity. Only opening the
/// envelope proves the bytes are the bytes that were sealed.
pub fn is_well_formed(bytes: &[u8]) -> bool {
    match decode(bytes) {
        Ok(d) => {
            check_version(d.header.v).is_ok()
                && d.header.fmt == "hl-entry"
                && !d.wrapped.is_empty()
                && !d.payload.is_empty()
        }
        Err(_) => false,
    }
}

/// Enrollment: re-wrap the CEK under `new_root`/`new_key_label` without touching the
/// payload — DEK to passphrase-master, or one device's master to another's, with
/// zero re-encryption. Works on v1 and v2 alike and preserves the version.
///
/// This is the reason v2 binds the header into the *wrap* AAD rather than the
/// payload's: the header changes on a re-key, so a payload authenticated under it
/// would have to be re-encrypted every time the passphrase changed.
pub fn reseal_key(
    old_root: &MasterKey,
    new_root: &MasterKey,
    new_key_label: &str,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let d = decode(bytes)?;
    let mut header = d.header;
    check_version(header.v)?;
    // Zeroizing: the CEK is wiped on Drop, including the `?` paths on serialize /
    // re-wrap failure between here and the end.
    let cek = Zeroizing::new(crypto::open(
        &wrap_kek(old_root),
        &d.wrapped,
        &wrap_aad(header.v, &header.id, &header.key, &d.header_bytes),
    )?);
    // The new label goes into the header BEFORE the re-wrap, because in v2 the
    // re-serialized header is itself the AAD the new wrap is authenticated under.
    header.key = new_key_label.to_string();
    let new_hjson = serde_json::to_vec(&header)?;
    let new_wrapped = crypto::seal(
        &wrap_kek(new_root),
        &cek[..],
        &wrap_aad(header.v, &header.id, new_key_label, &new_hjson),
    )?;
    Ok(encode(&new_hjson, &new_wrapped, &d.payload))
}

/// Upgrade a v1 envelope to v2, preserving every header field — `id`, `date`, `key`
/// and `created` — byte for byte, because reconcile orders records by `created` and
/// a migration that restamped it would silently reorder the vault.
///
/// Unlike `reseal_key` this DOES re-encrypt the payload: v2 changed the payload's
/// AAD, so the old ciphertext cannot be carried across unchanged. The record's own
/// `lastModified` lives inside that payload and is re-encrypted verbatim with it.
///
/// Returns `Ok(None)` if the file is already v2, so a migration pass is idempotent.
pub fn migrate_v1_to_v2(root: &MasterKey, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let probe = read_header(bytes)?;
    check_version(probe.v)?;
    if probe.v == ENVELOPE_VERSION {
        return Ok(None);
    }
    let (header, plaintext) = open_envelope(root, bytes)?;
    let upgraded = EnvelopeHeader {
        v: ENVELOPE_VERSION,
        ..header
    };
    Ok(Some(seal_envelope(root, &upgraded, &plaintext)?))
}

// ---- wire encode/decode ----

/// Takes the already-serialized header, never a struct: the stored bytes and the
/// authenticated bytes must be the same bytes.
fn encode(hjson: &[u8], wrapped: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + hjson.len() + 4 + wrapped.len() + payload.len());
    out.extend_from_slice(&(hjson.len() as u32).to_le_bytes());
    out.extend_from_slice(hjson);
    out.extend_from_slice(&(wrapped.len() as u32).to_le_bytes());
    out.extend_from_slice(wrapped);
    out.extend_from_slice(payload);
    out
}

/// A decoded envelope: the parsed header, the header's **raw stored bytes** (which
/// are the v2 wrap AAD, and must be the stored bytes rather than a re-serialization),
/// the wrapped content key, and the payload.
struct Decoded {
    header: EnvelopeHeader,
    header_bytes: Vec<u8>,
    wrapped: Vec<u8>,
    payload: Vec<u8>,
}

fn decode(bytes: &[u8]) -> Result<Decoded> {
    let take_u32 = |b: &[u8], at: usize| -> Result<usize> {
        let end = at
            .checked_add(4)
            .ok_or_else(|| Error::Format("length overflow".into()))?;
        let slice = b
            .get(at..end)
            .ok_or_else(|| Error::Format("truncated length".into()))?;
        Ok(u32::from_le_bytes(slice.try_into().unwrap()) as usize)
    };
    let hlen = take_u32(bytes, 0)?;
    let hstart: usize = 4;
    let hend = hstart
        .checked_add(hlen)
        .ok_or_else(|| Error::Format("header overflow".into()))?;
    let hjson = bytes
        .get(hstart..hend)
        .ok_or_else(|| Error::Format("truncated header".into()))?;
    let header: EnvelopeHeader = serde_json::from_slice(hjson)?;
    let wlen = take_u32(bytes, hend)?;
    let wstart = hend + 4;
    let wend = wstart
        .checked_add(wlen)
        .ok_or_else(|| Error::Format("wrap overflow".into()))?;
    let wrapped = bytes
        .get(wstart..wend)
        .ok_or_else(|| Error::Format("truncated wrapped key".into()))?;
    let payload = bytes
        .get(wend..)
        .ok_or_else(|| Error::Format("truncated payload".into()))?;
    Ok(Decoded {
        header,
        header_bytes: hjson.to_vec(),
        wrapped: wrapped.to_vec(),
        payload: payload.to_vec(),
    })
}

fn crypto_fill(buf: &mut [u8; 32]) {
    use chacha20poly1305::aead::OsRng;
    OsRng.fill_bytes(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(seed: u8) -> MasterKey {
        MasterKey::from_bytes([seed; 32])
    }
    fn hdr(key: &str) -> EnvelopeHeader {
        EnvelopeHeader::new("abc123", "2026-08-10", key, "2026-08-10T12:00:00Z")
    }

    #[test]
    fn envelope_roundtrip() {
        let r = root(1);
        let pt = b"test entry one";
        let env = seal_envelope(&r, &hdr(KEY_LABEL_DEK), pt).unwrap();
        let (h, out) = open_envelope(&r, &env).unwrap();
        assert_eq!(out, pt);
        assert_eq!(h.id, "abc123");
        assert_eq!(h.key, KEY_LABEL_DEK);
    }

    #[test]
    fn wrong_root_cannot_unwrap() {
        let env = seal_envelope(&root(1), &hdr(KEY_LABEL_DEK), b"test entry three").unwrap();
        assert!(open_envelope(&root(2), &env).is_err());
    }

    #[test]
    fn enrollment_rewraps_without_reencrypting_payload() {
        // Seal under the DEK.
        let dek = root(9);
        let pt = b"test entry two";
        let env_dek = seal_envelope(&dek, &hdr(KEY_LABEL_DEK), pt).unwrap();

        // The payload bytes we must NOT re-encrypt.
        let payload_before = decode(&env_dek).unwrap().payload;

        // Enroll: re-wrap under the passphrase-master, discard the DEK.
        let master = root(42);
        let env_master = reseal_key(&dek, &master, KEY_LABEL_MASTER, &env_dek).unwrap();

        // Payload is byte-identical (no re-encryption).
        let payload_after = decode(&env_master).unwrap().payload;
        assert_eq!(
            payload_before, payload_after,
            "payload must not be re-encrypted on enrollment"
        );

        // The new root opens it; the old DEK no longer can.
        let (h, out) = open_envelope(&master, &env_master).unwrap();
        assert_eq!(out, pt);
        assert_eq!(h.key, KEY_LABEL_MASTER);
        assert!(
            open_envelope(&dek, &env_master).is_err(),
            "DEK must be useless after enrollment"
        );
    }

    /// Rebuild a file with one byte of the header JSON changed, leaving every length
    /// prefix and every ciphertext byte exactly as it was. This is the whole attack:
    /// the header is plaintext, so anyone with write access can do it.
    fn tamper_header(bytes: &[u8], find: &str, replace: &str) -> Vec<u8> {
        let d = decode(bytes).unwrap();
        let text = String::from_utf8(d.header_bytes).unwrap();
        assert!(text.contains(find), "header does not contain {find}");
        let forged = text.replace(find, replace);
        assert_eq!(forged.len(), text.len(), "keep the header the same length");
        encode(forged.as_bytes(), &d.wrapped, &d.payload)
    }

    #[test]
    fn v2_is_what_writers_emit() {
        let env = seal_envelope(&root(1), &hdr(KEY_LABEL_DEK), b"test entry").unwrap();
        assert_eq!(read_header(&env).unwrap().v, 2);
        assert_eq!(ENVELOPE_VERSION, 2);
    }

    #[test]
    fn v2_header_tamper_is_caught() {
        let r = root(1);
        let env = seal_envelope(&r, &hdr(KEY_LABEL_DEK), b"test entry").unwrap();
        assert!(open_envelope(&r, &env).is_ok(), "the untampered file opens");

        // `created` is the field that matters: reconcile picks the winner by it.
        let forged = tamper_header(&env, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");
        assert!(
            read_header(&forged).unwrap().created.starts_with("2099"),
            "the forged stamp is readable without a key, as headers always are"
        );
        assert!(
            open_envelope(&r, &forged).is_err(),
            "a forged `created` must make the record unopenable in v2"
        );

        // and every other header field, for the same reason
        for (find, replace) in [
            ("2026-08-10", "2026-01-01"),               // date
            ("abc123", "abc124"),                       // id
            ("dek:v1", "xxx:v1"),                       // key label
            ("xchacha20poly1305", "Xchacha20poly1305"), // aead
            ("hl-entry", "hl-entrY"),                   // fmt
        ] {
            let forged = tamper_header(&env, find, replace);
            assert!(
                open_envelope(&r, &forged).is_err(),
                "tampering with {find} must fail the tag"
            );
        }
    }

    #[test]
    fn v1_header_tamper_was_not_caught_and_v2_catches_it() {
        // The weakness v2 fixes, demonstrated rather than asserted. Build the same
        // record in each version and forge the same byte in each.
        let r = root(1);
        let mut h1 = hdr(KEY_LABEL_DEK);
        h1.v = 1;
        let v1 = seal_envelope(&r, &h1, b"test entry").unwrap();
        let v2 = seal_envelope(&r, &hdr(KEY_LABEL_DEK), b"test entry").unwrap();

        let forged_v1 = tamper_header(&v1, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");
        let forged_v2 = tamper_header(&v2, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");

        // v1: the record still opens, and now claims to have been written in 2099.
        // Reconcile would hand this forgery the newest-wins race.
        let (header, plaintext) = open_envelope(&r, &forged_v1).expect("v1 accepts the forgery");
        assert_eq!(header.created, "2099-08-10T12:00:00Z");
        assert_eq!(plaintext, b"test entry");

        // v2: the same forgery fails the tag.
        assert!(open_envelope(&r, &forged_v2).is_err());
    }

    #[test]
    fn v1_files_still_open_and_migrate_to_v2() {
        let r = root(1);
        let mut h1 = hdr(KEY_LABEL_DEK);
        h1.v = 1;
        let pt = b"test entry written before v2";
        let v1 = seal_envelope(&r, &h1, pt).unwrap();

        // a v1 file on disk keeps opening, forever
        let (h, out) = open_envelope(&r, &v1).unwrap();
        assert_eq!((h.v, out.as_slice()), (1, pt.as_slice()));

        let migrated = migrate_v1_to_v2(&r, &v1).unwrap().expect("v1 migrates");
        let (h2, out2) = open_envelope(&r, &migrated).unwrap();
        assert_eq!(h2.v, 2);
        assert_eq!(out2, pt, "content survives the migration");

        // every header field is preserved byte for byte, because reconcile orders on
        // `created` and a restamped migration would reorder the vault
        assert_eq!(
            (h2.id, h2.date, h2.key, h2.created),
            (h.id, h.date, h.key, h.created)
        );

        // the forgery that v1 accepted is now caught on the migrated file
        let forged = tamper_header(&migrated, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");
        assert!(open_envelope(&r, &forged).is_err());

        // idempotent: migrating a v2 file is a no-op, not an error or a rewrite
        assert!(migrate_v1_to_v2(&r, &migrated).unwrap().is_none());
    }

    #[test]
    fn rekeying_a_v2_file_never_re_encrypts_the_payload() {
        // The property that decided where v2 binds the header: a passphrase change
        // must stay a 32-byte re-wrap, not a whole-vault re-encryption.
        let dek = root(9);
        let pt = b"test entry two";
        let env = seal_envelope(&dek, &hdr(KEY_LABEL_DEK), pt).unwrap();
        let payload_before = decode(&env).unwrap().payload;

        let master = root(42);
        let resealed = reseal_key(&dek, &master, KEY_LABEL_MASTER, &env).unwrap();

        assert_eq!(
            decode(&resealed).unwrap().payload,
            payload_before,
            "payload untouched"
        );
        let (h, out) = open_envelope(&master, &resealed).unwrap();
        assert_eq!(
            (h.v, h.key.as_str(), out.as_slice()),
            (2, KEY_LABEL_MASTER, pt.as_slice())
        );
        assert!(
            open_envelope(&dek, &resealed).is_err(),
            "the old root is useless"
        );

        // and the re-wrapped file is still tamper-evident under its NEW header
        let forged = tamper_header(&resealed, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");
        assert!(open_envelope(&master, &forged).is_err());
    }

    #[test]
    fn unknown_versions_are_refused_not_guessed() {
        let r = root(1);
        let env = seal_envelope(&r, &hdr(KEY_LABEL_DEK), b"test entry").unwrap();
        let future = tamper_header(&env, "\"v\":2", "\"v\":9");
        assert_eq!(read_header(&future).unwrap().v, 9);
        assert!(open_envelope(&r, &future).is_err());
        assert!(!is_well_formed(&future));
    }

    #[test]
    fn well_formed_is_structure_only_never_integrity() {
        let env = seal_envelope(&root(1), &hdr(KEY_LABEL_DEK), b"test entry").unwrap();
        assert!(is_well_formed(&env));
        assert!(!is_well_formed(b"not an envelope"));
        assert!(
            !is_well_formed(&env[..env.len() / 2]),
            "a truncated file is malformed"
        );
        // A forged header is still perfectly well-formed. Only the key can tell.
        let forged = tamper_header(&env, "2026-08-10T12:00:00Z", "2099-08-10T12:00:00Z");
        assert!(is_well_formed(&forged));
        assert!(open_envelope(&root(1), &forged).is_err());
    }

    #[test]
    fn header_readable_without_key() {
        let env = seal_envelope(&root(1), &hdr(KEY_LABEL_DEK), b"test entry four").unwrap();
        let h = read_header(&env).unwrap();
        assert_eq!(h.date, "2026-08-10");
    }
}
