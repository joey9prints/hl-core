//! hl-core — Human Layer's shared crypto + envelope + vault store.
//!
//! Portable and platform-agnostic: the desktop app and the iOS app both build
//! on this so journal entries persist in ONE canonical encrypted format, and
//! the sync layer has a single format to target.
//!
//! - [`crypto`]  — Argon2id / XChaCha20-Poly1305 / HKDF (verbatim from desktop).
//! - [`models`]  — `Entry` and friends (desktop-identical) + `voice`/`sealed`.
//! - [`envelope`]— the per-entry content-key envelope: wrap, unwrap, enroll,
//!   migrate. v2 authenticates the stored header; see FORMAT.md §11.
//! - [`store`]   — one envelope file per record under an injected vault root.
//! - [`sync`]    — key-free reconcile of two vault directories (see FORMAT.md).
//! - [`tombstone`]— deletion markers that carry a delete across the keyless
//!   sync boundary so it propagates to every peer.
//!
//! # INTENTIONAL: a restored device backup yields an UNREADABLE vault
//!
//! On iOS the vault's root key is a DEK held in the Keychain as
//! `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` with biometric access control.
//! `ThisDeviceOnly` means the DEK is **excluded from iCloud Keychain and from
//! encrypted device backups**. The vault *files* (`entries/`, `media/`) ride a
//! device backup, but the key does not — so restoring a backup to a NEW device
//! produces a vault that is present but cryptographically unreadable.
//!
//! This is deliberate, not a bug: the vault key must only ever travel via
//! explicit **recovery-phrase enrollment** (re-wrapping the per-entry content
//! keys under a passphrase-master, then discarding the DEK — see
//! [`envelope::reseal_key`]). Until that enrollment path ships, a lost/replaced
//! device means a lost vault by design. Do NOT "fix" this by loosening the
//! Keychain accessibility class or letting the DEK sync — that would silently
//! push the vault key into Apple's backup/cloud, which the privacy model forbids.

pub mod crypto;
pub mod envelope;
pub mod error;
pub mod models;
pub mod store;
pub mod sync;
pub mod tombstone;

pub use error::{Error, Result};
pub use models::{Entry, SealMeta, VaultManifest, VoiceMeta};
pub use store::{envelope_files, export_bundle, migrate_files_to_v2, verify_desktop_master, Store};
