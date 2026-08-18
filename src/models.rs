//! Record models. `Entry` and its sub-structs are identical across every
//! platform (each serde rename/default preserved) so they all serialize the same
//! bytes and sync never has to migrate a record.
//!
//! `voice` and `sealed` are optional and lazy-migrated — the non-breaking
//! convention here is that an older record loads with `None` and never grows the
//! field on disk unless it is actually set.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct Metrics {
    #[serde(rename = "wordCount")]
    pub word_count: u32,
    #[serde(rename = "valence")]
    pub valence: f64,
    #[serde(rename = "selfFocus")]
    pub self_focus: f64,
    #[serde(rename = "intensity")]
    pub intensity: f64,
    #[serde(rename = "futureRatio")]
    pub future_ratio: f64,
    #[serde(rename = "richness")]
    pub richness: f64,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EntrySignificance {
    #[serde(default)]
    pub nouns: Vec<String>,
    #[serde(default)]
    pub verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(
        default,
        rename = "extractedAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub extracted_at: Option<String>,
    #[serde(
        default,
        rename = "promptVersion",
        skip_serializing_if = "Option::is_none"
    )]
    pub prompt_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<String>,
}

/// One Life Map mark on an entry. `mark_type`/`category` kept as free Strings
/// (not enums) so unknown future values round-trip through any build.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mark {
    #[serde(rename = "type")]
    pub mark_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub category: String,
    #[serde(rename = "createdAt", default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A spoken entry. The transcript lives in `Entry.text`; the audio, when kept,
/// is encrypted alongside it at `media/<audioId>.hla`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VoiceMeta {
    #[serde(rename = "audioId")]
    pub audio_id: String,
    #[serde(rename = "durationSecs")]
    pub duration_secs: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

/// A sealed page or capsule: readers show date + seal only, never the content.
/// `unseal_at` is a STATIC label ("sealed until <date>"), never a live countdown,
/// and is optional — a sealed page with no release date stays sealed indefinitely.
///
/// NOTE: sealing is enforced by policy, not by cryptography. A sealed entry is
/// encrypted exactly like any other and the vault key decrypts it. See FORMAT.md.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SealMeta {
    #[serde(rename = "sealId")]
    pub seal_id: String,
    #[serde(rename = "sealedAt")]
    pub sealed_at: String,
    #[serde(default, rename = "unsealAt", skip_serializing_if = "Option::is_none")]
    pub unseal_at: Option<String>,
    /// "sealed_page" | "capsule". Free String (an unknown future kind round-trips
    /// through any build rather than failing to deserialize).
    pub kind: String,
}

/// Seal kinds. Strings, not an enum, for forward-compat.
pub const SEAL_KIND_PAGE: &str = "sealed_page";
pub const SEAL_KIND_CAPSULE: &str = "capsule";

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub id: String,
    pub date: String, // YYYY-MM-DD
    pub text: String,
    pub mood: u8,
    #[serde(default, rename = "moodSet", skip_serializing_if = "Option::is_none")]
    pub mood_set: Option<bool>,
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mentions: Vec<String>,
    #[serde(default, rename = "embedText", skip_serializing_if = "Option::is_none")]
    pub embed_text: Option<String>,
    pub metrics: Option<Metrics>,
    /// ISO 8601 UTC ms — the newer-wins merge key. Stamped on every save.
    #[serde(
        default,
        rename = "lastModified",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_modified: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub marks: Vec<Mark>,
    #[serde(default, rename = "parentId", skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub significance: Option<EntrySignificance>,
    // ---- mobile additions (optional, lazy-migrated) ----
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voice: Option<VoiceMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealMeta>,
}

impl Entry {
    /// A minimal text entry, with the same field defaults every composer uses.
    pub fn new_text(id: String, date: String, text: String) -> Self {
        Entry {
            id,
            date,
            text,
            mood: 3,
            mood_set: None,
            tags: Vec::new(),
            mentions: Vec::new(),
            embed_text: None,
            metrics: None,
            last_modified: None,
            marks: Vec::new(),
            parent_id: None,
            significance: None,
            voice: None,
            sealed: None,
        }
    }
}

/// vault.json — plaintext manifest. `kdf` is present only for passphrase-mode
/// vaults; DEK-mode (mobile pre-enrollment) omits it. `key_mode` records which.
#[derive(Serialize, Deserialize, Clone)]
pub struct VaultManifest {
    #[serde(rename = "formatVersion")]
    pub format_version: u32,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// "dek" (mobile, key in the device Keychain) | "master" (passphrase-derived).
    #[serde(rename = "keyMode")]
    pub key_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kdf: Option<crate::crypto::KdfParams>,
    #[serde(
        default,
        rename = "lastBackupAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_backup_at: Option<String>,
}
