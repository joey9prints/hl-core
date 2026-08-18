//! The on-disk vault: `vault.json` + one envelope file per record under
//! `entries/<date>_<id>.hlj`. The root key and the vault root are both injected —
//! hl-core makes no home-dir or platform assumption, so each host supplies its
//! own path (on iOS, the app container).
//!
//! Listing and search decrypt, because the payload is opaque without the key.
//! For vaults of the size this targets that is fine; a larger vault would want a
//! plaintext index sealed under its own key, which is not implemented here.

use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::{self, KdfParams, MasterKey};
use crate::envelope::{self, EnvelopeHeader, KEY_LABEL_MASTER};
use crate::error::{Error, Result};
use crate::models::{Entry, VaultManifest};

const FORMAT_VERSION: u32 = 1;

pub struct Store {
    root: PathBuf,
    key: MasterKey,
    key_label: String,
}

impl Store {
    /// Open (creating if needed) the vault at `root`, sealed under `key`.
    /// `key_label` is the envelope header label (e.g. `envelope::KEY_LABEL_DEK`).
    pub fn open(
        root: impl Into<PathBuf>,
        key: MasterKey,
        key_label: impl Into<String>,
    ) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("entries"))?;
        fs::create_dir_all(root.join("media"))?;
        let store = Store {
            root,
            key,
            key_label: key_label.into(),
        };
        store.ensure_manifest()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure_manifest(&self) -> Result<()> {
        let path = self.root.join("vault.json");
        if path.exists() {
            return Ok(());
        }
        let manifest = VaultManifest {
            format_version: FORMAT_VERSION,
            created_at: now_iso(),
            key_mode: "dek".into(),
            kdf: None,
            last_backup_at: None,
        };
        atomic_write(&path, serde_json::to_vec_pretty(&manifest)?.as_slice())
    }

    // ---- entries ----

    /// Persist an entry, stamping `last_modified = now` (the newer-wins key).
    /// One file per id: `entries/<date>_<id>.hlj`; older files for the same id
    /// are purged so a date edit can't leave a duplicate. Returns the stamped entry.
    pub fn save_entry(&self, entry: &Entry) -> Result<Entry> {
        let mut entry = entry.clone();
        let now = now_iso();
        entry.last_modified = Some(now.clone());
        let header = EnvelopeHeader::new(&entry.id, &entry.date, &self.key_label, now);
        let plaintext = serde_json::to_vec(&entry)?;
        let env = envelope::seal_envelope(&self.key, &header, &plaintext)?;

        let path = self.entry_path(&entry.date, &entry.id);
        atomic_write(&path, &env)?;
        self.purge_other_entry_files_for_id(&entry.id, &path)?;
        Ok(entry)
    }

    pub fn load_entry_file(&self, path: &Path) -> Result<Entry> {
        let bytes = fs::read(path)?;
        let (_h, pt) = envelope::open_envelope(&self.key, &bytes)?;
        Ok(serde_json::from_slice(&pt)?)
    }

    /// All entries, newest-first by `last_modified` then `date`.
    pub fn all_entries(&self) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        let dir = self.root.join("entries");
        if !dir.exists() {
            return Ok(out);
        }
        for de in fs::read_dir(&dir)? {
            let path = de?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("hlj") {
                continue;
            }
            match self.load_entry_file(&path) {
                Ok(e) => out.push(e),
                Err(e) => return Err(e), // fail loud: a corrupt or wrong-key file is a bug to see
            }
        }
        // newest-first by last_modified, with date then id as deterministic
        // tiebreakers so same-millisecond saves (and cross-device merges) order stably.
        out.sort_by(|a, b| {
            sort_key(b)
                .cmp(&sort_key(a))
                .then_with(|| b.date.cmp(&a.date))
                .then_with(|| b.id.cmp(&a.id))
        });
        Ok(out)
    }

    /// Most-recent `limit` entries.
    pub fn recent(&self, limit: usize) -> Result<Vec<Entry>> {
        let mut all = self.all_entries()?;
        all.truncate(limit);
        Ok(all)
    }

    /// Keyword search — case-insensitive substring over the entry text, newest
    /// first. The single input the semantic embedder will later feed into; the
    /// call site and UI don't change when that lands.
    pub fn search(&self, query: &str) -> Result<Vec<Entry>> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        Ok(self
            .all_entries()?
            .into_iter()
            .filter(|e| e.sealed.is_none() && e.text.to_lowercase().contains(&q))
            .collect())
    }

    // ---- media (voice audio) ----

    /// Encrypt+store an audio blob at `media/<audio_id>.hla`, sealed with the
    /// same envelope model so enrollment re-wraps (never re-encrypts) it.
    pub fn save_media(&self, audio_id: &str, date: &str, bytes: &[u8]) -> Result<PathBuf> {
        let header = EnvelopeHeader::new(audio_id, date, &self.key_label, now_iso());
        let env = envelope::seal_envelope(&self.key, &header, bytes)?;
        let path = self.root.join("media").join(format!("{audio_id}.hla"));
        atomic_write(&path, &env)?;
        Ok(path)
    }

    pub fn load_media(&self, audio_id: &str) -> Result<Vec<u8>> {
        let path = self.root.join("media").join(format!("{audio_id}.hla"));
        let bytes = fs::read(path)?;
        Ok(envelope::open_envelope(&self.key, &bytes)?.1)
    }

    // ---- enrollment (device pairing) ----

    fn manifest(&self) -> Result<VaultManifest> {
        let bytes = fs::read(self.root.join("vault.json"))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Current key mode from the manifest: "dek" (device Keychain) | "master"
    /// (passphrase-derived, shareable across devices).
    pub fn key_mode(&self) -> Result<String> {
        Ok(self.manifest()?.key_mode)
    }

    /// The stored KDF params — present only after enrollment (master mode). A peer
    /// device must use these same params + the passphrase to derive the same key.
    pub fn kdf_params(&self) -> Result<Option<KdfParams>> {
        Ok(self.manifest()?.kdf)
    }

    /// Re-key this vault to a passphrase-derived master: enrollment away from a
    /// device DEK, and equally joining one device's master to another's. Derives the
    /// new master, re-wraps every entry and media content key under it (payloads
    /// untouched, via `reseal_key`), rewrites the manifest, and switches this live Store.
    ///
    /// ATOMIC: all re-wraps are computed in memory first, then written to `.rekey`
    /// temp files, then committed by rename. Any failure BEFORE the commit leaves the
    /// vault completely untouched (still readable under the old key) — a mistyped
    /// passphrase (caught earlier by the probe) or a mid-reseal error can never leave a
    /// half-re-keyed vault. Returns (records re-wrapped, new master).
    pub fn enroll_to_master(
        &mut self,
        passphrase: &str,
        params: KdfParams,
    ) -> Result<(usize, MasterKey)> {
        let new_master = crypto::derive_master_key(passphrase, &params)?;

        // Phase A — re-wrap every file IN MEMORY. Any read/reseal error returns here
        // via `?` with zero files touched.
        let mut pending: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        for (sub, ext) in [("entries", "hlj"), ("media", "hla")] {
            let dir = self.root.join(sub);
            if !dir.exists() {
                continue;
            }
            for de in fs::read_dir(&dir)? {
                let path = de?.path();
                if path.extension().and_then(|e| e.to_str()) != Some(ext) {
                    continue;
                }
                let bytes = fs::read(&path)?;
                let out = envelope::reseal_key(&self.key, &new_master, KEY_LABEL_MASTER, &bytes)?;
                pending.push((path, out));
            }
        }

        // Phase B — write temps (originals still untouched), then commit by rename.
        let mut temps: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (path, bytes) in &pending {
            let mut tmp = path.clone().into_os_string();
            tmp.push(".rekey");
            let tmp = PathBuf::from(tmp);
            if let Err(e) = fs::write(&tmp, bytes) {
                for (t, _) in &temps {
                    let _ = fs::remove_file(t);
                }
                let _ = fs::remove_file(&tmp);
                return Err(e.into()); // nothing committed → vault intact under old key
            }
            temps.push((tmp, path.clone()));
        }
        for (tmp, final_path) in &temps {
            fs::rename(tmp, final_path)?;
        }

        // Phase C — manifest + switch the live key.
        let mut manifest = self.manifest()?;
        manifest.key_mode = "master".into();
        manifest.kdf = Some(params);
        atomic_write(
            &self.root.join("vault.json"),
            serde_json::to_vec_pretty(&manifest)?.as_slice(),
        )?;
        self.key = new_master.clone();
        self.key_label = KEY_LABEL_MASTER.to_string();
        Ok((temps.len(), new_master))
    }

    // ---- format migration ----

    /// Upgrade every v1 envelope in this vault to v2, so no record is left with an
    /// unauthenticated header (FORMAT.md §11). Idempotent — files already at v2 are
    /// counted and left alone — so this is safe to run on every launch. Atomic across
    /// entries and media together. Returns (upgraded, already at v2).
    pub fn migrate_to_v2(&self) -> Result<(usize, usize)> {
        let mut files = Vec::new();
        for (sub, ext) in [("entries", "hlj"), ("media", "hla")] {
            files.extend(envelope_files(&self.root.join(sub), ext)?);
        }
        migrate_files_to_v2(&self.key, &files)
    }

    // ---- import (v0 legacy → v1 envelope) ----

    /// Decrypt a v0 (legacy desktop) entry file and save it into THIS vault. v0 seals
    /// each entry directly as `[24-byte nonce][ciphertext||tag]` under
    /// `master.subkey("entries/v1")` with AAD `"entries/v1|<id>"` — no wrapped content
    /// key, same primitives, different wrapper (see FORMAT.md §7). This vault must be
    /// open under the SAME master key; the entry is re-sealed into a v1 envelope.
    pub fn import_desktop_entry(&self, id: &str, bytes: &[u8]) -> Result<Entry> {
        let subkey = self.key.subkey(b"entries/v1");
        let aad = format!("entries/v1|{id}");
        let pt = crypto::open(&subkey, bytes, aad.as_bytes())?;
        let entry: Entry = serde_json::from_slice(&pt)?;
        self.save_entry(&entry)
    }

    /// Import every `<date>_<id>.hlj` in a v0 `entries/` directory. Idempotent:
    /// an id already present is SKIPPED (never clobbers a local edit), so running
    /// twice is harmless. Returns (imported, skipped, failed) — failures (unreadable /
    /// wrong-key files) are counted, not fatal, so one bad file can't abort the import.
    pub fn import_desktop_dir(&self, entries_dir: &Path) -> Result<(usize, usize, usize)> {
        let existing: std::collections::HashSet<String> =
            self.all_entries()?.into_iter().map(|e| e.id).collect();
        let (mut imported, mut skipped, mut failed) = (0usize, 0usize, 0usize);
        for de in fs::read_dir(entries_dir)? {
            let path = de?.path();
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) if n.ends_with(".hlj") => n,
                _ => continue,
            };
            let stem = &name[..name.len() - 4];
            let id = stem.split_once('_').map(|(_, i)| i).unwrap_or(stem);
            if existing.contains(id) {
                skipped += 1;
                continue;
            }
            match fs::read(&path)
                .map_err(Error::from)
                .and_then(|b| self.import_desktop_entry(id, &b))
            {
                Ok(_) => imported += 1,
                Err(_) => failed += 1,
            }
        }
        Ok((imported, skipped, failed))
    }

    // ---- paths ----

    fn entry_path(&self, date: &str, id: &str) -> PathBuf {
        self.root.join("entries").join(format!("{date}_{id}.hlj"))
    }

    fn purge_other_entry_files_for_id(&self, id: &str, keep: &Path) -> Result<()> {
        let dir = self.root.join("entries");
        let needle = format!("_{id}.hlj");
        for de in fs::read_dir(&dir)? {
            let path = de?.path();
            if path == keep {
                continue;
            }
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(&needle))
            {
                let _ = fs::remove_file(&path);
            }
        }
        Ok(())
    }
}

/// Every `*.<ext>` file directly inside `dir`, sorted. Missing directory → empty.
pub fn envelope_files(dir: &Path, ext: &str) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out: Vec<PathBuf> = Vec::new();
    for de in fs::read_dir(dir)? {
        let path = de?.path();
        if path.is_file() && path.extension().and_then(|e| e.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Upgrade a set of envelope files from v1 to v2 in place, atomically as a group.
///
/// This exists as a free function because a **sync container** needs it as much as a
/// vault does, and a container is not a `Store`: it is a bare directory of envelopes
/// with no manifest. Migration preserves `created` by design (§11), so a migrated
/// local file and a v1 container copy compare equal and reconcile will never push one
/// over the other — the container has to be migrated directly, once.
///
/// ATOMIC: every upgrade is computed in memory first, then written to `.v2` temp
/// files, then committed by rename. A failure anywhere before the commit leaves every
/// file exactly as it was, readable under the same key. Idempotent: files already at
/// v2 are counted, not rewritten. Returns (upgraded, already at v2).
pub fn migrate_files_to_v2(root: &MasterKey, files: &[PathBuf]) -> Result<(usize, usize)> {
    // Phase A — compute every upgrade in memory. Any error returns here, having
    // touched nothing at all.
    let mut pending: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let mut already = 0usize;
    for path in files {
        let bytes = fs::read(path)?;
        match envelope::migrate_v1_to_v2(root, &bytes)? {
            Some(upgraded) => pending.push((path.clone(), upgraded)),
            None => already += 1,
        }
    }

    // Phase B — write temps (originals untouched), then commit by rename.
    let mut temps: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (path, bytes) in &pending {
        let mut tmp = path.clone().into_os_string();
        tmp.push(".v2");
        let tmp = PathBuf::from(tmp);
        if let Err(e) = fs::write(&tmp, bytes) {
            for (t, _) in &temps {
                let _ = fs::remove_file(t);
            }
            let _ = fs::remove_file(&tmp);
            return Err(e.into()); // nothing committed → every file still v1 and readable
        }
        temps.push((tmp, path.clone()));
    }
    for (tmp, final_path) in &temps {
        fs::rename(tmp, final_path)?;
    }
    Ok((temps.len(), already))
}

/// Prove a candidate master (derived from an exported salt + the typed passphrase)
/// by decrypting ONE probe entry from an export bundle — WITHOUT touching the
/// destination vault or its keys. A mistyped passphrase fails here, loudly, before
/// any re-key. `probe_id` is the id parsed from the probe file's name; `probe_bytes`
/// are its raw v0 bytes.
pub fn verify_desktop_master(master: &MasterKey, probe_id: &str, probe_bytes: &[u8]) -> Result<()> {
    let subkey = master.subkey(b"entries/v1");
    let aad = format!("entries/v1|{probe_id}");
    crypto::open(&subkey, probe_bytes, aad.as_bytes())?;
    Ok(())
}

/// Export a DUMB, safe bundle from a vault at `vault_root` into `dest`:
///   dest/kdf.json      — Argon2id params + salt (public; needed to derive the key)
///   dest/entries/*.hlj — the sealed entry files, VERBATIM (ciphertext)
///   dest/manifest.json — { format, entryCount, contentHash }
/// No decryption happens — the bundle is ciphertext + public parameters, so the
/// transfer channel need not be trusted. Only `entries/` is exported. Returns (entry_count, content_hash_hex).
pub fn export_bundle(vault_root: &Path, dest: &Path) -> Result<(usize, String)> {
    use sha2::{Digest, Sha256};
    fs::create_dir_all(dest.join("entries"))?;

    // Pull just the `kdf` object out of the source manifest (robust to any other
    // manifest-shape differences between a v0 vault and this one).
    let vjson: serde_json::Value =
        serde_json::from_slice(&fs::read(vault_root.join("vault.json"))?)?;
    let kdf_val = vjson.get("kdf").cloned().ok_or_else(|| {
        Error::Format("source vault.json has no kdf (not passphrase-enrolled)".into())
    })?;
    let kdf: KdfParams = serde_json::from_value(kdf_val)?;
    atomic_write(
        &dest.join("kdf.json"),
        serde_json::to_vec_pretty(&kdf)?.as_slice(),
    )?;

    // Copy entry files verbatim, in sorted order, hashing name+bytes for integrity.
    let src = vault_root.join("entries");
    let mut names: Vec<String> = Vec::new();
    if src.exists() {
        for de in fs::read_dir(&src)? {
            let p = de?.path();
            if p.extension().and_then(|e| e.to_str()) == Some("hlj") {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    names.push(n.to_string());
                }
            }
        }
    }
    names.sort();
    let mut hasher = Sha256::new();
    for name in &names {
        let bytes = fs::read(src.join(name))?;
        hasher.update(name.as_bytes());
        hasher.update(&bytes);
        fs::write(dest.join("entries").join(name), &bytes)?;
    }
    let hash = format!("{:x}", hasher.finalize());
    let bundle_manifest = serde_json::json!({
        "format": "hlexport/v1",
        "entryCount": names.len(),
        "contentHash": hash,
    });
    atomic_write(
        &dest.join("manifest.json"),
        serde_json::to_vec_pretty(&bundle_manifest)?.as_slice(),
    )?;
    Ok((names.len(), hash))
}

fn sort_key(e: &Entry) -> String {
    // last_modified is ISO-8601 and sorts lexically; fall back to the date.
    e.last_modified
        .clone()
        .unwrap_or_else(|| format!("{}T00:00:00Z", e.date))
}

fn now_iso() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Write to a sibling temp file then rename — a crash never leaves a half-written
/// record.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no parent dir",
        ))
    })?;
    fs::create_dir_all(parent)?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::KEY_LABEL_DEK;

    fn tmp_root() -> PathBuf {
        let mut p = std::env::temp_dir();
        // unique-ish without Date/rand: use a counter file name via nanos-free id
        p.push(format!("hlcore-test-{}", uuid::Uuid::new_v4()));
        p
    }

    fn store() -> Store {
        Store::open(tmp_root(), MasterKey::from_bytes([3u8; 32]), KEY_LABEL_DEK).unwrap()
    }

    #[test]
    fn save_load_recent_and_search() {
        let s = store();
        s.save_entry(&Entry::new_text(
            "1".into(),
            "2026-08-05".into(),
            "test entry one".into(),
        ))
        .unwrap();
        s.save_entry(&Entry::new_text(
            "2".into(),
            "2026-08-09".into(),
            "test entry two, with the word quiet".into(),
        ))
        .unwrap();

        let recent = s.recent(10).unwrap();
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].id, "2", "newest first"); // 08-09 after 08-05

        let hits = s.search("QUIET").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].id, "2");

        assert!(s.search("nonexistent").unwrap().is_empty());
    }

    #[test]
    fn one_file_per_id_on_date_change() {
        let s = store();
        s.save_entry(&Entry::new_text(
            "x".into(),
            "2026-08-01".into(),
            "test entry one".into(),
        ))
        .unwrap();
        // same id, different date → old file must be purged
        let mut e = Entry::new_text(
            "x".into(),
            "2026-08-02".into(),
            "test entry one, moved".into(),
        );
        e.mood = 4;
        s.save_entry(&e).unwrap();
        let all = s.all_entries().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].date, "2026-08-02");
    }

    #[test]
    fn enroll_dek_to_master_keeps_entries_readable() {
        use crate::crypto::{derive_master_key, KdfParams};
        use crate::envelope::KEY_LABEL_MASTER;
        let root = tmp_root();
        let mut s = Store::open(&root, MasterKey::from_bytes([3u8; 32]), KEY_LABEL_DEK).unwrap();
        s.save_entry(&Entry::new_text(
            "1".into(),
            "2026-08-05".into(),
            "test entry before pairing".into(),
        ))
        .unwrap();
        s.save_media("aud1", "2026-08-05", &[7u8; 2048]).unwrap();
        assert_eq!(s.key_mode().unwrap(), "dek");

        let params = KdfParams::new_default();
        let (n, _master) = s
            .enroll_to_master("test-passphrase", params.clone())
            .unwrap();
        assert_eq!(n, 2, "one entry + one media resealed");
        assert_eq!(s.key_mode().unwrap(), "master");
        // live store still reads after the switch
        assert_eq!(s.all_entries().unwrap().len(), 1);

        // a fresh open with the passphrase-derived master reads the same vault —
        // this is exactly what a paired device does.
        let master = derive_master_key("test-passphrase", &params).unwrap();
        let s2 = Store::open(&root, master, KEY_LABEL_MASTER).unwrap();
        assert_eq!(
            s2.all_entries().unwrap()[0].text,
            "test entry before pairing"
        );
        assert_eq!(s2.load_media("aud1").unwrap(), vec![7u8; 2048]);

        // the wrong passphrase cannot open it
        let wrong = derive_master_key("wrong-passphrase", &params).unwrap();
        let s3 = Store::open(&root, wrong, KEY_LABEL_MASTER).unwrap();
        assert!(
            s3.all_entries().is_err(),
            "wrong passphrase must fail to decrypt"
        );
    }

    #[test]
    fn imports_a_desktop_format_entry() {
        use crate::crypto::{self, derive_master_key, KdfParams};
        use crate::envelope::KEY_LABEL_MASTER;
        // A v0 entry file: sealed directly under master.subkey("entries/v1")
        // with AAD "entries/v1|<id>" — exactly the legacy on-disk format.
        let params = KdfParams::new_default();
        let master = derive_master_key("test-shared-passphrase", &params).unwrap();
        let entry = Entry::new_text(
            "abc123".into(),
            "2026-08-05".into(),
            "test entry written on the other device".into(),
        );
        let pt = serde_json::to_vec(&entry).unwrap();
        let desktop_bytes =
            crypto::seal(&master.subkey(b"entries/v1"), &pt, b"entries/v1|abc123").unwrap();

        // A vault open under the SAME master imports and re-stores it.
        let s = Store::open(tmp_root(), master, KEY_LABEL_MASTER).unwrap();
        let imported = s.import_desktop_entry("abc123", &desktop_bytes).unwrap();
        assert_eq!(imported.text, "test entry written on the other device");
        assert_eq!(imported.id, "abc123");
        // and it reads back through the normal hl-core envelope path
        assert_eq!(
            s.recent(1).unwrap()[0].text,
            "test entry written on the other device"
        );

        // wrong master cannot import (tamper/again wrong key → error, counted not fatal)
        let wrong = derive_master_key("wrong-passphrase", &params).unwrap();
        let s2 = Store::open(tmp_root(), wrong, KEY_LABEL_MASTER).unwrap();
        assert!(s2.import_desktop_entry("abc123", &desktop_bytes).is_err());
    }

    #[test]
    fn phase2_export_probe_rekey_import_roundtrip() {
        use crate::crypto::{self, derive_master_key, KdfParams};
        use crate::envelope::KEY_LABEL_MASTER;

        // --- a v0 vault: master mode, legacy-format entry files ---
        let params = KdfParams::new_default();
        let desk_master = derive_master_key("test-shared-passphrase", &params).unwrap();
        let desk_root = tmp_root();
        fs::create_dir_all(desk_root.join("entries")).unwrap();
        let manifest = serde_json::json!({
            "formatVersion": 1, "createdAt": "2026-01-01T00:00:00Z", "keyMode": "master",
            "kdf": serde_json::to_value(&params).unwrap(),
        });
        fs::write(
            desk_root.join("vault.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let write_desk = |e: &Entry| {
            let pt = serde_json::to_vec(e).unwrap();
            let b = crypto::seal(
                &desk_master.subkey(b"entries/v1"),
                &pt,
                format!("entries/v1|{}", e.id).as_bytes(),
            )
            .unwrap();
            fs::write(
                desk_root
                    .join("entries")
                    .join(format!("{}_{}.hlj", e.date, e.id)),
                b,
            )
            .unwrap();
        };
        let mut e1 = Entry::new_text(
            "d1".into(),
            "2026-08-01".into(),
            "test entry one #private marker".into(),
        );
        e1.embed_text = Some("test entry one".into()); // the #private-stripped projection
        write_desk(&e1);
        write_desk(&Entry::new_text(
            "d2".into(),
            "2026-08-02".into(),
            "test entry two".into(),
        ));

        // --- export a dumb bundle (ciphertext + public params only) ---
        let bundle = tmp_root();
        let (count, hash) = export_bundle(&desk_root, &bundle).unwrap();
        assert_eq!(count, 2);
        assert!(bundle.join("kdf.json").exists() && bundle.join("manifest.json").exists());
        assert!(!hash.is_empty());

        // --- destination vault already holds a locally-written entry ---
        let dest_root = tmp_root();
        let dest_master =
            derive_master_key("test-local-passphrase", &KdfParams::new_default()).unwrap();
        let mut dest = Store::open(&dest_root, dest_master, KEY_LABEL_MASTER).unwrap();
        dest.save_entry(&Entry::new_text(
            "p1".into(),
            "2026-08-03".into(),
            "test entry written locally".into(),
        ))
        .unwrap();

        // --- probe: derive candidate from bundle kdf + typed passphrase ---
        let bundle_kdf: KdfParams =
            serde_json::from_slice(&fs::read(bundle.join("kdf.json")).unwrap()).unwrap();
        let probe_path = fs::read_dir(bundle.join("entries"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let probe_name = probe_path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let probe_id = probe_name
            .strip_suffix(".hlj")
            .unwrap()
            .split_once('_')
            .unwrap()
            .1;
        let probe_bytes = fs::read(&probe_path).unwrap();

        // wrong passphrase FAILS at the probe — before any re-key
        let wrong = derive_master_key("wrong-passphrase", &bundle_kdf).unwrap();
        assert!(verify_desktop_master(&wrong, probe_id, &probe_bytes).is_err());
        // right passphrase passes
        let cand = derive_master_key("test-shared-passphrase", &bundle_kdf).unwrap();
        verify_desktop_master(&cand, probe_id, &probe_bytes).unwrap();

        // --- atomic re-key to the desktop identity, then import ---
        dest.enroll_to_master("test-shared-passphrase", bundle_kdf)
            .unwrap();
        assert!(
            dest.all_entries().unwrap().iter().any(|e| e.id == "p1"),
            "local entry survives re-key"
        );

        let (imp, skip, fail) = dest.import_desktop_dir(&bundle.join("entries")).unwrap();
        assert_eq!((imp, skip, fail), (2, 0, 0));
        let ids: std::collections::HashSet<_> = dest
            .all_entries()
            .unwrap()
            .into_iter()
            .map(|e| e.id)
            .collect();
        assert!(ids.contains("d1") && ids.contains("d2") && ids.contains("p1"));

        // COVENANT: the #private-stripped embedText carried across intact
        let d1 = dest
            .all_entries()
            .unwrap()
            .into_iter()
            .find(|e| e.id == "d1")
            .unwrap();
        assert_eq!(d1.embed_text.as_deref(), Some("test entry one"));

        // idempotent: a second import skips everything
        assert_eq!(
            dest.import_desktop_dir(&bundle.join("entries")).unwrap(),
            (0, 2, 0)
        );
    }

    #[test]
    fn migrate_to_v2_is_atomic_idempotent_and_preserves_stamps() {
        use crate::envelope::{seal_envelope, EnvelopeHeader};
        let root = tmp_root();
        let key = MasterKey::from_bytes([3u8; 32]);
        let s = Store::open(&root, key.clone(), KEY_LABEL_DEK).unwrap();

        // Hand-write two v1 files, as an older build would have left them, plus one
        // v2 file written normally.
        let mut stamps = Vec::new();
        for (id, date) in [("v1a", "2026-08-01"), ("v1b", "2026-08-02")] {
            let e = Entry::new_text(id.into(), date.into(), format!("test entry {id}"));
            let created = format!("{date}T09:00:00.000Z");
            let mut h = EnvelopeHeader::new(id, date, KEY_LABEL_DEK, &created);
            h.v = 1;
            let bytes = seal_envelope(&key, &h, &serde_json::to_vec(&e).unwrap()).unwrap();
            fs::write(root.join("entries").join(format!("{date}_{id}.hlj")), bytes).unwrap();
            stamps.push(created);
        }
        s.save_entry(&Entry::new_text(
            "v2a".into(),
            "2026-08-03".into(),
            "test entry v2a".into(),
        ))
        .unwrap();

        // everything reads before the migration — v1 files are not broken, just weak
        assert_eq!(s.all_entries().unwrap().len(), 3);

        let (upgraded, already) = s.migrate_to_v2().unwrap();
        assert_eq!((upgraded, already), (2, 1));

        // every file is now v2, and `created` survived byte for byte
        for (i, (id, date)) in [("v1a", "2026-08-01"), ("v1b", "2026-08-02")]
            .iter()
            .enumerate()
        {
            let bytes = fs::read(root.join("entries").join(format!("{date}_{id}.hlj"))).unwrap();
            let h = envelope::read_header(&bytes).unwrap();
            assert_eq!(h.v, 2);
            assert_eq!(
                h.created, stamps[i],
                "reconcile orders on this; it must not move"
            );
        }
        assert_eq!(s.all_entries().unwrap().len(), 3, "content intact");

        // idempotent
        assert_eq!(s.migrate_to_v2().unwrap(), (0, 3));
    }

    #[test]
    fn media_roundtrip() {
        let s = store();
        let audio = vec![9u8; 4096];
        s.save_media("aud1", "2026-08-09", &audio).unwrap();
        assert_eq!(s.load_media("aud1").unwrap(), audio);
    }

    #[test]
    fn sealed_entries_hidden_from_search() {
        let s = store();
        let mut e = Entry::new_text("s1".into(), "2026-08-09".into(), "test entry sealed".into());
        e.sealed = Some(crate::models::SealMeta {
            seal_id: "seal-1".into(),
            sealed_at: "2026-08-09T10:00:00Z".into(),
            unseal_at: Some("2027-01-01T00:00:00Z".into()),
            kind: crate::models::SEAL_KIND_PAGE.into(),
        });
        s.save_entry(&e).unwrap();
        assert!(
            s.search("sealed").unwrap().is_empty(),
            "sealed content must not surface in search"
        );
        assert_eq!(
            s.recent(10).unwrap().len(),
            1,
            "but the sealed record still lists, so a reader can show date + seal"
        );
    }
}
