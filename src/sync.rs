//! Byte-level reconcile between a local vault directory and a shared container
//! directory (on Apple platforms, an iCloud container).
//!
//! The container holds id-named entry envelopes plus id-named `.tomb` deletion
//! markers — no manifest, no index, no file that two devices both write. That is a
//! deliberate invariant: devices never contend on a file, so the cloud provider
//! never has to make a conflict copy.
//!
//! Reconcile needs NO key and never decrypts a payload. It compares the plaintext
//! envelope header's `created` stamp, newest wins, and moves whole files with
//! temp+atomic-rename — which is why the cloud only ever holds ciphertext (plus
//! tiny, contentless tombstones). Deletions are NOT inferred from an absent file;
//! they propagate ONLY as explicit tombstone markers (see [`crate::tombstone`]),
//! which are applied first each pass. One envelope per id per directory afterward.

//! # Quarantine
//!
//! A file that cannot be trusted must not be allowed to win a merge. Reconcile holds
//! no key, so it can only check that a file is structurally well formed — which is
//! not integrity. A caller that *does* hold the key can pass a verifier to
//! [`reconcile_with`]; anything that fails it is quarantined, meaning it is excluded
//! from the newest-wins comparison entirely, is never copied to the other side, and
//! is never deleted. A good copy of the same record still propagates normally, so a
//! tampered or corrupt file heals rather than spreading.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::envelope;
use crate::error::Result;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Entries copied container → local (arrived from another device).
    pub pulled: usize,
    /// Entries copied local → container (published for other devices).
    pub pushed: usize,
    /// Files that couldn't be read/written this pass (placeholders, IO) — retried next time.
    pub errors: usize,
    /// Files excluded from this pass as untrustworthy: malformed, or rejected by the
    /// caller's verifier. They never win newest-wins, never propagate, never deleted.
    pub quarantined: usize,
    /// Envelope files removed this pass because a tombstone marks their id deleted.
    pub deleted: usize,
}

/// A caller-supplied integrity check over a whole envelope file. Reconcile itself
/// holds no key; a caller that has one passes a closure that tries to open the
/// envelope, which is the only way to know a file is what it claims to be.
pub type Verifier<'a> = &'a dyn Fn(&[u8]) -> bool;

struct Item {
    path: PathBuf,
    created: String,
}

/// Map id → newest trustworthy file in `dir`, the set of paths quarantined, and
/// the set of paths that could not be read this pass.
///
/// A file is quarantined if it does not parse as a well-formed envelope, or if a
/// verifier was supplied and rejects it. Quarantined files are left on disk exactly
/// as they are and take no part in anything that follows. An *unreadable* file — an
/// un-materialized iCloud placeholder, say — is likewise set aside: protected from
/// purge (we can't vouch for a file we can't read) and counted as an error, so it is
/// retried on a later pass rather than silently skipped.
fn scan(
    dir: &Path,
    verify: Option<Verifier<'_>>,
) -> Result<(HashMap<String, Item>, HashSet<PathBuf>, HashSet<PathBuf>)> {
    let mut map: HashMap<String, Item> = HashMap::new();
    let mut quarantined: HashSet<PathBuf> = HashSet::new();
    let mut unreadable: HashSet<PathBuf> = HashSet::new();
    if !dir.exists() {
        return Ok((map, quarantined, unreadable));
    }
    for de in fs::read_dir(dir)? {
        let path = de?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("hlj") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            // e.g. an un-materialized cloud placeholder: don't skip it silently —
            // set it aside so purge never deletes it, count it, and retry next pass.
            Err(_) => {
                unreadable.insert(path.clone());
                continue;
            }
        };
        if !envelope::is_well_formed(&bytes) {
            quarantined.insert(path.clone());
            continue;
        }
        if let Some(verify) = verify {
            if !verify(&bytes) {
                quarantined.insert(path.clone());
                continue;
            }
        }
        let h = match envelope::read_header(&bytes) {
            Ok(h) => h,
            Err(_) => {
                quarantined.insert(path.clone());
                continue;
            }
        };
        match map.get(&h.id) {
            Some(existing) if existing.created >= h.created => {}
            _ => {
                map.insert(
                    h.id.clone(),
                    Item {
                        path: path.clone(),
                        created: h.created.clone(),
                    },
                );
            }
        }
    }
    Ok((map, quarantined, unreadable))
}

fn filename(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

/// Copy `src` into `dest_dir/filename` via temp + atomic rename (never a half file).
fn atomic_copy(src: &Path, dest_dir: &Path, name: &str) -> Result<()> {
    fs::create_dir_all(dest_dir)?;
    let bytes = fs::read(src)?;
    let final_path = dest_dir.join(name);
    let mut tmp = final_path.clone().into_os_string();
    tmp.push(".synctmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, &bytes)?;
    fs::rename(&tmp, &final_path)?;
    Ok(())
}

/// Remove any OTHER `*_<id>.hlj` in `dir` (one file per id — e.g. after a date
/// change). Quarantined files are never removed: whatever is wrong with them, it is
/// not reconcile's business to destroy the evidence.
fn purge_other(dir: &Path, id: &str, keep_name: &str, protected: &HashSet<PathBuf>) -> Result<()> {
    let needle = format!("_{id}.hlj");
    for de in fs::read_dir(dir)? {
        let p = de?.path();
        if protected.contains(&p) {
            continue;
        }
        let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if n != keep_name && n.ends_with(&needle) {
            let _ = fs::remove_file(&p);
        }
    }
    Ok(())
}

/// Reconcile `local` with `remote` using no key at all: structurally malformed files
/// are quarantined, but a file whose header has been forged cannot be detected here.
/// Prefer [`reconcile_with`] wherever a key is available.
pub fn reconcile(local: &Path, remote: &Path) -> Result<SyncReport> {
    reconcile_with(local, remote, None)
}

/// Reconcile `local` (a vault's `entries/`) with `remote` (a shared container's
/// `entries/`). Newest `created` wins; ties are left alone. Symmetric and idempotent —
/// running it repeatedly converges and does nothing once in sync.
///
/// `verify`, when supplied by a caller that holds the key, decides which files are
/// trustworthy. Anything it rejects is quarantined: excluded from newest-wins, never
/// copied over a good copy, never deleted. This is what stops a tampered file — one
/// with a forged `created` stamp, say — from winning a merge it should lose.
pub fn reconcile_with(
    local: &Path,
    remote: &Path,
    verify: Option<Verifier<'_>>,
) -> Result<SyncReport> {
    // Deletes travel as tombstones. Apply them first so a tombstoned id is gone on
    // both sides before newest-wins runs — otherwise the surviving copy would just
    // be re-pushed to the peer that deleted it.
    let deleted = crate::tombstone::reconcile_pair(local, remote)?;

    let (l, l_bad, l_unread) = scan(local, verify)?;
    let (r, r_bad, r_unread) = scan(remote, verify)?;
    let mut rep = SyncReport {
        quarantined: l_bad.len() + r_bad.len(),
        // Unreadable files (cloud placeholders / IO) — counted here and retried
        // next pass, matching the `errors` field's contract.
        errors: l_unread.len() + r_unread.len(),
        deleted,
        ..SyncReport::default()
    };
    // purge_other must never delete a file it can't vouch for: quarantined, OR
    // merely unreadable (a placeholder that will materialize on a later pass).
    let l_protected: HashSet<PathBuf> = l_bad.union(&l_unread).cloned().collect();
    let r_protected: HashSet<PathBuf> = r_bad.union(&r_unread).cloned().collect();

    let mut ids: HashSet<String> = HashSet::new();
    ids.extend(l.keys().cloned());
    ids.extend(r.keys().cloned());

    for id in ids {
        match (l.get(&id), r.get(&id)) {
            (Some(li), None) => {
                let name = filename(&li.path);
                match atomic_copy(&li.path, remote, &name) {
                    Ok(_) => rep.pushed += 1,
                    Err(_) => rep.errors += 1,
                }
            }
            (None, Some(ri)) => {
                let name = filename(&ri.path);
                match atomic_copy(&ri.path, local, &name) {
                    Ok(_) => {
                        let _ = purge_other(local, &id, &name, &l_protected);
                        rep.pulled += 1;
                    }
                    Err(_) => rep.errors += 1,
                }
            }
            (Some(li), Some(ri)) => {
                if ri.created > li.created {
                    let name = filename(&ri.path);
                    match atomic_copy(&ri.path, local, &name) {
                        Ok(_) => {
                            let _ = purge_other(local, &id, &name, &l_protected);
                            rep.pulled += 1;
                        }
                        Err(_) => rep.errors += 1,
                    }
                } else if li.created > ri.created {
                    let name = filename(&li.path);
                    match atomic_copy(&li.path, remote, &name) {
                        Ok(_) => {
                            let _ = purge_other(remote, &id, &name, &r_protected);
                            rep.pushed += 1;
                        }
                        Err(_) => rep.errors += 1,
                    }
                }
            }
            (None, None) => {}
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MasterKey;
    use crate::envelope::{seal_envelope, EnvelopeHeader, KEY_LABEL_MASTER};

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("hlcore-sync-{}", uuid::Uuid::new_v4()))
    }

    // write an entry envelope file into `dir` with a given id/date/created stamp
    fn put(dir: &Path, id: &str, date: &str, created: &str, body: &[u8]) {
        fs::create_dir_all(dir).unwrap();
        let key = MasterKey::from_bytes([7u8; 32]);
        let mut h = EnvelopeHeader::new(id, date, KEY_LABEL_MASTER, created);
        h.created = created.to_string();
        let bytes = seal_envelope(&key, &h, body).unwrap();
        fs::write(dir.join(format!("{date}_{id}.hlj")), bytes).unwrap();
    }

    #[test]
    fn reconcile_is_bidirectional_newest_wins_and_idempotent() {
        let local = tmp();
        let remote = tmp();
        // local-only, remote-only, and a shared id where remote is newer
        put(
            &local,
            "a",
            "2026-08-01",
            "2026-08-01T10:00:00Z",
            b"a-local",
        );
        put(
            &remote,
            "b",
            "2026-08-02",
            "2026-08-02T10:00:00Z",
            b"b-remote",
        );
        put(&local, "c", "2026-08-03", "2026-08-03T10:00:00Z", b"c-old");
        put(&remote, "c", "2026-08-03", "2026-08-03T12:00:00Z", b"c-new");

        let rep = reconcile(&local, &remote).unwrap();
        assert_eq!(rep.pulled, 2, "b (new) + c (newer remote)");
        assert_eq!(rep.pushed, 1, "a");
        assert_eq!(rep.errors, 0);

        // both dirs now hold a, b, c
        for dir in [&local, &remote] {
            let ids: HashSet<_> = scan(dir, None).unwrap().0.into_keys().collect();
            assert!(ids.contains("a") && ids.contains("b") && ids.contains("c"));
        }
        // c resolved to the newer bytes on the local side
        let c = fs::read(local.join("2026-08-03_c.hlj")).unwrap();
        let (_h, pt) = envelope::open_envelope(&MasterKey::from_bytes([7u8; 32]), &c).unwrap();
        assert_eq!(pt, b"c-new");

        // idempotent: a second pass moves nothing
        assert_eq!(reconcile(&local, &remote).unwrap(), SyncReport::default());
    }

    #[test]
    fn a_forged_stamp_cannot_win_a_merge_when_a_verifier_is_supplied() {
        // The attack v2 is meant to survive: someone with write access to the shared
        // container edits an entry's plaintext `created` stamp to a future date, so
        // that reconcile hands their stale copy the newest-wins race.
        let local = tmp();
        let remote = tmp();
        let key = MasterKey::from_bytes([7u8; 32]);

        put(
            &local,
            "a",
            "2026-08-01",
            "2026-08-01T12:00:00Z",
            b"the real entry",
        );
        put(
            &remote,
            "a",
            "2026-08-01",
            "2026-08-01T09:00:00Z",
            b"the stale entry",
        );

        // Forge the remote copy's stamp to 2099, changing nothing else: same lengths,
        // same wrapped key, same ciphertext. Only the plaintext header moves.
        let remote_path = remote.join("2026-08-01_a.hlj");
        let bytes = fs::read(&remote_path).unwrap();
        let hlen = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let header = String::from_utf8(bytes[4..4 + hlen].to_vec()).unwrap();
        let forged_header = header.replace("2026-08-01T09:00:00Z", "2099-08-01T09:00:00Z");
        assert_eq!(forged_header.len(), header.len());
        let mut forged = bytes.clone();
        forged.splice(4..4 + hlen, forged_header.bytes());
        fs::write(&remote_path, &forged).unwrap();

        // Keyless reconcile cannot see it: the forged stamp is simply newer, and it
        // wins. This is the residual limit of a sync layer that holds no key.
        let keyless = scan(&remote, None).unwrap().0;
        assert_eq!(keyless.get("a").unwrap().created, "2099-08-01T09:00:00Z");

        // With a verifier, the forgery fails to open and is quarantined instead.
        let verify = |b: &[u8]| envelope::open_envelope(&key, b).is_ok();
        let rep = reconcile_with(&local, &remote, Some(&verify)).unwrap();
        assert_eq!(rep.quarantined, 1, "the forged file is set aside");
        assert_eq!(rep.pulled, 0, "and it never overwrites the good local copy");
        assert_eq!(rep.pushed, 1, "the good copy propagates in its place");

        // the local record is untouched and still says what it always said
        let local_bytes = fs::read(local.join("2026-08-01_a.hlj")).unwrap();
        let (h, pt) = envelope::open_envelope(&key, &local_bytes).unwrap();
        assert_eq!(pt, b"the real entry");
        assert_eq!(h.created, "2026-08-01T12:00:00Z");

        // the quarantined file was set aside, not deleted
        assert!(
            remote_path.exists(),
            "reconcile never destroys a file it distrusts"
        );
    }

    #[test]
    fn a_malformed_file_is_quarantined_without_a_key() {
        let local = tmp();
        let remote = tmp();
        put(
            &local,
            "a",
            "2026-08-01",
            "2026-08-01T12:00:00Z",
            b"the real entry",
        );
        fs::create_dir_all(&remote).unwrap();
        fs::write(
            remote.join("2026-08-01_a.hlj"),
            b"this is not an envelope at all",
        )
        .unwrap();

        let rep = reconcile(&local, &remote).unwrap();
        assert_eq!(rep.quarantined, 1);
        assert_eq!(rep.pushed, 1, "the good copy replaces it");
        assert_eq!(rep.pulled, 0, "the junk never travels");
        let bytes = fs::read(remote.join("2026-08-01_a.hlj")).unwrap();
        assert!(envelope::open_envelope(&MasterKey::from_bytes([7u8; 32]), &bytes).is_ok());
    }

    #[test]
    fn a_tombstone_deletes_on_both_sides_and_does_not_resurrect() {
        let local = tmp();
        let remote = tmp();
        // "a" is synced on both; "b" is a normal local-only entry that must survive.
        put(&local, "a", "2026-08-01", "2026-08-01T10:00:00Z", b"to be deleted");
        put(&remote, "a", "2026-08-01", "2026-08-01T10:00:00Z", b"to be deleted");
        put(&local, "b", "2026-08-02", "2026-08-02T10:00:00Z", b"keep me");
        // a delete of "a" originated on the peer (its tombstone is in the container).
        crate::tombstone::mark(&remote, "a", "2026-08-03T09:00:00Z").unwrap();

        let rep = reconcile(&local, &remote).unwrap();
        assert!(rep.deleted >= 2, "a removed on both sides");
        // a is gone everywhere, b propagated normally
        assert!(!local.join("2026-08-01_a.hlj").exists());
        assert!(!remote.join("2026-08-01_a.hlj").exists());
        assert!(remote.join("2026-08-02_b.hlj").exists(), "b pushed to remote");
        // the tombstone reached the local side too
        assert!(local.join("a.tomb").exists());

        // idempotent + no resurrection: a stays gone, nothing new deleted or moved
        let rep2 = reconcile(&local, &remote).unwrap();
        assert_eq!(rep2.deleted, 0);
        assert_eq!((rep2.pushed, rep2.pulled), (0, 0));
        assert!(!local.join("2026-08-01_a.hlj").exists());
    }

    #[test]
    fn date_change_keeps_one_file_per_id() {
        let local = tmp();
        let remote = tmp();
        // remote has the entry under a NEW date (an edit that moved the date), newer
        put(&local, "x", "2026-08-01", "2026-08-01T10:00:00Z", b"x-old");
        put(&remote, "x", "2026-08-05", "2026-08-05T10:00:00Z", b"x-new");
        reconcile(&local, &remote).unwrap();
        // local should now hold ONLY the new-date file for x
        let xs: Vec<_> = fs::read_dir(&local)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_str().unwrap().ends_with("_x.hlj"))
            .collect();
        assert_eq!(xs.len(), 1, "one file per id after a date change");
        assert!(local.join("2026-08-05_x.hlj").exists());
    }
}
