//! Deletion tombstones — how a delete crosses the keyless sync boundary.
//!
//! A tombstone is a tiny `<id>.tomb` file that lives in the SAME `entries/`
//! directory as the envelopes. It holds one line — the RFC3339 instant of the
//! delete — and carries no key and no plaintext, so it rides the shared container
//! exactly like an envelope. Every entry scan in this crate filters to `*.hlj`,
//! so a `.tomb` is invisible to entry logic; only this module reads them.
//!
//! Ids are never reused (each entry is minted with a fresh UUID), so a tombstone
//! for id `X` means `X` is gone for good: reconcile removes every `*_X.hlj` on
//! every peer and never re-pushes it. Delete therefore wins over a concurrent
//! edit — the predictable outcome for a journal (a thing you deleted does not
//! quietly come back).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::Result;

pub const EXT: &str = "tomb";

/// "now" as an RFC3339 UTC stamp, the same shape as an envelope `created`.
pub fn now_stamp() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

/// Write (or advance) `<id>.tomb` in `dir`. Idempotent: an equal or newer stamp
/// already present is left untouched. Atomic via temp + rename.
pub fn mark(dir: &Path, id: &str, at: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let path = dir.join(format!("{id}.{EXT}"));
    if let Ok(existing) = fs::read_to_string(&path) {
        if existing.trim() >= at {
            return Ok(());
        }
    }
    let tmp = dir.join(format!("{id}.{EXT}.tmp"));
    fs::write(&tmp, at.as_bytes())?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Every tombstone in `dir` as id → deleted-at (newest kept on duplicates).
pub fn read_all(dir: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return out,
    };
    for de in rd.flatten() {
        let p = de.path();
        if p.extension().and_then(|e| e.to_str()) != Some(EXT) {
            continue;
        }
        let id = match p.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };
        let at = fs::read_to_string(&p)
            .unwrap_or_default()
            .trim()
            .to_string();
        if at.is_empty() {
            continue;
        }
        match out.get(&id) {
            Some(cur) if *cur >= at => {}
            _ => {
                out.insert(id, at);
            }
        }
    }
    out
}

/// Delete every `*_<id>.hlj` envelope in `dir`. Returns how many were removed.
pub fn remove_envelopes(dir: &Path, id: &str) -> Result<usize> {
    let needle = format!("_{id}.hlj");
    let mut n = 0;
    if let Ok(rd) = fs::read_dir(dir) {
        for de in rd.flatten() {
            let p = de.path();
            let name = p.file_name().and_then(|x| x.to_str()).unwrap_or("");
            if name.ends_with(&needle) && fs::remove_file(&p).is_ok() {
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Symmetric tombstone reconcile between two `entries/` dirs: every tombstone
/// either side knows is written into both, and each tombstoned id's envelopes are
/// removed on both. Returns the number of envelope files deleted. Used for the
/// keyless phone ⇄ container pass.
pub fn reconcile_pair(a: &Path, b: &Path) -> Result<usize> {
    let mut tombs = read_all(a);
    for (id, at) in read_all(b) {
        match tombs.get(&id) {
            Some(cur) if *cur >= at => {}
            _ => {
                tombs.insert(id, at);
            }
        }
    }
    let mut deleted = 0;
    for (id, at) in &tombs {
        let _ = mark(a, id, at);
        let _ = mark(b, id, at);
        deleted += remove_envelopes(a, id)?;
        deleted += remove_envelopes(b, id)?;
    }
    Ok(deleted)
}
