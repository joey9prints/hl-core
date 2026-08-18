//! migrate_v2 — upgrade a vault or a sync container from the v1 envelope to v2.
//!
//! v1 left the envelope header unauthenticated apart from the record id, so `created`
//! and `date` could be edited undetectably; v2 binds the stored header bytes into the
//! content key's AAD, and any altered byte now fails the tag (FORMAT.md §11). This
//! tool performs that upgrade on files already written.
//!
//!   cargo run --example migrate_v2 -- <dir> [--kdf <vault.json>] [--dry-run]
//!
//! Point it at a vault root — a directory holding `vault.json` — and it migrates
//! `entries/` and `media/` together. Point it at a bare directory of envelopes, such
//! as a sync container, and pass `--kdf` with the `vault.json` whose passphrase seals
//! them. **A container has to be migrated directly**: migration preserves `created`
//! on purpose, so a migrated local file and a v1 container copy compare equal and
//! reconcile will never push one over the other.
//!
//! The upgrade is atomic as a group and idempotent. Every file is re-sealed in memory
//! first, then written to a temp file, then committed by rename, so an interruption
//! leaves every record exactly as it was and readable under the same key. Running it
//! twice is a no-op. The passphrase is prompted for, never taken from an argument.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hl_core::crypto::{derive_master_key, KdfParams, MasterKey};
use hl_core::{envelope_files, migrate_files_to_v2};

const USAGE: &str = "usage: migrate_v2 <dir> [--kdf <vault.json>] [--dry-run]\n\
                     \n\
                     \x20 <dir>              a vault root, or a bare directory of envelopes\n\
                     \x20 --kdf <vault.json> where to read the Argon2id parameters from,\n\
                     \x20                    required when <dir> has no vault.json of its own\n\
                     \x20 --dry-run          report what would change and write nothing";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e == "help" => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("migrate_v2: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (dir, kdf_path, dry_run) = parse_args()?;
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", dir.display()))?;

    // A vault root migrates entries/ and media/; a bare directory migrates itself.
    let is_vault = dir.join("vault.json").is_file();
    let manifest = match (&kdf_path, is_vault) {
        (Some(p), _) => p.clone(),
        (None, true) => dir.join("vault.json"),
        (None, false) => {
            return Err(format!(
                "{} has no vault.json, so pass --kdf <vault.json> to say which \
                 passphrase seals these files",
                dir.display()
            ))
        }
    };

    let files: Vec<PathBuf> = if is_vault && kdf_path.is_none() {
        let mut f = envelope_files(&dir.join("entries"), "hlj").map_err(|e| e.to_string())?;
        f.extend(envelope_files(&dir.join("media"), "hla").map_err(|e| e.to_string())?);
        f
    } else {
        let mut f = envelope_files(&dir, "hlj").map_err(|e| e.to_string())?;
        f.extend(envelope_files(&dir, "hla").map_err(|e| e.to_string())?);
        f
    };
    if files.is_empty() {
        return Err(format!("no envelope files found under {}", dir.display()));
    }

    let kdf = read_kdf(&manifest)?;
    let master = read_passphrase().and_then(|pass| {
        derive_master_key(&pass, &kdf).map_err(|e| format!("key derivation failed: {e}"))
    })?;

    // Probe before anything else: a wrong passphrase stops here, having written
    // nothing. Migration re-seals content, so it must never run on a doubtful key.
    if !files.iter().any(|f| opens(&master, f)) {
        return Err(format!(
            "the passphrase did not open any of the {} files here. Nothing was changed.",
            files.len()
        ));
    }

    let pending = files.iter().filter(|f| !is_v2(f)).count();
    println!(
        "{} file(s) here: {pending} to upgrade, {} already at v2",
        files.len(),
        files.len() - pending
    );
    if dry_run {
        println!("--dry-run: nothing written");
        return Ok(());
    }
    if pending == 0 {
        return Ok(());
    }

    let (upgraded, already) =
        migrate_files_to_v2(&master, &files).map_err(|e| format!("migration failed: {e}"))?;
    println!("upgraded {upgraded}, left {already} already at v2");
    Ok(())
}

fn parse_args() -> Result<(PathBuf, Option<PathBuf>, bool), String> {
    let mut dir: Option<PathBuf> = None;
    let mut kdf: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dry-run" => dry_run = true,
            "--kdf" => kdf = Some(PathBuf::from(it.next().ok_or("--kdf needs a path")?)),
            "-h" | "--help" => return Err("help".into()),
            s if s.starts_with('-') => return Err(format!("unknown option: {s}")),
            s if dir.is_none() => dir = Some(PathBuf::from(s)),
            s => return Err(format!("unexpected argument: {s}")),
        }
    }
    Ok((dir.ok_or("missing <dir>")?, kdf, dry_run))
}

fn read_kdf(manifest: &Path) -> Result<KdfParams, String> {
    let bytes =
        std::fs::read(manifest).map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not valid JSON: {e}", manifest.display()))?;
    let kdf = json.get("kdf").ok_or_else(|| {
        format!(
            "{} has no `kdf` block: this vault is sealed under a device key, not a \
             passphrase, and can only be migrated on the device that holds it",
            manifest.display()
        )
    })?;
    serde_json::from_value(kdf.clone()).map_err(|e| format!("unreadable kdf parameters: {e}"))
}

fn read_passphrase() -> Result<String, String> {
    use std::io::{BufRead, IsTerminal};
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password("Vault passphrase (hidden): ")
            .map_err(|e| format!("could not read the passphrase: {e}"));
    }
    eprintln!("reading the passphrase from stdin (stdin is not a terminal)");
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("could not read the passphrase from stdin: {e}"))?;
    let line = line.trim_end_matches(['\n', '\r']).to_string();
    if line.is_empty() {
        return Err("no passphrase on stdin".into());
    }
    Ok(line)
}

fn opens(master: &MasterKey, path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .map(|b| hl_core::envelope::open_envelope(master, &b).is_ok())
        .unwrap_or(false)
}

fn is_v2(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|b| hl_core::envelope::read_header(&b).ok())
        .map(|h| h.v >= hl_core::envelope::ENVELOPE_VERSION)
        .unwrap_or(false)
}
