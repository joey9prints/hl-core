//! read_vault — decrypt a Human Layer vault with nothing but the passphrase.
//!
//! This file is the answer to "what happens to my journal if the company goes away".
//! It is a complete, standalone reader: point it at a vault directory, type the
//! passphrase, and it writes your entries out as plain Markdown (or JSON) that any
//! text editor can open. It depends on nothing but this crate — no app, no account,
//! no network. Everything it does is described in FORMAT.md, so it doubles as an
//! executable specification: if the document and this reader ever disagree, one of
//! them is a bug. It reads every vault layout there has ever been — the current v2
//! envelope, the v1 envelope, and the v0 legacy format written by earlier desktop
//! releases — detecting each file's format from its own bytes.
//!
//!   cargo run --example read_vault -- <vault-dir> [--out <dir>] [--json]
//!
//! With no `--out` the export goes to stdout; with `--out` it is written as one file
//! per entry, named `YYYY-MM-DD-<id>.md`. The tool never writes inside the vault
//! directory and never modifies a vault file. The passphrase is prompted for with
//! hidden input and is never accepted as an argument: secrets do not belong in argv,
//! shell history, or a process listing. When stdin is not a terminal the passphrase is
//! read as a single line from stdin instead, so the reader can be scripted.
//!
//! Sealed entries are reported, not exported. Sealing in this format is a policy
//! rule rather than a cryptographic one (FORMAT.md §6) — the vault key does decrypt
//! them — so a reference reader that dumped their contents would quietly turn every
//! seal into a suggestion. It prints the seal and its release date instead.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use hl_core::crypto::{self, derive_master_key, KdfParams, MasterKey};
use hl_core::envelope;
use hl_core::models::Entry;

const USAGE: &str = "usage: read_vault <vault-dir> [--out <dir>] [--json]\n\
                     \n\
                     \x20 <vault-dir>   a vault root (the directory holding vault.json and entries/)\n\
                     \x20 --out <dir>   write one file per entry into <dir> (default: stdout)\n\
                     \x20 --json        emit the decrypted record as JSON instead of Markdown\n\
                     \n\
                     The passphrase is prompted for. It is never read from an argument.";

struct Args {
    vault: PathBuf,
    out: Option<PathBuf>,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut vault: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut json = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--out" => {
                let d = it.next().ok_or("--out needs a directory")?;
                out = Some(PathBuf::from(d));
            }
            "-h" | "--help" => return Err("help".into()),
            s if s.starts_with('-') => return Err(format!("unknown option: {s}")),
            s if vault.is_none() => vault = Some(PathBuf::from(s)),
            s => return Err(format!("unexpected argument: {s}")),
        }
    }
    Ok(Args {
        vault: vault.ok_or("missing <vault-dir>")?,
        out,
        json,
    })
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if e != "help" {
                eprintln!("read_vault: {e}\n");
            }
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("read_vault: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), String> {
    let vault = args
        .vault
        .canonicalize()
        .map_err(|e| format!("cannot open {}: {e}", args.vault.display()))?;

    // Refuse to write anywhere inside the vault. The reader is read-only with
    // respect to the vault, and that must hold even if --out points into it.
    if let Some(out) = &args.out {
        let resolved = resolve_out(out)?;
        if resolved == vault || resolved.starts_with(&vault) {
            return Err("--out points inside the vault; refusing to write into a vault".into());
        }
    }

    let kdf = read_kdf(&vault)?;
    let files = entry_files(&vault)?;
    if files.is_empty() {
        return Err(format!(
            "no entries found in {}",
            vault.join("entries").display()
        ));
    }

    let passphrase = read_passphrase()?;
    let master =
        derive_master_key(&passphrase, &kdf).map_err(|e| format!("key derivation failed: {e}"))?;
    drop(passphrase);

    // Probe first: prove the passphrase opens at least one entry before creating a
    // directory, writing a file, or printing anything. A wrong passphrase stops here.
    if !files.iter().any(|f| decrypt(&master, f).is_some()) {
        return Err(format!(
            "the passphrase did not decrypt any of the {} entries in this vault.\n\
             Nothing was written. (If this vault is sealed under a device key rather \
             than a passphrase, no passphrase can open it — see FORMAT.md §3.)",
            files.len()
        ));
    }

    if let Some(out) = &args.out {
        std::fs::create_dir_all(out)
            .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    }

    let mut written = 0usize;
    let mut sealed = 0usize;
    let mut pre_v2 = 0usize;
    let mut failed: Vec<String> = Vec::new();

    for path in &files {
        let Some(rec) = decrypt(&master, path) else {
            failed.push(name_of(path));
            continue;
        };
        if rec.entry.sealed.is_some() {
            sealed += 1;
        }
        if rec.format != "v2-envelope" {
            pre_v2 += 1;
        }
        let body = if args.json {
            render_json(&rec)
        } else {
            render_markdown(&rec)
        };
        match &args.out {
            Some(dir) => {
                let ext = if args.json { "json" } else { "md" };
                let file = dir.join(format!("{}.{ext}", basename(&rec.entry)));
                std::fs::write(&file, body)
                    .map_err(|e| format!("cannot write {}: {e}", file.display()))?;
            }
            None => print!("{body}"),
        }
        written += 1;
    }

    let where_to = match &args.out {
        Some(d) => format!("{}", d.display()),
        None => "stdout".to_string(),
    };
    eprintln!("\nread {written} of {} entries -> {where_to}", files.len());
    if sealed > 0 {
        eprintln!("{sealed} sealed, reported but not exported (FORMAT.md §6)");
    }
    if pre_v2 > 0 {
        eprintln!(
            "note: {pre_v2} record(s) predate the v2 envelope and so have no authenticated \
             header (FORMAT.md §11). They read correctly; the app upgrades them in place."
        );
    }
    if !failed.is_empty() {
        eprintln!(
            "{} file(s) could not be decrypted: {}",
            failed.len(),
            failed.join(", ")
        );
    }
    let media = vault.join("media");
    if media.is_dir()
        && std::fs::read_dir(&media)
            .map(|d| d.count() > 0)
            .unwrap_or(false)
    {
        eprintln!("note: this vault also holds encrypted media in media/, which this reader does not export");
    }
    Ok(())
}

/// The passphrase is read from the terminal with echo off, or, when stdin is not a
/// terminal, as a single line from stdin so the reader can be scripted. It is never
/// taken from an argument: argv is visible in shell history and in a process listing.
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

/// Resolve `--out` to an absolute path without requiring it to exist yet. Canonicalize
/// the nearest ancestor that does exist, then re-append the rest, so that a nested new
/// directory still gets checked against the vault root rather than failing outright.
fn resolve_out(out: &Path) -> Result<PathBuf, String> {
    let mut existing = out.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name().map(|n| n.to_os_string()) else {
            break;
        };
        rest.push(name);
        existing = match existing.parent() {
            Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
            _ => PathBuf::from("."),
        };
    }
    let mut resolved = existing
        .canonicalize()
        .map_err(|e| format!("cannot resolve --out ({}): {e}", existing.display()))?;
    for name in rest.iter().rev() {
        resolved.push(name);
    }
    Ok(resolved)
}

// ---- reading the vault ----

/// The Argon2id parameters live in plaintext in `vault.json`; they have to, because
/// they are what lets the passphrase reproduce the key. Only the salt and cost
/// parameters are stored — never the key, never a verifier for the passphrase.
fn read_kdf(vault: &Path) -> Result<KdfParams, String> {
    let path = vault.join("vault.json");
    let bytes = std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    let kdf = json.get("kdf").ok_or_else(|| {
        format!(
            "{} has no `kdf` block, so this vault is not sealed under a passphrase.\n\
             A vault in `dek` key mode is sealed under a key held in the device keystore \
             and cannot be opened by passphrase on another machine (FORMAT.md §3).",
            path.display()
        )
    })?;
    serde_json::from_value(kdf.clone()).map_err(|e| format!("unreadable kdf parameters: {e}"))
}

fn entry_files(vault: &Path) -> Result<Vec<PathBuf>, String> {
    let dir = vault.join("entries");
    let rd = std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|d| d.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("hlj"))
        .collect();
    out.sort();
    Ok(out)
}

struct Record {
    entry: Entry,
    /// Which on-disk layout this file used: "v2-envelope", "v1-envelope" or "v0-legacy".
    format: String,
    /// The envelope header's `created` stamp; v0 files have no header.
    created: Option<String>,
}

/// Decrypt one entry file, detecting its layout from its own bytes. A v1 or v2
/// envelope self-describes in a plaintext header; anything else is tried as a v0
/// file, whose AAD is derived from the id in the filename.
fn decrypt(master: &MasterKey, path: &Path) -> Option<Record> {
    let bytes = std::fs::read(path).ok()?;

    if envelope::read_header(&bytes).is_ok() {
        let (header, plaintext) = envelope::open_envelope(master, &bytes).ok()?;
        return Some(Record {
            entry: serde_json::from_slice(&plaintext).ok()?,
            format: format!("v{}-envelope", header.v),
            created: Some(header.created),
        });
    }

    let id = legacy_id(path)?;
    let aad = format!("entries/v1|{id}");
    let plaintext = crypto::open(&master.subkey(b"entries/v1"), &bytes, aad.as_bytes()).ok()?;
    Some(Record {
        entry: serde_json::from_slice(&plaintext).ok()?,
        format: "v0-legacy".to_string(),
        created: None,
    })
}

/// v0 files are named `<date>_<id>.hlj`, and the id is bound into the AAD — so the
/// filename is integrity-protected in practice: rename the file and it stops opening.
fn legacy_id(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".hlj")?;
    Some(match stem.split_once('_') {
        Some((_date, id)) => id.to_string(),
        None => stem.to_string(),
    })
}

fn name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("?")
        .to_string()
}

// ---- rendering ----

fn basename(entry: &Entry) -> String {
    format!("{}-{}", safe(&entry.date), safe(&entry.id))
}

/// Ids and dates come out of the decrypted record, so they are trusted only as far
/// as the vault is. Keep them to characters that cannot escape the output directory.
fn safe(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches('-').to_string();
    if cleaned.is_empty() {
        "untitled".to_string()
    } else {
        cleaned.chars().take(80).collect()
    }
}

fn render_markdown(rec: &Record) -> String {
    let e = &rec.entry;
    let mut fm: BTreeMap<&str, String> = BTreeMap::new();
    fm.insert("id", yaml_str(&e.id));
    fm.insert("date", yaml_str(&e.date));
    fm.insert("format", yaml_str(&rec.format));
    fm.insert("mood", e.mood.to_string());
    if let Some(c) = &rec.created {
        fm.insert("created", yaml_str(c));
    }
    if let Some(m) = &e.last_modified {
        fm.insert("modified", yaml_str(m));
    }
    if let Some(p) = &e.parent_id {
        fm.insert("parent", yaml_str(p));
    }
    if !e.tags.is_empty() {
        fm.insert("tags", yaml_list(&e.tags));
    }
    let mut flags: Vec<String> = Vec::new();
    if e.sealed.is_some() {
        flags.push("sealed".into());
    }
    if e.voice.is_some() {
        flags.push("voice".into());
    }
    if !e.marks.is_empty() {
        flags.push("marked".into());
    }
    if !flags.is_empty() {
        fm.insert("flags", yaml_list(&flags));
    }

    let mut out = String::from("---\n");
    for (k, v) in &fm {
        out.push_str(&format!("{k}: {v}\n"));
    }
    out.push_str("---\n\n");
    out.push_str(&body_text(rec));
    out.push('\n');
    out
}

fn body_text(rec: &Record) -> String {
    match &rec.entry.sealed {
        Some(seal) => {
            let until = seal
                .unseal_at
                .as_deref()
                .map(|d| format!("sealed until {d}"))
                .unwrap_or_else(|| "sealed with no release date".to_string());
            format!(
                "[This entry is {} ({}, sealed {}). Its contents are not exported: \
                 the seal is a rule this reader keeps, not a lock it could pick. \
                 See FORMAT.md §6.]",
                until, seal.kind, seal.sealed_at
            )
        }
        None => rec.entry.text.clone(),
    }
}

fn render_json(rec: &Record) -> String {
    let e = &rec.entry;
    let value = if let Some(seal) = &e.sealed {
        serde_json::json!({
            "id": e.id,
            "date": e.date,
            "format": rec.format,
            "created": rec.created,
            "sealed": seal,
            "note": "sealed; contents not exported by the reference reader (FORMAT.md §6)",
        })
    } else {
        let mut v = serde_json::to_value(e).unwrap_or(serde_json::Value::Null);
        if let Some(obj) = v.as_object_mut() {
            obj.insert("_format".into(), serde_json::json!(rec.format));
            if let Some(c) = &rec.created {
                obj.insert("_created".into(), serde_json::json!(c));
            }
        }
        v
    };
    let mut s = serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

fn yaml_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn yaml_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|i| yaml_str(i)).collect();
    format!("[{}]", inner.join(", "))
}
