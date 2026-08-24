//! Export a vault into a portable bundle: ciphertext plus the public KDF
//! parameters, and nothing else.
//!
//!   cargo run --example export -- <vault-root> <dest-dir>
//!
//! Nothing is decrypted here. The bundle contains the sealed entry files verbatim,
//! the Argon2id parameters and salt needed to re-derive the key from the passphrase,
//! and a manifest with a SHA-256 over the whole set. Because it is ciphertext plus
//! public parameters, the transfer channel does not have to be trusted.
//!
//! The destination must be OUTSIDE the vault directory — the tool refuses otherwise,
//! so the bundle is never written among the files it is copying or swept into its
//! own content hash.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: export <vault-root> <dest-dir>");
        std::process::exit(2);
    }
    let vault = Path::new(&args[1]);
    let dest = Path::new(&args[2]);
    if dest_inside_vault(vault, dest) {
        eprintln!(
            "refusing to export into the vault directory ({}); choose a dest outside it",
            args[1]
        );
        std::process::exit(2);
    }
    match hl_core::export_bundle(vault, dest) {
        Ok((n, hash)) => {
            println!("exported {n} entries -> {}", args[2]);
            println!("contentHash {hash}");
        }
        Err(e) => {
            eprintln!("export failed: {e}");
            std::process::exit(1);
        }
    }
}

/// True if `dest` is the vault directory or lives inside it. Compares canonical
/// paths so `.`/`..`/symlinks can't slip past; `dest` need not exist yet — its
/// existing parent is canonicalized and the final component rejoined.
fn dest_inside_vault(vault: &Path, dest: &Path) -> bool {
    let v = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
    let d = dest
        .canonicalize()
        .unwrap_or_else(|_| match (dest.parent(), dest.file_name()) {
            (Some(parent), Some(name)) => parent
                .canonicalize()
                .unwrap_or_else(|_| parent.to_path_buf())
                .join(name),
            _ => dest.to_path_buf(),
        });
    d == v || d.starts_with(&v)
}
