//! Export a vault into a portable bundle: ciphertext plus the public KDF
//! parameters, and nothing else.
//!
//!   cargo run --example export -- <vault-root> <dest-dir>
//!
//! Nothing is decrypted here. The bundle contains the sealed entry files verbatim,
//! the Argon2id parameters and salt needed to re-derive the key from the passphrase,
//! and a manifest with a SHA-256 over the whole set. Because it is ciphertext plus
//! public parameters, the transfer channel does not have to be trusted.

use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: export <vault-root> <dest-dir>");
        std::process::exit(2);
    }
    match hl_core::export_bundle(Path::new(&args[1]), Path::new(&args[2])) {
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
