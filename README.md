# hl-core

The vault format and cryptographic core of [The Human Layer](https://thehumanlayer.co) —
a local, encrypted journal with on-device AI.

This repository exists so our security claims are checkable instead of assertable.
The app is proprietary. The part you have to trust is the part you can read.

## What this is

- **The encryption and key management** (`src/crypto.rs`): Argon2id passphrase KDF,
  HKDF-SHA256 subkey derivation, XChaCha20-Poly1305 AEAD, keys zeroized on drop.
- **The envelope** (`src/envelope.rs`): each record is sealed under its own random
  content key, and that content key is wrapped by a key derived from the vault root.
  The wrap is authenticated under the record's stored header bytes, so no part of the
  header can be altered without the record failing to open. Changing your passphrase
  re-wraps 32 bytes per record and never re-encrypts a word of what you wrote.
- **The vault** (`src/store.rs`): one file per record, written atomically, one file
  per id, no shared index. The state of the vault is the directory listing.
- **The sync reconcile** (`src/sync.rs`): moves whole encrypted files between a local
  vault and a shared container. It takes no key and never decrypts a payload, which
  is why a synced container can only ever hold ciphertext. A caller that holds the key
  can pass a verifier, and anything failing it is quarantined rather than merged.
- **A reference reader** (`examples/read_vault.rs`): decrypts a vault with nothing
  but the passphrase and writes it out as Markdown. No app, no account, no network.
  It reads every layout the format has ever had.

- **A migration tool** (`examples/migrate_v2.rs`): upgrades a vault or a sync
  container from the v1 envelope to v2 in place, atomically.

Everything on disk is specified in [FORMAT.md](FORMAT.md), in enough detail to write
a compatible reader without reading the Rust.

## What this is not

- Not the app. The interface, the on-device models, the reflection and composition
  pipelines, and everything that decides what to show you are proprietary and are
  not here.
- Not audited. Scrutiny is the point of publishing. See [SECURITY.md](SECURITY.md),
  which lists what we already know is worth a second opinion.

## Threat model, short form

**Protects:** vault contents at rest, on any disk or any transport, against anyone
who does not have the passphrase — including us. Keys are derived on your device and
never leave it. There is no recovery, no escrow and no backdoor: if you lose the
passphrase to a passphrase-mode vault, the contents are gone, and we cannot help you.

**Does not protect against:** a compromised device, a keylogger, malware reading
memory while the vault is unlocked, or anyone who has your passphrase. Nor does it
hide metadata: an entry file's name and its plaintext envelope header expose the
record's id, its date, and when it was last written, to anyone who can see the file.
That is the deliberate cost of a sync layer that never needs a key (FORMAT.md §4.2,
§9). That metadata is readable, but since v2 it is not editable: the header is
authenticated, and altering any of it makes the record fail to open.

Sealed entries are a policy rule kept by the reader, not a cryptographic lock. The
vault key decrypts them like anything else. See FORMAT.md §6.

## Verifying the claims

1. Read the format: [FORMAT.md](FORMAT.md).
2. Read the crypto: [`src/crypto.rs`](src/crypto.rs) and
   [`src/envelope.rs`](src/envelope.rs).
3. Check the tamper claim yourself: `cargo test v2_header_tamper_is_caught`, and
   `cargo test v1_header_tamper_was_not_caught_and_v2_catches_it`, which forges the
   same byte in each version and shows v1 accepting it and v2 refusing.
4. Decrypt your own vault without the app:

   ```
   cargo run --example read_vault -- <vault-dir> --out ./my-journal
   ```

   It prompts for the passphrase with hidden input, refuses to take it as an
   argument, proves it can open one record before it writes anything, and never
   writes inside the vault directory.
5. Check that reconcile has no key: `sync::reconcile` takes two directory paths and
   nothing else, and outside its test module `src/sync.rs` imports no cipher at all —
   only the envelope header parser. Its verifier is a closure the *caller* supplies,
   so even the hardened path keeps the key on the caller's side. Grep it.
6. Watch the network while you use the app. It makes no network calls except checking
   for its own updates. One opt-in exception: email-to-vault capture from your phone
   transits mail servers and a small ingestion relay we run; it is off by default and
   separate from the vault, the AI, and everything documented here.

## Building

```
cargo test        # 26 tests
cargo clippy --all-targets -- -D warnings
```

Requires Rust 1.77.2 or newer. CI runs the same three commands on macOS and Linux.
Nothing here is Apple-specific, even though the apps are.

## License

MIT or Apache-2.0, at your option. "The Human Layer" name and marks are not licensed
by this repository.

---

*Mirrored from our main repository; issues and PRs welcome, we sync upstream.*
