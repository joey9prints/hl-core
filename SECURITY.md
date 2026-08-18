# Security policy

## Reporting

Email **security@thehumanlayer.co**. You will get a reply from a person within 72
hours. Please give us reasonable time to fix an issue before disclosing it publicly,
and tell us how you would like to be credited, including not at all.

There is no bounty program. We would rather say that plainly than imply one.

## Scope

In scope, and the reason this repository exists:

- `src/crypto.rs`, `src/envelope.rs`, `src/store.rs`, `src/sync.rs`
- the format as specified in [FORMAT.md](FORMAT.md) — including any place the
  document and the code disagree, which is always a bug in one of them
- `examples/read_vault.rs`

The shipped app is closed source but its **claims** are in scope. If you can show
that the app sends data it says it does not send, or writes something to disk that
this format says is encrypted, that is a report we want, and the absence of source
is not a reason to skip it.

## Status

**Not independently audited.** Publishing is the first step toward that, not a
substitute for it. It has already been worth it once: item 1 below is a flaw that
writing the format documentation exposed, and that was fixed before this repository
was ever public.

These are the things we already believe are worth another pair of eyes. Listing them
is not a disclaimer — they are the questions we would ask first if this were someone
else's code.

1. **The envelope header was unauthenticated in v1 — found here, fixed before
   release.** Writing FORMAT.md turned up a real flaw: v1 bound only the record id
   and the key label into an AAD, leaving `created`, `date`, `v`, `fmt` and `aead`
   covered by no tag. `created` is what sync reconcile uses for newest-wins, so
   anyone with write access to a shared container could restamp a stale copy into the
   future and win the merge against the real record. They could not read it, forge
   its contents, or substitute another record — but they could choose which version
   survived.

   **v2 binds the stored header bytes, verbatim, into the AAD of the wrapped content
   key.** Alter any header byte and the content key no longer unwraps, so the record
   does not open. Writers emit v2 only; v1 and v0 stay readable forever; existing
   records migrate in place. See FORMAT.md §11 for the full write-up and §4.3 for the
   construction. What we would value review on is the construction itself, not the
   decision to fix it.

2. **Reconcile still trusts a plaintext timestamp when it has no key.** v2 makes a
   forged header fail to open, which is what lets a caller holding the key quarantine
   it (FORMAT.md §9.1). But reconcile is deliberately keyless, and a caller that
   passes no verifier still orders records by a stamp it cannot authenticate. We
   think keeping the sync path keyless and pushing verification to the caller is the
   right shape, and we would like that specific trade-off argued with.

3. **Argon2id parameters: m = 64 MiB, t = 3, p = 4.** Comfortably above the common
   19 MiB floor, and well short of what a machine with memory to spare could afford.
   They are stored per vault so they can be raised for new vaults, but there is no
   upgrade path that re-derives an existing vault at higher cost.
4. **The AEAD is not key-committing.** XChaCha20-Poly1305 offers no key commitment,
   so a ciphertext can in principle be made to open under two different keys by
   someone who chooses both. Nothing in this format's threat model turns on that
   today, and we would rather hear why we are wrong about it.
5. **Sealed entries are policy, not cryptography** (FORMAT.md §6). The vault key
   decrypts them. Only the reader's behavior keeps them sealed. We say this in the
   product too, and we would treat any interface that implies otherwise as a bug.
6. **Plaintext is not zeroized.** Keys are (`MasterKey` and `SubKey` zeroize on
   drop, and content keys are wiped after use), but decrypted record text is an
   ordinary `String` and lives in the heap until it is dropped. `Store::all_entries`
   decrypts every record into memory, so a search touches the whole vault in the
   clear.
7. **No passphrase verifier, by design.** A wrong passphrase is detected only by a
   failed AEAD tag. Nothing derived from the passphrase is stored anywhere in the
   vault. The cost is that a reader cannot tell a wrong passphrase from a corrupt
   file, and should say so rather than guess.
8. **`keyMode: "dek"` vaults are unrecoverable by design** (FORMAT.md §3). The key
   lives in the device keystore, marked so that it is excluded from cloud keychain
   sync and from encrypted device backups. Restoring a backup to a new device gives
   you every file and no way to read any of them. We consider loosening that
   accessibility class a security regression, not a usability fix.
9. **Dependencies are not pinned and `Cargo.lock` is not committed** (this is a
   library). The crypto dependencies are the RustCrypto crates at caret versions.

## What a report does not need to argue

That losing the passphrase loses the vault, that an unlocked device is readable, or
that file names and envelope headers expose dates and ids. Those are documented
properties of the design, in the README threat model and in FORMAT.md §4.2. If you
think one of them is a worse trade than we think it is, that is a conversation worth
having — just tell us that is the argument you are making.
