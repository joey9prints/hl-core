# Vault format

This document describes the bytes on disk. It is written so that a third party can
implement a compatible reader without reading the Rust, and so that any claim made
about the format can be checked against a real file. Where this document and the
code disagree, the code is authoritative and the document is a bug — please report
it (see [SECURITY.md](SECURITY.md)).

Three layouts are described. **v2** is the current envelope (§4) and the only one any
writer emits. **v1** is the previous envelope, readable forever, whose header
authentication was weak — see §11, which documents both the weakness and the fix.
**v0** is the legacy layout written by earlier desktop releases (§7). A single vault
may hold all three, and readers detect the layout per file from its own bytes.

The reference reader, [`examples/read_vault.rs`](examples/read_vault.rs), implements
everything below and can be used as an executable version of this document.

---

## 1. Conventions

- All integers on the wire are **little-endian**, unsigned, 4 bytes.
- All base64 in the format is **standard alphabet, no padding** (`STANDARD_NO_PAD`).
- All timestamps are ISO 8601 UTC strings. Record stamps carry milliseconds
  (`%Y-%m-%dT%H:%M:%S%.3fZ`); they are compared as strings, which is why the
  fixed-width UTC form matters.
- "AAD" is the associated data of an AEAD: authenticated, not encrypted, and not
  stored — it is reconstructed by the reader and must match exactly or the open fails.

## 2. Directory layout

```
<vault-root>/
  vault.json                       plaintext manifest (§3)
  entries/
    <YYYY-MM-DD>_<id>.hlj          one file per entry
  media/
    <audioId>.hla                  one file per media blob (same envelope, §4)
```

Properties a reader may rely on:

- **One file per id.** After a write, no other `*_<id>.hlj` exists in `entries/`.
  A date change rewrites the file under the new name and removes the old one.
- **No shared mutable file** other than `vault.json`. There is no index and no
  append log; the state of the vault *is* the directory listing. This is what lets
  two devices write into one synced directory without ever touching the same file.
- **Writes are atomic.** Every file is written to a sibling temp path and then
  renamed over the target, so an interrupted write never leaves a partial record.
- The `id` is opaque to the format. In practice it is a UUID, but a reader must
  treat it as a string.

The date in the filename is a convenience for listing and is **not** authenticated
in any version. The authenticated copy of the date lives in the header (`date`,
authenticated in v2) and in the encrypted record (§8).

## 3. Keys and key modes

`vault.json`:

```json
{
  "formatVersion": 1,
  "createdAt": "2026-08-18T14:25:35.069Z",
  "keyMode": "master",
  "kdf": {
    "algo": "argon2id",
    "version": 19,
    "m_cost": 65536,
    "t_cost": 3,
    "p_cost": 4,
    "salt_b64": "fDWxNPF2pERvZBCDAe2efw"
  },
  "lastBackupAt": null
}
```

`keyMode` is either:

- **`"master"`** — the 32-byte root key is derived from a passphrase. `kdf` is
  present and is what makes the vault portable: any machine with the passphrase and
  these parameters reproduces the key.
- **`"dek"`** — the root key is a random 32-byte data-encryption key held in the
  device keystore (on iOS, the Keychain, `WhenUnlockedThisDeviceOnly` with biometric
  access control). `kdf` is absent. **No passphrase can open a `dek` vault**, on any
  machine, including the original one if the keystore entry is gone. `ThisDeviceOnly`
  deliberately excludes the key from cloud keychain sync and from encrypted device
  backups, so restoring a backup to a new device yields a vault whose files are all
  present and none of them readable. That is the intended behavior, not a defect: the
  key travels only by explicit re-enrollment (§4.4).

### 3.1 Passphrase → root key

```
root = Argon2id(
    password = passphrase (UTF-8 bytes, no normalization, no trimming),
    salt     = base64_nopad_decode(kdf.salt_b64),   // 16 bytes
    m_cost   = kdf.m_cost KiB,                      // 65536 = 64 MiB
    t_cost   = kdf.t_cost,                          // 3
    p_cost   = kdf.p_cost,                          // 4 lanes
    version  = 0x13 (19),
    output   = 32 bytes
)
```

The parameters are stored in the clear because they must be. Nothing derived from
the passphrase is stored — there is no verifier and no hash of it anywhere in the
vault. A wrong passphrase is discovered only by an AEAD tag failing to verify (§5),
which is also why a reader should probe one record before doing any work.

### 3.2 Root key → subkeys

Every purpose-specific key is HKDF-SHA256 expanded from the root, with **no salt**
(`Hkdf::<Sha256>::new(None, root)`) and a 32-byte output:

```
subkey(purpose) = HKDF-SHA256-Expand(PRK = HKDF-Extract(salt = none, IKM = root),
                                     info = purpose, L = 32)
```

Purposes used by the format:

| purpose (`info`)     | used for                                       |
|----------------------|------------------------------------------------|
| `hl-entry/wrap/v1`   | the KEK that wraps a v1 per-record content key |
| `entries/v1`         | the direct record key in the v0 layout (§7)    |

Because the KEK is derived from the root, a `dek` root and a `master` root drive the
identical code path. Nothing about the envelope depends on where the root came from.

## 4. The envelope (v2)

### 4.1 Wire layout

```
[u32 header_len][header JSON][u32 wrap_len][wrapped CEK][payload]
```

A real 456-byte entry file decomposes as:

| offset            | bytes | contents                                       |
|-------------------|-------|------------------------------------------------|
| 0                 | 4     | `header_len` = 140                              |
| 4                 | 140   | header JSON (§4.2)                              |
| 144               | 4     | `wrap_len` = 72                                 |
| 148               | 72    | wrapped CEK: 24 nonce ‖ 32 ciphertext ‖ 16 tag  |
| 220               | rest  | payload: 24 nonce ‖ ciphertext ‖ 16 tag         |

The payload runs to end of file; it carries no length prefix of its own. There is no
magic number and no trailer. A reader identifies an envelope file by reading
`header_len`, parsing the header JSON, and finding `fmt == "hl-entry"`; the header's
`v` then says which version's AADs apply.

`wrap_len` is 72 in every file written to date, but it is explicit on the wire so the
key-wrapping AEAD can change without breaking the outer parse.

### 4.2 Header

Serialized with no whitespace, fields in this order:

```json
{"v":2,"fmt":"hl-entry","aead":"xchacha20poly1305","id":"aaa111",
 "date":"2026-08-01","key":"master:v1","created":"2026-08-18T14:25:35.069Z"}
```

| field     | meaning                                                             |
|-----------|---------------------------------------------------------------------|
| `v`       | envelope version: `2` for anything newly written, `1` read-only      |
| `fmt`     | always `"hl-entry"` (media blobs use the same envelope and the same value) |
| `aead`    | always `"xchacha20poly1305"`                                         |
| `id`      | record id; bound into both AADs (§5)                                 |
| `date`    | `YYYY-MM-DD`, so a listing can be built without a key                |
| `key`     | which root wrapped the CEK: `"dek:v1"` or `"master:v1"`              |
| `created` | ISO 8601 UTC ms; the stamp sync reconciles on (§9)                   |

The header is plaintext by design: a keyless listing and a keyless sync both depend
on reading it. **In v2 every byte of it is authenticated.** The stored header bytes
are the AAD of the wrapped content key (§4.3), so altering any field — including
`created`, which is what sync reconciles on — makes the content key fail to unwrap and
the record fail to open. In v1 only `id` and `key` were bound, which is the weakness
§11 describes.

Because the header bytes are the AAD, a reader must use **the bytes as stored**, never
a re-serialization of the parsed struct: any difference in field order, spacing or
escaping would produce a different AAD and fail the tag. Field order here is the
struct's declaration order, but nothing in the format requires canonical JSON, and a
reader must not assume key order and must ignore unknown fields.

### 4.3 Sealing and opening

Sealing one record:

```
header_bytes = the exact JSON bytes written to the file, from §4.2

cek      = 32 random bytes                                  (fresh per record, per save)
payload  = XChaCha20-Poly1305_seal(key = cek,
                                   plaintext,
                                   aad = "entries/v2|payload|<id>")
wrapped  = XChaCha20-Poly1305_seal(key = subkey("hl-entry/wrap/v1"),
                                   plaintext = cek,
                                   aad = "entries/v2|wrap|<id>|" ++ header_bytes)
```

The header is authenticated **through the content key**: it is the AAD of the wrap,
not of the payload. Change a header byte and the CEK does not unwrap, so the payload
is never even reached. The reason to bind it there rather than into the payload's own
AAD is §4.4 — the header changes on every re-key, and a payload authenticated under it
would have to be re-encrypted every time a passphrase changed.

Opening reverses it: unwrap the CEK with the KEK, then decrypt the payload with the
CEK. Both AADs are rebuilt from the header, so a reader never stores them.

The KEK's HKDF purpose is still `hl-entry/wrap/v1`. The derivation was not what was
weak, and leaving it alone lets a v1 and a v2 record coexist under one root key.

Note that the CEK is regenerated on every save. Two saves of the same record produce
completely different bytes; there is no way to tell from ciphertext whether an edit
changed one character or all of them.

### 4.4 Re-keying (enrollment)

Changing the root key **re-wraps the content keys and never re-encrypts content**.
For each file: unwrap the CEK under the old root, wrap it under the new root with
the new key label, rewrite `header.key`, and leave the payload bytes byte-identical.
`vault.json` then gets the new `keyMode` and `kdf`.

The new label is written into the header **before** the re-wrap, because the
re-serialized header is itself the AAD the new wrap is authenticated under. The
re-keyed file is therefore tamper-evident under its new header, exactly as it was
under its old one.

This is how a device-key vault becomes a passphrase vault, and how one device's
passphrase identity is adopted by another. Because the payload is untouched, the
operation costs one AEAD open and seal of 32 bytes per record, whatever the size of
the record. A test asserts the payload bytes are unchanged, on a v2 file.

The whole re-key is staged in memory, then written to temp files, then committed by
rename, so a failure at any point before the commit leaves every file readable under
the old key.

## 5. Ciphers

Everything is **XChaCha20-Poly1305**: a 256-bit key, a 192-bit nonce, a 128-bit tag.

```
sealed_blob = nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)
```

Nonces are drawn from the OS CSPRNG per operation. A 192-bit random nonce makes
collision a non-issue at any realistic volume, and in v1 the question is narrower
still: each record has its own content key, so the payload nonce space is per-record
rather than shared.

Failure looks like exactly one thing: the tag does not verify and the open returns an
error. The format does not distinguish "wrong key" from "tampered file", and callers
should not claim to — both mean the bytes are not the bytes that were sealed under
the key you supplied.

AAD strings, verbatim:

| what               | AAD                                                    |
|--------------------|--------------------------------------------------------|
| v2 payload         | `entries/v2\|payload\|<id>`                              |
| v2 wrapped CEK     | `entries/v2\|wrap\|<id>\|` ++ the stored header bytes     |
| v1 payload         | `hl-entry/v1\|payload\|<id>`               (read-only)   |
| v1 wrapped CEK     | `hl-entry/v1\|wrap\|<id>\|<key label>`      (read-only)   |
| v0 record (§7)     | `entries/v1\|<id>`                                       |

The `<id>` binding is what stops a whole record being substituted for another one:
move the ciphertext of entry B into entry A's file and it will not open. The header
binding in v2 extends that to every field of the header, including the key label,
which the v1 wrap AAD had to name explicitly.

## 6. Sealed entries and capsules

A record may carry a `sealed` block (§8). It marks the record as one a reader should
present as a seal and a date rather than as content.

**This is a policy rule, not a cryptographic one.** A sealed record is encrypted
exactly like every other record, under the same key, with no additional secret and no
time-lock. Anyone holding the vault key can decrypt it, and the format offers no way
to prevent that — a "sealed until 2030" entry is unreadable to a reader that honors
the rule, and readable to one that does not.

We document this rather than implying more, and the reference reader is written to be
the first kind of reader: it reports the seal, its kind and its release date, and does
not export the contents. An implementer building on this format should decide
deliberately which kind of reader they are writing.

`sealed.kind` is `"sealed_page"` or `"capsule"`, carried as a free string so an
unknown future kind round-trips through an old reader instead of failing to parse.
`unsealAt` is optional; absent means sealed with no release date.

## 7. The v0 legacy layout

Earlier desktop releases wrote entries with no envelope: the record was sealed
directly under a subkey of the root.

```
file:  entries/<YYYY-MM-DD>_<id>.hlj
bytes: nonce (24) ‖ ciphertext ‖ tag (16)        — no header, no magic, no wrapped key
key:   subkey("entries/v1")
aad:   "entries/v1|<id>"
```

The `entries/v1` in that key purpose and AAD is a key-derivation label that predates
envelope versioning; it is unrelated to envelope v1 (§4).

The `id` comes from the filename (the portion after the first `_`, minus the `.hlj`
suffix). Because that id is bound into the AAD, a v0 file that is renamed stops
opening — the filename is effectively integrity-bound, while the date portion is not.

v0 has no per-record content key, so a v0 vault cannot be re-keyed without
re-encrypting every record; that is the reason v1 exists. It also has no header at
all, so it has no header to authenticate — the id in the filename is the only metadata
bound to the ciphertext, and the date component of the name is not. Reading v0 is
permanent: any future reader is expected to keep it, and the reference reader detects
and reads all three layouts in the same directory.

## 8. The record

The payload plaintext is a UTF-8 JSON object — the entry itself. Field names are the
serialized names, which are camelCase where they differ from the Rust field names.

| field          | type                | notes                                              |
|----------------|---------------------|----------------------------------------------------|
| `id`           | string              | matches the envelope header `id`                    |
| `date`         | string `YYYY-MM-DD` | authenticated copy of the filename date             |
| `text`         | string              | the entry                                           |
| `mood`         | integer 0–255       |                                                     |
| `moodSet`      | bool, optional      | distinguishes "unset" from a deliberate default     |
| `tags`         | array of string     |                                                     |
| `mentions`     | array of string, optional |                                               |
| `embedText`    | string, optional    | a projection of `text` for indexing                 |
| `metrics`      | object or null      | word count and derived scores; `extra` is free-form |
| `lastModified` | string, optional    | ISO 8601 UTC ms — the newest-wins merge key         |
| `marks`        | array, optional     | `{type, category, createdAt, source}`               |
| `parentId`     | string, optional    |                                                     |
| `significance` | object, optional    | extracted nouns/verbs and the model that did it     |
| `voice`        | object, optional    | `{audioId, durationSecs, mime}` → `media/<audioId>.hla` |
| `sealed`       | object, optional    | `{sealId, sealedAt, unsealAt, kind}` — see §6       |

Two rules make records forward-compatible, and a reader should follow both:

- **Optional fields are omitted, not nulled.** A record written by an older build
  simply lacks the field; it is never migrated on disk and never grows a field it
  does not use.
- **Open-ended values are strings, not enums** (`sealed.kind`, `marks[].type`). An
  unknown value must round-trip rather than fail to deserialize.

Media files (`media/<audioId>.hla`) use the identical envelope; their payload is the
raw blob rather than JSON, and their header `id` is the `audioId`.

## 9. Sync representation

A synced container holds the **same envelope files, byte for byte**. There is no
separate wire format, no re-encryption at the boundary, and nothing in the container
that is not an entry envelope: no manifest, no index, no lock file. Two devices
therefore never write the same path, and a cloud file provider never has to
manufacture a conflict copy.

Reconcile (`sync.rs`) needs **no key and never decrypts a payload**:

1. Scan both directories, parse each file's plaintext header, and map `id` → newest
   file by `header.created` (this also collapses stale same-id duplicates within one
   directory). Files that are not well-formed envelopes are quarantined here.
2. For an id present on one side only, copy the file to the other side.
3. For an id on both sides, the greater `created` string wins and its file is copied
   over; equal stamps are left alone.
4. After a pull, remove any other `*_<id>.hlj` in the destination, so a date change
   converges to one file per id. Quarantined files are exempt and never removed.
5. Copies go to a temp name and are committed by rename.

The operation is symmetric and idempotent: a second pass over a converged pair moves
nothing. Unreadable files (an un-materialized cloud placeholder, an I/O error) are
counted and retried next pass rather than treated as deletions — **reconcile never
deletes a record**, and propagates no deletions at all.

### 9.1 Quarantine

A file that cannot be trusted must not win a merge. Holding no key, reconcile can only
check that a file is a structurally well-formed envelope, which is not integrity. A
caller that *does* hold the key can supply a verifier — in practice, a closure that
tries to open the envelope — and anything failing it is **quarantined**: excluded from
the newest-wins comparison, never copied to the other side, and never deleted. A good
copy of the same record still propagates, so a corrupt or tampered file heals instead
of spreading.

With v2 this is what closes the forged-timestamp path: a header edited to claim a
newer `created` no longer opens, so a verifier rejects it and the honest copy wins.
Without a verifier the keyless reconcile still cannot tell, which is why a caller with
a key should always pass one.

### 9.2 Migrating a container

Migration to v2 preserves `created` deliberately (§11), which means a migrated local
file and a v1 container copy compare **equal**, and reconcile will never push one over
the other. A container therefore has to be migrated directly, once, rather than
waiting for sync to carry the upgrade — see `examples/migrate_v2.rs`, which takes a
bare directory of envelopes and a `--kdf` pointing at the manifest that seals them.

The consequence worth stating plainly: because reconcile works entirely on plaintext
headers, the sync path has no access to a key, and a synced container can only ever
contain ciphertext plus the metadata listed in §4.2.

## 10. Versioning

This document describes envelope version 2, envelope version 1, and the v0 legacy
layout.

A format change bumps `header.v` and adds a section here; it does not rewrite the
sections describing older versions. Old versions stay readable — v0 and v1 are both
the precedent and the commitment. A reader that encounters a `v` it does not know must
stop rather than guess at its AADs, and a reader that encounters an unknown *field*
should ignore it and carry on.

## 11. Version history

### v1 → v2: authenticating the header

**The weakness.** In v1 the AADs named only the record id and, for the wrapped key,
the key label:

```
v1 payload : "hl-entry/v1|payload|<id>"
v1 wrap    : "hl-entry/v1|wrap|<id>|<key label>"
```

Every other header field — `created`, `date`, `v`, `fmt`, `aead` — was therefore
covered by no tag at all. Anyone who could write to a vault file could edit those
fields and the record would still open, reporting the forged values. The field that
made this more than untidy is `created`: reconcile decides newest-wins by comparing
it (§9), so an attacker with write access to a shared container could restamp a stale
copy of a record into the future and have it win the merge against the real one. They
could not read the record, forge its contents, or substitute another record for it —
but they could choose which version of it survived.

**The fix.** v2 binds the stored header bytes, verbatim, into the AAD of the wrapped
content key (§4.3). Every header field is now authenticated: change one byte and the
CEK does not unwrap, so the record does not open. A forged stamp stops being a
convincing lie and becomes an unreadable file, which a verifier quarantines (§9.1)
instead of trusting.

Binding the header into the wrap rather than into the payload is what preserves cheap
re-keying (§4.4). The header changes on every re-key; a payload authenticated under it
would have to be re-encrypted every time a passphrase changed, which is the very cost
that per-record content keys exist to avoid.

**Migration.** `migrate_v1_to_v2` re-seals a v1 record as v2. Unlike a re-key this
does re-encrypt the payload, because the payload AAD changed too. Every header field
is preserved byte for byte — `created` above all, since restamping it would silently
reorder the vault. The pass is atomic as a group and idempotent, and a vault may hold
v1 and v2 records side by side while it happens.

This weakness was found while writing this document, before the format was published,
and was fixed in v2 before the first public release. No v1 vault was ever exposed to a
reader outside its owner's devices. It is written up here rather than quietly patched
because the process that caught it — specifying the bytes precisely enough for someone
else to reimplement them — is the reason this repository exists.
