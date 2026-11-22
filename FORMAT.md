# Easy Vault file format, version 1

How Easy Vault stores and encrypts a vault on disk. Everything here is implemented in
`Sources/VaultCore`, and `Tests/VaultCoreTests/Fixtures/format-v1` is a real vault folder
written by the shipped code, which the tests (and `evdecrypt`) open.

Conventions: JSON files use ISO 8601 dates and base64 for binary data. A UUID as bytes is its
16 bytes in RFC 4122 order. `‖` is concatenation. All AES-GCM is AES-256-GCM with a 12-byte nonce
and a 16-byte tag; "combined" means `nonce ‖ ciphertext ‖ tag`. HKDF is HKDF-SHA256 with a
32-byte output.

## Layout

```
<root>/
  device.json                 settings shared by every vault on the device
  <vault-id>/                 one folder per vault (the main vault and an optional second vault)
    vault.json                keyslots: the ways to unlock this vault
    index.evi                 the encrypted list of items and albums
    items/<item-id>.evf       each photo, video or file
    thumbs/<item-id>.evf      its thumbnail, if any
  inbox/                      files saved from other apps while the vault is locked
```

Nothing on disk says which vault is the main one and which is the second vault.

## Keys

```
passcode ─Argon2id─► stretched ─device binding─► bound ─HKDF "ev/passcode"─► passcode KEK ─┐
recovery key ─────────────────────────────────HKDF "ev/recovery"─► recovery KEK ───────────┼─► vault key (random, 32 bytes)
Face ID key (random, in the Keychain behind biometry) ─────────────────────────────────────┘        │
                                                                                                    ├─► index.evi
                                                                       item key (random, per item) ◄┘ (stored in the index)
                                                                            ├─► items/<id>.evf
                                                                            └─HKDF "ev/thumbnail"─► thumbs/<id>.evf
```

### Passcode

- Input bytes: `"pattern5x5:" ‖ dot indexes joined by ","` (dots 0–24, row by row), or
  `"password:" ‖ UTF-8 of the password in Unicode NFC`. The prefixes keep a pattern and a
  password from ever producing the same input.
- `stretched = Argon2id(input, salt, opsLimit, memLimit)`, 32 bytes, libsodium
  `crypto_pwhash` with `ARGON2ID13`. `salt` (16 bytes) and the limits are in `device.json`;
  the app uses 3 passes over 64 MiB.
- Device binding (`binding` in `device.json`):
  - `secureEnclave` (iPhone and iPad): a P-256 private scalar `p` is derived from `stretched`
    as the first valid key among `SHA-256("ev/passcode-scalar" ‖ stretched ‖ counter)`,
    counter 0, 1, …. The Secure Enclave key `d`, which can't leave the chip, computes the ECDH
    shared secret `d·p·G`. `bound = stretched ‖ HKDF(shared secret, salt "ev/device-binding",
    info "ev/secure-enclave")`. Every passcode guess needs that device's Secure Enclave.
  - `keychainSecret` (simulator only): `bound = stretched ‖ 32-byte secret from the Keychain`.
- `passcode KEK = HKDF(bound, salt = vault ID bytes, info = "ev/passcode")`.

### Recovery key

- 15 random bytes (120 bits), shown as 24 Crockford base32 characters plus a check character
  (`SHA-256(bytes)[0] & 0x1F`), grouped `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-C`. Parsing ignores
  case, dashes and spaces, and reads O as 0 and I or L as 1.
- `recovery KEK = HKDF(recovery key bytes, salt = vault ID bytes, info = "ev/recovery")`.
- Not bound to a device: this is what restores a backup on a new phone, and what
  `evdecrypt` uses.

### Face ID

A random 32-byte key kept in the Keychain behind biometry, used directly as the KEK.

## device.json

```json
{ "version": 1, "salt": "<16 bytes>", "argon2": { "opsLimit": 3, "memLimitBytes": 67108864 },
  "binding": "secureEnclave" }
```

## vault.json

```json
{ "version": 1, "id": "<vault UUID>", "createdAt": "…",
  "slots": [ { "kind": "passcode", "secretKind": "pattern", "sealed": "<base64>" },
             { "kind": "biometric", "sealed": "…" },
             { "kind": "recovery", "sealed": "…" } ] }
```

Each `sealed` is the 32-byte vault key, AES-GCM combined under that slot's KEK, with
associated data `"ev/slot/<kind>" ‖ vault ID bytes`. Contains no plaintext secrets.

## index.evi

AES-GCM combined, key = vault key, associated data `"ev/index" ‖ vault ID bytes`. The plaintext
is JSON:

```json
{ "version": 1,
  "items": [ { "id": "…", "name": "beach.jpg", "kind": "photo", "contentType": "public.jpeg",
               "byteCount": 123, "createdAt": "…", "addedAt": "…", "albumID": "…",
               "hasThumbnail": true, "key": "<32-byte item key>" } ],
  "albums": [ { "id": "…", "name": "Holiday", "createdAt": "…" } ],
  "isDuress": false, "decoyIsDuress": false, "thumbnailKeys": true,
  "inboxKey": "<32-byte X25519 private key>" }
```

`kind` is `photo`, `video` or `file`. `thumbnailKeys` says every thumbnail uses its own key
(below). Whether a vault is a Vanish-mode (duress) vault is only
in here, so it can't be seen without opening that vault. `inboxKey`, on the main vault only, is
the private key of the inbox (below). Optional fields that are missing mean `false` / none, and
readers ignore fields they don't know.

## Item files (.evf)

Used for items, thumbnails and inbox entries. A 24-byte header, then the content in chunks:

```
offset  size  field
0       4     magic "EVF1"
4       1     format version (1)
5       1     log2(chunk size), 12–24 (the app writes 20: 1 MiB chunks)
6       2     reserved, 0
8       16    item ID (UUID bytes)
24      …     chunks: AES-GCM ciphertext ‖ 16-byte tag, chunk size + 16 bytes each, the last shorter
```

- Key: for an item, its key from the index. For a thumbnail, its own key,
  `HKDF(item key, salt = item ID bytes, info = "ev/thumbnail")`: an item and its thumbnail share
  an item ID and therefore nonces, so they must not share a key.
- Nonce for chunk `i`: 3 zero bytes ‖ `i` as 8-byte big-endian ‖ 1 byte, 1 for the last
  chunk and 0 otherwise (the STREAM construction).
- Associated data: the 24-byte header.

Every item and every thumbnail has its own key, so nonces never repeat under a key.

**Earlier thumbnails.** Until November 2026, thumbnails were encrypted under the item key
itself, so a thumbnail's chunk 0 reused its item's nonce under the same key. On the first unlock
with the fixed code, each vault re-encrypts those thumbnails under their own key, replacing
each file atomically, then sets `thumbnailKeys`. Readers try the thumbnail key first and fall
back to the item key only while `thumbnailKeys` isn't set; once it is, a thumbnail under the
item key is refused. Backups compare thumbnails by checksum, so the re-encrypted ones replace
the old ones in iCloud on the next backup. Reordering, dropping or
appending chunks, or moving a file to another item, fails authentication.

## Inbox

Files saved from the share extension while the vault is locked. The extension only has the
inbox's X25519 public key. Each entry is two files named by a fresh entry ID:

- `<id>.evf`: the content, in the item format, under the entry key.
- `<id>.evm`: the 32-byte ephemeral X25519 public key ‖ AES-GCM combined JSON metadata.

`entry key = HKDF(X25519(ephemeral, inbox key), salt = entry ID bytes, info = "EasyVault inbox v1")`.

The extension only has the public key. The private key is `inboxKey` in the main vault's
encrypted index, so entries can only be opened once the main vault is unlocked; the app then
moves them into it. (Before Easy Vault 1.3 the private key was kept in the app's Keychain, outside
the vault; the first unlock with 1.3 moves it into the index and deletes the Keychain copy.)

## iCloud backup

The backup goes to the user's own private CloudKit database and is already encrypted before
it leaves the device. It holds:

- `vault.json` with only the recovery keyslot (passcode and Face ID slots are device-bound and
  useless elsewhere),
- `index.evi`, and every file under `items/` and `thumbs/`,

- `backup.json`: `{"version": 1, "updatedAt": <ISO 8601>}`, when this backup last changed. Not
  part of the vault folder,

each split into parts of up to 32 MiB named `<path>#<n>of<total>`. Joining the parts gives back
a vault folder in the layout above, which opens with the recovery key.

Every device keeps its own backup under `devices/<device ID>/` in the same store, so two
devices on one Apple Account never replace each other's (`DeviceBackupStore`). The device ID is
random and stays on the device. Restoring tries the recovery key on each device's backup; if
two hold the same vault, the newer `updatedAt` wins. Backups made before Easy Vault 1.3 sit at
the top of the store without the prefix. They still restore, and a device deletes its own once
its per-device backup is complete.

## Export

**Settings → Export encrypted vault** writes one vault folder in the layout above, zipped:
`vault.json` with only the recovery keyslot, `index.evi` (without `isDuress` and
`decoyIsDuress`, so it says nothing about a second vault, and without `inboxKey`), and the files
under `items/` and `thumbs/` that the index lists, plus a `README.txt`. It opens with the recovery
key alone. An item whose file is missing on the device is left out rather than stopping the
export; it stays listed and shows as missing when opened.

## Versions

Every JSON file has `version`, and `.evf` has a version byte. A reader rejects versions newer
than it knows. Released formats never change: a new format gets a new fixture folder in
`Tests/VaultCoreTests/Fixtures`, and the old ones must keep opening.
