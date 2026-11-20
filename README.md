# Easy Vault core

The encryption, file format and vault logic of [Easy Vault](https://easyvault.app), an
encrypted photo vault for iPhone and iPad. This is the code that encrypts your photos in the
app, published so anyone can check how it works, and so your files never depend on the app
existing.

- **AES-256-GCM** for every photo, video and file, each with its own random key, in 1 MiB
  authenticated chunks.
- **Argon2id** turns your pattern or password into a key, and the result is bound to the
  iPhone's **Secure Enclave**, so passcode guesses only work on your device.
- A **recovery key** (120 random bits) that isn't tied to any device: it opens your backup on a
  new phone, and opens a vault folder with `evdecrypt`, without the app.
- No account and no servers. Backups go to your own iCloud, already encrypted.
- **No lock-in.** Your photos are never trapped in the app. Even without Easy Vault, your
  recovery key opens them.

The full on-disk format is in [FORMAT.md](FORMAT.md).

## Open a vault without the app

In Easy Vault, **Settings → Export encrypted vault** saves the whole vault as one .zip, still
encrypted. Unzip it, then either:

- **In a browser:** open [easyvault.app/open](https://easyvault.app/open), or `web/index.html`
  from this repository (it works offline, straight from disk, in English, German, Spanish, Portuguese, Dutch and Italian). Choose the folder and type the
  recovery key. It uses only the browser's built-in Web Crypto, and the hosted page is served
  with a Content-Security-Policy that blocks it from sending anything.
- **On the command line:** `evdecrypt`, below.

## evdecrypt

A command-line tool that decrypts a vault folder with its recovery key and writes every item
back out under its original name, in a folder per album. Nothing leaves your computer.

```sh
swift run evdecrypt <vault-folder> <recovery-key> <output-folder>
```

Try it on the sample vault the tests use (its recovery key is fixed, for testing):

```sh
swift run evdecrypt Tests/VaultCoreTests/Fixtures/format-v1/9E2D3225-CF4F-4C3F-A460-245A94A610EB \
  144G-J289-144G-J289-144G-J289-G out
```

## Build and test

Swift 6.0 or later on macOS, or on Linux with `libsodium-dev` installed.

```sh
swift test
node web/test.mjs   # the browser opener, against the same sample vault
```

Every released format has a vault folder in `Tests/VaultCoreTests/Fixtures` that the tests
must keep opening, so a format change can't silently lock anyone out of their photos.

## What's not here

The app itself (SwiftUI screens, the camera, the share extension and the iCloud upload) lives
in a private repository. All the cryptography and the file format are here; the app only
supplies the Secure Enclave key, Keychain storage and the iCloud transport, through the
`DeviceBinding`, `DeviceSecretProvider` and `BackupStore` protocols.

## Security notes

What this protects: the files on the device and in iCloud. Without your pattern or password
and that device's Secure Enclave, or your recovery key, they're unreadable.

What it doesn't:

- **Someone with your unlocked vault.** Once it's open, it's open.
- **Guessing on your own phone.** Argon2id makes each guess slow (about half a second), and the
  app adds waiting time after 5 wrong tries, but a short pattern can still be guessed by someone
  with your phone and a lot of time. Use a longer pattern or a password.
- **Sizes and counts.** File sizes and the number of items are visible to anyone with the files;
  names, dates, albums and content are not.
- **Memory.** Keys are dropped when the vault locks, but Swift doesn't guarantee they're wiped
  from memory immediately.

## Reporting a security issue

Email support@easyvault.app with "Security" in the subject. Please don't open a public issue
for a vulnerability.

## License

Apache License 2.0, see [LICENSE](LICENSE). Third-party data is credited in [NOTICE](NOTICE).
