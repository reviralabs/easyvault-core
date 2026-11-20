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

The full on-disk format is in [FORMAT.md](FORMAT.md).

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
```

Every released format has a vault folder in `Tests/VaultCoreTests/Fixtures` that the tests
must keep opening, so a format change can't silently lock anyone out of their photos.

## What's not here

The app itself (SwiftUI screens, the camera, the share extension and the iCloud upload) lives
in a private repository. All the cryptography and the file format are here; the app only
supplies the Secure Enclave key, Keychain storage and the iCloud transport, through the
`DeviceBinding`, `DeviceSecretProvider` and `BackupStore` protocols.

## Reporting a security issue

Email support@easyvault.app with "Security" in the subject. Please don't open a public issue
for a vulnerability.

## License

Apache License 2.0, see [LICENSE](LICENSE). Third-party data is credited in [NOTICE](NOTICE).
