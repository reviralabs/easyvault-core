# Security policy

Please report vulnerabilities privately to support@easyvault.app with "Security" in the
subject, not in a public issue. Include steps to reproduce if you can. We'll reply within a few
days and credit you in the fix unless you'd rather not be named.

Fixed issues are listed below and in the commit history.

## Fixed

- **November 2026: thumbnails reused their item's AES-GCM nonce.** A thumbnail was encrypted
  under its item's key with the same item ID, so chunk 0 of both used the same nonce and key.
  Someone holding the encrypted files could XOR the two ciphertexts to get the XOR of the
  photo's first megabyte and its thumbnail, and recover that file's GCM authentication key. It
  did not expose the vault key, the passcode, or other items. Thumbnails now have their own key,
  and existing ones are re-encrypted on first unlock and re-uploaded on the next backup. See
  FORMAT.md, "Earlier thumbnails".
- **November 2026: files saved while locked weren't protected by the vault passcode.** Photos
  shared into the app while it was locked, and intruder photos, wait in an inbox until the next
  unlock. The inbox's private key was kept in the app's Keychain (this device only, readable
  while the phone is unlocked) rather than inside the vault, so someone who could read the
  app's Keychain on an unlocked phone could open those waiting files without the vault passcode.
  Everything already in the vault was unaffected. The key now lives in the main vault's encrypted
  index and is moved there, and deleted from the Keychain, on the first unlock with Easy Vault
  1.3. Vanish mode now also clears the inbox. See FORMAT.md, "Inbox".
- **November 2026, hardening:** an exported vault no longer fails as a whole if one item's file
  is missing on the device; and once a vault's thumbnails have all been re-encrypted, a thumbnail
  under the old key is refused instead of accepted.
