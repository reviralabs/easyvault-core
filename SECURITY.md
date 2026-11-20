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
