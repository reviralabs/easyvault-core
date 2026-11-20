// Opens the format-v1 fixture with open-vault.js and checks what comes out, the same as
// FormatCompatibilityTests. Run: node web/test.mjs
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = fileURLToPath(new URL('.', import.meta.url));
await import(new URL('./open-vault.js', import.meta.url));
const { openVault, parseRecoveryKey } = globalThis.EasyVaultOpener;

const folder = join(here, '../Tests/VaultCoreTests/Fixtures/format-v1/9E2D3225-CF4F-4C3F-A460-245A94A610EB');
const files = new Map();
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else files.set(relative(folder, path), new Blob([readFileSync(path)]));
  }
})(folder);

const key = '144G-J289-144G-J289-144G-J289-G';
await assert.rejects(parseRecoveryKey('144G-J289-144G-J289-144G-J289-H'), { code: 'invalidKey' });
// A well-formed key for different bytes: right shape, wrong vault.
const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const zeros = new Uint8Array(15);
const check = new Uint8Array(await crypto.subtle.digest('SHA-256', zeros))[0] & 0x1f;
await assert.rejects(openVault(files, '0'.repeat(24) + A[check]), { code: 'wrongKey' });

const vault = await openVault(files, key.toLowerCase().replace(/-/g, ' '));
assert.equal(vault.id, '9E2D3225-CF4F-4C3F-A460-245A94A610EB');
assert.deepEqual(vault.items.map((i) => i.name).sort(), ['beach.jpg', 'passport.pdf']);
assert.deepEqual(vault.albums, ['Holiday']);

const photo = vault.items.find((i) => i.name === 'beach.jpg');
const doc = vault.items.find((i) => i.name === 'passport.pdf');
assert.equal(photo.album, 'Holiday');
assert.equal(doc.album, null);
assert.equal(new TextDecoder().decode(await vault.read(photo)), 'a photo from format v1');
assert.equal(new TextDecoder().decode(await vault.thumbnail(photo)), 'its thumbnail'); // a pre-November thumbnail
assert.deepEqual(await vault.read(doc), Uint8Array.from({ length: 5000 }, (_, i) => (i * 7) & 0xff));

// A changed byte fails, rather than giving wrong content.
const tampered = new Map(files);
const itemPath = `items/${photo.id}.evf`;
const bytes = new Uint8Array(await files.get(itemPath).arrayBuffer());
bytes[bytes.length - 1] ^= 1;
tampered.set(itemPath, new Blob([bytes]));
await assert.rejects((await openVault(tampered, key)).read(photo), { code: 'damaged' });

console.log('open-vault.js: format-v1 fixture opens');
