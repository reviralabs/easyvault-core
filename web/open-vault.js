// Opens an Easy Vault folder with its recovery key, in the browser, without the app.
// The same steps as Vault.open(folder:recoveryKey:) in Sources/VaultCore; FORMAT.md has the
// details. Uses only the browser's built-in Web Crypto, and never sends anything anywhere.
//
// A plain script (not a module), so index.html also works opened straight from disk.
(function () {
  'use strict';
  const subtle = globalThis.crypto.subtle;
  const utf8 = new TextEncoder();
  const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const TAG = 16, HEADER = 24;

  class OpenError extends Error {
    constructor(code, message) { super(message); this.code = code; }
  }

  // Recovery key: 24 Crockford base32 characters (120 bits) plus a check character, any case,
  // dashes and spaces ignored, O read as 0 and I or L as 1.
  async function parseRecoveryKey(text) {
    const symbols = [...text.toUpperCase()]
      .filter((c) => c !== '-' && !/\s/.test(c))
      .map((c) => (c === 'O' ? '0' : c === 'I' || c === 'L' ? '1' : c));
    const values = symbols.map((c) => ALPHABET.indexOf(c));
    if (values.length !== 25 || values.includes(-1)) throw new OpenError('invalidKey', 'Not a recovery key.');
    const bytes = new Uint8Array(15);
    let buffer = 0, bits = 0, n = 0;
    for (const v of values.slice(0, 24)) {
      buffer = ((buffer << 5) | v) & 0xffff;
      bits += 5;
      if (bits >= 8) { bits -= 8; bytes[n++] = (buffer >> bits) & 0xff; }
    }
    const hash = new Uint8Array(await subtle.digest('SHA-256', bytes));
    if ((hash[0] & 0x1f) !== values[24]) throw new OpenError('invalidKey', 'The recovery key has a typo.');
    return bytes;
  }

  function uuidBytes(uuid) {
    const hex = uuid.replace(/-/g, '');
    if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new OpenError('damaged', 'Invalid ID.');
    return Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
  }

  function base64(text) {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  }

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }

  async function hkdf(ikm, salt, info) {
    const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8.encode(info) }, key, 256));
  }

  async function aesKey(raw) {
    return subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
  }

  // nonce ‖ ciphertext ‖ tag
  async function openCombined(key, combined, aad) {
    return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: combined.slice(0, 12), additionalData: aad, tagLength: 128 }, key, combined.slice(12)));
  }

  // An .evf file, chunk by chunk (STREAM): nonce = 3 zero bytes ‖ 8-byte big-endian index ‖
  // final flag, associated data = the 24-byte header. Calls onChunk with each plaintext chunk.
  async function decryptFile(blob, itemID, rawKey, onChunk) {
    const header = new Uint8Array(await blob.slice(0, HEADER).arrayBuffer());
    const magic = String.fromCharCode(...header.slice(0, 4));
    if (blob.size < HEADER + TAG || magic !== 'EVF1') throw new OpenError('damaged', 'Not an Easy Vault item file.');
    if (header[4] !== 1 || header[5] < 12 || header[5] > 24 || header[6] || header[7]) throw new OpenError('damaged', 'Unknown item format.');
    if (!uuidBytes(itemID).every((b, i) => b === header[8 + i])) throw new OpenError('damaged', 'Item file belongs to another item.');
    const key = await aesKey(rawKey);
    const sealedSize = 2 ** header[5] + TAG;
    for (let offset = HEADER, index = 0; ; offset += sealedSize, index++) {
      const end = Math.min(offset + sealedSize, blob.size);
      const final = end === blob.size;
      if (end - offset < TAG) throw new OpenError('damaged', 'Item file is cut short.');
      const nonce = new Uint8Array(12);
      new DataView(nonce.buffer).setBigUint64(3, BigInt(index));
      nonce[11] = final ? 1 : 0;
      let chunk;
      try {
        chunk = await subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 }, key, await blob.slice(offset, end).arrayBuffer());
      } catch {
        throw new OpenError('damaged', 'Item file was damaged or changed.');
      }
      await onChunk(new Uint8Array(chunk));
      if (final) return;
    }
  }

  async function readAll(blob, itemID, rawKey) {
    const chunks = [];
    await decryptFile(blob, itemID, rawKey, (c) => { chunks.push(c); });
    return concat(...chunks);
  }

  // files: Map of path inside the vault folder ("vault.json", "items/<id>.evf", …) to a Blob.
  async function openVault(files, recoveryKeyText) {
    const recoveryKey = await parseRecoveryKey(recoveryKeyText);
    const headerFile = files.get('vault.json'), indexFile = files.get('index.evi');
    if (!headerFile || !indexFile) throw new OpenError('noVault', 'No vault.json and index.evi in this folder.');
    const header = JSON.parse(await headerFile.text());
    if (header.version > 1) throw new OpenError('newer', 'Made by a newer version of Easy Vault.');
    const vaultID = uuidBytes(header.id);
    const slot = (header.slots || []).find((s) => s.kind === 'recovery');
    if (!slot) throw new OpenError('noRecoverySlot', 'This vault has no recovery key.');

    let vaultKey;
    try {
      const kek = await aesKey(await hkdf(recoveryKey, vaultID, 'ev/recovery'));
      vaultKey = await openCombined(kek, base64(slot.sealed), concat(utf8.encode('ev/slot/recovery'), vaultID));
    } catch {
      throw new OpenError('wrongKey', 'This recovery key doesn’t open this vault.');
    }
    let index;
    try {
      const json = await openCombined(await aesKey(vaultKey), new Uint8Array(await indexFile.arrayBuffer()), concat(utf8.encode('ev/index'), vaultID));
      index = JSON.parse(new TextDecoder().decode(json));
    } catch {
      throw new OpenError('damaged', 'The vault’s list of items is damaged.');
    }
    if (index.version > 1) throw new OpenError('newer', 'Made by a newer version of Easy Vault.');

    const albums = new Map((index.albums || []).map((a) => [a.id, a.name]));
    const items = (index.items || [])
      .map((item) => ({
        id: item.id, name: item.name, kind: item.kind, contentType: item.contentType, size: item.byteCount,
        createdAt: item.createdAt, addedAt: item.addedAt, album: albums.get(item.albumID) || null,
        hasThumbnail: !!item.hasThumbnail, key: base64(item.key),
      }))
      .sort((a, b) => (a.addedAt < b.addedAt ? 1 : -1));

    function fileFor(folder, item) {
      const blob = files.get(`${folder}/${item.id.toUpperCase()}.evf`) || files.get(`${folder}/${item.id.toLowerCase()}.evf`);
      if (!blob) throw new OpenError('missing', `${item.name} is missing from the folder.`);
      return blob;
    }

    return {
      id: header.id,
      items,
      albums: [...albums.values()],
      // Each chunk of an item's content, in order: for saving large videos without holding them in memory.
      decrypt: (item, onChunk) => decryptFile(fileFor('items', item), item.id, item.key, onChunk),
      read: (item) => readAll(fileFor('items', item), item.id, item.key),
      // A thumbnail has its own key. Ones written before November 2026 used the item key, and
      // are only accepted until the index says every thumbnail has its own (thumbnailKeys).
      async thumbnail(item) {
        if (!item.hasThumbnail) return null;
        const blob = fileFor('thumbs', item);
        try {
          return await readAll(blob, item.id, await hkdf(item.key, uuidBytes(item.id), 'ev/thumbnail'));
        } catch (error) {
          if (index.thumbnailKeys === true) throw error;
          return readAll(blob, item.id, item.key);
        }
      },
    };
  }

  // Keeps names to one plain path component, like evdecrypt.
  function safeName(name) {
    let cleaned = String(name || '').replace(/[\/\\:\u0000\r\n]/g, '_').slice(0, 200);
    if (!cleaned || cleaned.startsWith('.')) cleaned = 'item' + cleaned;
    return cleaned;
  }

  globalThis.EasyVaultOpener = { openVault, parseRecoveryKey, safeName, OpenError };
})();
