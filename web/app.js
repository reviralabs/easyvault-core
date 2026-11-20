// The page around open-vault.js: choose a folder, type the recovery key, save what's inside.
(function () {
  'use strict';
  const { openVault, safeName } = globalThis.EasyVaultOpener;
  const $ = (id) => document.getElementById(id);
  let files = null, vault = null, urls = [];

  const messages = {
    invalidKey: 'That isn’t a recovery key. It has 25 letters and numbers, like XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-X. Check for a typo.',
    wrongKey: 'This recovery key doesn’t open this vault. If you made a new recovery key in the app, use the newest one.',
    noVault: 'This folder isn’t an Easy Vault export. Choose the folder you got by unzipping the exported file.',
    noRecoverySlot: 'This vault has no recovery key. In the app, create one in Settings, then export again.',
    newer: 'This vault was made by a newer Easy Vault. Get the newest version of this page from github.com/reviralabs/easyvault-core.',
  };

  function showError(error) {
    $('error').textContent = messages[error.code] || `Something went wrong: ${error.message}`;
    $('error').hidden = false;
  }

  // The vault folder is wherever vault.json is; paths inside it become "items/<id>.evf" etc.
  $('folder').addEventListener('change', () => {
    $('error').hidden = true;
    const picked = [...$('folder').files];
    const header = picked
      .filter((f) => (f.webkitRelativePath || f.name).split('/').pop() === 'vault.json')
      .sort((a, b) => a.webkitRelativePath.length - b.webkitRelativePath.length)[0];
    if (!header) { files = null; showError({ code: 'noVault' }); update(); return; }
    const prefix = header.webkitRelativePath.slice(0, -'vault.json'.length);
    files = new Map(picked.filter((f) => f.webkitRelativePath.startsWith(prefix)).map((f) => [f.webkitRelativePath.slice(prefix.length), f]));
    update();
  });
  $('key').addEventListener('input', update);
  function update() { $('open').disabled = !files || !$('key').value.trim(); }

  $('open').addEventListener('click', async () => {
    $('error').hidden = true;
    $('open').disabled = true;
    $('open').textContent = 'Opening…';
    try {
      vault = await openVault(files, $('key').value);
      $('key').value = '';
      show();
    } catch (error) {
      showError(error);
    } finally {
      $('open').textContent = 'Open my vault';
      update();
    }
  });

  function show() {
    $('start').hidden = true;
    $('vault').hidden = false;
    const n = vault.items.length;
    const a = vault.albums.length;
    $('summary').textContent = `Your vault is open: ${n} ${n === 1 ? 'item' : 'items'}` + (a ? `, ${a} ${a === 1 ? 'album' : 'albums'}` : '');
    const groups = new Map();
    for (const item of vault.items) {
      const name = item.album || 'Not in an album';
      if (!groups.has(name)) groups.set(name, []);
      groups.get(name).push(item);
    }
    const root = $('albums');
    root.replaceChildren();
    for (const [name, items] of groups) {
      const heading = document.createElement('h2');
      heading.textContent = `${name} (${items.length})`;
      const grid = document.createElement('div');
      grid.className = 'grid';
      for (const item of items) grid.append(tile(item));
      root.append(heading, grid);
    }
  }

  function tile(item) {
    const button = document.createElement('button');
    button.className = 'tile';
    const thumb = document.createElement('span');
    thumb.className = 'thumb';
    thumb.textContent = item.kind === 'video' ? 'Video' : item.kind === 'photo' ? 'Photo' : 'File';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = item.name;
    button.append(thumb, name);
    button.title = item.name;
    button.addEventListener('click', () => download(item).catch((e) => status(`Couldn’t save ${item.name}: ${e.message}`)));
    vault.thumbnail(item).then((data) => {
      if (!data) return;
      const url = URL.createObjectURL(new Blob([data], { type: 'image/jpeg' }));
      urls.push(url);
      thumb.textContent = '';
      thumb.style.backgroundImage = `url("${url}")`;
    }).catch(() => {});
    return button;
  }

  function status(text) { $('status').textContent = text; }

  async function download(item) {
    const chunks = [];
    await vault.decrypt(item, (c) => { chunks.push(c); });
    const url = URL.createObjectURL(new Blob(chunks, { type: item.contentType && item.contentType.includes('/') ? item.contentType : '' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = safeName(item.name);
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  // Into a folder the user picks, where the browser allows it (Chrome, Edge); otherwise one
  // download per item.
  $('save-all').addEventListener('click', async () => {
    $('save-all').disabled = true;
    let done = 0, failed = 0;
    const total = vault.items.length;
    try {
      if (window.showDirectoryPicker) {
        const root = await window.showDirectoryPicker({ mode: 'readwrite' });
        for (const item of vault.items) {
          status(`Saving ${done + 1} of ${total}…`);
          try {
            const folder = item.album ? await root.getDirectoryHandle(safeName(item.album), { create: true }) : root;
            const file = await folder.getFileHandle(await freeName(folder, safeName(item.name)), { create: true });
            const out = await file.createWritable();
            try { await vault.decrypt(item, (c) => out.write(c)); await out.close(); } catch (e) { await out.abort(); throw e; }
          } catch { failed++; }
          done++;
        }
      } else {
        for (const item of vault.items) {
          status(`Saving ${done + 1} of ${total}… Your browser may ask to allow several downloads.`);
          try { await download(item); } catch { failed++; }
          done++;
          await new Promise((r) => setTimeout(r, 400));
        }
      }
      status(`Saved ${done - failed} of ${total}.` + (failed ? ` ${failed} couldn’t be read.` : ''));
    } catch (e) {
      if (e.name !== 'AbortError') status(`Couldn’t save: ${e.message}`);
    } finally {
      $('save-all').disabled = false;
    }
  });

  async function freeName(folder, name) {
    const dot = name.lastIndexOf('.');
    const base = dot > 0 ? name.slice(0, dot) : name, ext = dot > 0 ? name.slice(dot) : '';
    for (let n = 1; ; n++) {
      const candidate = n === 1 ? name : `${base} (${n})${ext}`;
      try { await folder.getFileHandle(candidate); } catch { return candidate; }
    }
  }

  $('close').addEventListener('click', () => {
    vault = null; files = null;
    urls.forEach(URL.revokeObjectURL); urls = [];
    $('folder').value = '';
    $('albums').replaceChildren();
    status('');
    $('vault').hidden = true;
    $('start').hidden = false;
    update();
  });
})();
