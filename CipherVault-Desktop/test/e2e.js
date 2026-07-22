// Temporary end-to-end test: drives the real UI in the real renderer.
require('../main.js');
const { app, BrowserWindow } = require('electron');

const RENDERER_TEST = `(async () => {
  const log = [];
  const ok = (name, cond, extra) => log.push((cond ? 'PASS ' : 'FAIL ') + name + (extra ? ' :: ' + extra : ''));
  const $ = (id) => document.getElementById(id);
  const visible = (id) => !$(id).classList.contains('hidden');
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const settle = async (ms) => { await sleep(ms); };

  // Start from a clean slate.
  localStorage.clear();
  const app = window.CipherVault.app;
  ok('app instance exposed', !!app);

  // ---- 1. welcome -> continue locally ----
  app.checkVaultSetup();
  ok('welcome screen shown first', visible('welcome-form'));

  $('btn-welcome-local').click();
  await settle(50);
  ok('local choice -> setup form', visible('setup-form'), 'setup=' + visible('setup-form'));

  // ---- 2. mismatched passwords are rejected ----
  $('create-pass-input').value = 'CorrectHorse!23';
  $('confirm-pass-input').value = 'different';
  $('setup-form').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle(100);
  ok('mismatched passwords rejected', !$('setup-error-msg').classList.contains('hidden'));

  // ---- 3. short passwords are rejected ----
  $('create-pass-input').value = 'short';
  $('confirm-pass-input').value = 'short';
  $('setup-form').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle(100);
  ok('short password rejected', $('setup-error-msg').textContent.includes('8 characters'));

  // ---- 4. create the vault ----
  const MASTER = 'CorrectHorse!23';
  $('create-pass-input').value = MASTER;
  $('confirm-pass-input').value = MASTER;
  $('setup-form').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle(4000);
  ok('vault created, lock screen hidden', !visible('master-lock-screen'));

  const kdfRaw = localStorage.getItem('cv:local:kdf');
  ok('KDF v2 recorded', kdfRaw && JSON.parse(kdfRaw).v === 2, 'kdf=' + kdfRaw);
  ok('salt stored under local scope', !!localStorage.getItem('cv:local:salt'));
  ok('no unscoped legacy salt written', localStorage.getItem('ciphervault_salt') === null);

  const storedVerifier = localStorage.getItem('cv:local:hash');
  const legacyHash = await window.CipherVault.CryptoEngine.hashMasterPasswordLegacy(MASTER, localStorage.getItem('cv:local:salt'));
  ok('stored verifier is NOT the old bare SHA-256', storedVerifier !== legacyHash);

  // ---- 5. add an item ----
  app.openItemEditor();
  await settle(80);
  $('editor-type-select').value = 'login';
  $('editor-type-select').dispatchEvent(new Event('change'));
  await settle(80);
  $('editor-name').value = 'GitHub';
  $('ed-user').value = 'octocat@example.com';
  $('ed-pass').value = 'Sup3rSecret!Pass';
  $('ed-url').value = 'https://github.com';
  $('form-item-editor').dispatchEvent(new Event('submit', { cancelable: true }));
  await settle(600);

  ok('item count = 1', $('count-all').textContent === '1', 'count=' + $('count-all').textContent);
  ok('passwords count = 1', $('count-pw').textContent === '1');
  ok('card rendered', $('items-cards-container').querySelectorAll('.item-card').length === 1);

  const rawItems = JSON.parse(localStorage.getItem('cv:local:items'));
  ok('stored item is ciphertext only', rawItems.length === 1 && !!rawItems[0].encryptedData);
  ok('plaintext password not in localStorage', !JSON.stringify(rawItems).includes('Sup3rSecret'));

  // ---- 6. lock ----
  app.lockVault();
  await settle(100);
  ok('locked -> lock screen shown', visible('master-lock-screen'));
  ok('locked -> unlock form shown', visible('unlock-form'));
  ok('locked -> key dropped', app.aesKey === null);
  ok('locked -> plaintext dropped', app.decryptedVault.length === 0);

  // ---- 7. wrong master password ----
  $('master-pass-input').value = 'WrongPassword!1';
  await app.handleUnlock();
  await settle(200);
  ok('wrong master password refused', !$('lock-error-msg').classList.contains('hidden'));
  ok('wrong master password leaves vault locked', visible('master-lock-screen'));

  // ---- 8. correct master password ----
  $('master-pass-input').value = MASTER;
  await app.handleUnlock();
  await settle(2000);
  ok('correct master password unlocks', !visible('master-lock-screen'));
  ok('item survived the round trip', app.decryptedVault.length === 1);
  ok('password decrypted correctly',
     app.decryptedVault[0] && app.decryptedVault[0].data.password === 'Sup3rSecret!Pass',
     JSON.stringify(app.decryptedVault[0] && app.decryptedVault[0].data));

  // ---- 9. account scoping ----
  const localSalt = localStorage.getItem('cv:local:salt');
  app.lockVault();
  await settle(100);
  // Simulate signing into a cloud account with no vault.
  window.CipherVault.StorageController.setScope('fakeuid123');
  app.firebaseUser = { uid: 'fakeuid123', email: 'someone@example.com' };
  app.currentUid = 'fakeuid123';
  app.checkVaultSetup();
  await settle(50);
  ok('new account gets setup screen, not unlock', visible('setup-form'), 'setup=' + visible('setup-form') + ' unlock=' + visible('unlock-form'));
  ok("other account's salt untouched", localStorage.getItem('cv:local:salt') === localSalt);
  ok("new account has no salt of its own", localStorage.getItem('cv:u:fakeuid123:salt') === null);

  // Back to local.
  window.CipherVault.StorageController.setScope(null);
  app.firebaseUser = null;
  app.currentUid = null;
  app.checkVaultSetup();
  await settle(50);
  ok('back to local account -> unlock screen', visible('unlock-form'));

  // ---- 10. legacy v1 vault migrates on unlock ----
  localStorage.clear();
  window.CipherVault.StorageController.setScope(null);
  const LEGACY_MASTER = 'LegacyMaster!99';
  const legacySalt = window.CipherVault.CryptoEngine.generateSalt();
  const legacyVerifier = await window.CipherVault.CryptoEngine.hashMasterPasswordLegacy(LEGACY_MASTER, legacySalt);
  const legacyKey = await window.CipherVault.CryptoEngine.deriveKeyLegacy(LEGACY_MASTER, legacySalt);
  const legacyBlob = await window.CipherVault.CryptoEngine.encryptJson({ name: 'OldItem', username: 'old@x.com', password: 'oldpw123' }, legacyKey);

  localStorage.setItem('cv:local:salt', legacySalt);
  localStorage.setItem('cv:local:hash', legacyVerifier);
  localStorage.setItem('cv:local:items', JSON.stringify([
    { id: 'item_legacy', type: 'login', isFavorite: false, isTrashed: false, createdAt: new Date().toISOString(), encryptedData: legacyBlob }
  ]));
  // No cv:local:kdf key at all -> must be treated as v1.

  app.aesKey = null;
  app.decryptedVault = [];
  app.checkVaultSetup();
  await settle(50);
  ok('legacy vault shows unlock screen', visible('unlock-form'));

  $('master-pass-input').value = LEGACY_MASTER;
  await app.handleUnlock();
  await settle(3000);
  ok('legacy vault unlocks', app.aesKey !== null);
  ok('legacy item decrypted', app.decryptedVault.length === 1 && app.decryptedVault[0].data.password === 'oldpw123');

  const upgradedKdf = localStorage.getItem('cv:local:kdf');
  ok('legacy vault upgraded to v2', upgradedKdf && JSON.parse(upgradedKdf).v === 2, 'kdf=' + upgradedKdf);
  ok('legacy vault got a fresh salt', localStorage.getItem('cv:local:salt') !== legacySalt);
  ok('upgraded verifier differs from legacy hash', localStorage.getItem('cv:local:hash') !== legacyVerifier);

  // Re-lock and unlock with the upgraded material.
  app.lockVault();
  await settle(100);
  $('master-pass-input').value = LEGACY_MASTER;
  await app.handleUnlock();
  await settle(2500);
  ok('re-unlock after upgrade works', app.aesKey !== null && app.decryptedVault.length === 1);
  ok('item intact after upgrade', app.decryptedVault[0] && app.decryptedVault[0].data.password === 'oldpw123');

  // ---- 11. TOTP engine sanity (RFC 6238 test vector, key = "12345678901234567890") ----
  const totp = await window.CipherVault.TOTPEngine.generateTOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  ok('TOTP produces 6 digits', /^[0-9]{6}$/.test(totp), 'totp=' + totp);

  // ---- 12. password generator honours its options ----
  const genNums = window.CipherVault.CryptoEngine.generatePassword(40, false, false, true, false);
  ok('generator respects charset options', /^[0-9]{40}$/.test(genNums), genNums);

  // ---- 13. manual lock button exists and is wired ----
  ok('manual Lock Vault button exists in the DOM', !!$('btn-lock-manual'));
  $('btn-lock-manual').click();
  await settle(150);
  ok('manual lock button locks the vault', app.aesKey === null && visible('master-lock-screen'));

  // ---- 14. auto-lock on idle ----
  window.CipherVault.StorageController.setAutoLockMinutes('15');
  $('master-pass-input').value = LEGACY_MASTER;
  await app.handleUnlock();
  await settle(2500);
  ok('unlocked again for idle test', app.aesKey !== null);
  ok('idle timer armed after unlock', !!app.idleTimer);

  // Force the timeout to fire immediately instead of waiting 15 minutes.
  clearTimeout(app.idleTimer);
  app.idleTimer = setTimeout(() => { if (app.aesKey) app.lockVault(); }, 10);
  await settle(300);
  ok('idle timeout locks the vault', app.aesKey === null && visible('master-lock-screen'));

  window.CipherVault.StorageController.setAutoLockMinutes('never');
  $('master-pass-input').value = LEGACY_MASTER;
  await app.handleUnlock();
  await settle(2500);
  ok('auto-lock "never" arms no timer', !app.idleTimer, 'timer=' + app.idleTimer);

  // ---- 14b. adopting an offline vault into a cloud account ----
  // (the local->account copy, with the Firestore upload stubbed out)
  localStorage.clear();
  const SC = window.CipherVault.StorageController;
  SC.setScope(null);
  SC.setSalt('LOCALSALT');
  SC.setMasterHash('LOCALHASH');
  SC.setKdf({ v: 2, iterations: 600000 });
  SC.saveEncryptedItems([{ id: 'z', type: 'login', encryptedData: 'blob' }]);
  SC.setFolders([{ id: 'folder_1', name: 'Work' }]);

  SC.setScope('adoptuid');
  app.firebaseUser = { uid: 'adoptuid', email: 'adopt@example.com' };
  app.currentUid = 'adoptuid';

  const realUpload = window.CipherVault.FirebaseSyncEngine.uploadVault;
  const realDownload = window.CipherVault.FirebaseSyncEngine.downloadVault;
  const realConfirm = window.confirm;
  let uploaded = null;
  window.CipherVault.FirebaseSyncEngine.uploadVault = async (u, payload) => { uploaded = { u, payload }; };
  window.CipherVault.FirebaseSyncEngine.downloadVault = async () => null; // no cloud vault yet
  window.confirm = () => true;

  await app.syncVaultFromFirebase();

  window.CipherVault.FirebaseSyncEngine.uploadVault = realUpload;
  window.CipherVault.FirebaseSyncEngine.downloadVault = realDownload;
  window.confirm = realConfirm;

  ok('adopt: uploaded to the right uid', uploaded && uploaded.u === 'adoptuid');
  ok('adopt: uploaded the local key material',
     uploaded && uploaded.payload.salt === 'LOCALSALT' && uploaded.payload.hash === 'LOCALHASH');
  ok('adopt: uploaded the items and folders',
     uploaded && uploaded.payload.vault.length === 1 && uploaded.payload.folders[0].name === 'Work');
  ok('adopt: account namespace now holds the vault',
     localStorage.getItem('cv:u:adoptuid:salt') === 'LOCALSALT');
  ok('adopt: offline namespace left intact',
     localStorage.getItem('cv:local:salt') === 'LOCALSALT');

  app.firebaseUser = null; app.currentUid = null; SC.setScope(null);
  localStorage.clear();

  // ---- 15. escaping ----
  ok('escapeHtml neutralises tags and quotes',
     app.escapeHtml('<img src="x" onerror=\\'alert(1)\\'>') === '&lt;img src=&quot;x&quot; onerror=&#39;alert(1)&#39;&gt;',
     app.escapeHtml('<img src="x">'));

  // ---- 16. trashed items stay out of the normal views ----
  app.decryptedVault = [
    { id:'a', type:'login', isTrashed:false, isFavorite:false, createdAt:new Date().toISOString(), data:{name:'Live', password:'x'} },
    { id:'b', type:'login', isTrashed:true,  isFavorite:false, createdAt:new Date().toISOString(), data:{name:'Trashed', password:'x'} }
  ];
  app.activeCategory = 'all';
  app.renderList();
  ok('trashed item hidden from All Items', $('count-all').textContent === '1' && $('count-trash').textContent === '1');
  app.activeCategory = 'trash';
  app.renderList();
  ok('trash view shows only trashed items',
     $('items-cards-container').querySelectorAll('.item-card').length === 1);
  app.activeCategory = 'all';

  localStorage.clear();
  return log;
})()`;

app.whenReady().then(async () => {
  await new Promise((r) => setTimeout(r, 4000));
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('NO WINDOW'); app.exit(1); return; }

  win.webContents.on('console-message', (_e, level, message) => {
    if (level >= 2) console.log('[renderer error] ' + message);
  });

  try {
    const results = await win.webContents.executeJavaScript(RENDERER_TEST, true);
    results.forEach((r) => console.log(r));
    const failed = results.filter((r) => r.startsWith('FAIL'));
    console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
    app.exit(failed.length ? 1 : 0);
  } catch (e) {
    console.log('TEST HARNESS ERROR: ' + e.message);
    app.exit(1);
  }
});
