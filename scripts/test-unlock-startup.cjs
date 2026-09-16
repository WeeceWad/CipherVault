const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync('CipherVault-Android/www/js/mobile.js', 'utf8');
const method = source.slice(source.indexOf('    setupAuth() {'), source.indexOf('    updateSyncIndicator('));
let authCallback, finishSync;
const storage = { setScope() {}, getSalt: () => 'cached-salt', getMasterHash: () => 'cached-hash' };
const setup = new Function('FirebaseSyncEngine', 'StorageController', `return ({${method}}).setupAuth`)(
  {onAuthStateChanged(fn) {authCallback = fn;}}, storage);
const events = [];
const controller = {
  currentUid: null,
  showLockScreen() {events.push('lock');},
  checkVaultState() {events.push('unlock-ready');},
  updateSyncIndicator() {}, refreshSettings() {},
  syncFromCloud() {events.push('network'); return new Promise(resolve => {finishSync = resolve;});}
};
(async () => {
  setup.call(controller);
  const pending = authCallback({uid:'account-a'});
  assert.deepEqual(events, ['lock','unlock-ready','network']);
  finishSync(); await pending;
  console.log('PASS cached account unlock is ready while cloud download remains pending');
  events.length = 0;
  storage.getSalt = () => null;
  const fresh = authCallback({uid:'account-b'});
  assert.deepEqual(events, ['lock','network']);
  finishSync(); await fresh;
  assert.equal(events.at(-1), 'unlock-ready');
  console.log('PASS account without cached vault waits for cloud before choosing its unlock/setup pane');
})().catch(error => { console.error(error); process.exitCode = 1; });
