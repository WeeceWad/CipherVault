require('../main.js');
const { app, BrowserWindow } = require('electron');

app.whenReady().then(async () => {
  await new Promise((r) => setTimeout(r, 4500));
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('NO WINDOW'); app.exit(1); return; }

  const out = await win.webContents.executeJavaScript(`(async () => {
    const r = [];
    const ok = (n,c,e) => r.push((c?'PASS ':'FAIL ')+n+(e?' :: '+e:''));
    const b = window.cipherVaultDesktop;

    ok('preload bridge exposed', !!b && b.isDesktop === true);
    ok('update api present', b && typeof b.update.check === 'function' && typeof b.update.download === 'function' && typeof b.update.install === 'function' && typeof b.update.on === 'function');
    ok('no node access leaked to the renderer', typeof require === 'undefined' && typeof process === 'undefined');
    ok('no raw ipc leaked', typeof window.ipcRenderer === 'undefined' && !(b && b.ipcRenderer));

    const version = await b.getVersion();
    const parts = String(version).split('.');
    ok('version reported over the bridge', typeof version === 'string' && parts.length === 3 && parts.every(p => p !== '' && !isNaN(Number(p))), version);

    const res = await b.update.check();
    // Unpackaged, so the dev stub answers - which is the correct behaviour here.
    ok('check() answers without throwing', !!res && typeof res.status === 'string', JSON.stringify(res));

    let got = null;
    const off = b.update.on((name, payload) => { got = { name, payload }; });
    ok('subscribe returns an unsubscribe fn', typeof off === 'function');
    off();

    ok('settings section shown on desktop', !document.getElementById('settings-section-updates').classList.contains('hidden'));
    ok('version rendered in settings', document.getElementById('setting-app-version').textContent.includes(version));

    return r;
  })()`, true);

  out.forEach((l) => console.log(l));
  const failed = out.filter((l) => l.startsWith('FAIL'));
  console.log('\n' + (out.length - failed.length) + '/' + out.length + ' checks passed');
  app.exit(failed.length ? 1 : 0);
});
