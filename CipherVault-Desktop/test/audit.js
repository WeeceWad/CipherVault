// Builds a real vault with known secrets, then inspects EXACTLY what would be
// written to disk and uploaded, looking for anything readable.
require('../main.js');
const { app, BrowserWindow } = require('electron');

app.whenReady().then(async () => {
  await new Promise((r) => setTimeout(r, 4000));
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('NO WINDOW'); app.exit(1); return; }

  const out = await win.webContents.executeJavaScript(`(async () => {
    const log = [];
    const say = (s) => log.push(s);
    const CE = window.CipherVault.CryptoEngine;
    const SC = window.CipherVault.StorageController;
    const FSE = window.CipherVault.FirebaseSyncEngine;
    const a = window.CipherVault.app;

    localStorage.clear();
    SC.setScope(null);

    // Distinctive canaries so any leak is unmistakable.
    const MASTER  = 'CANARYmaster9911';
    const PW      = 'CANARYpassword2277';
    const USER    = 'CANARYuser@example.com';
    const NOTE    = 'CANARYnotebody3388';
    const CARD    = '4111CANARYCARD1111';
    const TITLE   = 'CANARYtitle4455';
    const URL     = 'https://CANARYdomain5566.example';
    const FOLDER  = 'CANARYfolder7788';
    const TOTP    = 'JBSWY3DPEHPK3PXP';
    const SLKEY   = 'CANARYsimplelogin9900';

    const salt = CE.generateSalt();
    const kdf = { v: CE.KDF_VERSION, iterations: CE.DEFAULT_ITERATIONS };
    const { aesKey, verifier } = await CE.deriveKeyAndVerifier(MASTER, salt, kdf.iterations);

    SC.setSalt(salt); SC.setMasterHash(verifier); SC.setKdf(kdf);
    a.aesKey = aesKey;
    a.folders = [{ id: 'folder_1', name: FOLDER }];
    await a.saveFolders({ sync: false });
    a.decryptedVault = [
      { id:'i1', type:'login', isFavorite:false, isTrashed:false, createdAt:new Date().toISOString(),
        data:{ name:TITLE, username:USER, password:PW, url:URL, totpSecret:TOTP, folderId:'folder_1' } },
      { id:'i2', type:'note', isFavorite:false, isTrashed:false, createdAt:new Date().toISOString(),
        data:{ name:'note', content:NOTE } },
      { id:'i3', type:'card', isFavorite:false, isTrashed:false, createdAt:new Date().toISOString(),
        data:{ name:'card', cardNumber:CARD, cvv:'123' } }
    ];
    a.simpleLoginKey = SLKEY;
    SC.setSimpleLoginKeyEnc(await CE.encrypt(SLKEY, aesKey));

    // Capture the exact upload payload instead of sending it.
    let uploaded = null;
    const realUpload = FSE.uploadVault;
    FSE.uploadVault = async (uid, payload) => { uploaded = payload; };
    a.currentUid = 'auditUid';
    await a.saveEncryptedVault();
    a.currentUid = null;
    FSE.uploadVault = realUpload;

    const atRest = JSON.stringify(localStorage);
    const onWire = JSON.stringify(uploaded);

    const canaries = {
      'master password': MASTER,
      'item password':   PW,
      'username':        USER,
      'note body':       NOTE,
      'card number':     CARD,
      'item title':      TITLE,
      'website url':     URL,
      'TOTP secret':     TOTP,
      'SimpleLogin key': SLKEY,
      'folder name':     FOLDER,
    };

    say('WHAT IS STORED ON DISK (localStorage)');
    for (const [label, value] of Object.entries(canaries)) {
      say('  ' + (atRest.includes(value) ? 'LEAKED  ' : 'sealed  ') + label);
    }

    say('');
    say('WHAT IS SENT TO FIRESTORE');
    for (const [label, value] of Object.entries(canaries)) {
      say('  ' + (onWire.includes(value) ? 'LEAKED  ' : 'sealed  ') + label);
    }

    say('');
    say('FIELDS VISIBLE TO THE SERVER: ' + Object.keys(uploaded).join(', '));
    say('folders as uploaded: ' + JSON.stringify(uploaded.folders));
    say('a vault entry as uploaded: ' + JSON.stringify(uploaded.vault[0]).slice(0, 150) + '…');

    say('');
    say('KEY DERIVATION: PBKDF2-SHA256 v' + CE.KDF_VERSION + ', ' + CE.DEFAULT_ITERATIONS.toLocaleString() + ' iterations');
    say('verifier == a plain hash of the password? ' +
        ((await CE.hashMasterPasswordLegacy(MASTER, salt)) === verifier ? 'YES - BAD' : 'no'));

    // Does the key survive locking?
    a.lockVault();
    say('after lock -> key in memory: ' + (a.aesKey === null ? 'no' : 'YES - BAD') +
        ', plaintext items: ' + a.decryptedVault.length +
        ', SimpleLogin key: ' + (a.simpleLoginKey ? 'YES - BAD' : 'no'));

    localStorage.clear();
    return log;
  })()`, true);

  out.forEach((l) => console.log(l));
  app.exit(0);
});
