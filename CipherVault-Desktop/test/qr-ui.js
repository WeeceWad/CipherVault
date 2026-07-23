require('../main.js');
const { app, BrowserWindow } = require('electron');

app.whenReady().then(async () => {
  await new Promise((r) => setTimeout(r, 4000));
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('NO WINDOW'); app.exit(1); return; }

  const results = await win.webContents.executeJavaScript(`(async () => {
    const out=[]; const ok=(n,c,e)=>out.push((c?'PASS ':'FAIL ')+n+(e?' :: '+e:''));
    const $=id=>document.getElementById(id); const vis=id=>!$(id).classList.contains('hidden');
    const wait=ms=>new Promise(r=>setTimeout(r,ms));
    const a=window.CipherVault.app, SC=window.CipherVault.StorageController, CE=window.CipherVault.CryptoEngine;

    ok('qrcode library loaded', typeof qrcode === 'function');
    ok('QR modal exists', !!$('modal-qr-unlock') && !!$('qr-canvas'));

    // Make a vault so the unlock pane is what shows.
    localStorage.clear(); SC.setScope(null);
    const M='QrTest!Master2026';
    const salt=CE.generateSalt(), kdf={v:2,iterations:600000};
    const {verifier}=await CE.deriveKeyAndVerifier(M,salt,kdf.iterations);
    SC.setSalt(salt); SC.setMasterHash(verifier); SC.setKdf(kdf); SC.saveEncryptedItems([]);

    // Signed out: the button must stay hidden, there is no channel.
    a.firebaseUser=null; a.currentUid=null;
    a.checkVaultSetup(); await wait(80);
    ok('unlock pane shown', vis('unlock-form'));
    ok('QR button hidden when signed out', !vis('btn-qr-unlock'));

    // Signed in: offered.
    a.firebaseUser={uid:'qruid', email:'q@x.com'}; a.currentUid='qruid';
    a.checkVaultSetup(); await wait(80);
    ok('QR button offered when signed in', vis('btn-qr-unlock'));

    // Open it with the Firestore listener stubbed.
    let watched=null, deleted=[];
    const FSE = window.CipherVault.FirebaseSyncEngine;
    const realWatch = FSE.watchLinkSession, realDel = FSE.deleteLinkSession;
    FSE.watchLinkSession = (uid, sid, onResp) => { watched={uid,sid,onResp}; return ()=>{}; };
    FSE.deleteLinkSession = async (uid,sid) => { deleted.push(sid); };

    await a.openQrUnlock(); await wait(400);
    ok('QR modal opened', vis('modal-qr-unlock'));
    ok('session created', !!a.qrSession && !!a.qrSession.sessionId);
    ok('listening on the right path', watched && watched.uid==='qruid' && watched.sid===a.qrSession.sessionId);

    // Canvas actually painted something.
    const ctx=$('qr-canvas').getContext('2d');
    const px=ctx.getImageData(0,0,240,240).data;
    let dark=0; for(let i=0;i<px.length;i+=4){ if(px[i]<80) dark++; }
    ok('QR rendered onto the canvas', dark > 500, dark+' dark pixels');

    // Rotation produces a genuinely new session.
    const first=a.qrSession.sessionId, firstKey=JSON.parse(a.qrSession.qrPayload).k;
    await a.rotateQrSession(); await wait(400);
    ok('rotation makes a new session', a.qrSession.sessionId!==first);
    ok('rotation makes a new keypair', JSON.parse(a.qrSession.qrPayload).k!==firstKey);
    ok('old session cleaned up', deleted.includes(first));

    // The real thing: a phone approves.
    const LSE=window.CipherVault.LinkSessionEngine;
    const live=a.qrSession;
    const parsed=LSE.parseQrPayload(live.qrPayload);
    const resp=await LSE.buildResponse(parsed.sessionId, parsed.publicKey, M);
    await a.handleQrResponse(resp); await wait(2500);

    ok('vault unlocked from the phone response', a.aesKey!==null);
    ok('lock screen dismissed', !vis('master-lock-screen'));
    ok('QR modal closed', !vis('modal-qr-unlock'));
    ok('consumed session deleted', deleted.includes(parsed.sessionId));
    ok('listener torn down', a.qrSession===null);

    // A phone sending the WRONG password must not open the vault.
    a.lockVault(); await wait(150);
    await a.openQrUnlock(); await wait(400);
    const live2=a.qrSession, p2=LSE.parseQrPayload(live2.qrPayload);
    const badResp=await LSE.buildResponse(p2.sessionId, p2.publicKey, 'NotTheMasterPassword');
    await a.handleQrResponse(badResp); await wait(2000);
    ok('wrong password from phone is refused', a.aesKey===null);
    ok('refusal is explained on screen', !vis('qr-error')===false && $('qr-error').textContent.length>0, $('qr-error').textContent);

    a.stopQrSession();
    FSE.watchLinkSession=realWatch; FSE.deleteLinkSession=realDel;
    localStorage.clear();
    return out;
  })()`, true);

  results.forEach((r) => console.log(r));
  const failed = results.filter((r) => r.startsWith('FAIL'));
  console.log('\n' + (results.length - failed.length) + '/' + results.length + ' checks passed');
  app.exit(failed.length ? 1 : 0);
});
