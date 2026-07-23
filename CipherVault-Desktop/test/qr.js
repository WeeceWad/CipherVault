// Exercises the QR handshake in a real browser engine, both sides.
require('../main.js');
const { app, BrowserWindow } = require('electron');

app.whenReady().then(async () => {
  await new Promise((r) => setTimeout(r, 4000));
  const win = BrowserWindow.getAllWindows()[0];
  if (!win) { console.log('NO WINDOW'); app.exit(1); return; }

  const results = await win.webContents.executeJavaScript(`(async () => {
    const out = [];
    const ok = (n,c,e) => out.push((c?'PASS ':'FAIL ')+n+(e?' :: '+e:''));
    const LSE = window.CipherVault.LinkSessionEngine;
    const CE  = window.CipherVault.CryptoEngine;

    // ---- desktop mints a session ----
    const session = await LSE.createSession();
    ok('session id generated', typeof session.sessionId === 'string' && session.sessionId.length >= 16);
    ok('qr payload is json', (() => { try { JSON.parse(session.qrPayload); return true; } catch(e){ return false; } })());

    const payload = JSON.parse(session.qrPayload);
    ok('payload carries version + id + key', payload.v === 1 && !!payload.s && !!payload.k);
    ok('public key is a P-256 point', CE.base64ToBytes(payload.k).length === 65 && CE.base64ToBytes(payload.k)[0] === 4);
    ok('private key is non-extractable', session.keyPair.privateKey.extractable === false);

    // ---- phone parses it ----
    const parsed = LSE.parseQrPayload(session.qrPayload);
    ok('phone parses the payload', parsed.sessionId === session.sessionId && parsed.publicKey === payload.k);

    // ---- phone seals the master password ----
    const MASTER = 'MyMaster!Password2026';
    const response = await LSE.buildResponse(parsed.sessionId, parsed.publicKey, MASTER);
    ok('response has phone key + ciphertext', !!response.publicKey && !!response.ciphertext);
    ok('phone key is a distinct P-256 point', response.publicKey !== payload.k && CE.base64ToBytes(response.publicKey).length === 65);

    // THE point of the whole design: what lands in Firestore reveals nothing.
    const overTheWire = JSON.stringify({ pk: response.publicKey, ct: response.ciphertext });
    ok('wire payload contains no plaintext password', !overTheWire.includes(MASTER));
    ok('wire payload contains no fragment of it', !overTheWire.includes('MyMaster') && !overTheWire.includes('Password2026'));

    // ---- desktop opens it ----
    const recovered = await LSE.openResponse(session.keyPair, session.sessionId, response);
    ok('desktop recovers the master password', recovered === MASTER, recovered === MASTER ? '' : 'got: '+recovered);

    // ---- an eavesdropper with both public keys learns nothing ----
    const attacker = await LSE.createSession();
    let attackerFailed = false;
    try {
      await LSE.openResponse(attacker.keyPair, session.sessionId, response);
    } catch (e) { attackerFailed = true; }
    ok('a different keypair cannot decrypt it', attackerFailed);

    // ---- session id is bound into the key derivation ----
    let wrongSessionFailed = false;
    try {
      await LSE.openResponse(session.keyPair, 'some-other-session-id', response);
    } catch (e) { wrongSessionFailed = true; }
    ok('wrong session id cannot decrypt it', wrongSessionFailed);

    // ---- replay against a fresh session fails ----
    const session2 = await LSE.createSession();
    let replayFailed = false;
    try {
      await LSE.openResponse(session2.keyPair, session2.sessionId, response);
    } catch (e) { replayFailed = true; }
    ok('a captured response cannot be replayed at a new session', replayFailed);

    // ---- tampered ciphertext is rejected (AES-GCM auth tag) ----
    const bytes = CE.base64ToBytes(response.ciphertext);
    bytes[bytes.length - 1] ^= 0xFF;
    let tamperFailed = false;
    try {
      await LSE.openResponse(session.keyPair, session.sessionId,
        { publicKey: response.publicKey, ciphertext: CE.bytesToBase64(bytes) });
    } catch (e) { tamperFailed = true; }
    ok('tampered ciphertext is rejected', tamperFailed);

    // ---- malformed QR codes are refused, not crashed on ----
    const bad = ['not json', '{}', '{"v":99,"s":"a","k":"b"}', '{"v":1,"s":"","k":""}', '{"v":1,"s":"x","k":"AAAA"}'];
    let allRejected = true;
    for (const b of bad) {
      try { LSE.parseQrPayload(b); allRejected = false; } catch (e) { /* expected */ }
    }
    ok('malformed codes are rejected with a message', allRejected);

    // ---- expiry ----
    ok('fresh session is not expired', LSE.isExpired(Date.now()) === false);
    ok('old session is expired', LSE.isExpired(Date.now() - 60000) === true);

    // ---- two sessions never collide ----
    const a = await LSE.createSession(), b = await LSE.createSession();
    ok('session ids are unique', a.sessionId !== b.sessionId);
    ok('session keys are unique', JSON.parse(a.qrPayload).k !== JSON.parse(b.qrPayload).k);

    return out;
  })()`, true);

  results.forEach((r) => console.log(r));
  const failed = results.filter((r) => r.startsWith('FAIL'));
  console.log('\n' + (results.length - failed.length) + '/' + results.length + ' checks passed');
  app.exit(failed.length ? 1 : 0);
});
