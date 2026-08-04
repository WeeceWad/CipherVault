/**
 * CipherVault QR unlock engine (browser extension)
 *
 * GENERATED FILE - DO NOT EDIT.
 * Source: CipherVault/js/app.js
 * Regenerate: cd CipherVault-Android && npm run sync:core
 *
 * Editing this by hand will be silently overwritten, and any drift from the
 * source means a vault encrypted on one device cannot be opened on another.
 */

// --- QR UNLOCK / DEVICE LINK ENGINE ---
//
// Unlocks a signed-in desktop by scanning a QR code with an already-unlocked
// phone. The master password has to travel from phone to desktop, and the
// only channel they share is Firestore - which must never see it.
//
// So the QR carries an ephemeral ECDH public key generated on the desktop.
// The phone generates its own pair, does ECDH against the key it read off the
// screen, derives an AES-GCM key through HKDF, and writes only the resulting
// ciphertext plus its own public key. The desktop performs the same ECDH and
// decrypts.
//
// Firestore therefore stores two public keys and a ciphertext. Recovering the
// password from those is the ECDH problem. The screen is the authenticated
// channel: an attacker on the network cannot substitute the desktop's public
// key, because it reached the phone as pixels rather than over the wire.
//
// Sessions are random, single-use, expire in well under a minute, and the
// document is deleted the moment it has been consumed.
class LinkSessionEngine {
  static PROTOCOL_VERSION = 1;
  static SESSION_TTL_MS = 45000;
  static HKDF_INFO = "ciphervault-link-v1";

  /** Desktop: mints a session and the payload to render as a QR code. */
  static async createSession() {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,                       // private key stays non-extractable
      ["deriveBits"]
    );

    const sessionId = CryptoEngine.bytesToBase64(crypto.getRandomValues(new Uint8Array(16)))
      .replace(/[+/=]/g, (c) => ({ "+": "-", "/": "_", "=": "" }[c]));

    const publicKey = CryptoEngine.bytesToBase64(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey))
    );

    return {
      sessionId,
      keyPair,
      createdAt: Date.now(),
      qrPayload: JSON.stringify({ v: this.PROTOCOL_VERSION, s: sessionId, k: publicKey }),
    };
  }

  /** Phone: reads a scanned QR string, rejecting anything malformed. */
  static parseQrPayload(text) {
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new Error("That isn't a CipherVault code.");
    }

    if (!parsed || parsed.v !== this.PROTOCOL_VERSION) {
      throw new Error("That code is from a different version of CipherVault.");
    }
    if (typeof parsed.s !== "string" || !parsed.s || typeof parsed.k !== "string" || !parsed.k) {
      throw new Error("That code is incomplete. Try again.");
    }

    // A P-256 uncompressed point is 65 bytes; anything else is not a key.
    let keyBytes;
    try {
      keyBytes = CryptoEngine.base64ToBytes(parsed.k);
    } catch (e) {
      throw new Error("That code is malformed.");
    }
    if (keyBytes.length !== 65 || keyBytes[0] !== 0x04) {
      throw new Error("That code is malformed.");
    }

    return { version: parsed.v, sessionId: parsed.s, publicKey: parsed.k };
  }

  /**
   * Both sides run this and land on the same AES key.
   * The session id is mixed in as HKDF salt so two concurrent sessions can
   * never derive the same key even if a keypair were somehow reused.
   */
  static async deriveSharedKey(privateKey, peerPublicKeyBase64, sessionId) {
    const peerPublicKey = await crypto.subtle.importKey(
      "raw",
      CryptoEngine.base64ToBytes(peerPublicKeyBase64),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      []
    );

    const sharedBits = await crypto.subtle.deriveBits(
      { name: "ECDH", public: peerPublicKey },
      privateKey,
      256
    );

    const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);

    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new TextEncoder().encode(sessionId),
        info: new TextEncoder().encode(this.HKDF_INFO),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** Phone: seals the master password for this one desktop session. */
  static async buildResponse(sessionId, desktopPublicKeyBase64, masterPassword) {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false,
      ["deriveBits"]
    );

    const sharedKey = await this.deriveSharedKey(keyPair.privateKey, desktopPublicKeyBase64, sessionId);

    return {
      publicKey: CryptoEngine.bytesToBase64(
        new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey))
      ),
      ciphertext: await CryptoEngine.encrypt(masterPassword, sharedKey),
    };
  }

  /** Desktop: opens the phone's response. */
  static async openResponse(keyPair, sessionId, response) {
    if (!response || typeof response.publicKey !== "string" || typeof response.ciphertext !== "string") {
      throw new Error("The approval from your phone was incomplete.");
    }

    const sharedKey = await this.deriveSharedKey(keyPair.privateKey, response.publicKey, sessionId);
    return CryptoEngine.decrypt(response.ciphertext, sharedKey);
  }

  static isExpired(createdAt) {
    return Date.now() - createdAt > this.SESSION_TTL_MS;
  }
}
