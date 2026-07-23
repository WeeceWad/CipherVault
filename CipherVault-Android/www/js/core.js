/**
 * CipherVault shared engine layer (Android)
 *
 * GENERATED FILE - DO NOT EDIT.
 * Source: CipherVault/js/app.js
 * Regenerate: cd CipherVault-Android && npm run sync:core
 *
 * Editing this by hand will be silently overwritten, and any drift from the
 * source means a vault encrypted on one device cannot be opened on another.
 */

// --- CRYPTOGRAPHIC ENGINE (WebCrypto AES-256-GCM & PBKDF2 & TOTP) ---
//
// KDF v2 (current)
//   One PBKDF2-SHA256 pass over the master password produces 512 bits.
//   The first 256 become the AES-GCM vault key and are never stored.
//   The last 256 become the "verifier" that proves you typed the right
//   master password, and that is what gets written to disk / the cloud.
//
// KDF v1 (legacy, migrated on unlock)
//   Stored a bare SHA-256(password || salt). That is a single hash with no
//   stretching at all, so anybody who obtained the stored value could brute
//   force the master password offline at GPU speed. v2 makes checking a
//   guess cost exactly as much as deriving the real key.
class CryptoEngine {
  static KDF_VERSION = 2;
  static DEFAULT_ITERATIONS = 600000; // OWASP 2023+ guidance for PBKDF2-SHA256
  static LEGACY_ITERATIONS = 100000;

  static generateSalt(length = 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return this.bytesToBase64(bytes);
  }

  static async _importPasswordKey(masterPassword) {
    return crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(masterPassword),
      "PBKDF2",
      false,
      ["deriveKey", "deriveBits"]
    );
  }

  /**
   * KDF v2. Returns the vault key plus the verifier stored alongside it.
   * @returns {Promise<{aesKey: CryptoKey, verifier: string}>}
   */
  static async deriveKeyAndVerifier(masterPassword, saltBase64, iterations = this.DEFAULT_ITERATIONS) {
    const baseKey = await this._importPasswordKey(masterPassword);

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: this.base64ToBytes(saltBase64),
        iterations: iterations,
        hash: "SHA-256",
      },
      baseKey,
      512
    );

    const all = new Uint8Array(bits);
    const keyBytes = all.slice(0, 32);
    const verifierBytes = all.slice(32, 64);

    const aesKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    return { aesKey, verifier: this.bytesToBase64(verifierBytes) };
  }

  /** KDF v1 key derivation, kept only so old vaults can still be opened. */
  static async deriveKeyLegacy(masterPassword, saltBase64, iterations = this.LEGACY_ITERATIONS) {
    const baseKey = await this._importPasswordKey(masterPassword);
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: this.base64ToBytes(saltBase64),
        iterations: iterations,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** KDF v1 verifier, kept only so old vaults can still be opened. */
  static async hashMasterPasswordLegacy(masterPassword, saltBase64) {
    const saltBytes = this.base64ToBytes(saltBase64);
    const passwordBytes = new TextEncoder().encode(masterPassword);

    const combined = new Uint8Array(passwordBytes.length + saltBytes.length);
    combined.set(passwordBytes, 0);
    combined.set(saltBytes, passwordBytes.length);

    const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
    return this.bytesToBase64(new Uint8Array(hashBuffer));
  }

  /**
   * Verifies a master password against any supported KDF version and, on
   * success, returns the vault key.
   * @returns {Promise<{ok: boolean, aesKey?: CryptoKey, needsUpgrade?: boolean}>}
   */
  static async unlock(masterPassword, saltBase64, storedVerifier, kdf) {
    const version = (kdf && kdf.v) || 1;

    if (version >= 2) {
      const iterations = (kdf && kdf.iterations) || this.DEFAULT_ITERATIONS;
      const { aesKey, verifier } = await this.deriveKeyAndVerifier(masterPassword, saltBase64, iterations);
      if (!this.timingSafeEquals(verifier, storedVerifier)) return { ok: false };
      return { ok: true, aesKey, needsUpgrade: iterations < this.DEFAULT_ITERATIONS };
    }

    const legacyVerifier = await this.hashMasterPasswordLegacy(masterPassword, saltBase64);
    if (!this.timingSafeEquals(legacyVerifier, storedVerifier)) return { ok: false };
    const aesKey = await this.deriveKeyLegacy(masterPassword, saltBase64);
    return { ok: true, aesKey, needsUpgrade: true };
  }

  /** Constant-time-ish string compare, so a wrong guess leaks no prefix info. */
  static timingSafeEquals(a, b) {
    const sa = String(a || "");
    const sb = String(b || "");
    if (sa.length !== sb.length) return false;
    let diff = 0;
    for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
    return diff === 0;
  }

  static async encrypt(plaintext, aesKey) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encoder = new TextEncoder();
    const data = encoder.encode(plaintext);

    const encryptedBuffer = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      data
    );

    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const combined = new Uint8Array(iv.length + encryptedBytes.length);
    combined.set(iv, 0);
    combined.set(encryptedBytes, iv.length);

    return this.bytesToBase64(combined);
  }

  static async decrypt(ciphertextBase64, aesKey) {
    const combined = this.base64ToBytes(ciphertextBase64);
    if (combined.length < 16) throw new Error("Invalid ciphertext structure");

    const iv = combined.slice(0, 16);
    const cipherBytes = combined.slice(16);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      cipherBytes
    );

    return new TextDecoder().decode(decryptedBuffer);
  }

  static async encryptJson(dataObject, aesKey) {
    return await this.encrypt(JSON.stringify(dataObject), aesKey);
  }

  static async decryptJson(ciphertextBase64, aesKey) {
    const jsonString = await this.decrypt(ciphertextBase64, aesKey);
    return JSON.parse(jsonString);
  }

  static bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  static base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  static generatePassword(length = 18, upper = true, lower = true, nums = true, syms = true) {
    let chars = "";
    if (upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (lower) chars += "abcdefghijklmnopqrstuvwxyz";
    if (nums) chars += "0123456789";
    if (syms) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";
    if (!chars) chars = "abcdefghijklmnopqrstuvwxyz";

    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    let result = "";
    for (let i = 0; i < length; i++) {
      result += chars[randomValues[i] % chars.length];
    }
    return result;
  }
}

// --- TOTP AUTHENTICATOR ENGINE (RFC 6238) ---
class TOTPEngine {
  static async generateTOTP(secretBase32, period = 30, digits = 6) {
    try {
      const keyBytes = this.base32ToBytes(secretBase32);
      if (keyBytes.length === 0) return "------";

      const epoch = Math.floor(Date.now() / 1000);
      const counter = Math.floor(epoch / period);

      const buffer = new ArrayBuffer(8);
      const view = new DataView(buffer);
      view.setUint32(4, counter, false);

      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-1" },
        false,
        ["sign"]
      );

      const signature = await crypto.subtle.sign("HMAC", cryptoKey, buffer);
      const sigBytes = new Uint8Array(signature);

      const offset = sigBytes[sigBytes.length - 1] & 0x0f;
      const code =
        ((sigBytes[offset] & 0x7f) << 24) |
        ((sigBytes[offset + 1] & 0xff) << 16) |
        ((sigBytes[offset + 2] & 0xff) << 8) |
        (sigBytes[offset + 3] & 0xff);

      return (code % Math.pow(10, digits)).toString().padStart(digits, "0");
    } catch (e) {
      return "------";
    }
  }

  static base32ToBytes(base32) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const clean = (base32 || "").toUpperCase().replace(/[\s=]/g, "");
    let bits = "";
    for (let i = 0; i < clean.length; i++) {
      const val = alphabet.indexOf(clean[i]);
      if (val === -1) continue;
      bits += val.toString(2).padStart(5, "0");
    }

    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    return bytes;
  }
}

// --- FIREBASE CLOUD SYNC ENGINE ---
const firebaseConfig = {
  apiKey: "AIzaSyCAGLosHtxjPKjLGEbxtxrbT3HfXg9gtg0",
  authDomain: "ciphervault-51754.firebaseapp.com",
  projectId: "ciphervault-51754",
  storageBucket: "ciphervault-51754.firebasestorage.app",
  messagingSenderId: "666567446130",
  appId: "1:666567446130:web:8abb23ef021e2594753ceb",
  measurementId: "G-H1SC7HYVTZ"
};

class FirebaseSyncEngine {
  static init() {
    if (typeof firebase !== 'undefined' && !firebase.apps.length) {
      firebase.initializeApp(firebaseConfig);
    }
  }

  static onAuthStateChanged(callback) {
    if (typeof firebase === 'undefined') return;
    firebase.auth().onAuthStateChanged(callback);
  }

  static async login(email, password) {
    if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
    const userCredential = await firebase.auth().signInWithEmailAndPassword(email, password);
    return userCredential.user;
  }

  static async signup(email, password) {
    if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
    const userCredential = await firebase.auth().createUserWithEmailAndPassword(email, password);
    return userCredential.user;
  }

  static async logout() {
    if (typeof firebase === 'undefined') return;
    await firebase.auth().signOut();
  }

  static async sendPasswordReset(email) {
    if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
    if (!email) throw new Error("Please enter your email address first.");
    await firebase.auth().sendPasswordResetEmail(email);
  }

  static async uploadVault(uid, { vault, folders, salt, hash, kdf, slKeyEnc }) {
    if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
    if (!uid) throw new Error("Not signed in.");
    if (!salt || !hash) throw new Error("Refusing to sync a vault with no master key material.");

    const db = firebase.firestore();
    await db.collection("users").doc(uid).set({
      schemaVersion: 3,
      vault: Array.isArray(vault) ? vault : [],
      folders: Array.isArray(folders) ? folders : [],
      salt: salt,
      hash: hash,
      kdf: kdf || { v: 1, iterations: 100000 },
      // Encrypted with the vault key, so the server never sees the API key.
      slKeyEnc: typeof slKeyEnc === "string" ? slKeyEnc : "",
      updatedAtMs: Date.now(),
      lastSynced: firebase.firestore.FieldValue.serverTimestamp()
    });
  }

  static async deleteVault(uid) {
    if (typeof firebase === 'undefined' || !uid) return;
    await firebase.firestore().collection("users").doc(uid).delete();
  }

  static async downloadVault(uid) {
    if (typeof firebase === 'undefined') return null;
    if (!uid) return null;
    const db = firebase.firestore();
    const doc = await db.collection("users").doc(uid).get();
    if (!doc.exists) return null;

    const data = doc.data() || {};
    // Normalise: an older/partial document must never be able to clobber
    // good local data with `undefined`.
    return {
      vault: Array.isArray(data.vault) ? data.vault : [],
      folders: Array.isArray(data.folders) ? data.folders : [],
      salt: typeof data.salt === "string" ? data.salt : null,
      hash: typeof data.hash === "string" ? data.hash : null,
      kdf: data.kdf && typeof data.kdf.v === "number" ? data.kdf : { v: 1, iterations: 100000 },
      slKeyEnc: typeof data.slKeyEnc === "string" ? data.slKeyEnc : "",
      updatedAtMs: typeof data.updatedAtMs === "number" ? data.updatedAtMs : 0,
      // A document only counts as a real vault once it carries key material.
      isProvisioned: typeof data.salt === "string" && typeof data.hash === "string",
    };
  }
}

// --- LOCAL ENCRYPTED STORAGE CONTROLLER ---
//
// Every vault lives under a namespace so that a vault always belongs to an
// *account*, never to "whatever browser profile happens to be open".
//   cv:local:*        -> the offline-only vault ("Continue Locally")
//   cv:u:<uid>:*      -> the vault belonging to Firebase user <uid>
//
// Without this, logging out of account A and into account B left A's salt and
// master-password hash behind, so B was prompted to unlock with A's master
// password and was then (correctly, but confusingly) refused.
class StorageController {
  static SCOPE_LOCAL = "local";

  // Legacy (pre-namespace) keys, migrated once into the "local" scope.
  static LEGACY_KEYS = {
    salt: "ciphervault_salt",
    hash: "ciphervault_mp_hash",
    items: "ciphervault_encrypted_items",
    slKey: "ciphervault_sl_api_key",
    folders: "cv_folders",
  };

  static KEY_CLIPBOARD_DELAY = "ciphervault_clipboard_delay";

  static _scope = "local";

  static setScope(uid) {
    this._scope = uid ? `u:${uid}` : this.SCOPE_LOCAL;
  }

  static getScope() { return this._scope; }

  /** Restores a scope string previously returned by getScope(). */
  static restoreScope(scope) {
    this._scope = scope || this.SCOPE_LOCAL;
  }

  /** Reads a whole vault out of another namespace without disturbing this one. */
  static readScope(scope) {
    const previous = this._scope;
    this._scope = scope;
    try {
      return {
        salt: this.getSalt(),
        hash: this.getMasterHash(),
        kdf: this.getKdf(),
        items: this.getEncryptedItems(),
        folders: this.getFolders(),
        slKeyEnc: this.getSimpleLoginKeyEnc(),
      };
    } finally {
      this._scope = previous;
    }
  }

  static _key(name, scope = this._scope) { return `cv:${scope}:${name}`; }

  static _get(name) { return localStorage.getItem(this._key(name)); }
  static _set(name, value) { localStorage.setItem(this._key(name), value); }
  static _del(name) { localStorage.removeItem(this._key(name)); }

  /** One-time move of pre-1.1 unnamespaced data into the local scope. */
  static migrateLegacyData() {
    if (localStorage.getItem("cv:migrated_v1")) return;
    const L = this.LEGACY_KEYS;
    const localKey = (n) => this._key(n, this.SCOPE_LOCAL);

    const copy = (legacy, name) => {
      const val = localStorage.getItem(legacy);
      if (val !== null && localStorage.getItem(localKey(name)) === null) {
        localStorage.setItem(localKey(name), val);
      }
      localStorage.removeItem(legacy);
    };

    copy(L.salt, "salt");
    copy(L.hash, "hash");
    copy(L.items, "items");
    copy(L.slKey, "sl_key");
    copy(L.folders, "folders");

    // The old "have they picked local mode?" flag.
    const choice = localStorage.getItem("cv_local_choice");
    if (choice === "true") localStorage.setItem("cv:local_choice", "true");
    localStorage.removeItem("cv_local_choice");

    localStorage.setItem("cv:migrated_v1", "1");
  }

  static hasVaultFor(scope) {
    return (
      localStorage.getItem(this._key("salt", scope)) !== null &&
      localStorage.getItem(this._key("hash", scope)) !== null
    );
  }

  static getSalt() { return this._get("salt"); }
  static setSalt(saltBase64) { this._set("salt", saltBase64); }

  static getMasterHash() { return this._get("hash"); }
  static setMasterHash(hashBase64) { this._set("hash", hashBase64); }

  /** KDF descriptor, e.g. { v: 2, iterations: 600000 }. Absent means v1. */
  static getKdf() {
    const raw = this._get("kdf");
    if (!raw) return { v: 1, iterations: 100000 };
    try {
      const parsed = JSON.parse(raw);
      return parsed && typeof parsed.v === "number" ? parsed : { v: 1, iterations: 100000 };
    } catch (e) {
      return { v: 1, iterations: 100000 };
    }
  }
  static setKdf(kdf) { this._set("kdf", JSON.stringify(kdf)); }

  static getEncryptedItems() {
    const raw = this._get("items");
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      console.error("Corrupt local vault index, starting empty.", e);
      return [];
    }
  }

  static saveEncryptedItems(itemsList) {
    this._set("items", JSON.stringify(Array.isArray(itemsList) ? itemsList : []));
  }

  /**
   * SimpleLogin API key.
   *
   * Held as a blob encrypted with the vault key, so it syncs between devices
   * through the same Firestore document as everything else and is never at
   * rest in the clear. It used to sit in localStorage as plaintext, readable
   * by anything with access to the profile - and it grants full control of
   * the user's aliases.
   *
   * `sl_key` (plaintext) is only still read so an existing one can be
   * migrated on the next unlock; see CipherVaultApp.migrateSimpleLoginKey.
   */
  static getLegacySimpleLoginKey() { return this._get("sl_key") || ""; }
  static clearLegacySimpleLoginKey() { this._del("sl_key"); }

  static getSimpleLoginKeyEnc() { return this._get("sl_key_enc") || ""; }
  static setSimpleLoginKeyEnc(blob) {
    if (blob) this._set("sl_key_enc", blob);
    else this._del("sl_key_enc");
  }

  /** Clipboard timeout is a device preference, so it stays outside the scope. */
  static getClipboardDelay() {
    return localStorage.getItem(this.KEY_CLIPBOARD_DELAY) || "30";
  }
  static setClipboardDelay(seconds) {
    localStorage.setItem(this.KEY_CLIPBOARD_DELAY, seconds);
  }

  /** Idle auto-lock, in minutes, or "never". Also a device preference. */
  static getAutoLockMinutes() {
    return localStorage.getItem("ciphervault_auto_lock") || "15";
  }
  static setAutoLockMinutes(minutes) {
    localStorage.setItem("ciphervault_auto_lock", minutes);
  }

  static getFolders() {
    const f = this._get("folders");
    if (!f) return [];
    try {
      const parsed = JSON.parse(f);
      return Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      return [];
    }
  }
  static setFolders(folders) {
    this._set("folders", JSON.stringify(Array.isArray(folders) ? folders : []));
  }

  /** Wipes every trace of the currently scoped vault from this device. */
  static wipeScope() {
    ["salt", "hash", "kdf", "items", "sl_key", "sl_key_enc", "folders"].forEach((n) => this._del(n));
  }

  static getLocalChoice() { return localStorage.getItem("cv:local_choice") === "true"; }
  static setLocalChoice(on) {
    if (on) localStorage.setItem("cv:local_choice", "true");
    else localStorage.removeItem("cv:local_choice");
  }
}

// --- SIMPLELOGIN REST API CLIENT ---
class SimpleLoginClient {
  static API_BASE = "https://app.simplelogin.io/api";

  static async fetchAliasOptions(apiKey) {
    if (!apiKey) throw new Error("SimpleLogin API Key required.");
    const res = await fetch(`${this.API_BASE}/v5/alias/options`, {
      headers: { "Authentication": apiKey },
    });
    if (!res.ok) throw new Error("Failed to load SimpleLogin options");
    return await res.json();
  }

  static async fetchMailboxes(apiKey) {
    if (!apiKey) return [];
    const res = await fetch(`${this.API_BASE}/v2/mailboxes`, {
      headers: { "Authentication": apiKey },
    });
    if (!res.ok) return [];
    const data = await res.json();
    return data.mailboxes || [];
  }

  static async createCustomAlias(apiKey, prefix, suffix, note = "CipherVault Alias") {
    if (!apiKey) throw new Error("SimpleLogin API Key required.");

    // Fetch mailboxes to get the default mailbox ID
    const mailboxes = await this.fetchMailboxes(apiKey);
    const defaultMb = mailboxes.find(mb => mb.default) || mailboxes[0];
    const mailboxIds = defaultMb ? [defaultMb.id] : [];

    const res = await fetch(`${this.API_BASE}/v3/alias/custom/new`, {
      method: "POST",
      headers: {
        "Authentication": apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ alias_prefix: prefix, signed_suffix: suffix, note, mailbox_ids: mailboxIds }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to create SimpleLogin alias");
    return data;
  }

  static async deleteAlias(apiKey, aliasId) {
    if (!apiKey) return false;
    const res = await fetch(`${this.API_BASE}/aliases/${aliasId}`, {
      method: "DELETE",
      headers: { "Authentication": apiKey },
    });
    return res.ok;
  }

  static async fetchAliases(apiKey) {
    if (!apiKey) return [];

    const res = await fetch(`${this.API_BASE}/v2/aliases?page_id=0`, {
      headers: { "Authentication": apiKey },
    });

    if (!res.ok) return [];
    const data = await res.json();
    return data.aliases || [];
  }
}

// --- BREACH SCANNER ENGINE (HIBP k-Anonymity) ---
class BreachScannerEngine {
  static async sha1(text) {
    const buffer = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-1", buffer);
    return Array.from(new Uint8Array(hash))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("").toUpperCase();
  }

  static async checkPassword(password) {
    const hash = await this.sha1(password);
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    try {
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
      if (!res.ok) return 0;
      const text = await res.text();
      const lines = text.split("\n");
      for (const line of lines) {
        const [hashSuffix, count] = line.split(":");
        if (hashSuffix.trim() === suffix) {
          return parseInt(count, 10);
        }
      }
      return 0;
    } catch (e) {
      return -1;
    }
  }
}


// --- PASSWORD HEALTH DIAGNOSTICS ---
class PasswordHealthEngine {
  static analyzeVault(decryptedVault) {
    const loginItems = decryptedVault.filter((i) => !i.isTrashed && (i.type === "login" || i.type === "passwords") && i.data.password);
    if (loginItems.length === 0) {
      return { score: 100, weakCount: 0, weakItems: [], reusedGroups: 0, reusedItems: [] };
    }

    let weakCount = 0;
    const weakItems = [];
    const passwordCounts = {};

    loginItems.forEach((item) => {
      const pw = item.data.password || "";
      if (!passwordCounts[pw]) passwordCounts[pw] = [];
      passwordCounts[pw].push(item);

      if (pw.length < 10 || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw) || !/[!@#$%^&*]/.test(pw)) {
        weakCount++;
        weakItems.push(item);
      }
    });

    let reusedGroups = 0;
    const reusedItems = [];
    Object.values(passwordCounts).forEach((items) => {
      if (items.length > 1) {
        reusedGroups++;
        reusedItems.push(...items);
      }
    });
    
    let score = 100;
    score -= reusedGroups * 15;
    score -= weakCount * 10;
    score = Math.max(10, Math.min(100, score));

    return { score, weakCount, weakItems, reusedGroups, reusedItems };
  }
}
