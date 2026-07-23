/**
 * CipherVault - Zero-Knowledge Desktop Security Workspace
 * Production-Grade Self-Contained JavaScript Architecture (Monochrome Dark Theme)
 */

(function () {
  'use strict';

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

    static async uploadVault(uid, { vault, foldersEnc, salt, hash, kdf, slKeyEnc }) {
      if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
      if (!uid) throw new Error("Not signed in.");
      if (!salt || !hash) throw new Error("Refusing to sync a vault with no master key material.");

      const db = firebase.firestore();
      await db.collection("users").doc(uid).set({
        schemaVersion: 4,
        vault: Array.isArray(vault) ? vault : [],
        // Encrypted with the vault key: folder names are not metadata we want
        // the server to hold. `folders` is no longer written.
        foldersEnc: typeof foldersEnc === "string" ? foldersEnc : "",
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

    // --- QR unlock transport -------------------------------------------
    // Only ever carries ephemeral public keys and a ciphertext; see
    // LinkSessionEngine for why that is safe to put in a database.

    static _linkDoc(uid, sessionId) {
      return firebase.firestore().collection("users").doc(uid)
        .collection("linkSessions").doc(sessionId);
    }

    /** Desktop: waits for the phone to approve. Returns an unsubscribe fn. */
    static watchLinkSession(uid, sessionId, onResponse, onError) {
      if (typeof firebase === 'undefined' || !uid) return () => {};

      return this._linkDoc(uid, sessionId).onSnapshot(
        (doc) => {
          if (!doc.exists) return;
          const data = doc.data() || {};
          if (typeof data.pk === "string" && typeof data.ct === "string") {
            onResponse({ publicKey: data.pk, ciphertext: data.ct });
          }
        },
        (err) => { if (onError) onError(err); }
      );
    }

    /** Phone: publishes the sealed approval. */
    static async postLinkResponse(uid, sessionId, response) {
      if (typeof firebase === 'undefined') throw new Error("Firebase SDK not loaded.");
      if (!uid) throw new Error("Not signed in.");

      await this._linkDoc(uid, sessionId).set({
        pk: response.publicKey,
        ct: response.ciphertext,
        createdAt: firebase.firestore.FieldValue.serverTimestamp(),
      });
    }

    /** Single-use: the document is destroyed as soon as it has been consumed. */
    static async deleteLinkSession(uid, sessionId) {
      if (typeof firebase === 'undefined' || !uid || !sessionId) return;
      try {
        await this._linkDoc(uid, sessionId).delete();
      } catch (err) {
        console.warn("Could not clear the link session:", err);
      }
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
        foldersEnc: typeof data.foldersEnc === "string" ? data.foldersEnc : "",
        // Read only so a vault written before v1.4 can be migrated.
        legacyFolders: Array.isArray(data.folders) ? data.folders : [],
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
          foldersEnc: this.getFoldersEnc(),
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

    /**
     * Folder names.
     *
     * Encrypted with the vault key, like the SimpleLogin key. They used to be
     * written in the clear, which meant "Banking", "Crypto" or an employer's
     * name were readable from disk without unlocking and were visible in the
     * synced document. The names alone say a lot about what a vault contains.
     *
     * `folders` (plaintext) is only still read so an existing list can be
     * migrated on the next unlock.
     */
    static getFoldersEnc() { return this._get("folders_enc") || ""; }
    static setFoldersEnc(blob) {
      if (blob) this._set("folders_enc", blob);
      else this._del("folders_enc");
    }

    static getLegacyFolders() {
      const f = this._get("folders");
      if (!f) return [];
      try {
        const parsed = JSON.parse(f);
        return Array.isArray(parsed) ? parsed : [];
      } catch (e) {
        return [];
      }
    }
    static clearLegacyFolders() { this._del("folders"); }

    /** Wipes every trace of the currently scoped vault from this device. */
    static wipeScope() {
      ["salt", "hash", "kdf", "items", "sl_key", "sl_key_enc", "folders", "folders_enc"]
        .forEach((n) => this._del(n));
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

  // --- MAIN APPLICATION CONTROLLER ---
  class CipherVaultApp {
    constructor() {
      this.aesKey = null;
      this.decryptedVault = [];
      this.folders = [];
      this.activeCategory = "all";
      this.selectedItemId = null;
      this.editingItemId = null;
      this.clipboardTimeout = null;
      this.firebaseUser = null;
      this.currentUid = null;
      this.authResolved = false;
      // Only ever populated while the vault is unlocked.
      this.simpleLoginKey = "";

      this.init();
    }

    async init() {
      StorageController.migrateLegacyData();
      StorageController.setScope(null);
      // Folders are encrypted, so they stay empty until the vault is unlocked.
      this.folders = [];

      this.bindEvents();
      FirebaseSyncEngine.init();
      this.setupFirebaseSync();
      this.startTotpInterval();
      this.setupDesktopUpdates();

      // Firebase restores a persisted session asynchronously. Show the correct
      // screen straight away for the offline case; onAuthStateChanged will
      // re-run this once it knows whether somebody is signed in.
      this.checkVaultSetup();
    }

    /** Reflects the current auth state in the sidebar + auth modal. */
    updateSyncIndicator(syncing = false) {
      const user = this.firebaseUser;
      const syncDot = document.getElementById("sync-status-dot");
      const syncText = document.getElementById("sync-status-text");
      const btnLoginTrigger = document.getElementById("btn-sync-trigger");
      const btnLogout = document.getElementById("btn-fb-logout");

      if (user) {
        if (syncDot) syncDot.style.backgroundColor = syncing ? "#facc15" : "#4ade80";
        if (syncText) syncText.textContent = syncing ? "Syncing…" : "Synced";
        if (btnLoginTrigger) btnLoginTrigger.textContent = user.email || "Account";
        if (btnLogout) btnLogout.classList.remove("hidden");
      } else {
        if (syncDot) syncDot.style.backgroundColor = "var(--text-disabled)";
        if (syncText) syncText.textContent = "Local Only";
        if (btnLoginTrigger) btnLoginTrigger.textContent = "Login";
        if (btnLogout) btnLogout.classList.add("hidden");
      }
    }

    setupFirebaseSync() {
      FirebaseSyncEngine.onAuthStateChanged(async (user) => {
        const newUid = user ? user.uid : null;
        const changed = newUid !== this.currentUid;

        this.firebaseUser = user;
        this.currentUid = newUid;
        this.authResolved = true;

        if (changed) {
          // Identity changed: drop every decrypted secret from memory and point
          // storage at the new account's namespace before touching anything.
          this.aesKey = null;
          this.decryptedVault = [];
          this.simpleLoginKey = "";
          this.selectedItemId = null;
          this.editingItemId = null;
          StorageController.setScope(newUid);
          this.folders = [];
          this.renderFoldersList();
          this.renderList();
          this.showLockScreen();
        }

        this.updateSyncIndicator(!!user);

        if (user) {
          await this.syncVaultFromFirebase();
        }

        this.updateSyncIndicator(false);
        this.checkVaultSetup();
      });

      document.getElementById("btn-close-firebase-auth")?.addEventListener("click", () => this.closeModal("modal-firebase-auth"));

      const errorDiv = document.getElementById("firebase-auth-error");
      const successDiv = document.getElementById("firebase-auth-success");
      const emailInput = document.getElementById("fb-email");
      const pwdInput = document.getElementById("fb-password");

      const clearAuthMessages = () => {
        if (errorDiv) errorDiv.style.display = "none";
        if (successDiv) successDiv.style.display = "none";
      };
      const showAuthError = (message) => {
        if (errorDiv) {
          errorDiv.style.display = "block";
          errorDiv.textContent = message;
        }
      };

      document.getElementById("btn-fb-login")?.addEventListener("click", async () => {
        clearAuthMessages();
        const email = (emailInput?.value || "").trim();
        const pwd = pwdInput?.value || "";
        if (!email || !pwd) return showAuthError("Enter both an email address and a password.");
        try {
          await FirebaseSyncEngine.login(email, pwd);
          if (pwdInput) pwdInput.value = "";
          this.closeModal("modal-firebase-auth");
          this.showToast("Signed in — syncing your vault…");
        } catch (err) {
          showAuthError(this.friendlyAuthError(err));
        }
      });

      document.getElementById("btn-fb-signup")?.addEventListener("click", async () => {
        clearAuthMessages();
        const email = (emailInput?.value || "").trim();
        const pwd = pwdInput?.value || "";
        if (!email || !pwd) return showAuthError("Enter both an email address and a password.");
        if (pwd.length < 6) return showAuthError("Your account password must be at least 6 characters.");
        try {
          await FirebaseSyncEngine.signup(email, pwd);
          if (pwdInput) pwdInput.value = "";
          this.closeModal("modal-firebase-auth");
          this.showToast("Account created — now choose a master password");
        } catch (err) {
          showAuthError(this.friendlyAuthError(err));
        }
      });

      document.getElementById("btn-fb-logout")?.addEventListener("click", async () => {
        clearAuthMessages();
        await FirebaseSyncEngine.logout();
        StorageController.setLocalChoice(false);
        this.closeModal("modal-firebase-auth");
        this.showToast("Signed out. Your encrypted vault stays safe in the cloud.");
      });

      document.getElementById("btn-fb-forgot")?.addEventListener("click", async () => {
        clearAuthMessages();
        const email = (emailInput?.value || "").trim();
        if (!email) return showAuthError("Please enter your email address above first.");
        try {
          await FirebaseSyncEngine.sendPasswordReset(email);
          if (successDiv) {
            successDiv.style.display = "block";
            successDiv.textContent = `Password reset email sent to ${email}. Note: this resets your ACCOUNT password, not your master password.`;
          }
        } catch (err) {
          showAuthError(this.friendlyAuthError(err));
        }
      });
    }

    friendlyAuthError(err) {
      const code = (err && err.code) || "";
      switch (code) {
        case "auth/invalid-email": return "That email address doesn't look valid.";
        case "auth/user-not-found":
        case "auth/wrong-password":
        case "auth/invalid-credential": return "Incorrect email or password.";
        case "auth/email-already-in-use": return "An account already exists for that email — use Log In instead.";
        case "auth/weak-password": return "Pick a longer account password (at least 6 characters).";
        case "auth/network-request-failed": return "Can't reach Firebase. Check your internet connection.";
        case "auth/too-many-requests": return "Too many attempts. Wait a moment and try again.";
        default: return (err && err.message) || "Authentication failed.";
      }
    }

    /**
     * Pulls this account's vault down from Firestore.
     *
     * Rules:
     *  - A cloud document only counts once it carries salt + hash. A half-written
     *    document must never wipe a working local vault.
     *  - If the account has no cloud vault yet but this device has an offline
     *    vault, that offline vault is adopted and pushed up, so "Continue
     *    Locally" then "Create Cloud Account" keeps your data.
     */
    async syncVaultFromFirebase() {
      const uid = this.currentUid;
      if (!uid) return;

      let cloud = null;
      try {
        cloud = await FirebaseSyncEngine.downloadVault(uid);
      } catch (err) {
        console.error("Cloud sync failed:", err);
        this.showToast("Couldn't reach the cloud — working from this device's copy.");
        return;
      }

      if (cloud && cloud.isProvisioned) {
        const localSalt = StorageController.getSalt();
        const localHash = StorageController.getMasterHash();
        const keyMaterialChanged = localSalt !== cloud.salt || localHash !== cloud.hash;

        StorageController.setSalt(cloud.salt);
        StorageController.setMasterHash(cloud.hash);
        StorageController.setKdf(cloud.kdf);
        StorageController.saveEncryptedItems(cloud.vault);
        StorageController.setSimpleLoginKeyEnc(cloud.slKeyEnc);
        StorageController.setFoldersEnc(cloud.foldersEnc);
        // A vault written before v1.4 still has plaintext folders; keep them
        // so the next unlock can encrypt them.
        if (!cloud.foldersEnc && cloud.legacyFolders.length) {
          StorageController._set("folders", JSON.stringify(cloud.legacyFolders));
        }

        // The master password behind the cached key no longer matches the cloud
        // vault, so the in-memory key can't decrypt it. Force a re-unlock.
        if (keyMaterialChanged && this.aesKey) {
          this.aesKey = null;
          this.decryptedVault = [];
          this.simpleLoginKey = "";
          this.folders = [];
          this.showLockScreen();
        }

        this.renderFoldersList();
        if (this.aesKey) {
          await this.loadAndDecryptVault({ keepView: true });
          this.showToast("Vault synced from cloud");
        }
        return;
      }

      // No cloud vault for this account yet.
      const adoptable =
        StorageController.hasVaultFor(StorageController.SCOPE_LOCAL) &&
        !StorageController.hasVaultFor(`u:${uid}`);

      if (adoptable) {
        const ok = confirm(
          "This account has no cloud vault yet.\n\n" +
          "Upload the offline vault stored on this device to it?\n\n" +
          "Your master password and all items stay end-to-end encrypted."
        );
        if (ok) {
          // Copy the offline namespace into this account's namespace.
          const { salt, hash, kdf, items, foldersEnc, slKeyEnc } =
            StorageController.readScope(StorageController.SCOPE_LOCAL);

          StorageController.setSalt(salt);
          StorageController.setMasterHash(hash);
          StorageController.setKdf(kdf);
          StorageController.saveEncryptedItems(items);
          StorageController.setFoldersEnc(foldersEnc);
          StorageController.setSimpleLoginKeyEnc(slKeyEnc);
          await this.loadFolders();
          this.renderFoldersList();

          try {
            await FirebaseSyncEngine.uploadVault(uid, { vault: items, foldersEnc, salt, hash, kdf, slKeyEnc });
            this.showToast("Offline vault linked to your account.");
          } catch (err) {
            console.error("Failed to upload adopted vault:", err);
            this.showToast(this.friendlySyncError(err));
          }
        }
      }
      // Otherwise checkVaultSetup() will show "Create Master Password".
    }

    friendlySyncError(err) {
      const code = (err && err.code) || "";
      if (code === "permission-denied") {
        return "Cloud sync blocked by Firestore security rules — see README-SETUP.md.";
      }
      if (code === "unavailable") return "Cloud unreachable. Changes are saved on this device.";
      return "Cloud sync failed: " + ((err && err.message) || "unknown error");
    }

    showLockScreen() {
      const screen = document.getElementById("master-lock-screen");
      if (screen) screen.classList.remove("hidden");
      const input = document.getElementById("master-pass-input");
      if (input) input.value = "";
    }

    checkVaultSetup() {
      const salt = StorageController.getSalt();
      const hash = StorageController.getMasterHash();

      const setupForm = document.getElementById("setup-form");
      const unlockForm = document.getElementById("unlock-form");
      const welcomeForm = document.getElementById("welcome-form");
      const lockTitle = document.getElementById("lock-title");
      const lockSub = document.getElementById("lock-subtitle");

      if (setupForm) setupForm.classList.add("hidden");
      if (unlockForm) unlockForm.classList.add("hidden");
      if (welcomeForm) welcomeForm.classList.add("hidden");
      document.getElementById("btn-qr-unlock")?.classList.add("hidden");

      const account = this.firebaseUser ? this.firebaseUser.email : null;

      if (salt && hash) {
        if (unlockForm) unlockForm.classList.remove("hidden");
        if (lockTitle) lockTitle.textContent = "Unlock Vault";
        if (lockSub) {
          lockSub.textContent = account
            ? `Enter the master password for ${account}.`
            : "Enter your master password to decrypt this device's vault.";
        }
        // Only grab focus when the lock screen is actually on screen, otherwise
        // a background sync would yank the caret out of whatever the user is
        // currently typing into.
        const lockScreen = document.getElementById("master-lock-screen");
        if (lockScreen && !lockScreen.classList.contains("hidden")) {
          document.getElementById("master-pass-input")?.focus();
        }

        // Both devices have to be on the same account for the handshake.
        document.getElementById("btn-qr-unlock")?.classList.toggle("hidden", !this.currentUid);
      } else if (this.firebaseUser || StorageController.getLocalChoice()) {
        if (setupForm) setupForm.classList.remove("hidden");
        if (lockTitle) lockTitle.textContent = "Create Master Password";
        if (lockSub) {
          lockSub.textContent = account
            ? `Set the master password that encrypts the vault for ${account}. It is never sent anywhere.`
            : "Set up a master password to protect your zero-knowledge vault.";
        }
      } else {
        if (welcomeForm) welcomeForm.classList.remove("hidden");
        if (lockTitle) lockTitle.textContent = "Welcome to CipherVault";
        if (lockSub) lockSub.textContent = "Your secure, zero-knowledge workspace.";
      }
    }

    bindEvents() {
      // Welcome Screen
      const btnWelcomeLocal = document.getElementById("btn-welcome-local");
      if (btnWelcomeLocal) {
        btnWelcomeLocal.addEventListener("click", () => {
          StorageController.setLocalChoice(true);
          this.checkVaultSetup();
        });
      }
      const btnWelcomeLogin = document.getElementById("btn-welcome-login");
      if (btnWelcomeLogin) {
        btnWelcomeLogin.addEventListener("click", () => {
          this.openModal("modal-firebase-auth");
        });
      }
      const btnBackWelcome = document.getElementById("btn-back-to-welcome");
      if (btnBackWelcome) {
        btnBackWelcome.addEventListener("click", async () => {
          if (this.firebaseUser) {
            await FirebaseSyncEngine.logout();
          }
          StorageController.setLocalChoice(false);
          this.checkVaultSetup();
        });
      }
      const btnBackUnlock = document.getElementById("btn-back-to-welcome-unlock");
      if (btnBackUnlock) {
        btnBackUnlock.addEventListener("click", () => {
          this.openModal("modal-firebase-auth");
        });
      }
      // Sidebar "Login" / account button.
      document.getElementById("btn-sync-trigger")?.addEventListener("click", () => this.openModal("modal-firebase-auth"));

      document.getElementById("btn-qr-unlock")?.addEventListener("click", () => this.openQrUnlock());
      document.getElementById("btn-close-qr")?.addEventListener("click", () => this.stopQrSession());
      // Global Keyboard Shortcuts
      document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "k") {
          e.preventDefault();
          const searchInput = document.getElementById("vault-search-input");
          if (searchInput) searchInput.focus();
        }
        if ((e.ctrlKey || e.metaKey) && e.key === "n") {
          e.preventDefault();
          this.openItemEditor();
        }
        if (e.key === "Escape") {
          this.closeAllModals();
        }
      });

      // Password Eye Toggles
      const toggleCreate = document.getElementById("btn-toggle-create");
      if (toggleCreate) {
        toggleCreate.addEventListener("click", () => {
          const input = document.getElementById("create-pass-input");
          input.type = input.type === "password" ? "text" : "password";
        });
      }

      const toggleMaster = document.getElementById("btn-toggle-master");
      if (toggleMaster) {
        toggleMaster.addEventListener("click", () => {
          const input = document.getElementById("master-pass-input");
          input.type = input.type === "password" ? "text" : "password";
        });
      }

      // Live Password Strength Meter
      const createPassInput = document.getElementById("create-pass-input");
      if (createPassInput) {
        createPassInput.addEventListener("input", () => {
          const val = createPassInput.value;
          const bar = document.getElementById("setup-strength-bar");
          const text = document.getElementById("setup-strength-text");

          if (!val) {
            bar.style.width = "0%";
            text.textContent = "Password Strength: None";
            return;
          }

          let score = 0;
          if (val.length >= 8) score += 25;
          if (val.length >= 14) score += 25;
          if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score += 25;
          if (/[0-9]/.test(val) && /[!@#$%^&*]/.test(val)) score += 25;

          bar.style.width = `${score}%`;
          if (score <= 25) {
            bar.style.backgroundColor = "var(--text-muted)";
            text.textContent = "Password Strength: Weak";
          } else if (score <= 50) {
            bar.style.backgroundColor = "var(--text-secondary)";
            text.textContent = "Password Strength: Fair";
          } else if (score <= 75) {
            bar.style.backgroundColor = "var(--text-secondary)";
            text.textContent = "Password Strength: Good";
          } else {
            bar.style.backgroundColor = "var(--text-primary)";
            text.textContent = "Password Strength: Strong";
          }
        });
      }

      // FORM A: FIRST TIME MASTER PASSWORD SETUP
      const setupForm = document.getElementById("setup-form");
      if (setupForm) {
        setupForm.addEventListener("submit", async (e) => {
          e.preventDefault();
          const pass = document.getElementById("create-pass-input").value;
          const confirmPass = document.getElementById("confirm-pass-input").value;
          const errorMsg = document.getElementById("setup-error-msg");

          if (pass !== confirmPass) {
            errorMsg.textContent = "Passwords do not match!";
            errorMsg.classList.remove("hidden");
            return;
          }
          if (pass.length < 8) {
            errorMsg.textContent = "Master password must be at least 8 characters long.";
            errorMsg.classList.remove("hidden");
            return;
          }

          errorMsg.classList.add("hidden");

          const submitBtn = document.getElementById("btn-create-vault");
          if (submitBtn) submitBtn.disabled = true;

          try {
            const salt = CryptoEngine.generateSalt();
            const kdf = { v: CryptoEngine.KDF_VERSION, iterations: CryptoEngine.DEFAULT_ITERATIONS };
            const { aesKey, verifier } = await CryptoEngine.deriveKeyAndVerifier(pass, salt, kdf.iterations);
            const hash = verifier;

            StorageController.setSalt(salt);
            StorageController.setMasterHash(hash);
            StorageController.setKdf(kdf);
            StorageController.saveEncryptedItems([]);
            StorageController.setFoldersEnc("");

            this.aesKey = aesKey;
            this.decryptedVault = [];
            this.folders = [];

            // Publish the new key material immediately. Previously nothing was
            // written to Firestore until the first item was saved, so a fresh
            // account looked empty to every other device — the browser
            // extension would prompt for the master password and then refuse.
            if (this.currentUid) {
              try {
                await FirebaseSyncEngine.uploadVault(this.currentUid, {
                  vault: [], foldersEnc: "", salt, hash, kdf, slKeyEnc: "",
                });
              } catch (err) {
                console.error("Failed to provision cloud vault:", err);
                this.showToast(this.friendlySyncError(err));
              }
            }

            document.getElementById("master-lock-screen").classList.add("hidden");
            document.getElementById("create-pass-input").value = "";
            document.getElementById("confirm-pass-input").value = "";
            this.renderFoldersList();
            this.renderList();
            this.showView("detail-watermark");
            this.resetIdleTimer();
            this.showToast("Master password created! Vault initialized.");
          } catch (err) {
            errorMsg.textContent = "Setup error: " + err.message;
            errorMsg.classList.remove("hidden");
          } finally {
            if (submitBtn) submitBtn.disabled = false;
          }
        });
      }

      // FORM B: UNLOCK EXISTING VAULT
      const unlockForm = document.getElementById("unlock-form");
      if (unlockForm) {
        unlockForm.addEventListener("submit", async (e) => {
          e.preventDefault();
          await this.handleUnlock();
        });
      }

      // RESET VAULT BUTTON
      const btnReset = document.getElementById("btn-reset-vault");
      if (btnReset) {
        btnReset.addEventListener("click", async () => {
          const who = this.firebaseUser
            ? `the vault for ${this.firebaseUser.email}`
            : "this device's offline vault";
          if (!confirm(
            `Reset ${who}?\n\n` +
            "The master password cannot be recovered, so every item encrypted with it is permanently lost. " +
            "You'll be asked to set a new master password.\n\nThis cannot be undone."
          )) return;

          StorageController.wipeScope();
          this.aesKey = null;
          this.decryptedVault = [];
          this.folders = [];

          if (this.currentUid) {
            try {
              await FirebaseSyncEngine.deleteVault(this.currentUid);
            } catch (err) {
              console.error("Failed to clear cloud vault:", err);
              this.showToast(this.friendlySyncError(err));
            }
          }

          this.renderFoldersList();
          this.renderList();
          this.checkVaultSetup();
          this.showToast("Vault reset. Please set a new master password.");
        });
      }

      // Sidebar Category Navigation (Fixes item disappearance across tabs!)
      document.querySelectorAll(".nav-item[data-category]").forEach((btn) => {
        btn.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          this.activeCategory = btn.dataset.category;
          this.selectedItemId = null;
          this.showView("detail-watermark");
          this.renderList();
        });
      });

      // Search Input Listener
      const searchInput = document.getElementById("vault-search-input");
      if (searchInput) {
        searchInput.addEventListener("input", () => this.renderList());
      }

      // Quick Add Button Listener
      const btnQuickAdd = document.getElementById("btn-quick-add");
      if (btnQuickAdd) {
        btnQuickAdd.addEventListener("click", () => this.openItemEditor());
      }

      // Modal Editor Controls
      const btnCloseEditor = document.getElementById("btn-close-editor");
      if (btnCloseEditor) btnCloseEditor.addEventListener("click", () => this.closeModal("modal-item-editor"));
      const btnCancelEditor = document.getElementById("btn-cancel-editor");
      if (btnCancelEditor) btnCancelEditor.addEventListener("click", () => this.closeModal("modal-item-editor"));

      const editorTypeSelect = document.getElementById("editor-type-select");
      if (editorTypeSelect) {
        editorTypeSelect.addEventListener("change", (e) => this.renderDynamicEditorFields(e.target.value));
      }

      const formEditor = document.getElementById("form-item-editor");
      if (formEditor) {
        formEditor.addEventListener("submit", async (e) => {
          e.preventDefault();
          await this.saveItemFromEditor();
        });
      }

      // Settings Modal Open / Close Controls
      const btnSettingsOpen = document.getElementById("btn-settings-open");
      if (btnSettingsOpen) {
        btnSettingsOpen.addEventListener("click", () => this.openSettingsModal());
      }
      const btnCloseSettings = document.getElementById("btn-close-settings");
      if (btnCloseSettings) {
        btnCloseSettings.addEventListener("click", () => this.closeModal("modal-settings"));
      }

      // Settings Actions: Firebase, SimpleLogin, Clipboard, Export, Import, Destroy
      const btnLinkFirebase = document.getElementById("btn-link-firebase");
      if (btnLinkFirebase) {
        btnLinkFirebase.addEventListener("click", () => {
          this.closeModal("modal-settings");
          this.openModal("modal-firebase-auth");
        });
      }

      const btnSaveSettingSl = document.getElementById("btn-save-setting-sl");
      if (btnSaveSettingSl) {
        btnSaveSettingSl.addEventListener("click", async () => {
          const val = document.getElementById("setting-sl-key-input").value.trim();
          await this.saveSimpleLoginKey(val);
          if (!document.getElementById("view-simplelogin-tool").classList.contains("hidden")) {
            this.loadSimpleLoginAliases();
          }
        });
      }

      const selectClipboard = document.getElementById("setting-clear-clipboard-select");
      if (selectClipboard) {
        selectClipboard.value = StorageController.getClipboardDelay();
        selectClipboard.addEventListener("change", (e) => {
          StorageController.setClipboardDelay(e.target.value);
          this.showToast(`Clipboard auto-clear set to ${e.target.value}s`);
        });
      }

      const btnExportJson = document.getElementById("btn-export-vault-json");
      if (btnExportJson) {
        btnExportJson.addEventListener("click", () => this.exportVaultAsJson());
      }

      const inputImportJson = document.getElementById("input-import-vault-json");
      if (inputImportJson) {
        inputImportJson.addEventListener("change", (e) => this.importVaultFromJson(e));
      }

      const btnDestroyVault = document.getElementById("btn-destroy-vault-data");
      if (btnDestroyVault) {
        btnDestroyVault.addEventListener("click", async () => {
          const who = this.firebaseUser
            ? `the vault for ${this.firebaseUser.email} (on this device AND in the cloud)`
            : "this device's offline vault";
          if (!confirm(`WARNING: this permanently destroys ${who}.\n\nEvery stored secret is deleted. Continue?`)) return;

          StorageController.wipeScope();
          if (this.currentUid) {
            try {
              await FirebaseSyncEngine.deleteVault(this.currentUid);
            } catch (err) {
              console.error("Failed to delete cloud vault:", err);
              this.showToast(this.friendlySyncError(err));
            }
          }

          this.aesKey = null;
          this.decryptedVault = [];
          this.folders = [];
          this.renderFoldersList();
          this.renderList();
          this.closeModal("modal-settings");
          this.showLockScreen();
          this.checkVaultSetup();
          this.showToast("Vault data destroyed.");
        });
      }

      // Advanced Tools Navigation
      const btnNavGenerator = document.getElementById("nav-btn-generator");
      if (btnNavGenerator) {
        btnNavGenerator.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btnNavGenerator.classList.add("active");
          this.renderPasswordGenerator();
        });
      }

      const btnNavHealth = document.getElementById("nav-btn-health");
      if (btnNavHealth) {
        btnNavHealth.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btnNavHealth.classList.add("active");
          this.renderHealthDashboard();
        });
      }

      const btnNavMasking = document.getElementById("nav-btn-email-masking");
      if (btnNavMasking) {
        btnNavMasking.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btnNavMasking.classList.add("active");
          this.renderSimpleLoginTool();
        });
      }

      const btnNavBreach = document.getElementById("nav-btn-breach");
      if (btnNavBreach) {
        btnNavBreach.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btnNavBreach.classList.add("active");
          this.renderBreachScanner();
        });
      }

      // Sidebar Folders Add
      const btnAddFolder = document.getElementById("btn-add-folder-trigger");
      if (btnAddFolder) {
        btnAddFolder.addEventListener("click", async () => {
          if (!this.aesKey) {
            this.showToast("Unlock your vault before creating folders.");
            return;
          }
          const name = prompt("Enter new folder name:");
          if (!name || !name.trim()) return;

          this.folders.push({ id: "folder_" + Date.now(), name: name.trim() });
          this.renderFoldersList();
          await this.saveFolders();
          this.showToast("Folder created!");
        });
      }

      const btnEmptyTrash = document.getElementById("btn-empty-trash");
      if (btnEmptyTrash) {
        btnEmptyTrash.addEventListener("click", () => {
          if (confirm("Are you sure you want to permanently delete all items in the Trash? This cannot be undone.")) {
            this.decryptedVault = this.decryptedVault.filter((i) => !i.isTrashed);
            this.saveEncryptedVault();
            this.renderList();
            this.showToast("Trash emptied.");
          }
        });
      }

      const btnSaveSl = document.getElementById("btn-tool-save-sl");
      if (btnSaveSl) {
        btnSaveSl.addEventListener("click", async () => {
          const key = document.getElementById("tool-sl-api-key").value.trim();
          await this.saveSimpleLoginKey(key);
          this.loadSimpleLoginAliases();
        });
      }

      const btnGenAlias = document.getElementById("btn-tool-gen-alias");
      if (btnGenAlias) {
        btnGenAlias.addEventListener("click", async () => {
          await this.handleToolGenerateAlias();
        });
      }

      // Manual Lock Button
      const btnLockManual = document.getElementById("btn-lock-manual");
      if (btnLockManual) {
        btnLockManual.addEventListener("click", () => this.lockVault());
      }

      const selectAutoLock = document.getElementById("setting-auto-lock-select");
      if (selectAutoLock) {
        selectAutoLock.value = StorageController.getAutoLockMinutes();
        selectAutoLock.addEventListener("change", (e) => {
          StorageController.setAutoLockMinutes(e.target.value);
          this.resetIdleTimer();
          this.showToast(
            e.target.value === "never"
              ? "Auto-lock disabled."
              : `Vault will auto-lock after ${e.target.value} minute(s) idle.`
          );
        });
      }

      // Any sign of life postpones the idle lock.
      ["mousemove", "mousedown", "keydown", "touchstart", "wheel", "focus"].forEach((evt) => {
        window.addEventListener(evt, () => this.resetIdleTimer(), { passive: true, capture: true });
      });
    }

    /**
     * Drops the decryption key after a period of inactivity, so an unlocked
     * vault left open on screen doesn't stay readable indefinitely.
     */
    resetIdleTimer() {
      if (this.idleTimer) clearTimeout(this.idleTimer);
      if (!this.aesKey) return;

      const setting = StorageController.getAutoLockMinutes();
      if (setting === "never") return;

      const minutes = parseInt(setting, 10);
      if (isNaN(minutes) || minutes <= 0) return;

      this.idleTimer = setTimeout(() => {
        if (!this.aesKey) return;
        this.lockVault();
        this.showToast("Vault auto-locked after inactivity.");
      }, minutes * 60 * 1000);
    }

    openSettingsModal() {
      const modal = document.getElementById("modal-settings");
      if (modal) {
        modal.classList.remove("hidden");
        document.getElementById("setting-sl-key-input").value = this.getSimpleLoginKey();
        document.getElementById("setting-clear-clipboard-select").value = StorageController.getClipboardDelay();
        const autoLock = document.getElementById("setting-auto-lock-select");
        if (autoLock) autoLock.value = StorageController.getAutoLockMinutes();
      }
    }

    async handleUnlock() {
      const passInput = document.getElementById("master-pass-input");
      const password = passInput.value;
      const errorMsg = document.getElementById("lock-error-msg");
      errorMsg.classList.add("hidden");

      const salt = StorageController.getSalt();
      const hash = StorageController.getMasterHash();

      if (!salt || !hash) {
        // Shouldn't happen, but never leave the user staring at a form that
        // can only ever say "no".
        this.checkVaultSetup();
        return;
      }

      const unlockBtn = document.getElementById("btn-unlock-vault");
      if (unlockBtn) unlockBtn.disabled = true;

      try {
        const result = await CryptoEngine.unlock(password, salt, hash, StorageController.getKdf());
        if (!result.ok) {
          errorMsg.textContent = "Invalid master password. Please try again.";
          errorMsg.classList.remove("hidden");
          return;
        }

        this.aesKey = result.aesKey;
        passInput.value = "";
        const failed = await this.loadAndDecryptVault();
        document.getElementById("master-lock-screen").classList.add("hidden");
        this.showToast(
          failed > 0
            ? `Unlocked, but ${failed} item(s) could not be decrypted.`
            : "CipherVault unlocked successfully"
        );

        this.resetIdleTimer();

        // Silently move older vaults onto the current key-derivation settings.
        if (result.needsUpgrade) await this.upgradeKdf(password);
      } catch (err) {
        console.error(err);
        errorMsg.textContent = "Error unlocking vault: " + err.message;
        errorMsg.classList.remove("hidden");
      } finally {
        if (unlockBtn) unlockBtn.disabled = false;
      }
    }

    // ---------------------------------------------------------------------
    // Desktop auto-update
    //
    // Only wired up when running inside the Electron shell, which exposes a
    // narrow bridge (see CipherVault-Desktop/preload.js). The browser build
    // has no installer to replace, so the whole section stays hidden there.
    // ---------------------------------------------------------------------

    get desktopBridge() {
      return (typeof window !== "undefined" && window.cipherVaultDesktop) || null;
    }

    async setupDesktopUpdates() {
      const bridge = this.desktopBridge;
      const section = document.getElementById("settings-section-updates");
      if (!bridge || !section) return;

      section.classList.remove("hidden");

      const versionLabel = document.getElementById("setting-app-version");
      const status = document.getElementById("setting-update-status");
      const button = document.getElementById("btn-check-updates");
      const track = document.getElementById("update-progress-track");
      const bar = document.getElementById("update-progress-bar");

      try {
        const version = await bridge.getVersion();
        this.desktopVersion = version;
        if (versionLabel) versionLabel.textContent = `v${version}`;
      } catch (e) {
        if (versionLabel) versionLabel.textContent = "unknown";
      }

      bridge.update.on((event, payload) => {
        switch (event) {
          case "checking":
            status.textContent = "Checking GitHub…";
            break;

          case "available":
            track.classList.add("hidden");
            status.textContent = `Version ${payload.version} is available.`;
            this.promptDesktopUpdate(payload);
            break;

          case "not-available":
            status.textContent = "You're on the latest version.";
            break;

          case "progress":
            track.classList.remove("hidden");
            bar.style.width = `${payload.percent}%`;
            status.textContent = `Downloading… ${payload.percent}%`;
            break;

          case "downloaded":
            track.classList.add("hidden");
            status.textContent = `Version ${payload.version} is ready to install.`;
            this.promptDesktopRestart(payload);
            break;

          case "error":
            track.classList.add("hidden");
            status.textContent = payload.message || "Update failed.";
            break;
        }
      });

      if (button) {
        button.addEventListener("click", async () => {
          button.disabled = true;
          status.textContent = "Checking GitHub…";
          const result = await bridge.update.check();

          if (result.status === "up-to-date") {
            status.textContent = `You're on the latest version (v${result.version || this.desktopVersion}).`;
            this.showToast("CipherVault is up to date.");
          } else if (result.status === "dev") {
            status.textContent = result.message;
          } else if (result.status === "error") {
            status.textContent = result.message;
          }
          button.disabled = false;
        });
      }

      // A quiet check on launch, at most once every six hours.
      const LAST_CHECK = "cv:desktop:last_update_check";
      const since = Date.now() - parseInt(localStorage.getItem(LAST_CHECK) || "0", 10);
      if (since > 6 * 60 * 60 * 1000) {
        localStorage.setItem(LAST_CHECK, String(Date.now()));
        setTimeout(() => bridge.update.check(), 4000);
      }
    }

    promptDesktopUpdate(info) {
      if (this.updatePromptOpen) return;
      this.updatePromptOpen = true;

      const notes = (info.notes || "").trim();
      const message =
        `CipherVault ${info.version} is available (you have v${this.desktopVersion}).` +
        (notes ? `\n\n${notes.slice(0, 600)}` : "") +
        `\n\nDownload it now? Your vault stays exactly as it is.`;

      if (confirm(message)) {
        this.showToast("Downloading update…");
        this.desktopBridge.update.download();
      }
      this.updatePromptOpen = false;
    }

    promptDesktopRestart(info) {
      const ok = confirm(
        `CipherVault ${info.version} has downloaded.\n\n` +
        `Restart now to install it? Your vault will be locked and you'll unlock it again afterwards.`
      );
      if (ok) this.desktopBridge.update.install();
    }

    // ---------------------------------------------------------------------
    // QR unlock (desktop side)
    //
    // Shows a rotating QR code carrying an ephemeral public key, and waits for
    // an already-unlocked phone to send back the master password sealed to
    // that key. See LinkSessionEngine for the protocol and why the database
    // never learns anything useful.
    // ---------------------------------------------------------------------

    async openQrUnlock() {
      if (!this.currentUid) {
        this.showToast("Sign in first — QR unlock needs both devices on the same account.");
        return;
      }
      if (typeof qrcode === "undefined") {
        this.showToast("QR support failed to load.");
        return;
      }

      this.openModal("modal-qr-unlock");
      document.getElementById("qr-error").classList.add("hidden");
      document.getElementById("qr-status").textContent = "Waiting for your phone…";
      await this.rotateQrSession();
    }

    async rotateQrSession() {
      this.stopQrSession({ keepModal: true });

      let session;
      try {
        session = await LinkSessionEngine.createSession();
      } catch (err) {
        console.error("Could not start a link session:", err);
        this.showQrError("Could not start a session: " + err.message);
        return;
      }

      this.qrSession = session;
      this.renderQrCode(session.qrPayload);

      this.qrUnsubscribe = FirebaseSyncEngine.watchLinkSession(
        this.currentUid,
        session.sessionId,
        (response) => this.handleQrResponse(response),
        (err) => {
          console.error("Link session listener failed:", err);
          this.showQrError(
            err && err.code === "permission-denied"
              ? "Firestore rules are blocking QR unlock — redeploy firestore.rules."
              : "Lost connection while waiting for your phone."
          );
        }
      );

      // Rotate before the session can go stale, so a photographed code is
      // useless within the minute.
      const ttl = LinkSessionEngine.SESSION_TTL_MS;
      const bar = document.getElementById("qr-timer-bar");
      let remaining = ttl;

      if (bar) {
        bar.style.transition = "none";
        bar.style.width = "100%";
        // Force a reflow so the reset width applies before the animation.
        void bar.offsetWidth;
        bar.style.transition = "width 1s linear";
      }

      this.qrTicker = setInterval(() => {
        remaining -= 1000;
        if (bar) bar.style.width = `${Math.max(0, (remaining / ttl) * 100)}%`;
        if (remaining <= 0) this.rotateQrSession();
      }, 1000);
    }

    renderQrCode(payload) {
      const canvas = document.getElementById("qr-canvas");
      if (!canvas) return;

      const qr = qrcode(0, "M");
      qr.addData(payload);
      qr.make();

      const count = qr.getModuleCount();
      const size = canvas.width;
      const quiet = 2;
      const scale = size / (count + quiet * 2);

      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#F8FAFC";
      ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = "#0B0C10";

      for (let row = 0; row < count; row++) {
        for (let col = 0; col < count; col++) {
          if (!qr.isDark(row, col)) continue;
          ctx.fillRect(
            Math.round((col + quiet) * scale),
            Math.round((row + quiet) * scale),
            Math.ceil(scale),
            Math.ceil(scale)
          );
        }
      }
    }

    async handleQrResponse(response) {
      const session = this.qrSession;
      if (!session || this.qrConsuming) return;
      this.qrConsuming = true;

      const status = document.getElementById("qr-status");
      if (status) status.textContent = "Approved — unlocking…";

      const sessionId = session.sessionId;

      try {
        if (LinkSessionEngine.isExpired(session.createdAt)) {
          throw new Error("That code had already expired. Scan the new one.");
        }

        const masterPassword = await LinkSessionEngine.openResponse(session.keyPair, sessionId, response);

        // The password still has to satisfy the stored verifier: a phone
        // cannot force the desktop open with the wrong one.
        const result = await CryptoEngine.unlock(
          masterPassword,
          StorageController.getSalt(),
          StorageController.getMasterHash(),
          StorageController.getKdf()
        );
        if (!result.ok) throw new Error("Your phone sent a master password this vault doesn't accept.");

        this.aesKey = result.aesKey;
        const failed = await this.loadAndDecryptVault();

        this.stopQrSession();
        this.closeModal("modal-qr-unlock");
        document.getElementById("master-lock-screen").classList.add("hidden");
        this.resetIdleTimer();
        this.showToast(
          failed > 0
            ? `Unlocked from your phone. ${failed} item(s) could not be decrypted.`
            : "Unlocked from your phone."
        );

        if (result.needsUpgrade) await this.upgradeKdf(masterPassword);
      } catch (err) {
        console.error("QR unlock failed:", err);
        this.showQrError(err.message);
        this.qrConsuming = false;
      } finally {
        // The session is single-use whatever happened.
        FirebaseSyncEngine.deleteLinkSession(this.currentUid, sessionId);
      }
    }

    showQrError(message) {
      const box = document.getElementById("qr-error");
      if (box) {
        box.textContent = message;
        box.classList.remove("hidden");
      }
      const status = document.getElementById("qr-status");
      if (status) status.textContent = "";
    }

    stopQrSession({ keepModal = false } = {}) {
      if (this.qrTicker) clearInterval(this.qrTicker);
      this.qrTicker = null;

      if (this.qrUnsubscribe) {
        try { this.qrUnsubscribe(); } catch (e) { /* already detached */ }
      }
      this.qrUnsubscribe = null;

      if (this.qrSession && this.currentUid) {
        FirebaseSyncEngine.deleteLinkSession(this.currentUid, this.qrSession.sessionId);
      }
      this.qrSession = null;
      this.qrConsuming = false;

      if (!keepModal) this.closeModal("modal-qr-unlock");
    }

    /**
     * Re-keys an already-unlocked vault onto the current KDF. Called right
     * after a successful unlock of a vault created by an older build, while
     * the plaintext is in memory and the master password is still known.
     */
    async upgradeKdf(masterPassword) {
      try {
        const salt = CryptoEngine.generateSalt();
        const kdf = { v: CryptoEngine.KDF_VERSION, iterations: CryptoEngine.DEFAULT_ITERATIONS };
        const { aesKey, verifier } = await CryptoEngine.deriveKeyAndVerifier(masterPassword, salt, kdf.iterations);

        this.aesKey = aesKey;
        StorageController.setSalt(salt);
        StorageController.setMasterHash(verifier);
        StorageController.setKdf(kdf);

        // Re-encrypts every item under the new key and pushes it to the cloud.
        await this.saveEncryptedVault();
        console.info("Vault upgraded to KDF v" + kdf.v);
      } catch (err) {
        console.error("KDF upgrade failed, vault left on previous settings:", err);
      }
    }

    lockVault() {
      this.stopQrSession();
      if (this.idleTimer) clearTimeout(this.idleTimer);
      this.idleTimer = null;
      this.aesKey = null;
      this.decryptedVault = [];
      this.simpleLoginKey = "";
      this.folders = [];
      this.selectedItemId = null;
      this.editingItemId = null;
      this.renderList();
      this.showView("detail-watermark");
      this.closeAllModals();
      this.showLockScreen();
      this.checkVaultSetup();
      this.showToast("CipherVault locked");
    }

    /**
     * Decrypts the locally cached vault with the in-memory key.
     * @returns {Promise<number>} how many items failed to decrypt.
     */
    async loadAndDecryptVault({ keepView = false } = {}) {
      const rawList = StorageController.getEncryptedItems();
      const decrypted = [];
      let failed = 0;

      for (const item of rawList) {
        try {
          const decryptedJson = await CryptoEngine.decryptJson(item.encryptedData, this.aesKey);
          decrypted.push({
            id: item.id,
            type: item.type || "login",
            isFavorite: item.isFavorite || false,
            isTrashed: item.isTrashed || false,
            createdAt: item.createdAt || new Date().toISOString(),
            data: decryptedJson,
          });
        } catch (e) {
          failed++;
          console.error("Failed to decrypt item", item.id, e);
        }
      }

      this.decryptedVault = decrypted;
      await this.loadFolders();
      await this.loadSimpleLoginKey();
      this.renderFoldersList();
      this.renderList();
      if (!keepView) this.showView("detail-watermark");
      return failed;
    }

    // ---------------------------------------------------------------------
    // SimpleLogin API key
    //
    // Kept in memory while unlocked, encrypted with the vault key at rest, and
    // carried in the synced document so it follows the account rather than
    // having to be re-entered on every device.
    // ---------------------------------------------------------------------

    // ---------------------------------------------------------------------
    // Folders
    //
    // Held in memory while unlocked, encrypted with the vault key at rest and
    // in the synced document. Folder names are not neutral metadata - a list
    // reading "Banking, Crypto, Work" describes the vault's contents.
    // ---------------------------------------------------------------------

    async loadFolders() {
      this.folders = [];
      if (!this.aesKey) return;

      const blob = StorageController.getFoldersEnc();
      if (blob) {
        try {
          const parsed = await CryptoEngine.decryptJson(blob, this.aesKey);
          if (Array.isArray(parsed)) this.folders = parsed;
        } catch (err) {
          console.warn("Could not decrypt the folder list.", err);
        }
      }

      await this.migrateFolders();
    }

    /** Moves a pre-1.4 plaintext folder list into the encrypted store, once. */
    async migrateFolders() {
      const legacy = StorageController.getLegacyFolders();
      if (!legacy.length) return;

      if (!this.folders.length) {
        this.folders = legacy;
        await this.saveFolders({ sync: false });
      }
      StorageController.clearLegacyFolders();
    }

    /** Persists the in-memory folder list. */
    async saveFolders({ sync = true } = {}) {
      if (!this.aesKey) return;

      const blob = this.folders.length
        ? await CryptoEngine.encryptJson(this.folders, this.aesKey)
        : "";
      StorageController.setFoldersEnc(blob);

      if (sync) await this.saveEncryptedVault();
    }

    async loadSimpleLoginKey() {
      this.simpleLoginKey = "";
      if (!this.aesKey) return;

      const blob = StorageController.getSimpleLoginKeyEnc();
      if (blob) {
        try {
          this.simpleLoginKey = await CryptoEngine.decrypt(blob, this.aesKey);
        } catch (err) {
          console.warn("Could not decrypt the stored SimpleLogin key.", err);
          this.simpleLoginKey = "";
        }
      }

      await this.migrateSimpleLoginKey();
    }

    /** Moves a pre-1.1 plaintext key into the encrypted store, once. */
    async migrateSimpleLoginKey() {
      const legacy = StorageController.getLegacySimpleLoginKey();
      if (!legacy) return;

      if (!this.simpleLoginKey) {
        this.simpleLoginKey = legacy;
        await this.saveSimpleLoginKey(legacy, { silent: true });
      }
      StorageController.clearLegacySimpleLoginKey();
    }

    async saveSimpleLoginKey(key, { silent = false } = {}) {
      if (!this.aesKey) {
        this.showToast("Unlock your vault first.");
        return;
      }

      this.simpleLoginKey = key || "";

      const blob = this.simpleLoginKey
        ? await CryptoEngine.encrypt(this.simpleLoginKey, this.aesKey)
        : "";
      StorageController.setSimpleLoginKeyEnc(blob);

      await this.saveEncryptedVault();
      if (!silent) {
        this.showToast(key ? "SimpleLogin key saved and synced." : "SimpleLogin key removed.");
      }
    }

    getSimpleLoginKey() {
      return this.simpleLoginKey || "";
    }

    updateCategoryCounts() {
      const total = this.decryptedVault.filter((i) => !i.isTrashed).length;
      const favs = this.decryptedVault.filter((i) => !i.isTrashed && i.isFavorite).length;
      const pass = this.decryptedVault.filter((i) => !i.isTrashed && (i.type === "login" || i.type === "passwords")).length;
      const passkeys = this.decryptedVault.filter((i) => !i.isTrashed && (i.type === "passkeys" || i.type === "passkey")).length;
      const notes = this.decryptedVault.filter((i) => !i.isTrashed && (i.type === "note" || i.type === "notes")).length;
      const cards = this.decryptedVault.filter((i) => !i.isTrashed && (i.type === "card" || i.type === "cards")).length;
      const identity = this.decryptedVault.filter((i) => !i.isTrashed && i.type === "identity").length;
      const trash = this.decryptedVault.filter((i) => i.isTrashed).length;

      const setEl = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
      setEl("count-all", total);
      setEl("count-fav", favs);
      setEl("count-pw", pass);
      setEl("count-passkeys", passkeys);
      setEl("count-notes", notes);
      setEl("count-cards", cards);
      setEl("count-identity", identity);
      setEl("count-trash", trash);

      const btnEmptyTrash = document.getElementById("btn-empty-trash");
      if (btnEmptyTrash) {
        if (this.activeCategory === "trash" && trash > 0) {
          btnEmptyTrash.classList.remove("hidden");
        } else {
          btnEmptyTrash.classList.add("hidden");
        }
      }

      const listContainer = document.getElementById("items-cards-container");
      
      const filtered = this.decryptedVault.filter((item) => {
        // 1. Trash tab: only show trashed items
        if (this.activeCategory === "trash") {
          return item.isTrashed;
        }
        // 2. Hide trashed items for all other tabs
        if (item.isTrashed) return false;

        // 3. Apply category filter
        if (this.activeCategory === "favorites" && !item.isFavorite) return false;
        
        if (this.activeCategory.startsWith("folder_")) {
          return item.data.folderId === this.activeCategory;
        }

        if (this.activeCategory === "passwords" && item.type !== "login" && item.type !== "passwords") return false;
        if (this.activeCategory === "passkeys" && item.type !== "passkeys" && item.type !== "passkey") return false;
        if (this.activeCategory === "notes" && item.type !== "note" && item.type !== "notes") return false;
        if (this.activeCategory === "cards" && item.type !== "card" && item.type !== "cards") return false;
        if (this.activeCategory === "identity" && item.type !== "identity") return false;
        
        return true;
      });

      let emptyViewHTML = `
          <div id="empty-items-view" style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;padding:40px;text-align:center;">
            <div style="background: var(--bg-surface); padding: 16px; border-radius: 50%; margin-bottom: 20px; border: 1px solid var(--border-color); display: flex; align-items: center; justify-content: center;">
              <svg viewBox="0 0 24 24" style="width:42px;height:42px;color:var(--text-muted);"><path fill="currentColor" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>
            </div>
            <h3 style="color:var(--text-primary); font-size: 16px; font-weight: 600; margin-bottom: 8px;">Your Vault is Empty</h3>
            <p style="color:var(--text-muted); font-size: 13px; line-height: 1.5; max-width: 250px;">Store your passwords, secure notes, and other sensitive items securely.</p>
          </div>
        `;

      const query = (document.getElementById("vault-search-input")?.value || "").toLowerCase().trim();

      listContainer.innerHTML = "";
      
      const searchFiltered = filtered.filter((item) => {
        if (!query) return true;
        const title = (item.data?.name || "").toLowerCase();
        const user = (item.data?.username || item.data?.accountName || item.data?.cardholder || item.data?.fullName || "").toLowerCase();
        const url = (item.data?.url || item.data?.relyingParty || "").toLowerCase();
        return title.includes(query) || user.includes(query) || url.includes(query);
      });

      if (searchFiltered.length === 0) {
        listContainer.innerHTML = emptyViewHTML;
        return;
      }

      searchFiltered.forEach((item) => {
        const card = document.createElement("div");
        card.className = `vault-item-card item-card ${item.id === this.selectedItemId ? "selected" : ""}`;
        
        let subtext = "";
        let typeTag = "Item";
        if (item.type === "login" || item.type === "passwords") {
          subtext = item.data.username || item.data.url || "Login Credential";
          typeTag = "Login";
        } else if (item.type === "passkeys" || item.type === "passkey") {
          subtext = item.data.relyingParty || item.data.userHandle || "Passkey";
          typeTag = "Passkey";
        } else if (item.type === "note" || item.type === "notes") {
          subtext = "Secure Note";
          typeTag = "Secure Note";
        } else if (item.type === "card" || item.type === "cards") {
          subtext = item.data.cardNumber ? `•••• ${item.data.cardNumber.slice(-4)}` : "Credit Card";
          typeTag = "Credit Card";
        } else if (item.type === "identity") {
          subtext = item.data.fullName || item.data.email || "Identity";
          typeTag = "Identity";
        }

        let folderName = "";
        if (item.data.folderId) {
          const folder = this.folders.find(f => f.id === item.data.folderId);
          if (folder) folderName = folder.name;
        }

        let iconHtml = "";
        let websiteUrl = item.data.url || item.data.relyingParty;
        if (websiteUrl) {
          try {
            const urlObj = new URL(websiteUrl.startsWith('http') ? websiteUrl : 'https://' + websiteUrl);
            iconHtml = `<img src="https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=64" alt="" style="width:24px; height:24px; border-radius:4px; filter: grayscale(100%) opacity(0.8);">`;
          } catch(e) {
            iconHtml = `<svg viewBox="0 0 24 24" style="width:24px;height:24px;color:var(--text-secondary);"><path fill="currentColor" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>`;
          }
        } else {
          if (typeTag === "Login") iconHtml = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;color:var(--text-secondary);"><path fill="currentColor" d="M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM8.9 6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2H8.9V6z"/></svg>`;
          else if (typeTag === "Secure Note") iconHtml = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;color:var(--text-secondary);"><path fill="currentColor" d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>`;
          else if (typeTag === "Credit Card") iconHtml = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;color:var(--text-secondary);"><path fill="currentColor" d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/></svg>`;
          else if (typeTag === "Identity") iconHtml = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;color:var(--text-secondary);"><path fill="currentColor" d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>`;
          else iconHtml = `<svg viewBox="0 0 24 24" style="width:20px;height:20px;color:var(--text-secondary);"><path fill="currentColor" d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>`;
        }

        card.innerHTML = `
          <div class="item-badge-icon">
            ${iconHtml}
          </div>
          <div class="item-meta" style="flex: 1; min-width: 0;">
            <span class="item-name" style="font-size:14px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${this.escapeHtml(item.data.name)}</span>
            <span class="item-subtext" style="color:var(--text-muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${this.escapeHtml(subtext)}</span>
          </div>
          <div style="display:flex; flex-direction:column; align-items:flex-end; gap:4px; flex-shrink:0;">
            <span style="font-size:10px; font-weight: 500; background:var(--bg-input); padding:2px 6px; border-radius:4px; color:var(--text-secondary); border:1px solid var(--border-color);">${typeTag}</span>
            ${folderName ? `<span style="font-size:10px; color:var(--text-muted); display:flex; align-items:center; gap:3px;"><svg viewBox="0 0 24 24" style="width:11px;height:11px;"><path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>${this.escapeHtml(folderName)}</span>` : ''}
          </div>
        `;
        
        card.addEventListener("click", () => {
          document.querySelectorAll(".item-card").forEach((c) => c.classList.remove("selected"));
          card.classList.add("selected");
          this.selectedItemId = item.id;
          this.renderDetailView(item);
        });

        listContainer.appendChild(card);
      });
    }

    renderFoldersList() {
      const container = document.getElementById("folders-container");
      if (!container) return;
      container.innerHTML = "";
      if (this.folders.length === 0) {
        container.innerHTML = `<span class="empty-folders-text">No folders yet</span>`;
        return;
      }
      for (const folder of this.folders) {
        const btn = document.createElement("button");
        btn.className = "nav-item";
        if (this.activeCategory === folder.id) btn.classList.add("active");
        btn.title = `${folder.name} — right-click to delete`;
        btn.innerHTML = `<svg viewBox="0 0 24 24" class="nav-icon"><path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg><span>${this.escapeHtml(folder.name)}</span>`;
        btn.addEventListener("contextmenu", async (e) => {
          e.preventDefault();
          if (!confirm(`Delete the folder "${folder.name}"?\n\nItems inside it are kept and moved back to "All Items".`)) return;

          this.folders = this.folders.filter((f) => f.id !== folder.id);
          this.decryptedVault.forEach((item) => {
            if (item.data && item.data.folderId === folder.id) item.data.folderId = "";
          });
          if (this.activeCategory === folder.id) this.activeCategory = "all";

          await this.saveFolders();
          this.renderFoldersList();
          this.renderList();
          this.showToast("Folder deleted.");
        });
        btn.addEventListener("click", () => {
          document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
          btn.classList.add("active");
          this.activeCategory = folder.id;
          this.selectedItemId = null;
          this.showView("detail-watermark");
          this.renderList();
        });
        container.appendChild(btn);
      }
    }

    renderList() {
      this.updateCategoryCounts();
    }

    showView(viewId) {
      if (viewId === "detail-view-container") {
        if (!this.currentViewId || this.currentViewId === "detail-watermark") {
          this.previousViewId = null;
        } else {
          this.previousViewId = this.currentViewId;
        }
      } else {
        this.previousViewId = null;
      }
      this.currentViewId = viewId;

      ["detail-watermark", "detail-view-container", "view-health-dashboard", "view-simplelogin-tool", "view-password-generator", "view-breach-scanner"].forEach((id) => {
        const el = document.getElementById(id);
        if (el) {
          if (id === viewId) el.classList.remove("hidden");
          else el.classList.add("hidden");
        }
      });
    }

    async renderDetailView(item) {
      this.showView("detail-view-container");

      const btnBack = document.getElementById("btn-detail-back");
      if (btnBack) {
        if (this.previousViewId === "view-health-dashboard" || this.previousViewId === "view-breach-scanner") {
          btnBack.classList.remove("hidden");
          btnBack.onclick = () => {
            this.showView(this.previousViewId);
            this.selectedItemId = null;
          };
        } else {
          btnBack.classList.add("hidden");
        }
      }

      document.getElementById("detail-item-title").textContent = item.data.name;
      document.getElementById("detail-type-badge").textContent = item.type.toUpperCase();

      const body = document.getElementById("detail-fields-body");
      body.innerHTML = "";

      if (item.type === "login" || item.type === "passwords") {
        if (item.data.username) body.appendChild(this.createFieldCard("Username / Email", item.data.username, true));
        if (item.data.password) body.appendChild(this.createFieldCard("Password", item.data.password, true, true));
        if (item.data.url) body.appendChild(this.createFieldCard("Website URL", item.data.url, true));
        if (item.data.totpSecret) {
          const totpCode = await TOTPEngine.generateTOTP(item.data.totpSecret);
          const totpCard = document.createElement("div");
          totpCard.className = "detail-field-card";
          totpCard.innerHTML = `
            <div class="field-label-row"><label>Authenticator 2FA Code (TOTP)</label></div>
            <div class="field-value-row">
              <div class="totp-live-gauge">
                <span class="totp-code-text" id="totp-val-display">${totpCode}</span>
              </div>
              <button class="btn-copy-sm" id="btn-copy-totp">Copy Code</button>
            </div>
          `;
          totpCard.querySelector("#btn-copy-totp").addEventListener("click", () => {
            // Read the live value: the code rotates every 30s and the one
            // captured when this card was built goes stale.
            const live = totpCard.querySelector("#totp-val-display")?.textContent || totpCode;
            this.copyToClipboard(live);
            this.showToast("2FA TOTP code copied!");
          });
          body.appendChild(totpCard);
        }
      } else if (item.type === "authenticator") {
        if (item.data.accountName) body.appendChild(this.createFieldCard("Account Name / Email", item.data.accountName, true));
        if (item.data.issuer) body.appendChild(this.createFieldCard("Issuer / Service", item.data.issuer, true));
        if (item.data.totpSecret) {
          const totpCode = await TOTPEngine.generateTOTP(item.data.totpSecret);
          body.appendChild(this.createFieldCard("Live 2FA TOTP Code", totpCode, true));
        }
      } else if (item.type === "passkeys" || item.type === "passkey") {
        if (item.data.relyingParty) body.appendChild(this.createFieldCard("Relying Party / Domain", item.data.relyingParty, true));
        if (item.data.userHandle) body.appendChild(this.createFieldCard("User Handle / Account", item.data.userHandle, true));
      } else if (item.type === "note" || item.type === "notes") {
        if (item.data.content) body.appendChild(this.createFieldCard("Confidential Note", item.data.content, true));
      } else if (item.type === "card" || item.type === "cards") {
        if (item.data.cardholder) body.appendChild(this.createFieldCard("Cardholder Name", item.data.cardholder, true));
        if (item.data.cardNumber) body.appendChild(this.createFieldCard("Card Number", item.data.cardNumber, true, true));
        if (item.data.expiry) body.appendChild(this.createFieldCard("Expiration Date", item.data.expiry, true));
        if (item.data.cvv) body.appendChild(this.createFieldCard("Security CVV", item.data.cvv, true, true));
      } else if (item.type === "identity") {
        if (item.data.fullName) body.appendChild(this.createFieldCard("Full Legal Name", item.data.fullName, true));
        if (item.data.email) body.appendChild(this.createFieldCard("Primary Email", item.data.email, true));
        if (item.data.phone) body.appendChild(this.createFieldCard("Phone Number", item.data.phone, true));
        if (item.data.address) body.appendChild(this.createFieldCard("Residential Address", item.data.address, true));
      }

      // Favorite toggle button listener with live UI + counter updates
      const btnFav = document.getElementById("btn-detail-fav");
      if (btnFav) {
        btnFav.onclick = () => {
          item.isFavorite = !item.isFavorite;
          this.saveEncryptedVault();
          this.updateCategoryCounts();
          this.renderList();
          this.showToast(item.isFavorite ? "Added to favorites" : "Removed from favorites");
        };
      }

      // Edit item button listener
      const btnEdit = document.getElementById("btn-detail-edit");
      if (btnEdit) {
        btnEdit.onclick = () => {
          this.openItemEditor(item);
        };
      }

      // Delete item button listener
      const btnDelete = document.getElementById("btn-detail-delete");
      if (btnDelete) {
        btnDelete.onclick = () => {
          if (confirm(`Move "${item.data.name}" to trash?`)) {
            item.isTrashed = true;
            this.saveEncryptedVault();
            this.updateCategoryCounts();
            this.showView("detail-watermark");
            this.renderList();
            this.showToast("Item moved to trash");
          }
        };
      }
    }

    // ==========================================
    // PASSWORD GENERATOR
    // ==========================================
    renderPasswordGenerator() {
      this.showView("view-password-generator");

      const slider = document.getElementById("gen-length-slider");
      const lengthDisplay = document.getElementById("gen-length-display");
      const btnGenerate = document.getElementById("btn-gen-generate");
      const btnCopy = document.getElementById("btn-gen-copy");
      const output = document.getElementById("gen-password-output");

      // Remove old listeners by cloning
      const newSlider = slider.cloneNode(true);
      slider.parentNode.replaceChild(newSlider, slider);
      const newBtnGen = btnGenerate.cloneNode(true);
      btnGenerate.parentNode.replaceChild(newBtnGen, btnGenerate);
      const newBtnCopy = btnCopy.cloneNode(true);
      btnCopy.parentNode.replaceChild(newBtnCopy, btnCopy);

      // Clone checkboxes to remove old listeners
      ["gen-opt-upper", "gen-opt-lower", "gen-opt-numbers", "gen-opt-symbols"].forEach((id) => {
        const cb = document.getElementById(id);
        if (cb) {
          const newCb = cb.cloneNode(true);
          cb.parentNode.replaceChild(newCb, cb);
          newCb.addEventListener("change", () => this._doGenerate());
        }
      });

      // Slider live update
      newSlider.addEventListener("input", () => {
        lengthDisplay.textContent = newSlider.value;
        this._doGenerate();
      });

      // Generate button
      newBtnGen.addEventListener("click", () => this._doGenerate());

      // Copy button
      newBtnCopy.addEventListener("click", () => {
        const pw = output.textContent;
        if (pw && pw !== "Click Generate") {
          this.copyToClipboard(pw);
          this.showToast("Password copied to clipboard!");
        }
      });

      // Auto-generate one on open
      this._doGenerate();
    }

    _doGenerate() {
      const length = parseInt(document.getElementById("gen-length-slider")?.value || "18", 10);
      const upper = document.getElementById("gen-opt-upper")?.checked ?? true;
      const lower = document.getElementById("gen-opt-lower")?.checked ?? true;
      const nums = document.getElementById("gen-opt-numbers")?.checked ?? true;
      const syms = document.getElementById("gen-opt-symbols")?.checked ?? true;

      const password = CryptoEngine.generatePassword(length, upper, lower, nums, syms);
      const output = document.getElementById("gen-password-output");
      if (output) output.textContent = password;

      // Calculate entropy & strength
      let poolSize = 0;
      if (upper) poolSize += 26;
      if (lower) poolSize += 26;
      if (nums) poolSize += 10;
      if (syms) poolSize += 28;
      if (poolSize === 0) poolSize = 26; // fallback to lowercase

      const entropy = Math.round(length * Math.log2(poolSize));

      const strengthBar = document.getElementById("gen-strength-bar");
      const strengthText = document.getElementById("gen-strength-text");
      const entropyText = document.getElementById("gen-entropy-bits");

      if (entropyText) entropyText.textContent = `${entropy} bits`;

      let strengthLabel = "Very Weak";
      let barWidth = 10;
      let barColor = "var(--text-muted)";

      if (entropy >= 128) {
        strengthLabel = "Excellent";
        barWidth = 100;
        barColor = "var(--text-primary)";
      } else if (entropy >= 80) {
        strengthLabel = "Very Strong";
        barWidth = 85;
        barColor = "var(--text-primary)";
      } else if (entropy >= 60) {
        strengthLabel = "Strong";
        barWidth = 70;
        barColor = "var(--text-secondary)";
      } else if (entropy >= 40) {
        strengthLabel = "Moderate";
        barWidth = 50;
        barColor = "var(--text-secondary)";
      } else if (entropy >= 28) {
        strengthLabel = "Weak";
        barWidth = 30;
        barColor = "var(--text-muted)";
      }

      if (strengthBar) {
        strengthBar.style.width = `${barWidth}%`;
        strengthBar.style.backgroundColor = barColor;
      }
      if (strengthText) strengthText.textContent = strengthLabel;
    }

    // ==========================================
    // PASSWORD HEALTH DASHBOARD
    // ==========================================
    renderHealthDashboard() {
      this.showView("view-health-dashboard");
      const analysis = PasswordHealthEngine.analyzeVault(this.decryptedVault);

      document.getElementById("health-weak-count").textContent = analysis.weakCount;
      document.getElementById("health-reused-count").textContent = analysis.reusedGroups;

      const attentionItems = [];
      const seen = new Set();
      [...analysis.weakItems, ...analysis.reusedItems].forEach(item => {
        if (!seen.has(item.id)) {
          seen.add(item.id);
          attentionItems.push(item);
        }
      });

      document.getElementById("health-attention-count").textContent = attentionItems.length;

      const emptyState = document.getElementById("health-empty-state");
      const listState = document.getElementById("health-attention-list");

      if (attentionItems.length === 0) {
        emptyState.style.display = "flex";
        listState.style.display = "none";
      } else {
        emptyState.style.display = "none";
        listState.style.display = "flex";
        listState.innerHTML = "";

        attentionItems.forEach(item => {
          const div = document.createElement("div");
          div.style.cssText = "display: flex; align-items: center; justify-content: space-between; padding: 12px; background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: 8px; cursor: pointer; transition: background 0.2s;";
          
          div.onmouseenter = () => div.style.background = "rgba(255,255,255,0.05)";
          div.onmouseleave = () => div.style.background = "rgba(255,255,255,0.02)";

          div.addEventListener("click", () => {
            this.selectedItemId = item.id;
            this.renderDetailView(item);
          });
          
          let problems = [];
          if (analysis.weakItems.find(i => i.id === item.id)) problems.push("Weak");
          if (analysis.reusedItems.find(i => i.id === item.id)) problems.push("Reused");

          const title = item.data.name || item.data.title || item.data.relyingParty || "Untitled";
          const email = item.data.email || item.data.username || "";
          
          div.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 4px;">
              <div style="font-size: 14px; font-weight: 600; color: var(--text-primary);">${this.escapeHtml(title)}</div>
              ${email ? `<div style="font-size: 11px; color: var(--text-muted);">${this.escapeHtml(email)}</div>` : ''}
            </div>
            <div style="display: flex; gap: 6px;">
              ${problems.map(p => `<span style="background: ${p === 'Weak' ? 'rgba(244,67,54,0.1)' : 'rgba(255,152,0,0.1)'}; color: ${p === 'Weak' ? '#f44336' : '#ff9800'}; font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 4px;">${p}</span>`).join('')}
            </div>
          `;
          listState.appendChild(div);
        });
      }
    }

    async renderSimpleLoginTool() {
      this.showView("view-simplelogin-tool");
      const key = this.getSimpleLoginKey();
      const msg = document.getElementById("tool-sl-alias-msg");
      
      const btnGen = document.getElementById("btn-tool-gen-alias");
      const newBtnGen = btnGen.cloneNode(true);
      btnGen.parentNode.replaceChild(newBtnGen, btnGen);

      newBtnGen.addEventListener("click", () => this.handleToolGenerateAlias());

      if (key) {
        this.loadSimpleLoginAliases();
        
        try {
          const opts = await SimpleLoginClient.fetchAliasOptions(key);
          const select = document.getElementById("tool-sl-alias-suffix");
          select.innerHTML = "";
          opts.suffixes.forEach(s => {
            const opt = document.createElement("option");
            opt.value = s.signed_suffix;
            opt.textContent = s.suffix;
            select.appendChild(opt);
          });
          
          if (opts.prefix_suggestion) {
            document.getElementById("tool-sl-alias-prefix").value = opts.prefix_suggestion;
          }
        } catch(e) {
          if (msg) {
            msg.style.display = "block";
            msg.textContent = "Error loading alias options. Check API Key.";
          }
        }
      }
    }

    async loadSimpleLoginAliases() {
      const key = this.getSimpleLoginKey();
      const container = document.getElementById("tool-sl-aliases-list");
      if (!key) return;

      container.innerHTML = `<p class="empty-text">Loading active aliases...</p>`;
      const aliases = await SimpleLoginClient.fetchAliases(key);

      if (aliases.length === 0) {
        container.innerHTML = `<p class="empty-text">No active aliases found on SimpleLogin.</p>`;
        return;
      }

      container.innerHTML = "";
      aliases.forEach((a) => {
        const card = document.createElement("div");
        card.className = "vault-item-card";
        card.style.display = "flex";
        card.style.justifyContent = "space-between";
        card.style.alignItems = "center";
        card.innerHTML = `
          <div class="item-meta">
            <span class="item-name sl-email-copyable" style="cursor: pointer;" title="Click to Copy">${this.escapeHtml(a.email)}</span>
            <span class="item-subtext">${this.escapeHtml(a.note || "SimpleLogin Alias")} • ${a.nb_email_received} emails received</span>
          </div>
          <button class="btn-action-icon danger btn-delete-alias" data-id="${a.id}" title="Delete Alias">
            <svg viewBox="0 0 24 24" class="icon" style="width:16px;height:16px;"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
          </button>
        `;
        
        card.querySelector(".sl-email-copyable").addEventListener("click", () => {
          this.copyToClipboard(a.email);
          this.showToast("Alias email copied to clipboard!");
        });
        
        card.querySelector(".btn-delete-alias").addEventListener("click", async () => {
          if (confirm(`Are you sure you want to delete ${a.email}?`)) {
            const success = await SimpleLoginClient.deleteAlias(key, a.id);
            if (success) {
              this.showToast("Alias deleted!");
              this.loadSimpleLoginAliases();
            } else {
              alert("Failed to delete alias.");
            }
          }
        });
        
        container.appendChild(card);
      });
    }

    async handleToolGenerateAlias() {
      const key = this.getSimpleLoginKey();
      const msg = document.getElementById("tool-sl-alias-msg");
      if (!key) {
        alert("Please enter and save your SimpleLogin API Key in Settings first!");
        return;
      }
      
      const prefix = document.getElementById("tool-sl-alias-prefix").value.trim();
      const suffix = document.getElementById("tool-sl-alias-suffix").value;
      
      if (!prefix || !suffix) {
        alert("Please enter a prefix and select a suffix domain.");
        return;
      }
      
      try {
        if (msg) msg.style.display = "none";
        const res = await SimpleLoginClient.createCustomAlias(key, prefix, suffix, "Generated from CipherVault");
        this.showToast(`Alias created: ${res.alias}`);
        if (msg) msg.style.display = "none";
        document.getElementById("tool-sl-alias-prefix").value = "";
        this.loadSimpleLoginAliases();
      } catch (err) {
        if (msg) {
          msg.style.display = "block";
          msg.style.color = "var(--color-danger, #ef4444)";
          msg.textContent = err.message;
        }
      }
    }

    // ==========================================
    // BREACH SCANNER
    // ==========================================
    renderBreachScanner() {
      this.showView("view-breach-scanner");
      const btnScan = document.getElementById("btn-run-breach-scan");
      if (!btnScan) return;
      const newBtnScan = btnScan.cloneNode(true);
      btnScan.parentNode.replaceChild(newBtnScan, btnScan);
  
      newBtnScan.addEventListener("click", async () => {
        const statusText = document.getElementById("breach-scan-status");
        const resultsList = document.getElementById("breach-results-list");
        
        statusText.textContent = "Scanning vault securely using k-Anonymity... Please wait.";
        newBtnScan.disabled = true;
        resultsList.innerHTML = "";
  
        const loginItems = this.decryptedVault.filter((i) => !i.isTrashed && (i.type === "login" || i.type === "passwords") && i.data.password);
        const breachedItems = [];
        const breachCounts = new Map();
        let lookupErrors = 0;

        for (const item of loginItems) {
          const pw = item.data.password;
          if (!pw) continue;

          let count;
          if (breachCounts.has(pw)) {
            count = breachCounts.get(pw);
          } else {
            count = await BreachScannerEngine.checkPassword(pw);
            breachCounts.set(pw, count);
            await new Promise(r => setTimeout(r, 50));
          }

          // checkPassword returns -1 when the HIBP request itself failed.
          // Treating that as "breached" produced false alarms when offline.
          if (count === -1) lookupErrors++;
          else if (count > 0) breachedItems.push(item);
        }

        newBtnScan.disabled = false;
        statusText.textContent =
          `Scan complete. Found ${breachedItems.length} breached item(s) out of ${loginItems.length} login(s) scanned.` +
          (lookupErrors > 0 ? ` ${lookupErrors} could not be checked (network error).` : "");
  
        if (breachedItems.length === 0) {
          resultsList.innerHTML = `<div style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 16px; padding: 20px 0;">
            <svg viewBox="0 0 24 24" style="width: 48px; height: 48px; color: #00e676;"><path fill="currentColor" d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>
            <div style="color: #00e676; font-size: 14px;">Great news! No breached passwords found.</div>
          </div>`;
        } else {
          breachedItems.forEach(item => {
            const div = document.createElement("div");
            div.style.cssText = "display: flex; align-items: center; justify-content: space-between; padding: 12px; background: rgba(255,255,255,0.02); border: 1px solid var(--border-color); border-radius: 8px; cursor: pointer; transition: background 0.2s;";
            div.onmouseenter = () => div.style.background = "rgba(255,255,255,0.05)";
            div.onmouseleave = () => div.style.background = "rgba(255,255,255,0.02)";
            div.addEventListener("click", () => {
              this.selectedItemId = item.id;
              this.renderDetailView(item);
            });
            
            const title = item.data.name || item.data.title || item.data.relyingParty || "Untitled";
            const email = item.data.email || item.data.username || "";
            
            div.innerHTML = `
              <div style="display: flex; flex-direction: column; gap: 4px;">
                <div style="font-size: 14px; font-weight: 600; color: var(--text-primary);">${this.escapeHtml(title)}</div>
                ${email ? `<div style="font-size: 11px; color: var(--text-muted);">${this.escapeHtml(email)}</div>` : ''}
              </div>
              <div style="display: flex; gap: 6px;">
                <span style="background: rgba(244,67,54,0.1); color: #f44336; font-size: 10px; font-weight: 700; padding: 4px 8px; border-radius: 4px;">Breached</span>
              </div>
            `;
            resultsList.appendChild(div);
          });
        }
      });
    }

    createFieldCard(label, value, allowCopy = true, isPassword = false) {
      const card = document.createElement("div");
      card.className = "detail-field-card";

      let displayVal = isPassword ? "••••••••••••••••" : value;

      card.innerHTML = `
        <div class="field-label-row"><label>${label}</label></div>
        <div class="field-value-row">
          <span class="field-value-text" id="field-val">${this.escapeHtml(displayVal)}</span>
          <div style="display:flex; gap:6px;">
            ${isPassword ? `<button class="btn-copy-sm" id="btn-toggle-eye">Show</button>` : ""}
            ${allowCopy ? `<button class="btn-copy-sm" id="btn-copy-field">Copy</button>` : ""}
          </div>
        </div>
      `;

      if (isPassword) {
        const btnEye = card.querySelector("#btn-toggle-eye");
        const valText = card.querySelector("#field-val");
        btnEye.addEventListener("click", () => {
          if (valText.textContent === "••••••••••••••••") {
            valText.textContent = value;
            btnEye.textContent = "Hide";
          } else {
            valText.textContent = "••••••••••••••••";
            btnEye.textContent = "Show";
          }
        });
      }

      if (allowCopy) {
        card.querySelector("#btn-copy-field").addEventListener("click", () => {
          this.copyToClipboard(value);
          this.showToast(`${label} copied to clipboard!`);
        });
      }

      return card;
    }

    openItemEditor(itemToEdit = null) {
      document.getElementById("modal-item-editor").classList.remove("hidden");

      // Populate Folder Select
      const folderSelect = document.getElementById("editor-folder-select");
      if (folderSelect) {
        folderSelect.innerHTML = '<option value="">No Folder</option>';
        this.folders.forEach(f => {
          const opt = document.createElement("option");
          opt.value = f.id;
          opt.textContent = f.name;
          folderSelect.appendChild(opt);
        });
      }

      if (itemToEdit) {
        this.editingItemId = itemToEdit.id;
        document.getElementById("editor-modal-title").textContent = "Edit Item";
        document.getElementById("editor-name").value = itemToEdit.data.name || "";
        document.getElementById("editor-type-select").value = itemToEdit.type || "login";
        if (folderSelect) folderSelect.value = itemToEdit.data.folderId || "";
        
        this.renderDynamicEditorFields(itemToEdit.type || "login");

        // Populate existing item values into fields
        setTimeout(() => {
          const setVal = (id, v) => { const el = document.getElementById(id); if (el && v !== undefined) el.value = v; };
          setVal("ed-user", itemToEdit.data.username);
          setVal("ed-pass", itemToEdit.data.password);
          setVal("ed-url", itemToEdit.data.url);
          setVal("ed-totp", itemToEdit.data.totpSecret);
          setVal("ed-pk-rp", itemToEdit.data.relyingParty);
          setVal("ed-pk-user", itemToEdit.data.userHandle);
          setVal("ed-note", itemToEdit.data.content);
          setVal("ed-card-name", itemToEdit.data.cardholder);
          setVal("ed-card-num", itemToEdit.data.cardNumber);
          setVal("ed-card-exp", itemToEdit.data.expiry);
          setVal("ed-card-cvv", itemToEdit.data.cvv);
          setVal("ed-id-name", itemToEdit.data.fullName);
          setVal("ed-id-email", itemToEdit.data.email);
          setVal("ed-id-phone", itemToEdit.data.phone);
          setVal("ed-id-address", itemToEdit.data.address);
        }, 10);
      } else {
        this.editingItemId = null;
        document.getElementById("editor-modal-title").textContent = "New Vault Item";
        document.getElementById("editor-name").value = "";
        if (folderSelect) folderSelect.value = "";
        this.renderDynamicEditorFields(document.getElementById("editor-type-select").value);
      }
    }

    renderDynamicEditorFields(type) {
      const container = document.getElementById("editor-dynamic-fields");
      container.innerHTML = "";

      if (type === "login" || type === "passwords") {
        container.innerHTML = `
          <div class="field-group">
            <label>Username / Email</label>
            <div style="display: flex; gap: 8px;">
              <input type="text" id="ed-user" placeholder="user@domain.com" style="flex: 1;">
              <select id="ed-alias-select" style="width: auto; max-width: 150px; background-color: var(--bg-surface); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: 6px;">
                <option value="">Alias...</option>
              </select>
            </div>
          </div>
          <div class="field-group">
            <label>Password</label>
            <div class="input-with-button">
              <input type="text" id="ed-pass" placeholder="••••••••">
              <button type="button" class="btn-secondary" id="btn-gen-pass">Generate</button>
            </div>
          </div>
          <div class="field-group"><label>Website URL</label><input type="text" id="ed-url" placeholder="https://example.com"></div>
          <div class="field-group">
            <label>Authenticator Secret (optional, Base32)</label>
            <input type="text" id="ed-totp" placeholder="JBSWY3DPEHPK3PXP" autocomplete="off">
          </div>
        `;

        container.querySelector("#btn-gen-pass").addEventListener("click", () => {
          container.querySelector("#ed-pass").value = CryptoEngine.generatePassword(18);
          this.showToast("Generated high-entropy password!");
        });
        
        // Load SimpleLogin aliases into dropdown
        const key = this.getSimpleLoginKey();
        const aliasSelect = container.querySelector("#ed-alias-select");
        if (key && aliasSelect) {
          SimpleLoginClient.fetchAliases(key).then(aliases => {
            aliases.forEach(a => {
              const opt = document.createElement("option");
              opt.value = a.email;
              opt.textContent = a.email;
              aliasSelect.appendChild(opt);
            });
          }).catch(e => console.error("Failed to load aliases for editor", e));
          
          aliasSelect.addEventListener("change", (e) => {
            if (e.target.value) {
              container.querySelector("#ed-user").value = e.target.value;
            }
          });
        }
      } else if (type === "passkeys" || type === "passkey") {
        container.innerHTML = `
          <div class="field-group"><label>Relying Party / Domain</label><input type="text" id="ed-pk-rp" placeholder="e.g. github.com"></div>
          <div class="field-group"><label>User Handle / Account</label><input type="text" id="ed-pk-user" placeholder="user@domain.com"></div>
        `;
      } else if (type === "note" || type === "notes") {
        container.innerHTML = `
          <div class="field-group"><label>Confidential Secure Note</label><textarea id="ed-note" rows="5" placeholder="Write secure notes..."></textarea></div>
        `;
      } else if (type === "card" || type === "cards") {
        container.innerHTML = `
          <div class="field-group"><label>Cardholder Name</label><input type="text" id="ed-card-name" placeholder="John Doe"></div>
          <div class="field-group"><label>Card Number</label><input type="text" id="ed-card-num" placeholder="4532 •••• •••• 8921"></div>
          <div class="input-with-button">
            <div class="field-group" style="flex:1;"><label>Expiry (MM/YY)</label><input type="text" id="ed-card-exp" placeholder="12/28"></div>
            <div class="field-group" style="flex:1;"><label>CVV Code</label><input type="text" id="ed-card-cvv" placeholder="892"></div>
          </div>
        `;
      } else if (type === "identity") {
        container.innerHTML = `
          <div class="field-group"><label>Full Legal Name</label><input type="text" id="ed-id-name" placeholder="Jane Doe"></div>
          <div class="field-group"><label>Primary Email</label><input type="text" id="ed-id-email" placeholder="jane@domain.com"></div>
          <div class="field-group"><label>Phone Number</label><input type="text" id="ed-id-phone" placeholder="+1 (555) 019-2834"></div>
          <div class="field-group"><label>Residential Address</label><textarea id="ed-id-address" rows="3" placeholder="123 Security Blvd..."></textarea></div>
        `;
      }
    }

    async saveItemFromEditor() {
      const type = document.getElementById("editor-type-select").value;
      const getVal = (id) => (document.getElementById(id) ? document.getElementById(id).value.trim() : "");
      
      const folderSelect = document.getElementById("editor-folder-select");

      const dataObj = {
        name: document.getElementById("editor-name").value.trim(),
        folderId: folderSelect ? folderSelect.value : "",
      };

      if (!dataObj.name) {
        this.showToast("Item name is required.");
        return;
      }

      if (type === "login" || type === "passwords") {
        dataObj.username = getVal("ed-user");
        dataObj.password = getVal("ed-pass");
        dataObj.url = getVal("ed-url");
        const totp = getVal("ed-totp").replace(/\s/g, "");
        if (totp) dataObj.totpSecret = totp;
      } else if (type === "passkeys" || type === "passkey") {
        dataObj.relyingParty = (document.getElementById("ed-pk-rp")?.value || "").trim();
        dataObj.userHandle = (document.getElementById("ed-pk-user")?.value || "").trim();
      } else if (type === "note" || type === "notes") {
        dataObj.content = document.getElementById("ed-note")?.value || "";
      } else if (type === "card" || type === "cards") {
        dataObj.cardholder = (document.getElementById("ed-card-name")?.value || "").trim();
        dataObj.cardNumber = (document.getElementById("ed-card-num")?.value || "").trim();
        dataObj.expiry = (document.getElementById("ed-card-exp")?.value || "").trim();
        dataObj.cvv = (document.getElementById("ed-card-cvv")?.value || "").trim();
      } else if (type === "identity") {
        dataObj.fullName = (document.getElementById("ed-id-name")?.value || "").trim();
        dataObj.email = (document.getElementById("ed-id-email")?.value || "").trim();
        dataObj.phone = (document.getElementById("ed-id-phone")?.value || "").trim();
        dataObj.address = (document.getElementById("ed-id-address")?.value || "").trim();
      }

      if (this.editingItemId) {
        // Edit existing item in place
        const item = this.decryptedVault.find((i) => i.id === this.editingItemId);
        if (item) {
          item.type = type;
          item.data = dataObj;
        }
      } else {
        // Create new item
        const newItem = {
          id: "item_" + Date.now(),
          type: type,
          isFavorite: false,
          isTrashed: false,
          createdAt: new Date().toISOString(),
          data: dataObj,
        };
        this.decryptedVault.push(newItem);
      }

      await this.saveEncryptedVault();
      this.closeModal("modal-item-editor");
      this.editingItemId = null;
      this.updateCategoryCounts();
      this.renderList();
      this.showToast(`Saved "${dataObj.name}" securely`);
    }

    async saveEncryptedVault() {
      if (!this.aesKey) {
        console.warn("saveEncryptedVault called while locked; ignoring.");
        return;
      }

      const encryptedList = [];
      for (const item of this.decryptedVault) {
        const encryptedBlob = await CryptoEngine.encryptJson(item.data, this.aesKey);
        encryptedList.push({
          id: item.id,
          type: item.type,
          isFavorite: !!item.isFavorite,
          isTrashed: !!item.isTrashed,
          createdAt: item.createdAt,
          encryptedData: encryptedBlob,
        });
      }
      StorageController.saveEncryptedItems(encryptedList);

      if (this.currentUid) {
        this.updateSyncIndicator(true);
        try {
          await FirebaseSyncEngine.uploadVault(this.currentUid, {
            vault: encryptedList,
            foldersEnc: StorageController.getFoldersEnc(),
            salt: StorageController.getSalt(),
            hash: StorageController.getMasterHash(),
            kdf: StorageController.getKdf(),
            slKeyEnc: StorageController.getSimpleLoginKeyEnc(),
          });
        } catch (err) {
          console.error("Failed to upload to Firebase:", err);
          this.showToast(this.friendlySyncError(err));
        } finally {
          this.updateSyncIndicator(false);
        }
      }
    }

    exportVaultAsJson() {
      if (!this.aesKey) {
        this.showToast("Unlock your vault before exporting.");
        return;
      }

      // The export is plaintext by design (so it can be read by other password
      // managers), which the settings copy used to describe as "encrypted".
      // Say what it really is before writing every secret to the disk.
      const proceed = confirm(
        "This backup is NOT encrypted.\n\n" +
        `It will contain all ${this.decryptedVault.length} item(s) — passwords, notes and card numbers — in plain readable text.\n\n` +
        "Save it somewhere safe and delete it when you're done. Continue?"
      );
      if (!proceed) return;

      const exportBlob = {
        exportedAt: new Date().toISOString(),
        version: "2.0.0",
        encrypted: false,
        items: this.decryptedVault,
      };

      const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportBlob, null, 2));
      const downloadAnchor = document.createElement("a");
      downloadAnchor.setAttribute("href", dataStr);
      downloadAnchor.setAttribute("download", `ciphervault-export-${Date.now()}.json`);
      document.body.appendChild(downloadAnchor);
      downloadAnchor.click();
      downloadAnchor.remove();
      this.showToast("Plaintext backup exported — store it securely.");
    }

    importVaultFromJson(event) {
      const file = event.target.files[0];
      if (!file) return;
      if (!this.aesKey) {
        this.showToast("Unlock your vault before importing.");
        event.target.value = "";
        return;
      }

      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const importedData = JSON.parse(e.target.result);
          const itemsToImport = importedData.items || (Array.isArray(importedData) ? importedData : []);

          let importedCount = 0;
          itemsToImport.forEach((item) => {
            if (item.data && item.data.name) {
              this.decryptedVault.push({
                id: "item_" + Date.now() + "_" + Math.random().toString(36).substr(2, 4),
                type: item.type || "login",
                isFavorite: item.isFavorite || false,
                isTrashed: item.isTrashed || false,
                createdAt: item.createdAt || new Date().toISOString(),
                data: item.data,
              });
              importedCount++;
            }
          });

          await this.saveEncryptedVault();
          this.updateCategoryCounts();
          this.renderList();
          this.closeModal("modal-settings");
          this.showToast(`Imported ${importedCount} items successfully!`);
        } catch (err) {
          alert("Import Error: Invalid JSON file format.");
        }
      };
      reader.readAsText(file);
    }

    startTotpInterval() {
      if (this.totpTimer) clearInterval(this.totpTimer);
      this.totpTimer = setInterval(async () => {
        if (this.selectedItemId) {
          const item = this.decryptedVault.find((i) => i.id === this.selectedItemId);
          if (item && item.data.totpSecret) {
            const code = await TOTPEngine.generateTOTP(item.data.totpSecret);
            const display = document.getElementById("totp-val-display");
            if (display) display.textContent = code;
          }
        }
      }, 1000);
    }

    showToast(message) {
      const container = document.getElementById("toast-container");
      const toast = document.createElement("div");
      toast.className = "toast";
      toast.innerHTML = `
        <svg viewBox="0 0 24 24" style="width:16px; height:16px; color:#F8FAFC;"><path fill="currentColor" d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
        <span>${this.escapeHtml(message)}</span>
      `;
      container.appendChild(toast);
      setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateX(40px)";
        setTimeout(() => toast.remove(), 250);
      }, 2500);
    }

    copyToClipboard(text) {
      navigator.clipboard.writeText(text);
      const delaySec = parseInt(StorageController.getClipboardDelay(), 10);
      if (!isNaN(delaySec) && delaySec > 0) {
        if (this.clipboardTimeout) clearTimeout(this.clipboardTimeout);
        this.clipboardTimeout = setTimeout(() => {
          navigator.clipboard.writeText("");
          this.showToast("Clipboard auto-cleared for security.");
        }, delaySec * 1000);
      }
    }

    
    openModal(id) {
      const el = document.getElementById(id);
      if (el) el.classList.remove("hidden");
    }

    closeModal(id) {
      const el = document.getElementById(id);
      if (el) el.classList.add("hidden");
    }

    closeAllModals() {
      document.querySelectorAll(".modal-overlay").forEach((m) => m.classList.add("hidden"));
    }

    escapeHtml(str) {
      return String(str === undefined || str === null ? "" : str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    }
  }

  function bootstrap() {
    const instance = new CipherVaultApp();
    // Exposed so the internals can be driven from the console and from the
    // automated end-to-end test. Everything here is already reachable by any
    // script running on the page.
    window.CipherVault = {
      app: instance,
      CryptoEngine,
      TOTPEngine,
      StorageController,
      FirebaseSyncEngine,
      PasswordHealthEngine,
      LinkSessionEngine,
    };
    return instance;
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }
})();
