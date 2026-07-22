/**
 * CipherVault Cryptographic Core Engine (browser extension)
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
