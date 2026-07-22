/**
 * CipherVault browser-extension popup.
 *
 * The extension is a read-only window onto the vault that the desktop/web app
 * owns. It signs in to the same account, pulls the encrypted blob down from
 * Firestore, and decrypts it locally with the master password. The master
 * password and the decrypted items never leave this popup.
 *
 * The old build showed "Unlock Vault" whenever you were signed in, even when
 * the account had no vault in the cloud at all, so every master password you
 * typed was rejected. Each distinct situation now has its own screen.
 */

// Firefox exposes `browser`; Chrome exposes `chrome`. MV3 aliases `chrome` in
// both, so prefer it and fall back for safety.
const ext = typeof chrome !== "undefined" ? chrome : (typeof browser !== "undefined" ? browser : null);

const firebaseConfig = {
  apiKey: "AIzaSyCAGLosHtxjPKjLGEbxtxrbT3HfXg9gtg0",
  authDomain: "ciphervault-51754.firebaseapp.com",
  projectId: "ciphervault-51754",
  storageBucket: "ciphervault-51754.firebasestorage.app",
  messagingSenderId: "666567446130",
  appId: "1:666567446130:web:8abb23ef021e2594753ceb"
};

// --- FIREBASE CLOUD SYNC ENGINE ---
class FirebaseSyncEngine {
  static init() {
    if (typeof firebase !== "undefined" && !firebase.apps.length) {
      firebase.initializeApp(firebaseConfig);
    }
  }

  static onAuthStateChanged(callback) {
    if (typeof firebase === "undefined") return;
    firebase.auth().onAuthStateChanged(callback);
  }

  static async login(email, password) {
    if (typeof firebase === "undefined") throw new Error("Firebase SDK not loaded.");
    const cred = await firebase.auth().signInWithEmailAndPassword(email, password);
    return cred.user;
  }

  static async logout() {
    if (typeof firebase === "undefined") return;
    await firebase.auth().signOut();
  }

  static async sendPasswordReset(email) {
    if (typeof firebase === "undefined") throw new Error("Firebase SDK not loaded.");
    if (!email) throw new Error("Please enter your email address first.");
    await firebase.auth().sendPasswordResetEmail(email);
  }

  static async downloadVault(uid) {
    if (typeof firebase === "undefined" || !uid) return null;
    const doc = await firebase.firestore().collection("users").doc(uid).get();
    if (!doc.exists) return null;

    const data = doc.data() || {};
    return {
      vault: Array.isArray(data.vault) ? data.vault : [],
      folders: Array.isArray(data.folders) ? data.folders : [],
      salt: typeof data.salt === "string" ? data.salt : null,
      hash: typeof data.hash === "string" ? data.hash : null,
      kdf: data.kdf && typeof data.kdf.v === "number" ? data.kdf : { v: 1, iterations: 100000 },
      isProvisioned: typeof data.salt === "string" && typeof data.hash === "string",
    };
  }
}

/**
 * Per-account cache of the encrypted vault, so the popup can still open
 * offline. Namespaced by uid: signing into a second account must never leave
 * the first account's salt behind, which is exactly what used to make the
 * unlock screen reject a perfectly correct master password.
 */
class VaultCache {
  static _key(uid, name) { return `cv:u:${uid}:${name}`; }

  static save(uid, { vault, salt, hash, kdf }) {
    if (!uid) return;
    localStorage.setItem(this._key(uid, "items"), JSON.stringify(vault || []));
    localStorage.setItem(this._key(uid, "salt"), salt || "");
    localStorage.setItem(this._key(uid, "hash"), hash || "");
    localStorage.setItem(this._key(uid, "kdf"), JSON.stringify(kdf || { v: 1, iterations: 100000 }));
  }

  static load(uid) {
    if (!uid) return null;
    const salt = localStorage.getItem(this._key(uid, "salt"));
    const hash = localStorage.getItem(this._key(uid, "hash"));
    if (!salt || !hash) return null;

    let vault = [];
    let kdf = { v: 1, iterations: 100000 };
    try {
      const raw = JSON.parse(localStorage.getItem(this._key(uid, "items")) || "[]");
      if (Array.isArray(raw)) vault = raw;
    } catch (e) { /* corrupt cache: treat as empty */ }
    try {
      const parsed = JSON.parse(localStorage.getItem(this._key(uid, "kdf")) || "null");
      if (parsed && typeof parsed.v === "number") kdf = parsed;
    } catch (e) { /* keep default */ }

    return { vault, salt, hash, kdf, isProvisioned: true };
  }

  static clear(uid) {
    if (!uid) return;
    ["items", "salt", "hash", "kdf"].forEach((n) => localStorage.removeItem(this._key(uid, n)));
  }
}

// --- EXTENSION POPUP CONTROLLER ---
class PopupController {
  constructor() {
    this.firebaseUser = null;
    this.uid = null;
    this.aesKey = null;
    this.decryptedVault = [];
    this.vaultRecord = null;   // { vault, salt, hash, kdf, isProvisioned }
    this.syncError = null;

    FirebaseSyncEngine.init();
    this.bindEvents();
    this.setView("view-loading");
    this.setupFirebaseSync();
  }

  // ---------- view plumbing ----------

  setView(id) {
    ["view-loading", "view-connect", "view-no-vault", "view-unlock", "view-vault"].forEach((v) => {
      const el = document.getElementById(v);
      if (el) el.classList.toggle("hidden", v !== id);
    });
  }

  setStatus(state, label) {
    const dot = document.getElementById("status-dot");
    const text = document.getElementById("status-label");
    const colors = {
      offline: "var(--danger)",
      syncing: "#facc15",
      online: "var(--success)",
      locked: "var(--text-muted)",
    };
    if (dot) dot.style.backgroundColor = colors[state] || colors.offline;
    if (text) text.textContent = label || "";
  }

  showError(id, message) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = message;
    el.classList.remove("hidden");
  }

  hideError(id) {
    document.getElementById(id)?.classList.add("hidden");
  }

  friendlyAuthError(err) {
    switch ((err && err.code) || "") {
      case "auth/invalid-email": return "That email address doesn't look valid.";
      case "auth/user-not-found":
      case "auth/wrong-password":
      case "auth/invalid-credential":
      case "auth/invalid-login-credentials": return "Incorrect email or password.";
      case "auth/network-request-failed": return "Can't reach the server. Check your connection.";
      case "auth/too-many-requests": return "Too many attempts. Wait a moment and try again.";
      default: return (err && err.message) || "Sign-in failed.";
    }
  }

  // ---------- auth + sync ----------

  setupFirebaseSync() {
    FirebaseSyncEngine.onAuthStateChanged(async (user) => {
      const newUid = user ? user.uid : null;

      if (newUid !== this.uid) {
        // Identity changed: forget every decrypted secret immediately.
        this.aesKey = null;
        this.decryptedVault = [];
        this.vaultRecord = null;
      }

      this.firebaseUser = user;
      this.uid = newUid;

      if (!user) {
        this.setStatus("offline", "Signed out");
        this.render();
        return;
      }

      this.setStatus("syncing", "Syncing");
      await this.refreshVault();
      this.render();
    });
  }

  /** Pulls the encrypted vault, falling back to the local cache when offline. */
  async refreshVault() {
    this.syncError = null;
    try {
      const cloud = await FirebaseSyncEngine.downloadVault(this.uid);
      if (cloud && cloud.isProvisioned) {
        VaultCache.save(this.uid, cloud);
        this.vaultRecord = cloud;
        this.setStatus("online", "Synced");
        return;
      }
      // Account exists but has no vault document yet.
      this.vaultRecord = VaultCache.load(this.uid);
      this.setStatus(this.vaultRecord ? "online" : "locked", this.vaultRecord ? "Cached" : "No vault");
    } catch (err) {
      console.error("Vault sync failed:", err);
      this.syncError =
        err && err.code === "permission-denied"
          ? "Cloud access denied by Firestore rules."
          : "Offline — showing this device's cached copy.";
      this.vaultRecord = VaultCache.load(this.uid);
      this.setStatus(this.vaultRecord ? "locked" : "offline", this.vaultRecord ? "Cached" : "Offline");
    }
  }

  render() {
    if (!this.firebaseUser) {
      this.setView("view-connect");
      return;
    }

    const email = this.firebaseUser.email || "this account";

    if (!this.vaultRecord || !this.vaultRecord.isProvisioned) {
      const label = document.getElementById("no-vault-account");
      if (label) label.textContent = email;
      this.setView("view-no-vault");
      if (this.syncError) this.showError("fb-error", this.syncError);
      return;
    }

    if (!this.aesKey) {
      const label = document.getElementById("unlock-account");
      if (label) label.textContent = email;
      this.setView("view-unlock");
      if (this.syncError) this.showError("unlock-error", this.syncError);
      else this.hideError("unlock-error");
      document.getElementById("master-password")?.focus();
      return;
    }

    this.setView("view-vault");
    this.renderVault(document.getElementById("search-input")?.value || "");
  }

  // ---------- unlock ----------

  async unlockVault(password) {
    const record = this.vaultRecord;
    if (!record || !record.isProvisioned) {
      throw new Error("No vault is available for this account yet.");
    }

    const result = await CryptoEngine.unlock(password, record.salt, record.hash, record.kdf);
    if (!result.ok) throw new Error("Incorrect master password.");

    this.aesKey = result.aesKey;
    await this.decryptVault();
    this.setStatus("online", "Unlocked");
  }

  async decryptVault() {
    const items = [];
    let failed = 0;

    for (const item of this.vaultRecord.vault) {
      try {
        const data = await CryptoEngine.decryptJson(item.encryptedData, this.aesKey);
        items.push({ id: item.id, type: item.type || "login", isTrashed: !!item.isTrashed, data });
      } catch (err) {
        failed++;
      }
    }

    if (failed > 0) console.warn(`${failed} item(s) could not be decrypted.`);
    this.decryptedVault = items;
  }

  lock() {
    this.aesKey = null;
    this.decryptedVault = [];
    this.setStatus("locked", "Locked");
    this.hideError("unlock-error");
    const input = document.getElementById("master-password");
    if (input) input.value = "";
    this.render();
  }

  async signOut() {
    const uid = this.uid;
    this.aesKey = null;
    this.decryptedVault = [];
    this.vaultRecord = null;
    // Drop only this account's cached blob, never the whole store.
    VaultCache.clear(uid);
    await FirebaseSyncEngine.logout();
  }

  // ---------- rendering the item list ----------

  renderVault(searchQuery = "") {
    const listEl = document.getElementById("vault-list");
    const countEl = document.getElementById("vault-count");
    listEl.innerHTML = "";

    const query = (searchQuery || "").toLowerCase().trim();

    // The main app writes logins as type "login"; older items used "passwords".
    const logins = this.decryptedVault.filter(
      (item) => !item.isTrashed && (item.type === "login" || item.type === "passwords")
    );

    const filtered = logins.filter((item) => {
      if (!query) return true;
      const d = item.data || {};
      return (
        (d.name || "").toLowerCase().includes(query) ||
        (d.username || "").toLowerCase().includes(query) ||
        (d.url || "").toLowerCase().includes(query)
      );
    });

    if (countEl) {
      countEl.textContent = logins.length
        ? `${filtered.length} of ${logins.length}`
        : "";
    }

    if (filtered.length === 0) {
      const p = document.createElement("p");
      p.className = "empty-list";
      p.textContent = logins.length === 0
        ? "No logins in this vault yet."
        : "No logins match your search.";
      listEl.appendChild(p);
      return;
    }

    filtered.forEach((item) => {
      // Built with DOM APIs rather than innerHTML: item names and passwords are
      // attacker-influenced strings and used to be interpolated straight into
      // markup (a password containing a quote broke the copy button outright).
      const row = document.createElement("div");
      row.className = "vault-item";

      const info = document.createElement("div");
      info.className = "item-info";

      const name = document.createElement("span");
      name.className = "item-name";
      name.textContent = item.data.name || "Unnamed Login";

      const user = document.createElement("span");
      user.className = "item-username";
      user.textContent = item.data.username || item.data.url || "";

      info.append(name, user);

      const actions = document.createElement("div");
      actions.className = "item-actions";
      actions.append(
        this.makeIconButton(
          "Copy password",
          "M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z",
          (btn) => this.copyPassword(item, btn)
        ),
        this.makeIconButton(
          "Autofill in current tab",
          "M20.71 5.63l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-3.12 3.12-1.93-1.91-1.41 1.41 1.42 1.42L3 16.25V21h4.75l8.92-8.92 1.42 1.42 1.41-1.41-1.92-1.92 3.12-3.12c.4-.4.4-1.03.01-1.42zM6.92 19L5 17.08l8.06-8.06 1.92 1.92L6.92 19z",
          () => this.triggerAutofill(item)
        )
      );

      row.append(info, actions);
      listEl.appendChild(row);
    });
  }

  makeIconButton(title, svgPath, onClick) {
    const btn = document.createElement("button");
    btn.className = "btn-icon";
    btn.title = title;
    btn.setAttribute("aria-label", title);

    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("fill", "currentColor");
    path.setAttribute("d", svgPath);
    svg.appendChild(path);
    btn.appendChild(svg);

    btn.addEventListener("click", () => onClick(btn));
    return btn;
  }

  async copyPassword(item, btn) {
    const password = item.data.password || "";
    if (!password) return;
    try {
      await navigator.clipboard.writeText(password);
      btn.style.color = "var(--success)";
      setTimeout(() => { btn.style.color = ""; }, 1000);
    } catch (err) {
      console.error("Clipboard write failed:", err);
    }
  }

  async triggerAutofill(item) {
    if (!ext || !ext.tabs) return;
    try {
      const tabs = await ext.tabs.query({ active: true, currentWindow: true });
      const tab = tabs && tabs[0];
      if (!tab) return;

      await ext.tabs.sendMessage(tab.id, {
        action: "FILL_CREDENTIALS",
        username: item.data.username || "",
        password: item.data.password || "",
      });
      window.close();
    } catch (err) {
      // Usually means no content script on this page (about:, addons store, PDF viewer…).
      console.error("Autofill failed:", err);
      this.showError("unlock-error", "Can't autofill on this page.");
    }
  }

  // ---------- events ----------

  bindEvents() {
    document.getElementById("connect-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = document.getElementById("btn-connect-submit");
      const email = document.getElementById("fb-email").value.trim();
      const pwd = document.getElementById("fb-password").value;

      this.hideError("fb-error");
      document.getElementById("fb-success").classList.add("hidden");
      btn.disabled = true;
      try {
        await FirebaseSyncEngine.login(email, pwd);
        document.getElementById("fb-password").value = "";
      } catch (err) {
        this.showError("fb-error", this.friendlyAuthError(err));
      } finally {
        btn.disabled = false;
      }
    });

    document.getElementById("btn-ext-forgot-fb").addEventListener("click", async () => {
      const email = document.getElementById("fb-email").value.trim();
      this.hideError("fb-error");
      if (!email) return this.showError("fb-error", "Enter your email address first.");
      try {
        await FirebaseSyncEngine.sendPasswordReset(email);
        const ok = document.getElementById("fb-success");
        ok.textContent = "Reset email sent. Note: this resets your ACCOUNT password, not your master password.";
        ok.classList.remove("hidden");
      } catch (err) {
        this.showError("fb-error", this.friendlyAuthError(err));
      }
    });

    document.getElementById("unlock-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = document.getElementById("btn-unlock-submit");
      const input = document.getElementById("master-password");

      this.hideError("unlock-error");
      btn.disabled = true;
      btn.textContent = "Unlocking…";
      try {
        await this.unlockVault(input.value);
        input.value = "";
        this.render();
      } catch (err) {
        this.showError("unlock-error", err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = "Unlock";
      }
    });

    document.getElementById("btn-retry-sync").addEventListener("click", async () => {
      this.hideError("fb-error");
      this.setStatus("syncing", "Syncing");
      await this.refreshVault();
      this.render();
    });

    document.getElementById("search-input").addEventListener("input", (e) => {
      this.renderVault(e.target.value);
    });

    document.getElementById("btn-lock").addEventListener("click", () => this.lock());

    ["btn-logout", "btn-unlock-signout", "btn-no-vault-signout"].forEach((id) => {
      document.getElementById(id)?.addEventListener("click", () => this.signOut());
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.cipherVaultPopup = new PopupController();
});
