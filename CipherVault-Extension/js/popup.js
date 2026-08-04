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

  // --- QR unlock transport (same as the desktop app) ---
  // Only ever carries ephemeral public keys and a ciphertext.

  static _linkDoc(uid, sessionId) {
    return firebase.firestore().collection("users").doc(uid)
      .collection("linkSessions").doc(sessionId);
  }

  /** Waits for the phone to approve; returns an unsubscribe fn. */
  static watchLinkSession(uid, sessionId, onResponse, onError) {
    if (typeof firebase === "undefined" || !uid) return () => {};
    return this._linkDoc(uid, sessionId).onSnapshot(
      (doc) => {
        if (!doc.exists) return;
        const d = doc.data() || {};
        if (typeof d.pk === "string" && typeof d.ct === "string") {
          onResponse({ publicKey: d.pk, ciphertext: d.ct });
        }
      },
      (err) => { if (onError) onError(err); }
    );
  }

  static async deleteLinkSession(uid, sessionId) {
    if (typeof firebase === "undefined" || !uid || !sessionId) return;
    try { await this._linkDoc(uid, sessionId).delete(); } catch (e) { /* best effort */ }
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

/**
 * Keeps the vault "unlocked" across popup opens for a limited idle window.
 *
 * A browser-action popup is destroyed the moment it closes, so the in-memory
 * key vanishes and the vault effectively re-locks every time you look away.
 * To get a real idle timer, the master password is stashed in
 * storage.session - which is in-memory, extension-only (content scripts can't
 * read it), never written to disk, and wiped when the browser closes - with a
 * 15-minute deadline. Reopening within the window restores the unlocked state
 * and pushes the deadline out; the background worker's alarm wipes the stash at
 * the deadline even if the popup is never reopened.
 *
 * This mirrors what the desktop and mobile apps already do: hold the key in
 * memory behind a 15-minute idle auto-lock.
 */
const SESSION_IDLE_MS = 15 * 60 * 1000;
const AUTOLOCK_ALARM = "cv-autolock";
const SESSION_KEY = "cvUnlock";

class SessionLock {
  static get available() {
    return !!(ext && ext.storage && ext.storage.session);
  }

  /** Stashes the master password and (re)arms the idle deadline. */
  static async save(uid, masterPassword) {
    if (!this.available || !uid || !masterPassword) return;
    const until = Date.now() + SESSION_IDLE_MS;
    try {
      await ext.storage.session.set({ [SESSION_KEY]: { uid, mp: masterPassword, until } });
      if (ext.alarms) ext.alarms.create(AUTOLOCK_ALARM, { when: until });
    } catch (e) { /* session storage unavailable; fall back to lock-on-close */ }
  }

  /** Returns { uid, mp, until } if still within the window, else null. */
  static async load() {
    if (!this.available) return null;
    try {
      const got = await ext.storage.session.get(SESSION_KEY);
      const unlock = got && got[SESSION_KEY];
      if (!unlock) return null;
      if (Date.now() >= unlock.until) { await this.clear(); return null; }
      return unlock;
    } catch (e) {
      return null;
    }
  }

  static async clear() {
    // Cancel the alarm first (synchronous) so callers that don't await this
    // still tear the timer down immediately.
    try { if (ext && ext.alarms) ext.alarms.clear(AUTOLOCK_ALARM); } catch (e) {}
    try { if (this.available) await ext.storage.session.remove(SESSION_KEY); } catch (e) {}
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
    this.masterPassword = "";  // held only while unlocked, for session restore
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
        this.masterPassword = "";
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
      // Re-open within the idle window? Restore the unlocked state silently.
      if (!this.aesKey && this.vaultRecord && this.vaultRecord.isProvisioned) {
        await this.tryRestoreSession();
      }
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
      this.stopQrUnlock();
      this.setView("view-connect");
      return;
    }

    const email = this.firebaseUser.email || "this account";

    if (!this.vaultRecord || !this.vaultRecord.isProvisioned) {
      this.stopQrUnlock();
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
      this.startQrUnlock();
      return;
    }

    // Unlocked: no QR needed. Opening the popup is activity, so extend the
    // idle window.
    this.stopQrUnlock();
    if (this.masterPassword) SessionLock.save(this.uid, this.masterPassword);

    this.setView("view-vault");
    // Learn what site the user is on so matching logins can be surfaced.
    this.refreshCurrentHost().then(() => {
      this.renderVault(document.getElementById("search-input")?.value || "");
    });
    this.renderVault(document.getElementById("search-input")?.value || "");
  }

  // ---------- QR unlock (scan with the phone) ----------

  async startQrUnlock() {
    if (!this.uid) return;
    if (typeof qrcode === "undefined" || typeof LinkSessionEngine === "undefined") return;
    if (this.qrSession) return;   // already running
    await this.rotateQrSession();
  }

  async rotateQrSession() {
    this.stopQrTimers();
    if (this.qrUnsub) { try { this.qrUnsub(); } catch (e) {} this.qrUnsub = null; }
    if (this.qrSession) FirebaseSyncEngine.deleteLinkSession(this.uid, this.qrSession.sessionId);
    this.qrSession = null;
    this.qrConsuming = false;

    let session;
    try {
      session = await LinkSessionEngine.createSession();
    } catch (e) {
      return;
    }
    this.qrSession = session;
    this.renderQr(session.qrPayload);

    this.qrUnsub = FirebaseSyncEngine.watchLinkSession(
      this.uid,
      session.sessionId,
      (resp) => this.handleQrResponse(resp),
      (err) => {
        const hint = document.getElementById("qr-hint");
        if (hint) {
          hint.textContent = (err && err.code === "permission-denied")
            ? "Blocked by Firestore rules — redeploy firestore.rules."
            : "Lost connection to the cloud.";
        }
      }
    );

    // Rotate before the code goes stale, so a photographed one is useless.
    const ttl = LinkSessionEngine.SESSION_TTL_MS;
    let remaining = ttl;
    const bar = document.getElementById("qr-timer-bar");
    if (bar) bar.style.width = "100%";
    this.qrTicker = setInterval(() => {
      remaining -= 1000;
      if (bar) bar.style.width = Math.max(0, (remaining / ttl) * 100) + "%";
      if (remaining <= 0) this.rotateQrSession();
    }, 1000);
  }

  async handleQrResponse(response) {
    if (!this.qrSession || this.qrConsuming) return;
    this.qrConsuming = true;
    const sessionId = this.qrSession.sessionId;

    try {
      if (LinkSessionEngine.isExpired(this.qrSession.createdAt)) {
        throw new Error("That code had expired. Scan the new one.");
      }
      const masterPassword = await LinkSessionEngine.openResponse(this.qrSession.keyPair, sessionId, response);
      // unlockVault verifies the password against the stored hash, so a phone
      // cannot force it open with the wrong one.
      await this.unlockVault(masterPassword);
      this.stopQrUnlock();
      this.render();
    } catch (err) {
      this.showError("unlock-error", err.message || "Phone unlock failed.");
      this.qrConsuming = false;
    } finally {
      FirebaseSyncEngine.deleteLinkSession(this.uid, sessionId);
    }
  }

  renderQr(payload) {
    const canvas = document.getElementById("qr-canvas");
    if (!canvas || typeof qrcode === "undefined") return;
    const qr = qrcode(0, "M");
    qr.addData(payload);
    qr.make();

    const count = qr.getModuleCount();
    const size = canvas.width;
    const quiet = 2;
    const scale = size / (count + quiet * 2);
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#f8fafc";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = "#0f172a";
    for (let r = 0; r < count; r++) {
      for (let c = 0; c < count; c++) {
        if (qr.isDark(r, c)) {
          ctx.fillRect(Math.round((c + quiet) * scale), Math.round((r + quiet) * scale), Math.ceil(scale), Math.ceil(scale));
        }
      }
    }
  }

  stopQrTimers() {
    if (this.qrTicker) clearInterval(this.qrTicker);
    this.qrTicker = null;
  }

  stopQrUnlock() {
    this.stopQrTimers();
    if (this.qrUnsub) { try { this.qrUnsub(); } catch (e) {} this.qrUnsub = null; }
    if (this.qrSession) {
      FirebaseSyncEngine.deleteLinkSession(this.uid, this.qrSession.sessionId);
      this.qrSession = null;
    }
  }

  /** The registrable host of the active tab, e.g. "bet365.com". */
  async refreshCurrentHost() {
    this.currentHost = "";
    if (!ext || !ext.tabs) return;
    try {
      const tabs = await ext.tabs.query({ active: true, currentWindow: true });
      const url = tabs && tabs[0] && tabs[0].url;
      this.currentHost = PopupController.hostFromUrl(url);
    } catch (e) { /* activeTab not granted on this page (about:, store, …) */ }
  }

  static hostFromUrl(url) {
    if (!url) return "";
    try {
      const u = new URL(url.includes("://") ? url : "https://" + url);
      return u.hostname.replace(/^www\./, "").toLowerCase();
    } catch (e) {
      return "";
    }
  }

  /** True when a saved login's URL is on the same registrable domain. */
  static loginMatchesHost(login, host) {
    if (!host) return false;
    const loginHost = PopupController.hostFromUrl((login.data && login.data.url) || "");
    if (!loginHost) return false;
    // Tolerant both ways: account.bet365.com should match bet365.com and vice
    // versa, without matching unrelated hosts.
    return loginHost === host || loginHost.endsWith("." + host) || host.endsWith("." + loginHost);
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
    this.masterPassword = password;
    await this.decryptVault();
    await SessionLock.save(this.uid, password);
    this.setStatus("online", "Unlocked");
  }

  /** Restores an unlocked vault from storage.session, if still within the window. */
  async tryRestoreSession() {
    const unlock = await SessionLock.load();
    if (!unlock || unlock.uid !== this.uid || !unlock.mp) return;
    try {
      // unlockVault re-derives the key, decrypts, and pushes the deadline out.
      await this.unlockVault(unlock.mp);
    } catch (e) {
      await SessionLock.clear();
    }
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
    this.masterPassword = "";
    SessionLock.clear();
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
    this.masterPassword = "";
    await SessionLock.clear();
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

    // Split into logins that belong to the current site and the rest, so the
    // one for the page you're on is offered first and can be filled in one tap.
    const host = this.currentHost || "";
    const forThisSite = host ? filtered.filter((i) => PopupController.loginMatchesHost(i, host)) : [];
    const others = filtered.filter((i) => !forThisSite.includes(i));

    if (forThisSite.length) {
      listEl.appendChild(this.groupHeading(`For ${host}`));
      forThisSite.forEach((item) => listEl.appendChild(this.vaultRow(item, true)));
    }
    if (others.length) {
      if (forThisSite.length) listEl.appendChild(this.groupHeading("Other logins"));
      others.forEach((item) => listEl.appendChild(this.vaultRow(item, false)));
    }
  }

  groupHeading(text) {
    const h = document.createElement("div");
    h.className = "list-heading";
    h.textContent = text;
    return h;
  }

  /**
   * One login row. When `matched` (belongs to the current site) the whole row
   * is a one-tap fill target, with a hint telling the user so.
   */
  vaultRow(item, matched) {
    // Built with DOM APIs rather than innerHTML: item names and passwords are
    // attacker-influenced strings.
    const row = document.createElement("div");
    row.className = matched ? "vault-item matched" : "vault-item";

    const info = document.createElement("div");
    info.className = "item-info";

    const name = document.createElement("span");
    name.className = "item-name";
    name.textContent = item.data.name || "Unnamed Login";

    const user = document.createElement("span");
    user.className = "item-username";
    user.textContent = matched
      ? (item.data.username || item.data.url || "") + "  ·  tap to fill"
      : (item.data.username || item.data.url || "");

    info.append(name, user);

    if (matched) {
      info.title = "Fill this login on the current page";
      info.style.cursor = "pointer";
      info.addEventListener("click", () => this.triggerAutofill(item));
    }

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
    return row;
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

      const result = await ext.tabs.sendMessage(tab.id, {
        action: "FILL_CREDENTIALS",
        username: item.data.username || "",
        password: item.data.password || "",
      });

      // The content script reports how many fields it actually filled.
      if (result && result.filled > 0) {
        window.close();
      } else {
        // The form is probably not open yet (many sites hide login behind a
        // button/modal). Tell the user instead of closing on a no-op.
        this.showVaultNote("No login box found. Open the site's sign-in form, then try again.");
      }
    } catch (err) {
      // No content script on this page (about:, the add-ons store, a PDF, …),
      // or the page hasn't finished loading.
      console.error("Autofill failed:", err);
      this.showVaultNote("Can't autofill on this page.");
    }
  }

  /** A transient status line inside the vault view. */
  showVaultNote(text) {
    let note = document.getElementById("vault-note");
    if (!note) {
      note = document.createElement("div");
      note.id = "vault-note";
      note.className = "vault-note";
      const list = document.getElementById("vault-list");
      list.parentNode.insertBefore(note, list);
    }
    note.textContent = text;
    note.classList.remove("hidden");
    clearTimeout(this._vaultNoteTimer);
    this._vaultNoteTimer = setTimeout(() => note.classList.add("hidden"), 4000);
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
