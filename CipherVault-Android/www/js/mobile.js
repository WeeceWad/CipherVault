/**
 * CipherVault for Android - UI controller.
 *
 * The crypto, storage, sync and analysis engines all come from js/core.js,
 * which is generated from CipherVault/js/app.js. Nothing security-relevant is
 * reimplemented here: this file is presentation and interaction only. That is
 * deliberate, because a vault encrypted on the desktop has to open on the
 * phone byte-for-byte.
 */

(function () {
  'use strict';

  const Cap = window.Capacitor || {};
  const CapPlugins = Cap.Plugins || {};
  const isNative = !!(Cap.isNativePlatform && Cap.isNativePlatform());

  // ---------------------------------------------------------------- helpers

  const $ = (id) => document.getElementById(id);

  /** Creates an element. Text goes in as text, never as markup. */
  function el(tag, opts = {}, children = []) {
    const node = document.createElement(tag);
    if (opts.class) node.className = opts.class;
    if (opts.text !== undefined) node.textContent = opts.text;
    if (opts.html !== undefined) node.innerHTML = opts.html; // only ever used for inline SVG literals
    if (opts.attrs) Object.entries(opts.attrs).forEach(([k, v]) => node.setAttribute(k, v));
    if (opts.style) node.style.cssText = opts.style;
    if (opts.on) Object.entries(opts.on).forEach(([k, v]) => node.addEventListener(k, v));
    (Array.isArray(children) ? children : [children]).forEach((c) => { if (c) node.appendChild(c); });
    return node;
  }

  const ICONS = {
    login: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 17c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm6-9h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM8.9 6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2H8.9V6z"/></svg>',
    passkey: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm5.65-4C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65z"/></svg>',
    note: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>',
    card: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M20 4H4c-1.11 0-1.99.89-1.99 2L2 18c0 1.11.89 2 2 2h16c1.11 0 2-.89 2-2V6c0-1.11-.89-2-2-2zm0 14H4v-6h16v6zm0-10H4V6h16v2z"/></svg>',
    identity: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>',
    star: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 17.27L18.18 21l-1.64-7.03L22 9.24l-7.19-.61L12 2 9.19 8.63 2 9.24l5.46 4.73L5.82 21z"/></svg>',
    trash: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>',
    edit: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>',
    restore: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M13 3a9 9 0 00-9 9H1l3.89 3.89.07.14L9 12H6c0-3.87 3.13-7 7-7s7 3.13 7 7-3.13 7-7 7c-1.93 0-3.68-.79-4.94-2.06l-1.42 1.42A8.954 8.954 0 0013 21a9 9 0 000-18z"/></svg>',
    download: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>',
    shield: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-5.45 9-12V5l-9-4z"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg>',
    warn: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>',
    empty: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>',
  };

  const TYPE_META = {
    login: { label: 'Login', icon: ICONS.login },
    passwords: { label: 'Login', icon: ICONS.login },
    passkeys: { label: 'Passkey', icon: ICONS.passkey },
    passkey: { label: 'Passkey', icon: ICONS.passkey },
    note: { label: 'Note', icon: ICONS.note },
    notes: { label: 'Note', icon: ICONS.note },
    card: { label: 'Card', icon: ICONS.card },
    cards: { label: 'Card', icon: ICONS.card },
    identity: { label: 'Identity', icon: ICONS.identity },
  };

  const typeMeta = (t) => TYPE_META[t] || { label: 'Item', icon: ICONS.login };

  // ============================================================== controller

  class MobileApp {
    constructor() {
      this.aesKey = null;
      this.decryptedVault = [];
      this.folders = [];
      // Only populated while unlocked; encrypted with the vault key at rest.
      this.simpleLoginKey = '';
      // Held only while the vault is open, so a scanned QR code can authorise
      // a desktop. The phone already holds every decrypted secret in memory at
      // this point, so retaining the password too adds little exposure - but it
      // is dropped the instant the vault locks, same as everything else.
      this.masterPassword = '';
      this.firebaseUser = null;
      this.currentUid = null;
      this.activeCategory = 'all';
      this.activeTab = 'vault';
      this.searchQuery = '';
      this.idleTimer = null;
      this.clipboardTimer = null;
      this.totpTimer = null;
      this.sheetStack = [];
      this.updater = new UpdateManager();

      this.init();
    }

    async init() {
      StorageController.migrateLegacyData();
      StorageController.setScope(null);
      // Folders are encrypted now, so they stay empty until unlock.
      this.folders = [];

      FirebaseSyncEngine.init();
      this.bindChrome();
      this.bindLockScreen();
      this.bindSettings();
      this.setupAuth();
      this.setupNativeHooks();
      this.startTotpTicker();

      await this.refreshVersionLabels();
      await this.refreshBiometricState();
      this.checkVaultState();

      // Background update check, throttled to once every few hours.
      if (UpdateStorage.getAutoCheck()) {
        setTimeout(() => this.checkUpdates({ silent: true }), 2500);
      }
    }

    // ------------------------------------------------------------ feedback

    toast(message) {
      const container = $('toast-container');
      const node = el('div', { class: 'toast', text: message });
      container.appendChild(node);
      setTimeout(() => {
        node.style.opacity = '0';
        node.style.transform = 'translateY(10px)';
        setTimeout(() => node.remove(), 240);
      }, 2600);
    }

    async haptic() {
      try {
        if (isNative && CapPlugins.Haptics) await CapPlugins.Haptics.impact({ style: 'LIGHT' });
      } catch (e) { /* haptics are optional */ }
    }

    /**
     * Shows a modal. `actions` is a list of {label, style, onClick, keepOpen}.
     * Returns nothing; use confirm() below when you want an answer.
     */
    dialog({ title, body, icon, actions = [], dismissible = true, progress = false }) {
      $('dialog-title').textContent = title || '';

      const iconBox = $('dialog-icon');
      iconBox.innerHTML = icon || '';

      const bodyBox = $('dialog-body');
      bodyBox.innerHTML = '';
      if (typeof body === 'string') bodyBox.textContent = body;
      else if (body) bodyBox.appendChild(body);

      $('dialog-progress').classList.toggle('hidden', !progress);
      $('dialog-progress-bar').style.width = '0%';

      const actionBox = $('dialog-actions');
      actionBox.innerHTML = '';
      actions.forEach((a) => {
        actionBox.appendChild(el('button', {
          class: `btn ${a.style || 'btn-ghost'} btn-block`,
          text: a.label,
          on: {
            click: async () => {
              if (!a.keepOpen) this.closeDialog();
              if (a.onClick) await a.onClick();
            },
          },
        }));
      });

      const backdrop = $('dialog-backdrop');
      backdrop.classList.remove('hidden');
      backdrop.dataset.dismissible = dismissible ? '1' : '0';
      this.dialogOpen = true;
    }

    closeDialog() {
      $('dialog-backdrop').classList.add('hidden');
      this.dialogOpen = false;
    }

    setDialogProgress(percent) {
      $('dialog-progress-bar').style.width = `${percent}%`;
    }

    /** Promise-based confirm, styled like the rest of the app. */
    confirm({ title, body, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, icon }) {
      return new Promise((resolve) => {
        this.dialog({
          title,
          body,
          icon: icon || (danger ? ICONS.warn : undefined),
          dismissible: false,
          actions: [
            { label: confirmLabel, style: danger ? 'btn-danger' : 'btn-primary', onClick: () => resolve(true) },
            { label: cancelLabel, style: 'btn-ghost', onClick: () => resolve(false) },
          ],
        });
      });
    }

    async copy(text, label = 'Copied') {
      try {
        if (isNative && CapPlugins.Clipboard) await CapPlugins.Clipboard.write({ string: text });
        else await navigator.clipboard.writeText(text);
      } catch (err) {
        console.error('Clipboard write failed:', err);
        this.toast('Could not copy.');
        return;
      }

      this.haptic();
      this.toast(label);

      const delay = StorageController.getClipboardDelay();
      if (delay !== 'never') {
        const seconds = parseInt(delay, 10);
        if (!isNaN(seconds) && seconds > 0) {
          if (this.clipboardTimer) clearTimeout(this.clipboardTimer);
          this.clipboardTimer = setTimeout(async () => {
            try {
              if (isNative && CapPlugins.Clipboard) await CapPlugins.Clipboard.write({ string: '' });
              else await navigator.clipboard.writeText('');
              this.toast('Clipboard cleared.');
            } catch (e) { /* app may be backgrounded; nothing to do */ }
          }, seconds * 1000);
        }
      }
    }

    // ------------------------------------------------------ native plumbing

    setupNativeHooks() {
      if (!isNative || !CapPlugins.App) return;

      // Android hardware/gesture back: unwind the deepest layer first.
      CapPlugins.App.addListener('backButton', () => {
        if (this.dialogOpen) {
          if ($('dialog-backdrop').dataset.dismissible === '1') this.closeDialog();
          return;
        }
        if (!$('sheet').classList.contains('hidden')) { this.closeSheet(); return; }
        if (!$('lock-screen').classList.contains('hidden')) { CapPlugins.App.minimizeApp(); return; }
        if (this.activeTab !== 'vault') { this.switchTab('vault'); return; }
        CapPlugins.App.minimizeApp();
      });

      CapPlugins.App.addListener('appStateChange', ({ isActive }) => {
        if (!isActive) {
          this.backgroundedAt = Date.now();
          if (this.lockOnBackground() && this.aesKey) this.lock({ silent: true });
        } else {
          // Coming back: if we were away longer than the auto-lock window, lock.
          const away = Date.now() - (this.backgroundedAt || Date.now());
          const setting = StorageController.getAutoLockMinutes();
          if (this.aesKey && setting !== 'never') {
            const limit = (parseInt(setting, 10) || 15) * 60 * 1000;
            if (away >= limit) this.lock({ reason: 'Vault auto-locked after inactivity.' });
          }
          this.resetIdleTimer();
        }
      });

      if (CapPlugins.StatusBar) {
        CapPlugins.StatusBar.setBackgroundColor({ color: '#11131B' }).catch(() => {});
        CapPlugins.StatusBar.setStyle({ style: 'DARK' }).catch(() => {});
      }
    }

    lockOnBackground() {
      return localStorage.getItem('cv:lock_on_background') === 'true';
    }

    // -------------------------------------------------------------- chrome

    bindChrome() {
      document.querySelectorAll('.nav-tab').forEach((tab) => {
        tab.addEventListener('click', () => this.switchTab(tab.dataset.tab));
      });

      $('btn-lock-now').addEventListener('click', () => this.lock());
      $('btn-add-item').addEventListener('click', () => this.openEditor(null));

      const search = $('vault-search');
      search.addEventListener('input', () => {
        this.searchQuery = search.value;
        $('btn-clear-search').classList.toggle('hidden', !search.value);
        this.renderVault();
      });
      $('btn-clear-search').addEventListener('click', () => {
        search.value = '';
        this.searchQuery = '';
        $('btn-clear-search').classList.add('hidden');
        this.renderVault();
      });

      document.querySelectorAll('#category-chips .chip[data-category]').forEach((chip) => {
        chip.addEventListener('click', () => this.selectCategory(chip.dataset.category));
      });

      $('btn-new-folder').addEventListener('click', () => this.promptNewFolder());

      document.querySelectorAll('.tool-card').forEach((card) => {
        card.addEventListener('click', () => this.openTool(card.dataset.tool));
      });

      $('sheet-back').addEventListener('click', () => this.closeSheet());

      $('dialog-backdrop').addEventListener('click', (e) => {
        if (e.target === $('dialog-backdrop') && e.currentTarget.dataset.dismissible === '1') this.closeDialog();
      });

      ['touchstart', 'keydown', 'click'].forEach((evt) => {
        window.addEventListener(evt, () => this.resetIdleTimer(), { passive: true, capture: true });
      });
    }

    // ------------------------------------------------------ QR unlock a PC
    //
    // The phone is the authority here: it is already unlocked, so it holds the
    // master password. Scanning the desktop's QR code gives us an ephemeral
    // public key that arrived visually rather than over the network, which is
    // what stops anyone in the middle substituting their own. We seal the
    // master password to that key and post only the ciphertext.

    async toolQrUnlock() {
      const body = el('div', { class: 'tool-body' });

      const explain = el('p', { class: 'row-desc', style: 'line-height:1.55;' , text:
        'On your computer, open CipherVault and press “Unlock with my phone” on the lock screen. Then scan the code it shows.' });

      const guard = (title, text) => {
        body.appendChild(el('div', { class: 'empty' }, [
          el('div', { class: 'empty-icon', html: ICONS.warn }),
          el('h3', { text: title }),
          el('p', { text }),
        ]));
        this.openSheet({ title: 'Unlock a PC', body });
      };

      if (!this.aesKey) {
        return guard('Vault is locked', 'Unlock your vault on this phone first — it is what authorises the computer.');
      }
      if (!this.currentUid) {
        return guard('Not signed in', 'QR unlock needs both devices signed in to the same CipherVault account.');
      }
      if (!this.masterPassword) {
        return guard('Unlock again first', 'For this to work, unlock this phone with your master password or biometrics once more, then try again.');
      }
      if (!isNative || !CapPlugins.CapacitorBarcodeScanner) {
        return guard('Camera unavailable', 'Scanning needs the CipherVault Android app — it is not available in a browser.');
      }

      const status = el('p', { class: 'row-desc' });

      const scanBtn = el('button', {
        class: 'btn btn-primary btn-block',
        text: 'Scan the code',
        on: { click: () => this.scanForPcUnlock(status, scanBtn) },
      });

      body.append(explain, scanBtn, status);
      this.openSheet({ title: 'Unlock a PC', body });
    }

    async scanForPcUnlock(status, button) {
      button.disabled = true;
      status.textContent = '';

      let scanned;
      try {
        const result = await CapPlugins.CapacitorBarcodeScanner.scanBarcode({
          hint: 17,              // ALL — the QR-only hint is unreliable across devices
          cameraDirection: 1,    // rear camera
          scanOrientation: 3,    // adaptive
        });
        scanned = result && result.ScanResult;
      } catch (err) {
        button.disabled = false;
        // Backing out of the scanner is not an error worth shouting about.
        if (err && /cancel/i.test(err.message || '')) return;
        status.textContent = 'Could not open the camera: ' + ((err && err.message) || 'unknown error');
        return;
      }

      button.disabled = false;
      if (!scanned) return;

      let session;
      try {
        session = LinkSessionEngine.parseQrPayload(scanned);
      } catch (err) {
        status.textContent = err.message;
        return;
      }

      const approved = await this.confirm({
        title: 'Unlock your computer?',
        body: 'This sends your master password to that computer, encrypted so only it can read it. Only approve this if you are looking at your own screen right now.',
        confirmLabel: 'Unlock it',
        icon: ICONS.shield,
      });
      if (!approved) {
        status.textContent = 'Cancelled.';
        return;
      }

      status.textContent = 'Approving…';
      try {
        const response = await LinkSessionEngine.buildResponse(
          session.sessionId,
          session.publicKey,
          this.masterPassword
        );
        await FirebaseSyncEngine.postLinkResponse(this.currentUid, session.sessionId, response);

        status.textContent = '';
        this.haptic();
        this.closeSheet();
        this.dialog({
          title: 'Computer unlocked',
          icon: ICONS.check,
          body: 'Your vault should now be open on that computer. The code you scanned is already used up and cannot be reused.',
          actions: [{ label: 'Done', style: 'btn-primary' }],
        });
      } catch (err) {
        console.error('QR approval failed:', err);
        status.textContent = (err && err.code === 'permission-denied')
          ? 'Blocked by Firestore rules — redeploy firestore.rules.'
          : 'Could not reach your computer: ' + ((err && err.message) || 'unknown error');
      }
    }

    // ---------------------------------------------------- biometric unlock
    //
    // The master password is sealed by an AndroidKeyStore key that requires a
    // biometric to use (see BiometricPlugin.java). Nothing readable is stored
    // here, and the master password is still what actually opens the vault -
    // biometrics only retrieve it.

    get biometrics() {
      return (isNative && CapPlugins.BiometricAuth) || null;
    }

    async refreshBiometricState() {
      const row = $('row-biometric');
      const toggle = $('set-biometric');
      const desc = $('set-biometric-desc');
      const unlockBtn = $('btn-biometric-unlock');

      if (!this.biometrics) {
        row.hidden = true;
        unlockBtn.classList.add('hidden');
        this.biometricStatus = { available: false, enrolled: false };
        return;
      }

      let status;
      try {
        status = await this.biometrics.isAvailable();
      } catch (err) {
        row.hidden = true;
        unlockBtn.classList.add('hidden');
        return;
      }

      this.biometricStatus = status;
      row.hidden = false;
      toggle.checked = !!status.enrolled;
      toggle.disabled = !status.available;

      desc.textContent = status.available
        ? 'Unlock with your fingerprint instead of typing your master password'
        : status.reason;

      // Only offer the shortcut on the lock screen once it is actually set up.
      unlockBtn.classList.toggle('hidden', !(status.available && status.enrolled));
    }

    async enableBiometrics(masterPassword) {
      if (!this.biometrics) return false;
      try {
        await this.biometrics.enable({ secret: masterPassword });
        this.toast('Biometric unlock enabled.');
        await this.refreshBiometricState();
        return true;
      } catch (err) {
        const code = (err && err.message) || '';
        if (code === 'BIOMETRIC_CANCELLED') this.toast('Cancelled.');
        else this.toast('Could not enable biometrics: ' + code);
        await this.refreshBiometricState();
        return false;
      }
    }

    async disableBiometrics({ silent = false } = {}) {
      if (!this.biometrics) return;
      try {
        await this.biometrics.disable();
        if (!silent) this.toast('Biometric unlock turned off.');
      } catch (err) {
        console.error('Could not disable biometrics:', err);
      }
      await this.refreshBiometricState();
    }

    /**
     * Offers biometric unlock once, after the first successful password unlock
     * on a device that supports it. Declining is remembered so it never nags;
     * Settings still has the toggle.
     */
    async maybeOfferBiometrics(masterPassword) {
      if (!this.biometrics) return;
      if (localStorage.getItem('cv:biometric:offered') === 'true') return;

      const status = this.biometricStatus || {};
      if (!status.available || status.enrolled) return;

      localStorage.setItem('cv:biometric:offered', 'true');

      this.dialog({
        title: 'Use biometrics?',
        icon: ICONS.shield,
        body: 'Unlock CipherVault with your fingerprint instead of typing your master password each time. Your master password is sealed by your device’s secure hardware and never stored in readable form.',
        actions: [
          { label: 'Enable', style: 'btn-primary', onClick: () => this.enableBiometrics(masterPassword) },
          { label: 'Not now', style: 'btn-ghost' },
        ],
      });
    }

    async unlockWithBiometrics() {
      if (!this.biometrics) return;

      const btn = $('btn-biometric-unlock');
      btn.disabled = true;
      this.hideMsg('unlock-error');

      try {
        const { secret } = await this.biometrics.unlock();
        $('master-pass').value = secret;
        await this.doUnlock();
      } catch (err) {
        const code = (err && err.message) || '';

        if (code === 'BIOMETRIC_INVALIDATED') {
          // A biometric was added or removed on the device since we sealed the
          // secret, so the key is gone. Requiring the master password again is
          // the correct outcome, not a bug.
          await this.refreshBiometricState();
          this.dialog({
            title: 'Biometrics changed',
            icon: ICONS.warn,
            body: 'The fingerprints or face data on this device changed, so the saved unlock was discarded for safety. Enter your master password, then turn biometric unlock back on in Settings.',
            actions: [{ label: 'OK', style: 'btn-primary' }],
          });
        } else if (code === 'BIOMETRIC_LOCKOUT') {
          this.showMsg('unlock-error', 'Too many failed attempts. Use your master password.');
        } else if (code !== 'BIOMETRIC_CANCELLED') {
          this.showMsg('unlock-error', code || 'Biometric unlock failed.');
        }
      } finally {
        btn.disabled = false;
        $('master-pass').value = '';
      }
    }

    // ------------------------------------------------- SimpleLogin API key
    //
    // Encrypted with the vault key and carried in the synced document, so
    // entering it on the desktop makes it available on the phone too. It used
    // to be plaintext localStorage, per device.

    async loadFolders() {
      this.folders = [];
      if (!this.aesKey) return;

      const blob = StorageController.getFoldersEnc();
      if (blob) {
        try {
          const parsed = await CryptoEngine.decryptJson(blob, this.aesKey);
          if (Array.isArray(parsed)) this.folders = parsed;
        } catch (err) {
          console.warn('Could not decrypt the folder list.', err);
        }
      }

      // One-time migration off the old plaintext list.
      const legacy = StorageController.getLegacyFolders();
      if (legacy.length) {
        if (!this.folders.length) {
          this.folders = legacy;
          await this.saveFolders({ sync: false });
        }
        StorageController.clearLegacyFolders();
      }
    }

    async saveFolders({ sync = true } = {}) {
      if (!this.aesKey) return;
      const blob = this.folders.length
        ? await CryptoEngine.encryptJson(this.folders, this.aesKey)
        : '';
      StorageController.setFoldersEnc(blob);
      if (sync) await this.saveVault();
    }

    async loadSimpleLoginKey() {
      this.simpleLoginKey = '';
      if (!this.aesKey) return;

      const blob = StorageController.getSimpleLoginKeyEnc();
      if (blob) {
        try {
          this.simpleLoginKey = await CryptoEngine.decrypt(blob, this.aesKey);
        } catch (err) {
          console.warn('Could not decrypt the stored SimpleLogin key.', err);
        }
      }

      // One-time migration off the old plaintext value.
      const legacy = StorageController.getLegacySimpleLoginKey();
      if (legacy) {
        if (!this.simpleLoginKey) {
          this.simpleLoginKey = legacy;
          await this.saveSimpleLoginKey(legacy, { silent: true });
        }
        StorageController.clearLegacySimpleLoginKey();
      }
    }

    async saveSimpleLoginKey(key, { silent = false } = {}) {
      if (!this.aesKey) return this.toast('Unlock your vault first.');

      this.simpleLoginKey = key || '';
      const blob = this.simpleLoginKey
        ? await CryptoEngine.encrypt(this.simpleLoginKey, this.aesKey)
        : '';
      StorageController.setSimpleLoginKeyEnc(blob);

      await this.saveVault();
      if (!silent) {
        this.toast(key ? 'SimpleLogin key saved and synced.' : 'SimpleLogin key removed.');
      }
    }

    getSimpleLoginKey() {
      return this.simpleLoginKey || '';
    }

    // ------------------------------------------------------------- folders

    selectCategory(category) {
      this.activeCategory = category;
      document.querySelectorAll('#category-chips .chip[data-category]').forEach((c) => {
        c.classList.toggle('active', c.dataset.category === category);
      });
      this.renderVault();
    }

    /**
     * Rebuilds the folder chips after the fixed categories. Kept in the same
     * scrolling row so folders read as just another way to filter, which is
     * how the desktop sidebar presents them.
     */
    renderFolderChips() {
      const row = $('category-chips');
      const divider = $('folder-divider');
      const addBtn = $('btn-new-folder');

      row.querySelectorAll('.chip-folder').forEach((c) => c.remove());
      divider.hidden = this.folders.length === 0;

      this.folders.forEach((folder) => {
        const count = this.decryptedVault.filter(
          (i) => !i.isTrashed && i.data && i.data.folderId === folder.id
        ).length;

        const chip = el('button', {
          class: `chip chip-folder${this.activeCategory === folder.id ? ' active' : ''}`,
          attrs: { 'data-category': folder.id },
        }, [
          el('span', { html: '<svg viewBox="0 0 24 24"><path fill="currentColor" d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>', class: 'chip-folder-icon' }),
          el('span', { text: folder.name }),
          el('span', { class: 'chip-count', text: String(count) }),
        ]);

        chip.addEventListener('click', () => this.selectCategory(folder.id));

        // Long-press to manage, since there is no room for a per-chip menu.
        let holdTimer = null;
        const startHold = () => {
          holdTimer = setTimeout(() => {
            holdTimer = null;
            this.haptic();
            this.manageFolder(folder);
          }, 550);
        };
        const cancelHold = () => { if (holdTimer) clearTimeout(holdTimer); holdTimer = null; };
        chip.addEventListener('touchstart', startHold, { passive: true });
        chip.addEventListener('touchend', cancelHold);
        chip.addEventListener('touchmove', cancelHold, { passive: true });
        chip.addEventListener('contextmenu', (e) => { e.preventDefault(); this.manageFolder(folder); });

        row.insertBefore(chip, addBtn);
      });
    }

    /** Small text-entry dialog; window.prompt is unavailable in the WebView. */
    askForText({ title, body, label, value = '', placeholder = '', confirmLabel = 'Save' }) {
      return new Promise((resolve) => {
        const input = el('input', { attrs: { type: 'text', placeholder, autocomplete: 'off' } });
        input.value = value;

        const wrap = el('div', { style: 'text-align:left;' }, [
          body ? el('p', { class: 'row-desc', style: 'margin-bottom:12px;', text: body }) : null,
          el('div', { class: 'field' }, [
            label ? el('label', { text: label }) : null,
            input,
          ]),
        ]);

        this.dialog({
          title,
          body: wrap,
          dismissible: false,
          actions: [
            { label: confirmLabel, style: 'btn-primary', onClick: () => resolve(input.value.trim()) },
            { label: 'Cancel', style: 'btn-ghost', onClick: () => resolve(null) },
          ],
        });

        setTimeout(() => input.focus(), 120);
      });
    }

    async promptNewFolder() {
      if (!this.aesKey) return this.toast('Unlock your vault first.');

      const name = await this.askForText({
        title: 'New Folder',
        label: 'Folder name',
        placeholder: 'e.g. Work',
        confirmLabel: 'Create',
      });
      if (!name) return null;

      const folder = { id: 'folder_' + Date.now(), name };
      this.folders.push(folder);
      await this.saveFolders();
      this.renderFolderChips();
      this.toast(`Folder “${name}” created.`);
      return folder;
    }

    async manageFolder(folder) {
      this.dialog({
        title: folder.name,
        body: 'Rename this folder, or delete it. Deleting keeps the items inside and just removes them from the folder.',
        actions: [
          {
            label: 'Rename',
            style: 'btn-primary',
            onClick: async () => {
              const name = await this.askForText({
                title: 'Rename Folder',
                label: 'Folder name',
                value: folder.name,
              });
              if (!name || name === folder.name) return;
              folder.name = name;
              await this.saveFolders();
              this.renderFolderChips();
              this.toast('Folder renamed.');
            },
          },
          {
            label: 'Delete folder',
            style: 'btn-danger',
            onClick: async () => {
              const ok = await this.confirm({
                title: 'Delete folder?',
                body: `“${folder.name}” will be removed. Items inside it stay in your vault and move back to All.`,
                confirmLabel: 'Delete',
                danger: true,
              });
              if (!ok) return;

              this.folders = this.folders.filter((f) => f.id !== folder.id);
              this.decryptedVault.forEach((i) => {
                if (i.data && i.data.folderId === folder.id) i.data.folderId = '';
              });
              if (this.activeCategory === folder.id) this.activeCategory = 'all';

              await this.saveFolders();
              this.selectCategory(this.activeCategory);
              this.renderFolderChips();
              this.toast('Folder deleted.');
            },
          },
          { label: 'Cancel', style: 'btn-ghost' },
        ],
      });
    }

    switchTab(name) {
      this.activeTab = name;
      document.querySelectorAll('.nav-tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
      ['vault', 'tools', 'settings'].forEach((t) => {
        $(`tab-${t}`).classList.toggle('hidden', t !== name);
      });
      $('app-bar-title').textContent = { vault: 'Vault', tools: 'Tools', settings: 'Settings' }[name];
      if (name === 'settings') this.refreshSettings();
    }

    // ---------------------------------------------------------------- sheet

    openSheet({ title, body, actions = [], footer = null }) {
      $('sheet-title').textContent = title;

      const actionBox = $('sheet-actions');
      actionBox.innerHTML = '';
      actions.forEach((a) => {
        actionBox.appendChild(el('button', {
          class: 'icon-btn',
          html: a.icon,
          attrs: { 'aria-label': a.label, title: a.label },
          on: { click: a.onClick },
        }));
      });

      const bodyBox = $('sheet-body');
      bodyBox.innerHTML = '';
      bodyBox.scrollTop = 0;
      if (body) bodyBox.appendChild(body);

      const footBox = $('sheet-footer');
      footBox.innerHTML = '';
      footBox.classList.toggle('hidden', !footer);
      if (footer) footBox.appendChild(footer);

      $('sheet').classList.remove('hidden');
    }

    closeSheet() {
      $('sheet').classList.add('hidden');
      $('sheet-body').innerHTML = '';
      this.activeTotp = null;
    }

    // ----------------------------------------------------------- auth/sync

    setupAuth() {
      FirebaseSyncEngine.onAuthStateChanged(async (user) => {
        const newUid = user ? user.uid : null;
        const changed = newUid !== this.currentUid;

        this.firebaseUser = user;
        this.currentUid = newUid;

        if (changed) {
          this.aesKey = null;
          this.decryptedVault = [];
          this.simpleLoginKey = '';
          this.masterPassword = '';
          StorageController.setScope(newUid);
          this.folders = [];
          this.showLockScreen();
        }

        this.updateSyncIndicator(!!user);
        if (user) await this.syncFromCloud();
        this.updateSyncIndicator(false);
        this.checkVaultState();
        this.refreshSettings();
      });
    }

    updateSyncIndicator(syncing = false) {
      const dot = $('sync-dot');
      const text = $('sync-text');
      if (this.firebaseUser) {
        dot.style.backgroundColor = syncing ? '#FACC15' : '#4ADE80';
        text.textContent = syncing ? 'Syncing' : 'Synced';
      } else {
        dot.style.backgroundColor = 'var(--text-disabled)';
        text.textContent = 'Local';
      }
    }

    async syncFromCloud() {
      const uid = this.currentUid;
      if (!uid) return;

      let cloud = null;
      try {
        cloud = await FirebaseSyncEngine.downloadVault(uid);
      } catch (err) {
        console.error('Cloud sync failed:', err);
        this.toast("Offline - using this device's copy.");
        return;
      }

      if (cloud && cloud.isProvisioned) {
        const changed =
          StorageController.getSalt() !== cloud.salt ||
          StorageController.getMasterHash() !== cloud.hash;

        StorageController.setSalt(cloud.salt);
        StorageController.setMasterHash(cloud.hash);
        StorageController.setKdf(cloud.kdf);
        StorageController.saveEncryptedItems(cloud.vault);
        StorageController.setSimpleLoginKeyEnc(cloud.slKeyEnc);
        StorageController.setFoldersEnc(cloud.foldersEnc);
        if (!cloud.foldersEnc && cloud.legacyFolders.length) {
          StorageController._set('folders', JSON.stringify(cloud.legacyFolders));
        }

        if (changed && this.aesKey) {
          this.aesKey = null;
          this.decryptedVault = [];
          this.simpleLoginKey = '';
          this.masterPassword = '';
          this.folders = [];
          this.showLockScreen();
        }
        if (this.aesKey) await this.loadAndDecrypt();
        return;
      }

      // Account has no cloud vault; offer to upload this phone's offline one.
      const adoptable =
        StorageController.hasVaultFor(StorageController.SCOPE_LOCAL) &&
        !StorageController.hasVaultFor(`u:${uid}`);

      if (adoptable) {
        const ok = await this.confirm({
          title: 'Link this vault?',
          body: "This account has no cloud vault yet. Upload the offline vault stored on this phone to it? Everything stays end-to-end encrypted.",
          confirmLabel: 'Upload',
          cancelLabel: 'Not now',
        });
        if (!ok) return;

        const { salt, hash, kdf, items, foldersEnc, slKeyEnc } =
          StorageController.readScope(StorageController.SCOPE_LOCAL);

        StorageController.setSalt(salt);
        StorageController.setMasterHash(hash);
        StorageController.setKdf(kdf);
        StorageController.saveEncryptedItems(items);
        StorageController.setFoldersEnc(foldersEnc);
        StorageController.setSimpleLoginKeyEnc(slKeyEnc);
        await this.loadFolders();

        try {
          await FirebaseSyncEngine.uploadVault(uid, { vault: items, foldersEnc, salt, hash, kdf, slKeyEnc });
          this.toast('Vault linked to your account.');
        } catch (err) {
          console.error(err);
          this.toast(this.syncErrorText(err));
        }
      }
    }

    syncErrorText(err) {
      const code = (err && err.code) || '';
      if (code === 'permission-denied') return 'Blocked by Firestore rules.';
      if (code === 'unavailable') return 'Cloud unreachable. Saved on this phone.';
      return 'Sync failed: ' + ((err && err.message) || 'unknown error');
    }

    authErrorText(err) {
      switch ((err && err.code) || '') {
        case 'auth/invalid-email': return "That email address doesn't look valid.";
        case 'auth/user-not-found':
        case 'auth/wrong-password':
        case 'auth/invalid-credential':
        case 'auth/invalid-login-credentials': return 'Incorrect email or password.';
        case 'auth/email-already-in-use': return 'An account already exists for that email - use Log In.';
        case 'auth/weak-password': return 'Pick a longer account password (6+ characters).';
        case 'auth/network-request-failed': return 'No connection. Check your internet.';
        case 'auth/too-many-requests': return 'Too many attempts. Wait a moment.';
        default: return (err && err.message) || 'Authentication failed.';
      }
    }

    // ----------------------------------------------------------- lock flow

    showLockScreen() {
      $('lock-screen').classList.remove('hidden');
      $('app-shell').classList.add('hidden');
      this.closeSheet();
      $('master-pass').value = '';
    }

    showLockPane(id) {
      ['welcome-pane', 'signin-pane', 'setup-pane', 'unlock-pane'].forEach((p) => {
        $(p).classList.toggle('hidden', p !== id);
      });
    }

    checkVaultState() {
      const salt = StorageController.getSalt();
      const hash = StorageController.getMasterHash();
      const account = this.firebaseUser ? this.firebaseUser.email : null;

      // Already unlocked: stay in the app.
      if (this.aesKey) return;

      $('lock-screen').classList.remove('hidden');
      $('app-shell').classList.add('hidden');

      if (salt && hash) {
        this.showLockPane('unlock-pane');
        $('lock-title').textContent = 'Unlock Vault';
        $('lock-subtitle').textContent = account
          ? `Enter the master password for ${account}.`
          : "Enter your master password.";
      } else if (this.firebaseUser || StorageController.getLocalChoice()) {
        this.showLockPane('setup-pane');
        $('lock-title').textContent = 'Create Master Password';
        $('lock-subtitle').textContent = account
          ? `This encrypts the vault for ${account}. It never leaves your phone.`
          : 'This encrypts your vault. It never leaves your phone.';
      } else {
        this.showLockPane('welcome-pane');
        $('lock-title').textContent = 'CipherVault';
        $('lock-subtitle').textContent = 'Your secure, zero-knowledge vault.';
      }
    }

    bindLockScreen() {
      $('btn-welcome-local').addEventListener('click', () => {
        StorageController.setLocalChoice(true);
        this.checkVaultState();
      });
      $('btn-welcome-login').addEventListener('click', () => {
        this.showLockPane('signin-pane');
        $('lock-title').textContent = 'Sign In';
        $('lock-subtitle').textContent = 'Sync your vault across your devices.';
      });
      $('btn-signin-back').addEventListener('click', () => this.checkVaultState());
      $('btn-setup-back').addEventListener('click', async () => {
        if (this.firebaseUser) await FirebaseSyncEngine.logout();
        StorageController.setLocalChoice(false);
        this.checkVaultState();
      });
      $('btn-switch-account').addEventListener('click', async () => {
        await this.disableBiometrics({ silent: true });
        localStorage.removeItem('cv:biometric:offered');
        if (this.firebaseUser) await FirebaseSyncEngine.logout();
        StorageController.setLocalChoice(false);
        this.checkVaultState();
        this.showLockPane('signin-pane');
      });

      const eye = (btnId, inputId) => {
        $(btnId).addEventListener('click', () => {
          const input = $(inputId);
          const show = input.type === 'password';
          input.type = show ? 'text' : 'password';
          $(btnId).classList.toggle('on', show);
        });
      };
      eye('btn-eye-create', 'create-pass');
      eye('btn-eye-unlock', 'master-pass');

      // Sign in / sign up
      $('signin-pane').addEventListener('submit', (e) => { e.preventDefault(); this.doSignIn(false); });
      $('btn-signup').addEventListener('click', () => this.doSignIn(true));

      $('btn-forgot').addEventListener('click', async () => {
        const email = $('fb-email').value.trim();
        this.hideMsg('signin-error');
        this.hideMsg('signin-success');
        if (!email) return this.showMsg('signin-error', 'Enter your email address first.');
        try {
          await FirebaseSyncEngine.sendPasswordReset(email);
          this.showMsg('signin-success', `Reset email sent to ${email}. This resets your ACCOUNT password, not your master password.`);
        } catch (err) {
          this.showMsg('signin-error', this.authErrorText(err));
        }
      });

      // Master password strength
      $('create-pass').addEventListener('input', () => this.updateStrengthMeter());

      $('setup-pane').addEventListener('submit', (e) => { e.preventDefault(); this.doCreateVault(); });
      $('unlock-pane').addEventListener('submit', (e) => { e.preventDefault(); this.doUnlock(); });

      $('btn-reset-vault').addEventListener('click', () => this.doResetVault());
      $('btn-biometric-unlock').addEventListener('click', () => this.unlockWithBiometrics());
    }

    showMsg(id, text) { const n = $(id); n.textContent = text; n.classList.remove('hidden'); }
    hideMsg(id) { $(id).classList.add('hidden'); }

    updateStrengthMeter() {
      const val = $('create-pass').value;
      const bar = $('setup-strength-bar');
      const label = $('setup-strength-text');

      if (!val) {
        bar.style.width = '0%';
        label.textContent = 'Password Strength: None';
        return;
      }

      let score = 0;
      if (val.length >= 8) score += 25;
      if (val.length >= 14) score += 25;
      if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score += 25;
      if (/[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) score += 25;

      bar.style.width = `${score}%`;
      const names = { 25: 'Weak', 50: 'Fair', 75: 'Good', 100: 'Strong' };
      bar.style.backgroundColor = score >= 75 ? 'var(--ok)' : score >= 50 ? 'var(--text-secondary)' : 'var(--warn)';
      label.textContent = `Password Strength: ${names[score] || 'Weak'}`;
    }

    async doSignIn(isSignup) {
      const email = $('fb-email').value.trim();
      const pwd = $('fb-password').value;
      this.hideMsg('signin-error');
      this.hideMsg('signin-success');

      if (!email || !pwd) return this.showMsg('signin-error', 'Enter both an email and a password.');
      if (isSignup && pwd.length < 6) return this.showMsg('signin-error', 'Account password must be at least 6 characters.');

      const btn = isSignup ? $('btn-signup') : $('btn-signin');
      btn.disabled = true;
      try {
        if (isSignup) await FirebaseSyncEngine.signup(email, pwd);
        else await FirebaseSyncEngine.login(email, pwd);
        $('fb-password').value = '';
        this.toast(isSignup ? 'Account created.' : 'Signed in.');
      } catch (err) {
        this.showMsg('signin-error', this.authErrorText(err));
      } finally {
        btn.disabled = false;
      }
    }

    async doCreateVault() {
      const pass = $('create-pass').value;
      const confirmPass = $('confirm-pass').value;
      this.hideMsg('setup-error');

      if (pass !== confirmPass) return this.showMsg('setup-error', 'Passwords do not match.');
      if (pass.length < 8) return this.showMsg('setup-error', 'Master password must be at least 8 characters.');

      const btn = $('btn-create-vault');
      btn.disabled = true;
      btn.textContent = 'Creating…';

      try {
        const salt = CryptoEngine.generateSalt();
        const kdf = { v: CryptoEngine.KDF_VERSION, iterations: CryptoEngine.DEFAULT_ITERATIONS };
        const { aesKey, verifier } = await CryptoEngine.deriveKeyAndVerifier(pass, salt, kdf.iterations);

        StorageController.setSalt(salt);
        StorageController.setMasterHash(verifier);
        StorageController.setKdf(kdf);
        StorageController.saveEncryptedItems([]);
        StorageController.setFoldersEnc('');

        this.aesKey = aesKey;
        this.masterPassword = pass;
        this.decryptedVault = [];
        this.folders = [];

        if (this.currentUid) {
          try {
            await FirebaseSyncEngine.uploadVault(this.currentUid, { vault: [], foldersEnc: '', salt, hash: verifier, kdf, slKeyEnc: '' });
          } catch (err) {
            console.error(err);
            this.toast(this.syncErrorText(err));
          }
        }

        $('create-pass').value = '';
        $('confirm-pass').value = '';
        this.enterApp();
        this.toast('Vault created.');
      } catch (err) {
        console.error(err);
        this.showMsg('setup-error', 'Setup error: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Vault';
      }
    }

    async doUnlock() {
      const input = $('master-pass');
      const password = input.value;
      this.hideMsg('unlock-error');

      const salt = StorageController.getSalt();
      const hash = StorageController.getMasterHash();
      if (!salt || !hash) return this.checkVaultState();

      const btn = $('btn-unlock');
      btn.disabled = true;
      btn.textContent = 'Unlocking…';

      try {
        const result = await CryptoEngine.unlock(password, salt, hash, StorageController.getKdf());
        if (!result.ok) {
          this.showMsg('unlock-error', 'Incorrect master password.');
          return;
        }

        this.aesKey = result.aesKey;
        this.masterPassword = password;
        input.value = '';
        const failed = await this.loadAndDecrypt();
        this.enterApp();
        this.toast(failed > 0 ? `Unlocked. ${failed} item(s) failed to decrypt.` : 'Vault unlocked.');

        if (result.needsUpgrade) await this.upgradeKdf(password);
        await this.maybeOfferBiometrics(password);
      } catch (err) {
        console.error(err);
        this.showMsg('unlock-error', 'Error unlocking: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'Unlock';
      }
    }

    /** Re-keys a vault written by an older build onto the current KDF. */
    async upgradeKdf(masterPassword) {
      try {
        const salt = CryptoEngine.generateSalt();
        const kdf = { v: CryptoEngine.KDF_VERSION, iterations: CryptoEngine.DEFAULT_ITERATIONS };
        const { aesKey, verifier } = await CryptoEngine.deriveKeyAndVerifier(masterPassword, salt, kdf.iterations);

        this.aesKey = aesKey;
        StorageController.setSalt(salt);
        StorageController.setMasterHash(verifier);
        StorageController.setKdf(kdf);
        await this.saveVault();
        console.info('Vault upgraded to KDF v' + kdf.v);
      } catch (err) {
        console.error('KDF upgrade failed:', err);
      }
    }

    enterApp() {
      $('lock-screen').classList.add('hidden');
      $('app-shell').classList.remove('hidden');
      this.switchTab('vault');
      this.renderVault();
      this.resetIdleTimer();
    }

    lock({ silent = false, reason = 'Vault locked.' } = {}) {
      if (this.idleTimer) clearTimeout(this.idleTimer);
      this.idleTimer = null;
      this.aesKey = null;
      this.decryptedVault = [];
      this.simpleLoginKey = '';
      this.masterPassword = '';
      this.folders = [];
      this.activeTotp = null;
      this.closeSheet();
      this.closeDialog();
      this.showLockScreen();
      this.checkVaultState();
      if (!silent) this.toast(reason);
    }

    resetIdleTimer() {
      if (this.idleTimer) clearTimeout(this.idleTimer);
      if (!this.aesKey) return;

      const setting = StorageController.getAutoLockMinutes();
      if (setting === 'never') return;

      const minutes = parseInt(setting, 10);
      if (isNaN(minutes) || minutes <= 0) return;

      this.idleTimer = setTimeout(() => {
        if (this.aesKey) this.lock({ reason: 'Vault auto-locked after inactivity.' });
      }, minutes * 60 * 1000);
    }

    async doResetVault() {
      const who = this.firebaseUser ? `the vault for ${this.firebaseUser.email}` : "this phone's offline vault";
      const ok = await this.confirm({
        title: 'Reset vault?',
        body: `This permanently destroys ${who}. Every item encrypted with your master password is lost. This cannot be undone.`,
        confirmLabel: 'Reset',
        danger: true,
      });
      if (!ok) return;

      StorageController.wipeScope();
      await this.disableBiometrics({ silent: true });
      this.aesKey = null;
      this.decryptedVault = [];
      this.folders = [];

      if (this.currentUid) {
        try { await FirebaseSyncEngine.deleteVault(this.currentUid); }
        catch (err) { this.toast(this.syncErrorText(err)); }
      }

      this.checkVaultState();
      this.toast('Vault reset.');
    }

    // ----------------------------------------------------------- vault data

    async loadAndDecrypt() {
      const raw = StorageController.getEncryptedItems();
      const items = [];
      let failed = 0;

      for (const item of raw) {
        try {
          const data = await CryptoEngine.decryptJson(item.encryptedData, this.aesKey);
          items.push({
            id: item.id,
            type: item.type || 'login',
            isFavorite: !!item.isFavorite,
            isTrashed: !!item.isTrashed,
            createdAt: item.createdAt || new Date().toISOString(),
            data,
          });
        } catch (e) {
          failed++;
        }
      }

      this.decryptedVault = items;
      await this.loadFolders();
      await this.loadSimpleLoginKey();
      this.renderVault();
      return failed;
    }

    async saveVault() {
      if (!this.aesKey) return;

      const encrypted = [];
      for (const item of this.decryptedVault) {
        encrypted.push({
          id: item.id,
          type: item.type,
          isFavorite: !!item.isFavorite,
          isTrashed: !!item.isTrashed,
          createdAt: item.createdAt,
          encryptedData: await CryptoEngine.encryptJson(item.data, this.aesKey),
        });
      }

      StorageController.saveEncryptedItems(encrypted);

      if (this.currentUid) {
        this.updateSyncIndicator(true);
        try {
          await FirebaseSyncEngine.uploadVault(this.currentUid, {
            vault: encrypted,
            foldersEnc: StorageController.getFoldersEnc(),
            salt: StorageController.getSalt(),
            hash: StorageController.getMasterHash(),
            kdf: StorageController.getKdf(),
            slKeyEnc: StorageController.getSimpleLoginKeyEnc(),
          });
        } catch (err) {
          console.error(err);
          this.toast(this.syncErrorText(err));
        } finally {
          this.updateSyncIndicator(false);
        }
      }
    }

    // ------------------------------------------------------- vault rendering

    matchesCategory(item) {
      const c = this.activeCategory;
      if (c === 'trash') return item.isTrashed;
      if (item.isTrashed) return false;
      if (c === 'all') return true;
      if (c === 'favorites') return !!item.isFavorite;
      if (c === 'passwords') return item.type === 'login' || item.type === 'passwords';
      if (c === 'passkeys') return item.type === 'passkeys' || item.type === 'passkey';
      if (c === 'notes') return item.type === 'note' || item.type === 'notes';
      if (c === 'cards') return item.type === 'card' || item.type === 'cards';
      if (c === 'identity') return item.type === 'identity';
      if (c.startsWith('folder_')) return item.data && item.data.folderId === c;
      return true;
    }

    updateCounts() {
      const live = this.decryptedVault.filter((i) => !i.isTrashed);
      const set = (id, n) => { const e = $(id); if (e) e.textContent = n; };
      set('c-all', live.length);
      set('c-fav', live.filter((i) => i.isFavorite).length);
      set('c-pw', live.filter((i) => i.type === 'login' || i.type === 'passwords').length);
      set('c-pk', live.filter((i) => i.type === 'passkeys' || i.type === 'passkey').length);
      set('c-notes', live.filter((i) => i.type === 'note' || i.type === 'notes').length);
      set('c-cards', live.filter((i) => i.type === 'card' || i.type === 'cards').length);
      set('c-id', live.filter((i) => i.type === 'identity').length);
      set('c-trash', this.decryptedVault.filter((i) => i.isTrashed).length);
    }

    subtitleFor(item) {
      const d = item.data || {};
      switch (item.type) {
        case 'login': case 'passwords': return d.username || d.url || 'Login';
        case 'passkeys': case 'passkey': return d.relyingParty || d.userHandle || 'Passkey';
        case 'note': case 'notes': return 'Secure note';
        case 'card': case 'cards': return d.cardNumber ? `•••• ${String(d.cardNumber).slice(-4)}` : 'Card';
        case 'identity': return d.fullName || d.email || 'Identity';
        default: return '';
      }
    }

    renderVault() {
      this.updateCounts();
      this.renderFolderChips();

      const list = $('vault-list');
      list.innerHTML = '';

      const query = this.searchQuery.toLowerCase().trim();
      const items = this.decryptedVault
        .filter((i) => this.matchesCategory(i))
        .filter((i) => {
          if (!query) return true;
          const d = i.data || {};
          return [d.name, d.username, d.url, d.relyingParty, d.fullName, d.email, d.cardholder]
            .some((v) => (v || '').toLowerCase().includes(query));
        })
        .sort((a, b) => (a.data.name || '').localeCompare(b.data.name || ''));

      if (items.length === 0) {
        list.appendChild(this.emptyState(query));
        return;
      }

      items.forEach((item) => list.appendChild(this.vaultRow(item)));
    }

    emptyState(query) {
      let title = 'Your vault is empty';
      let text = 'Tap + to store your first password, note or card.';

      if (query) {
        title = 'No matches';
        text = `Nothing in your vault matches “${query}”.`;
      } else if (this.activeCategory === 'trash') {
        title = 'Trash is empty';
        text = 'Deleted items appear here before being permanently removed.';
      } else if (this.activeCategory === 'favorites') {
        title = 'No favourites yet';
        text = 'Open an item and tap the star to keep it here.';
      } else if (this.activeCategory.startsWith('folder_')) {
        const folder = this.folders.find((f) => f.id === this.activeCategory);
        title = 'Folder is empty';
        text = `Nothing is filed under “${folder ? folder.name : 'this folder'}” yet. Edit an item and pick this folder to move it here.`;
      } else if (this.decryptedVault.some((i) => !i.isTrashed)) {
        title = 'Nothing in this category';
        text = 'Try another category, or tap + to add something.';
      }

      return el('div', { class: 'empty' }, [
        el('div', { class: 'empty-icon', html: ICONS.empty }),
        el('h3', { text: title }),
        el('p', { text }),
      ]);
    }

    vaultRow(item) {
      const meta = typeMeta(item.type);
      const icon = el('div', { class: 'row-icon', html: meta.icon });

      // Favicon for anything with a domain, falling back to the type glyph.
      const site = item.data.url || item.data.relyingParty;
      if (site) {
        try {
          const host = new URL(site.startsWith('http') ? site : `https://${site}`).hostname;
          const img = new Image();
          img.src = `https://www.google.com/s2/favicons?domain=${host}&sz=64`;
          img.alt = '';
          img.onload = () => { icon.innerHTML = ''; icon.appendChild(img); };
        } catch (e) { /* not a URL; keep the glyph */ }
      }

      const tags = el('div', { class: 'row-tags' }, [
        el('span', { class: 'tag', text: meta.label }),
        item.isFavorite ? el('div', { class: 'star', html: ICONS.star }) : null,
      ]);

      return el('div', {
        class: 'vault-row',
        on: { click: () => this.openDetail(item) },
      }, [
        icon,
        el('div', { class: 'row-text' }, [
          el('span', { class: 'row-title', text: item.data.name || 'Untitled' }),
          el('span', { class: 'row-sub', text: this.subtitleFor(item) }),
        ]),
        tags,
      ]);
    }

    // ------------------------------------------------------------- detail

    fieldCard(label, value, { secret = false, mono = false, multiline = false } = {}) {
      const valueNode = el('span', {
        class: `field-value${mono ? ' mono' : ''}${multiline ? ' multiline' : ''}`,
        text: secret ? '••••••••••••' : value,
      });

      const buttons = el('div', { class: 'field-btns' });

      if (secret) {
        let shown = false;
        const toggle = el('button', { class: 'mini-btn', text: 'Show' });
        toggle.addEventListener('click', () => {
          shown = !shown;
          valueNode.textContent = shown ? value : '••••••••••••';
          toggle.textContent = shown ? 'Hide' : 'Show';
        });
        buttons.appendChild(toggle);
      }

      buttons.appendChild(el('button', {
        class: 'mini-btn',
        text: 'Copy',
        on: { click: () => this.copy(value, `${label} copied`) },
      }));

      return el('div', { class: 'field-card' }, [
        el('label', { text: label }),
        el('div', { class: 'field-card-row' }, [valueNode, buttons]),
      ]);
    }

    async openDetail(item) {
      const meta = typeMeta(item.type);
      const body = el('div');

      body.appendChild(el('div', { class: 'detail-head' }, [
        el('div', { class: 'row-icon', html: meta.icon }),
        el('div', {}, [
          el('h2', { text: item.data.name || 'Untitled' }),
          el('span', { class: 'tag', text: meta.label }),
        ]),
      ]));

      const d = item.data || {};
      const add = (...args) => body.appendChild(this.fieldCard(...args));

      if (item.type === 'login' || item.type === 'passwords') {
        if (d.username) add('Username / Email', d.username);
        if (d.password) add('Password', d.password, { secret: true, mono: true });
        if (d.url) add('Website', d.url);
        if (d.totpSecret) body.appendChild(await this.totpCard(d.totpSecret));
      } else if (item.type === 'passkeys' || item.type === 'passkey') {
        if (d.relyingParty) add('Relying Party', d.relyingParty);
        if (d.userHandle) add('User Handle', d.userHandle);
      } else if (item.type === 'note' || item.type === 'notes') {
        if (d.content) add('Note', d.content, { multiline: true });
      } else if (item.type === 'card' || item.type === 'cards') {
        if (d.cardholder) add('Cardholder', d.cardholder);
        if (d.cardNumber) add('Card Number', d.cardNumber, { secret: true, mono: true });
        if (d.expiry) add('Expires', d.expiry, { mono: true });
        if (d.cvv) add('CVV', d.cvv, { secret: true, mono: true });
      } else if (item.type === 'identity') {
        if (d.fullName) add('Full Name', d.fullName);
        if (d.email) add('Email', d.email);
        if (d.phone) add('Phone', d.phone);
        if (d.address) add('Address', d.address, { multiline: true });
      }

      const actions = [];

      if (item.isTrashed) {
        actions.push({
          label: 'Restore', icon: ICONS.restore,
          onClick: async () => {
            item.isTrashed = false;
            await this.saveVault();
            this.renderVault();
            this.closeSheet();
            this.toast('Item restored.');
          },
        });
        actions.push({
          label: 'Delete permanently', icon: ICONS.trash,
          onClick: async () => {
            const ok = await this.confirm({
              title: 'Delete permanently?',
              body: `“${item.data.name}” will be gone for good. This cannot be undone.`,
              confirmLabel: 'Delete', danger: true,
            });
            if (!ok) return;
            this.decryptedVault = this.decryptedVault.filter((i) => i.id !== item.id);
            await this.saveVault();
            this.renderVault();
            this.closeSheet();
            this.toast('Item deleted.');
          },
        });
      } else {
        actions.push({
          label: item.isFavorite ? 'Remove favourite' : 'Add favourite',
          icon: ICONS.star,
          onClick: async () => {
            item.isFavorite = !item.isFavorite;
            await this.saveVault();
            this.renderVault();
            this.toast(item.isFavorite ? 'Added to favourites.' : 'Removed from favourites.');
            this.openDetail(item);
          },
        });
        actions.push({ label: 'Edit', icon: ICONS.edit, onClick: () => this.openEditor(item) });
        actions.push({
          label: 'Move to trash', icon: ICONS.trash,
          onClick: async () => {
            const ok = await this.confirm({
              title: 'Move to trash?',
              body: `“${item.data.name}” can be restored from Trash later.`,
              confirmLabel: 'Move to trash', danger: true,
            });
            if (!ok) return;
            item.isTrashed = true;
            await this.saveVault();
            this.renderVault();
            this.closeSheet();
            this.toast('Moved to trash.');
          },
        });
      }

      this.openSheet({ title: meta.label, body, actions });
    }

    async totpCard(secret) {
      const code = await TOTPEngine.generateTOTP(secret);
      const codeNode = el('span', { class: 'totp-code', text: code.replace(/(\d{3})(\d{3})/, '$1 $2') });

      const ring = el('div', {
        class: 'totp-ring',
        html: '<svg viewBox="0 0 24 24"><circle class="track" cx="12" cy="12" r="10"/><circle class="bar" cx="12" cy="12" r="10" stroke-dasharray="62.8" stroke-dashoffset="0"/></svg>',
      });

      const card = el('div', { class: 'field-card' }, [
        el('label', { text: 'Two-Factor Code' }),
        el('div', { class: 'field-card-row' }, [
          el('div', { class: 'totp-wrap' }, [codeNode, ring]),
          el('div', { class: 'field-btns' }, [
            el('button', {
              class: 'mini-btn', text: 'Copy',
              on: { click: () => this.copy(codeNode.textContent.replace(/\s/g, ''), '2FA code copied') },
            }),
          ]),
        ]),
      ]);

      // The ticker refreshes this while the sheet is open.
      this.activeTotp = { secret, codeNode, ring };
      return card;
    }

    startTotpTicker() {
      if (this.totpTimer) clearInterval(this.totpTimer);
      this.totpTimer = setInterval(async () => {
        if (!this.activeTotp) return;
        const { secret, codeNode, ring } = this.activeTotp;

        const remaining = 30 - (Math.floor(Date.now() / 1000) % 30);
        const bar = ring.querySelector('.bar');
        if (bar) bar.style.strokeDashoffset = String(62.8 * (1 - remaining / 30));

        const code = await TOTPEngine.generateTOTP(secret);
        const formatted = code.replace(/(\d{3})(\d{3})/, '$1 $2');
        if (codeNode.textContent !== formatted) codeNode.textContent = formatted;
      }, 1000);
    }

    // ------------------------------------------------------------- editor

    openEditor(existing) {
      if (!this.aesKey) return;

      const form = el('form', { class: 'editor-form' });
      const state = { type: existing ? existing.type : 'login' };

      const typeField = el('div', { class: 'field' }, [el('label', { text: 'Type' })]);
      const typeSelect = el('select', { class: 'select', style: 'width:100%;' });
      [['login', 'Login / Password'], ['passkeys', 'Passkey'], ['card', 'Credit Card'], ['note', 'Secure Note'], ['identity', 'Identity']]
        .forEach(([v, label]) => {
          const opt = el('option', { text: label });
          opt.value = v;
          typeSelect.appendChild(opt);
        });
      typeSelect.value = ['login', 'passwords'].includes(state.type) ? 'login'
        : ['passkeys', 'passkey'].includes(state.type) ? 'passkeys'
        : ['note', 'notes'].includes(state.type) ? 'note'
        : ['card', 'cards'].includes(state.type) ? 'card'
        : state.type;
      typeField.appendChild(typeSelect);

      const nameInput = el('input', { attrs: { type: 'text', placeholder: 'e.g. GitHub', id: 'ed-name' } });
      nameInput.value = existing ? (existing.data.name || '') : '';
      const nameField = el('div', { class: 'field' }, [el('label', { text: 'Title' }), nameInput]);

      // Folder picker, with an inline escape hatch so you can create a folder
      // without leaving the editor.
      const folderSelect = el('select', { class: 'select', style: 'width:100%;' });
      const NEW_FOLDER = '__new__';
      const fillFolders = (selected) => {
        folderSelect.innerHTML = '';
        const none = el('option', { text: 'No folder' });
        none.value = '';
        folderSelect.appendChild(none);

        this.folders.forEach((f) => {
          const opt = el('option', { text: f.name });
          opt.value = f.id;
          folderSelect.appendChild(opt);
        });

        const add = el('option', { text: '+ New folder…' });
        add.value = NEW_FOLDER;
        folderSelect.appendChild(add);

        folderSelect.value = selected || '';
      };
      fillFolders(existing ? (existing.data.folderId || '') : (
        // Adding from inside a folder view files it there by default.
        this.activeCategory.startsWith('folder_') ? this.activeCategory : ''
      ));

      folderSelect.addEventListener('change', async () => {
        if (folderSelect.value !== NEW_FOLDER) return;
        const previous = existing ? (existing.data.folderId || '') : '';
        const folder = await this.promptNewFolder();
        fillFolders(folder ? folder.id : previous);
      });

      const folderField = el('div', { class: 'field' }, [
        el('label', { text: 'Folder' }),
        folderSelect,
      ]);

      const dynamic = el('div', { class: 'field', style: 'gap:15px;' });

      const buildFields = (type) => {
        dynamic.innerHTML = '';
        const d = existing ? existing.data : {};
        const mk = (id, label, value, opts = {}) => {
          const input = opts.multiline
            ? el('textarea', { attrs: { id, placeholder: opts.placeholder || '' } })
            : el('input', { attrs: { type: opts.type || 'text', id, placeholder: opts.placeholder || '', autocomplete: 'off' } });
          input.value = value || '';
          const field = el('div', { class: 'field' }, [el('label', { text: label })]);

          if (opts.generate) {
            const row = el('div', { class: 'input-row' }, [
              input,
              el('button', {
                class: 'btn btn-small', attrs: { type: 'button' }, text: 'Generate',
                on: {
                  click: () => {
                    input.value = CryptoEngine.generatePassword(18);
                    this.toast('Password generated.');
                  },
                },
              }),
            ]);
            field.appendChild(row);
          } else {
            field.appendChild(input);
          }
          dynamic.appendChild(field);
        };

        if (type === 'login') {
          mk('ed-user', 'Username / Email', d.username, { placeholder: 'you@example.com' });
          mk('ed-pass', 'Password', d.password, { generate: true, placeholder: '••••••••' });
          mk('ed-url', 'Website', d.url, { placeholder: 'https://example.com' });
          mk('ed-totp', 'Authenticator Secret (optional)', d.totpSecret, { placeholder: 'Base32 secret' });
        } else if (type === 'passkeys') {
          mk('ed-pk-rp', 'Relying Party / Domain', d.relyingParty, { placeholder: 'github.com' });
          mk('ed-pk-user', 'User Handle', d.userHandle, { placeholder: 'you@example.com' });
        } else if (type === 'note') {
          mk('ed-note', 'Secure Note', d.content, { multiline: true, placeholder: 'Write something private…' });
        } else if (type === 'card') {
          mk('ed-card-name', 'Cardholder Name', d.cardholder, { placeholder: 'Jane Doe' });
          mk('ed-card-num', 'Card Number', d.cardNumber, { placeholder: '4532 •••• •••• 8921' });
          mk('ed-card-exp', 'Expiry (MM/YY)', d.expiry, { placeholder: '12/28' });
          mk('ed-card-cvv', 'CVV', d.cvv, { placeholder: '123' });
        } else if (type === 'identity') {
          mk('ed-id-name', 'Full Name', d.fullName, { placeholder: 'Jane Doe' });
          mk('ed-id-email', 'Email', d.email, { placeholder: 'jane@example.com' });
          mk('ed-id-phone', 'Phone', d.phone, { placeholder: '+44 …' });
          mk('ed-id-address', 'Address', d.address, { multiline: true });
        }
      };

      typeSelect.addEventListener('change', () => buildFields(typeSelect.value));
      buildFields(typeSelect.value);

      form.append(typeField, nameField, folderField, dynamic);

      const saveBtn = el('button', { class: 'btn btn-primary', attrs: { type: 'button' }, text: 'Save' });
      const cancelBtn = el('button', { class: 'btn btn-ghost', attrs: { type: 'button' }, text: 'Cancel', on: { click: () => this.closeSheet() } });

      const doSave = async () => {
        const val = (id) => { const n = $(id); return n ? n.value.trim() : ''; };
        const type = typeSelect.value;
        const name = nameInput.value.trim();

        if (!name) return this.toast('Give the item a title.');

        const folderId = folderSelect.value === NEW_FOLDER ? '' : folderSelect.value;
        const data = { name, folderId };

        if (type === 'login') {
          data.username = val('ed-user');
          data.password = val('ed-pass');
          data.url = val('ed-url');
          const totp = val('ed-totp').replace(/\s/g, '');
          if (totp) data.totpSecret = totp;
        } else if (type === 'passkeys') {
          data.relyingParty = val('ed-pk-rp');
          data.userHandle = val('ed-pk-user');
        } else if (type === 'note') {
          data.content = $('ed-note') ? $('ed-note').value : '';
        } else if (type === 'card') {
          data.cardholder = val('ed-card-name');
          data.cardNumber = val('ed-card-num');
          data.expiry = val('ed-card-exp');
          data.cvv = val('ed-card-cvv');
        } else if (type === 'identity') {
          data.fullName = val('ed-id-name');
          data.email = val('ed-id-email');
          data.phone = val('ed-id-phone');
          data.address = $('ed-id-address') ? $('ed-id-address').value : '';
        }

        saveBtn.disabled = true;
        saveBtn.textContent = 'Saving…';

        if (existing) {
          existing.type = type;
          existing.data = data;
        } else {
          this.decryptedVault.push({
            id: 'item_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6),
            type,
            isFavorite: false,
            isTrashed: false,
            createdAt: new Date().toISOString(),
            data,
          });
        }

        await this.saveVault();
        this.renderVault();
        this.closeSheet();
        this.toast(`Saved “${name}”.`);
      };

      saveBtn.addEventListener('click', doSave);
      form.addEventListener('submit', (e) => { e.preventDefault(); doSave(); });

      this.openSheet({
        title: existing ? 'Edit Item' : 'New Item',
        body: form,
        footer: el('div', { class: 'input-row', style: 'width:100%; gap:10px;' }, [cancelBtn, saveBtn]),
      });
    }

    // -------------------------------------------------------------- tools

    openTool(name) {
      if (name === 'generator') return this.toolGenerator();
      if (name === 'masking') return this.toolMasking();
      if (name === 'health') return this.toolHealth();
      if (name === 'breach') return this.toolBreach();
      if (name === 'qr-unlock') return this.toolQrUnlock();
    }

    toolGenerator() {
      const body = el('div', { class: 'tool-body' });
      const output = el('div', { class: 'gen-output', text: '…' });

      const lengthValue = el('span', { class: 'slider-value', text: '18' });
      const slider = el('input', { attrs: { type: 'range', min: '6', max: '64', value: '18' } });

      const opts = {};
      const toggles = el('div', { class: 'settings-card' });
      [['upper', 'Uppercase (A-Z)'], ['lower', 'Lowercase (a-z)'], ['numbers', 'Numbers (0-9)'], ['symbols', 'Symbols (!@#$)']]
        .forEach(([key, label]) => {
          const box = el('input', { class: 'switch', attrs: { type: 'checkbox' } });
          box.checked = true;
          opts[key] = box;
          toggles.appendChild(el('label', { class: 'row' }, [
            el('div', { class: 'row-meta' }, [el('span', { class: 'row-title', text: label })]),
            box,
          ]));
          box.addEventListener('change', () => regenerate());
        });

      const entropyLabel = el('span', { class: 'stat-value', text: '0' });
      const strengthLabel = el('span', { class: 'stat-value', text: '—' });

      const regenerate = () => {
        const length = parseInt(slider.value, 10);
        const u = opts.upper.checked, l = opts.lower.checked, n = opts.numbers.checked, s = opts.symbols.checked;

        if (!u && !l && !n && !s) {
          opts.lower.checked = true;
          return regenerate();
        }

        output.textContent = CryptoEngine.generatePassword(length, u, l, n, s);

        let pool = 0;
        if (u) pool += 26;
        if (l) pool += 26;
        if (n) pool += 10;
        if (s) pool += 28;
        const entropy = Math.round(length * Math.log2(pool || 26));
        entropyLabel.textContent = `${entropy}`;
        strengthLabel.textContent =
          entropy >= 128 ? 'Excellent' : entropy >= 80 ? 'Very Strong' : entropy >= 60 ? 'Strong'
          : entropy >= 40 ? 'Moderate' : entropy >= 28 ? 'Weak' : 'Very Weak';
      };

      slider.addEventListener('input', () => { lengthValue.textContent = slider.value; regenerate(); });

      body.append(
        output,
        el('div', { class: 'input-row', style: 'gap:10px;' }, [
          el('button', { class: 'btn btn-ghost', style: 'flex:1;', text: 'Regenerate', on: { click: regenerate } }),
          el('button', { class: 'btn btn-primary', style: 'flex:1;', text: 'Copy', on: { click: () => this.copy(output.textContent, 'Password copied') } }),
        ]),
        el('div', { class: 'stat-grid' }, [
          el('div', { class: 'stat-box' }, [el('div', { class: 'stat-label', text: 'Entropy (bits)' }), entropyLabel]),
          el('div', { class: 'stat-box' }, [el('div', { class: 'stat-label', text: 'Strength' }), strengthLabel]),
        ]),
        el('div', { class: 'stat-box' }, [
          el('div', { class: 'slider-row' }, [
            el('span', { class: 'stat-label', style: 'margin:0;', text: 'Length' }),
            lengthValue,
          ]),
          slider,
        ]),
        toggles,
      );

      regenerate();
      this.openSheet({ title: 'Password Generator', body });
    }

    async toolMasking() {
      const body = el('div', { class: 'tool-body' });
      const key = this.getSimpleLoginKey();

      if (!key) {
        body.appendChild(el('div', { class: 'empty' }, [
          el('div', { class: 'empty-icon', html: ICONS.note }),
          el('h3', { text: 'SimpleLogin not connected' }),
          el('p', { text: 'Add your SimpleLogin API key in Settings to create and manage throwaway email aliases here.' }),
          el('button', {
            class: 'btn btn-primary', text: 'Open Settings',
            on: { click: () => { this.closeSheet(); this.switchTab('settings'); } },
          }),
        ]));
        return this.openSheet({ title: 'Email Masking', body });
      }

      const prefixInput = el('input', { attrs: { type: 'text', placeholder: 'e.g. netflix', autocomplete: 'off' } });
      const suffixSelect = el('select', { class: 'select', style: 'width:100%;' });
      suffixSelect.appendChild(el('option', { text: 'Loading…' }));

      const status = el('p', { class: 'row-desc' });
      const list = el('div', { style: 'display:flex; flex-direction:column; gap:10px;' });

      const createBtn = el('button', {
        class: 'btn btn-primary btn-block', text: 'Create Alias',
        on: {
          click: async () => {
            const prefix = prefixInput.value.trim();
            const suffix = suffixSelect.value;
            if (!prefix || !suffix) return this.toast('Enter a prefix and pick a domain.');

            createBtn.disabled = true;
            createBtn.textContent = 'Creating…';
            try {
              const res = await SimpleLoginClient.createCustomAlias(key, prefix, suffix, 'Created in CipherVault');
              this.toast(`Created ${res.alias}`);
              prefixInput.value = '';
              loadAliases();
            } catch (err) {
              status.textContent = err.message;
            } finally {
              createBtn.disabled = false;
              createBtn.textContent = 'Create Alias';
            }
          },
        },
      });

      const loadAliases = async () => {
        list.innerHTML = '';
        list.appendChild(el('p', { class: 'row-desc', text: 'Loading aliases…' }));
        const aliases = await SimpleLoginClient.fetchAliases(key);
        list.innerHTML = '';

        if (aliases.length === 0) {
          list.appendChild(el('p', { class: 'row-desc', text: 'No aliases yet.' }));
          return;
        }

        aliases.forEach((a) => {
          list.appendChild(el('div', { class: 'result-row', on: { click: () => this.copy(a.email, 'Alias copied') } }, [
            el('div', { class: 'row-meta' }, [
              el('span', { class: 'row-title', text: a.email }),
              el('span', { class: 'row-desc', text: `${a.nb_email_received || 0} received · tap to copy` }),
            ]),
            el('button', {
              class: 'mini-btn', text: 'Delete',
              on: {
                click: async (e) => {
                  e.stopPropagation();
                  const ok = await this.confirm({
                    title: 'Delete alias?', body: `${a.email} will stop forwarding mail.`,
                    confirmLabel: 'Delete', danger: true,
                  });
                  if (!ok) return;
                  if (await SimpleLoginClient.deleteAlias(key, a.id)) { this.toast('Alias deleted.'); loadAliases(); }
                  else this.toast('Could not delete alias.');
                },
              },
            }),
          ]));
        });
      };

      body.append(
        el('div', { class: 'field' }, [el('label', { text: 'Alias prefix' }), prefixInput]),
        el('div', { class: 'field' }, [el('label', { text: 'Domain' }), suffixSelect]),
        createBtn,
        status,
        el('div', { class: 'section-label', text: 'Your aliases' }),
        list,
      );

      this.openSheet({ title: 'Email Masking', body });

      try {
        const options = await SimpleLoginClient.fetchAliasOptions(key);
        suffixSelect.innerHTML = '';
        (options.suffixes || []).forEach((s) => {
          const opt = el('option', { text: s.suffix });
          opt.value = s.signed_suffix;
          suffixSelect.appendChild(opt);
        });
        if (options.prefix_suggestion) prefixInput.value = options.prefix_suggestion;
      } catch (err) {
        suffixSelect.innerHTML = '';
        suffixSelect.appendChild(el('option', { text: 'Could not load domains' }));
        status.textContent = 'Check your SimpleLogin API key in Settings.';
      }

      loadAliases();
    }

    toolHealth() {
      const analysis = PasswordHealthEngine.analyzeVault(this.decryptedVault);
      const body = el('div', { class: 'tool-body' });

      body.appendChild(el('div', { class: 'stat-grid' }, [
        el('div', { class: 'stat-box' }, [
          el('div', { class: 'stat-label', text: 'Weak' }),
          el('div', { class: 'stat-value', text: String(analysis.weakCount) }),
        ]),
        el('div', { class: 'stat-box' }, [
          el('div', { class: 'stat-label', text: 'Reused groups' }),
          el('div', { class: 'stat-value', text: String(analysis.reusedGroups) }),
        ]),
      ]));

      const seen = new Set();
      const attention = [];
      [...analysis.weakItems, ...analysis.reusedItems].forEach((i) => {
        if (!seen.has(i.id)) { seen.add(i.id); attention.push(i); }
      });

      body.appendChild(el('div', { class: 'section-label', text: `Needs attention (${attention.length})` }));

      if (attention.length === 0) {
        body.appendChild(el('div', { class: 'empty' }, [
          el('div', { class: 'empty-icon', html: ICONS.check, style: 'color: var(--ok);' }),
          el('h3', { text: 'All clear' }),
          el('p', { text: 'No weak or reused passwords found in your vault.' }),
        ]));
      } else {
        attention.forEach((item) => {
          const problems = [];
          if (analysis.weakItems.some((i) => i.id === item.id)) problems.push(['Weak', 'pill-weak']);
          if (analysis.reusedItems.some((i) => i.id === item.id)) problems.push(['Reused', 'pill-reused']);

          body.appendChild(el('div', {
            class: 'result-row',
            on: { click: () => { this.closeSheet(); this.openDetail(item); } },
          }, [
            el('div', { class: 'row-meta' }, [
              el('span', { class: 'row-title', text: item.data.name || 'Untitled' }),
              el('span', { class: 'row-desc', text: item.data.username || '' }),
            ]),
            el('div', { style: 'display:flex; gap:6px;' }, problems.map(([t, c]) => el('span', { class: `pill ${c}`, text: t }))),
          ]));
        });
      }

      this.openSheet({ title: 'Password Health', body });
    }

    toolBreach() {
      const body = el('div', { class: 'tool-body' });
      const status = el('p', { class: 'row-desc', text: 'Only the first 5 characters of each password hash are sent, so HaveIBeenPwned never learns your passwords.' });
      const results = el('div', { style: 'display:flex; flex-direction:column; gap:10px;' });
      const progress = el('div', { class: 'progress-track hidden' }, [el('div', { class: 'progress-fill' })]);

      const scanBtn = el('button', {
        class: 'btn btn-primary btn-block', text: 'Start Scan',
        on: {
          click: async () => {
            const logins = this.decryptedVault.filter(
              (i) => !i.isTrashed && (i.type === 'login' || i.type === 'passwords') && i.data.password
            );

            if (logins.length === 0) {
              status.textContent = 'No logins with passwords to scan.';
              return;
            }

            scanBtn.disabled = true;
            scanBtn.textContent = 'Scanning…';
            results.innerHTML = '';
            progress.classList.remove('hidden');

            const bar = progress.querySelector('.progress-fill');
            const cache = new Map();
            const breached = [];
            let errors = 0;

            for (let i = 0; i < logins.length; i++) {
              const item = logins[i];
              const pw = item.data.password;

              let count;
              if (cache.has(pw)) count = cache.get(pw);
              else {
                count = await BreachScannerEngine.checkPassword(pw);
                cache.set(pw, count);
                await new Promise((r) => setTimeout(r, 60));
              }

              // -1 means the lookup itself failed; that is not a breach.
              if (count === -1) errors++;
              else if (count > 0) breached.push({ item, count });

              bar.style.width = `${Math.round(((i + 1) / logins.length) * 100)}%`;
              status.textContent = `Checked ${i + 1} of ${logins.length}…`;
            }

            progress.classList.add('hidden');
            scanBtn.disabled = false;
            scanBtn.textContent = 'Scan Again';
            status.textContent =
              `Found ${breached.length} breached password(s) across ${logins.length} login(s).` +
              (errors ? ` ${errors} could not be checked (no connection).` : '');

            if (breached.length === 0) {
              results.appendChild(el('div', { class: 'empty' }, [
                el('div', { class: 'empty-icon', html: ICONS.check, style: 'color: var(--ok);' }),
                el('h3', { text: 'Nothing breached' }),
                el('p', { text: 'None of your passwords appear in known breach data.' }),
              ]));
              return;
            }

            breached.forEach(({ item, count }) => {
              results.appendChild(el('div', {
                class: 'result-row',
                on: { click: () => { this.closeSheet(); this.openDetail(item); } },
              }, [
                el('div', { class: 'row-meta' }, [
                  el('span', { class: 'row-title', text: item.data.name || 'Untitled' }),
                  el('span', { class: 'row-desc', text: `Seen ${count.toLocaleString()} times in breaches` }),
                ]),
                el('span', { class: 'pill pill-breached', text: 'Breached' }),
              ]));
            });
          },
        },
      });

      body.append(scanBtn, progress, status, results);
      this.openSheet({ title: 'Breach Scanner', body });
    }

    // ------------------------------------------------------------ settings

    bindSettings() {
      $('set-btn-account').addEventListener('click', async () => {
        if (this.firebaseUser) {
          const ok = await this.confirm({
            title: 'Sign out?',
            body: 'Your encrypted vault stays safe in the cloud. You will need to sign in and unlock again.',
            confirmLabel: 'Sign out',
          });
          if (!ok) return;
          await this.disableBiometrics({ silent: true });
          localStorage.removeItem('cv:biometric:offered');
          await FirebaseSyncEngine.logout();
          StorageController.setLocalChoice(false);
          this.lock({ silent: true });
        } else {
          this.lock({ silent: true });
          this.showLockPane('signin-pane');
        }
      });

      $('set-btn-check-updates').addEventListener('click', () => this.checkUpdates({ silent: false }));

      const bioToggle = $('set-biometric');
      bioToggle.addEventListener('change', async () => {
        if (bioToggle.checked) {
          // Re-prove the master password before sealing it: the vault may have
          // been unlocked for a while, and this is the moment it gets stored.
          const password = await this.askForText({
            title: 'Confirm master password',
            body: 'Your master password is sealed behind your fingerprint. It is never stored in readable form.',
            label: 'Master password',
            confirmLabel: 'Enable',
          });
          if (!password) { bioToggle.checked = false; return; }

          const check = await CryptoEngine.unlock(
            password,
            StorageController.getSalt(),
            StorageController.getMasterHash(),
            StorageController.getKdf()
          );
          if (!check.ok) {
            bioToggle.checked = false;
            this.toast('That is not your master password.');
            return;
          }

          const enabled = await this.enableBiometrics(password);
          bioToggle.checked = enabled;
        } else {
          await this.disableBiometrics();
        }
      });

      $('set-btn-export').addEventListener('click', () => this.exportVault());
      $('set-btn-import').addEventListener('click', () => this.triggerImport());
      $('import-file-input').addEventListener('change', (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) this.importVaultFile(file);
        e.target.value = '';
      });

      const autoBox = $('set-auto-update');
      autoBox.checked = UpdateStorage.getAutoCheck();
      autoBox.addEventListener('change', () => {
        UpdateStorage.setAutoCheck(autoBox.checked);
        this.toast(autoBox.checked ? 'Automatic update checks on.' : 'Automatic update checks off.');
      });

      const autoLock = $('set-auto-lock');
      autoLock.value = StorageController.getAutoLockMinutes();
      autoLock.addEventListener('change', () => {
        StorageController.setAutoLockMinutes(autoLock.value);
        this.resetIdleTimer();
        this.toast(autoLock.value === 'never' ? 'Auto-lock disabled.' : `Auto-locks after ${autoLock.value} min idle.`);
      });

      const lockBg = $('set-lock-on-background');
      lockBg.checked = this.lockOnBackground();
      lockBg.addEventListener('change', () => {
        localStorage.setItem('cv:lock_on_background', lockBg.checked ? 'true' : 'false');
        this.toast(lockBg.checked ? 'Will lock when you leave the app.' : 'Stays unlocked in the background.');
      });

      const clip = $('set-clipboard');
      clip.value = StorageController.getClipboardDelay();
      clip.addEventListener('change', () => {
        StorageController.setClipboardDelay(clip.value);
        this.toast(clip.value === 'never' ? 'Clipboard will not be cleared.' : `Clipboard clears after ${clip.value}s.`);
      });

      $('set-btn-save-sl').addEventListener('click', async () => {
        await this.saveSimpleLoginKey($('set-sl-key').value.trim());
      });

      $('set-btn-destroy').addEventListener('click', async () => {
        const who = this.firebaseUser
          ? `the vault for ${this.firebaseUser.email}, on this phone AND in the cloud`
          : "this phone's offline vault";
        const ok = await this.confirm({
          title: 'Delete everything?',
          body: `This permanently destroys ${who}. Every stored secret is deleted and cannot be recovered.`,
          confirmLabel: 'Delete everything',
          danger: true,
        });
        if (!ok) return;

        StorageController.wipeScope();
        await this.disableBiometrics({ silent: true });
        if (this.currentUid) {
          try { await FirebaseSyncEngine.deleteVault(this.currentUid); }
          catch (err) { this.toast(this.syncErrorText(err)); }
        }
        this.aesKey = null;
        this.decryptedVault = [];
        this.folders = [];
        this.lock({ silent: true });
        this.toast('Vault destroyed.');
      });
    }

    // ------------------------------------------------------ import / export

    /**
     * Exports the decrypted vault as JSON and hands it to the Android share
     * sheet, so the user picks where it lands (Drive, email, Files…).
     *
     * The export is deliberately plaintext for portability into other password
     * managers, which is exactly why it asks first in blunt terms.
     */
    async exportVault() {
      if (!this.aesKey) return this.toast('Unlock your vault first.');

      const count = this.decryptedVault.length;
      const ok = await this.confirm({
        title: 'Export is not encrypted',
        body: `The backup will contain all ${count} item(s) — passwords, notes and card numbers — as plain readable text. Anyone who opens the file can read everything. Save it somewhere safe and delete it when you're done.`,
        confirmLabel: 'Export anyway',
        danger: true,
      });
      if (!ok) return;

      const payload = JSON.stringify({
        exportedAt: new Date().toISOString(),
        version: '2.0.0',
        encrypted: false,
        source: 'ciphervault-android',
        folders: this.folders,
        items: this.decryptedVault,
      }, null, 2);

      const filename = `ciphervault-export-${new Date().toISOString().slice(0, 10)}.json`;

      if (!isNative || !CapPlugins.Filesystem) {
        // Browser fallback so this is testable outside the APK.
        const url = URL.createObjectURL(new Blob([payload], { type: 'application/json' }));
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
        this.toast('Backup downloaded.');
        return;
      }

      try {
        // Cache, not Documents: the file is a transient hand-off to the share
        // sheet and should not linger in a user-visible folder.
        const written = await CapPlugins.Filesystem.writeFile({
          path: filename,
          data: payload,
          directory: 'CACHE',
          encoding: 'utf8',
        });

        if (CapPlugins.Share) {
          await CapPlugins.Share.share({
            title: 'CipherVault backup',
            text: 'CipherVault vault export (unencrypted)',
            url: written.uri,
            dialogTitle: 'Save your CipherVault backup',
          });
        }
        this.toast(`Exported ${count} item(s).`);
      } catch (err) {
        // The user dismissing the share sheet surfaces as an error too.
        if (err && /cancel/i.test(err.message || '')) return;
        console.error('Export failed:', err);
        this.toast('Export failed: ' + ((err && err.message) || 'unknown error'));
      }
    }

    /** Opens the system file picker. The WebView handles this natively. */
    triggerImport() {
      if (!this.aesKey) return this.toast('Unlock your vault first.');
      const input = $('import-file-input');
      input.value = '';
      input.click();
    }

    async importVaultFile(file) {
      if (!file || !this.aesKey) return;

      let parsed;
      try {
        parsed = JSON.parse(await file.text());
      } catch (err) {
        return this.dialog({
          title: "Couldn't read that file",
          icon: ICONS.warn,
          body: 'It does not look like valid JSON. Pick a file exported from CipherVault.',
          actions: [{ label: 'OK', style: 'btn-primary' }],
        });
      }

      const incoming = Array.isArray(parsed) ? parsed : (parsed.items || []);
      const usable = incoming.filter((i) => i && i.data && i.data.name);

      if (usable.length === 0) {
        return this.dialog({
          title: 'Nothing to import',
          icon: ICONS.warn,
          body: 'No vault items were found in that file.',
          actions: [{ label: 'OK', style: 'btn-primary' }],
        });
      }

      const incomingFolders = Array.isArray(parsed.folders) ? parsed.folders : [];
      const ok = await this.confirm({
        title: `Import ${usable.length} item(s)?`,
        body: 'These are added alongside what you already have — nothing is overwritten or removed. Duplicates are possible if you import the same file twice.',
        confirmLabel: 'Import',
      });
      if (!ok) return;

      // Bring folders across first so folderId references still resolve.
      const knownFolders = new Set(this.folders.map((f) => f.id));
      incomingFolders.forEach((f) => {
        if (f && f.id && f.name && !knownFolders.has(f.id)) {
          this.folders.push({ id: f.id, name: f.name });
          knownFolders.add(f.id);
        }
      });

      usable.forEach((item) => {
        const data = Object.assign({}, item.data);
        if (data.folderId && !knownFolders.has(data.folderId)) data.folderId = '';

        this.decryptedVault.push({
          id: 'item_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
          type: item.type || 'login',
          isFavorite: !!item.isFavorite,
          isTrashed: !!item.isTrashed,
          createdAt: item.createdAt || new Date().toISOString(),
          data,
        });
      });

      // saveFolders persists the (possibly extended) folder list and then
      // saves the vault, so imported folders are not silently dropped.
      await this.saveFolders();
      this.renderVault();
      this.toast(`Imported ${usable.length} item(s).`);
    }

    refreshSettings() {
      $('set-account-email').textContent = this.firebaseUser ? this.firebaseUser.email : 'Not signed in (this device only)';
      $('set-account-action').textContent = this.firebaseUser ? 'Sign Out' : 'Sign In';
      $('set-sl-key').value = this.getSimpleLoginKey();
      $('set-auto-lock').value = StorageController.getAutoLockMinutes();
      $('set-clipboard').value = StorageController.getClipboardDelay();
      this.refreshBiometricState();
    }

    async refreshVersionLabels() {
      const info = await this.updater.getInstalledInfo();
      const text = info.build ? `v${info.version} (build ${info.build})` : `v${info.version}`;
      $('set-app-version').textContent = info.native ? text : `${text} — running in a browser`;
      $('about-build').textContent = `v${info.version}`;
    }

    // ------------------------------------------------------------- updates

    async checkUpdates({ silent = true } = {}) {
      const statusLine = $('set-update-status');

      if (!silent) {
        statusLine.textContent = 'Checking GitHub…';
        $('set-btn-check-updates').disabled = true;
      }

      const result = await this.updater.check({ force: !silent });

      if (!silent) $('set-btn-check-updates').disabled = false;

      switch (result.status) {
        case 'update-available':
          if (!silent) statusLine.textContent = `Version ${result.latestVersion} is available.`;
          this.showUpdateDialog(result);
          return;

        case 'up-to-date':
          if (!silent) {
            statusLine.textContent = `You're on the latest version (v${result.installedVersion}).`;
            this.toast('CipherVault is up to date.');
          }
          return;

        case 'no-release':
          if (!silent) {
            statusLine.textContent = 'No releases published yet.';
            this.dialog({
              title: 'No releases yet',
              icon: ICONS.download,
              body: 'There are no published releases on GitHub for CipherVault yet, or the repository is private. Once a release is tagged, updates will appear here.',
              actions: [{ label: 'OK', style: 'btn-primary' }],
            });
          }
          return;

        case 'no-asset':
          if (!silent) statusLine.textContent = result.message;
          return;

        case 'skipped':
          return;

        case 'throttled':
          if (!silent) statusLine.textContent = 'Checked very recently.';
          return;

        default:
          if (!silent) {
            statusLine.textContent = result.message || 'Could not check for updates.';
            this.toast(result.message || 'Update check failed.');
          }
      }
    }

    showUpdateDialog(info) {
      const body = el('div');
      body.appendChild(el('p', {
        html: `<strong>Version ${info.latestVersion}</strong> is available. You have v${info.installedVersion}.`,
      }));

      const size = UpdateManager.formatSize(info.sizeBytes);
      if (size) body.appendChild(el('p', { class: 'row-desc', style: 'margin-top:6px;', text: `Download size: ${size}` }));

      if (info.notes) {
        body.appendChild(el('div', { class: 'release-notes', text: info.notes }));
      }

      this.dialog({
        title: 'Update Available',
        icon: ICONS.download,
        body,
        dismissible: true,
        actions: [
          { label: 'Download & Install', style: 'btn-primary', keepOpen: true, onClick: () => this.runUpdate(info) },
          { label: 'Later', style: 'btn-ghost' },
          {
            label: `Skip v${info.latestVersion}`,
            style: 'btn-ghost',
            onClick: () => {
              UpdateStorage.setSkipped(info.latestVersion);
              this.toast(`Skipping version ${info.latestVersion}.`);
            },
          },
        ],
      });
    }

    async runUpdate(info) {
      if (!this.updater.isNative) {
        window.open(info.downloadUrl, '_blank');
        this.closeDialog();
        return;
      }

      // Android will not let an app install packages without explicit consent.
      if (!(await this.updater.canInstallPackages())) {
        this.dialog({
          title: 'Permission needed',
          icon: ICONS.warn,
          body: 'Android needs your permission for CipherVault to install app updates. Enable "Allow from this source", then come back and tap Download again.',
          actions: [
            { label: 'Open Settings', style: 'btn-primary', onClick: () => this.updater.openInstallPermissionSettings() },
            { label: 'Cancel', style: 'btn-ghost' },
          ],
        });
        return;
      }

      this.dialog({
        title: `Downloading v${info.latestVersion}`,
        icon: ICONS.download,
        body: 'Keep CipherVault open until the installer appears.',
        progress: true,
        dismissible: false,
        actions: [],
      });

      try {
        await this.updater.downloadAndInstall(info.downloadUrl, (percent) => this.setDialogProgress(percent));
        this.closeDialog();
        this.toast('Opening installer…');
      } catch (err) {
        console.error('Update failed:', err);
        this.dialog({
          title: 'Update failed',
          icon: ICONS.warn,
          body: (err && err.message) || 'The download could not be completed. Check your connection and try again.',
          actions: [
            { label: 'Try Again', style: 'btn-primary', onClick: () => this.runUpdate(info) },
            { label: 'Close', style: 'btn-ghost' },
          ],
        });
      }
    }
  }

  function boot() {
    const instance = new MobileApp();
    window.CipherVault = {
      app: instance,
      CryptoEngine,
      TOTPEngine,
      StorageController,
      FirebaseSyncEngine,
      PasswordHealthEngine,
      SimpleLoginClient,
      BreachScannerEngine,
      LinkSessionEngine,
    };
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
