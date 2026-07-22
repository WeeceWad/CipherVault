/**
 * CipherVault update manager.
 *
 * The app is distributed as a sideloaded APK rather than through the Play
 * Store, so it checks GitHub Releases for itself and installs newer builds.
 *
 *   1. GET /repos/<owner>/<repo>/releases/latest
 *   2. Compare the release tag against the installed versionName
 *   3. If newer, offer it; on accept, the native AppUpdater plugin downloads
 *      the APK and hands it to Android's package installer
 *
 * The repository must be public for this to work. Release assets on a private
 * repo require an Authorization header, and any token shipped inside an APK
 * can be extracted by anyone holding that APK.
 */

const UPDATE_CONFIG = {
  owner: 'WeeceWad',
  repo: 'CipherVault',
  // Asset picked from the release. First match wins.
  assetPattern: /\.apk$/i,
  // Don't hit the API more than this often for background checks.
  minCheckIntervalMs: 6 * 60 * 60 * 1000, // 6 hours
};

const UpdateStorage = {
  KEY_LAST_CHECK: 'cv:update:last_check',
  KEY_SKIPPED: 'cv:update:skipped_version',
  KEY_AUTO: 'cv:update:auto_check',

  getLastCheck() { return parseInt(localStorage.getItem(this.KEY_LAST_CHECK) || '0', 10); },
  setLastCheck(ts) { localStorage.setItem(this.KEY_LAST_CHECK, String(ts)); },

  getSkipped() { return localStorage.getItem(this.KEY_SKIPPED) || ''; },
  setSkipped(v) { localStorage.setItem(this.KEY_SKIPPED, v || ''); },

  getAutoCheck() { return localStorage.getItem(this.KEY_AUTO) !== 'false'; },
  setAutoCheck(on) { localStorage.setItem(this.KEY_AUTO, on ? 'true' : 'false'); },
};

class UpdateManager {
  constructor() {
    this.installedVersion = null;
    this.installedBuild = null;
    this._infoPromise = null;
  }

  /** True when running inside the Capacitor Android shell. */
  get isNative() {
    return !!(window.Capacitor && window.Capacitor.isNativePlatform && window.Capacitor.isNativePlatform());
  }

  get plugin() {
    return (window.Capacitor && window.Capacitor.Plugins && window.Capacitor.Plugins.AppUpdater) || null;
  }

  /**
   * Installed version, from the APK itself when native.
   * In a plain browser there is no package, so fall back to the build constant
   * so the UI has something honest to show.
   */
  async getInstalledInfo() {
    if (this._infoPromise) return this._infoPromise;

    this._infoPromise = (async () => {
      if (this.isNative && this.plugin) {
        try {
          const info = await this.plugin.getInfo();
          this.installedVersion = info.version;
          this.installedBuild = info.build;
          return { version: info.version, build: info.build, canInstall: !!info.canInstall, native: true };
        } catch (err) {
          console.error('AppUpdater.getInfo failed:', err);
        }
      }

      const fallback = (window.CIPHERVAULT_BUILD && window.CIPHERVAULT_BUILD.version) || '0.0.0';
      this.installedVersion = fallback;
      return { version: fallback, build: null, canInstall: false, native: false };
    })();

    return this._infoPromise;
  }

  /**
   * Compares dotted version strings.
   * @returns 1 if a > b, -1 if a < b, 0 if equal.
   */
  static compareVersions(a, b) {
    const clean = (v) => String(v || '0').replace(/^v/i, '').split(/[-+]/)[0];
    const pa = clean(a).split('.').map((n) => parseInt(n, 10) || 0);
    const pb = clean(b).split('.').map((n) => parseInt(n, 10) || 0);
    const len = Math.max(pa.length, pb.length);

    for (let i = 0; i < len; i++) {
      const x = pa[i] || 0;
      const y = pb[i] || 0;
      if (x > y) return 1;
      if (x < y) return -1;
    }
    return 0;
  }

  /**
   * Asks GitHub for the latest release.
   *
   * @param {object}  opts
   * @param {boolean} opts.force   ignore the throttle and any skipped version
   * @returns {Promise<{status: string, ...}>}
   *   status is one of: 'update-available' | 'up-to-date' | 'throttled' |
   *   'skipped' | 'no-release' | 'no-asset' | 'error'
   */
  async check({ force = false } = {}) {
    const installed = await this.getInstalledInfo();

    if (!force) {
      const since = Date.now() - UpdateStorage.getLastCheck();
      if (since < UPDATE_CONFIG.minCheckIntervalMs) {
        return { status: 'throttled', installedVersion: installed.version };
      }
    }

    const url = `https://api.github.com/repos/${UPDATE_CONFIG.owner}/${UPDATE_CONFIG.repo}/releases/latest`;

    let release;
    try {
      const res = await fetch(url, {
        headers: { Accept: 'application/vnd.github+json' },
        cache: 'no-store',
      });

      UpdateStorage.setLastCheck(Date.now());

      if (res.status === 404) {
        // No releases published yet, or the repo is private.
        return { status: 'no-release', installedVersion: installed.version };
      }
      if (res.status === 403) {
        return {
          status: 'error',
          installedVersion: installed.version,
          message: 'GitHub rate limit reached. Try again in a little while.',
        };
      }
      if (!res.ok) {
        return {
          status: 'error',
          installedVersion: installed.version,
          message: `GitHub returned ${res.status}.`,
        };
      }

      release = await res.json();
    } catch (err) {
      console.error('Update check failed:', err);
      UpdateStorage.setLastCheck(Date.now());
      return {
        status: 'error',
        installedVersion: installed.version,
        message: 'No connection to GitHub.',
      };
    }

    const latestVersion = String(release.tag_name || '').replace(/^v/i, '');
    if (!latestVersion) {
      return { status: 'no-release', installedVersion: installed.version };
    }

    if (UpdateManager.compareVersions(latestVersion, installed.version) <= 0) {
      return { status: 'up-to-date', installedVersion: installed.version, latestVersion };
    }

    if (!force && UpdateStorage.getSkipped() === latestVersion) {
      return { status: 'skipped', installedVersion: installed.version, latestVersion };
    }

    const asset = (release.assets || []).find((a) => UPDATE_CONFIG.assetPattern.test(a.name || ''));
    if (!asset) {
      return {
        status: 'no-asset',
        installedVersion: installed.version,
        latestVersion,
        message: 'The latest release has no APK attached.',
      };
    }

    return {
      status: 'update-available',
      installedVersion: installed.version,
      latestVersion,
      name: release.name || `v${latestVersion}`,
      notes: (release.body || '').trim(),
      publishedAt: release.published_at,
      downloadUrl: asset.browser_download_url,
      sizeBytes: asset.size || 0,
      assetName: asset.name,
    };
  }

  /** Android 8+ requires explicit consent before an app may install packages. */
  async canInstallPackages() {
    if (!this.isNative || !this.plugin) return false;
    try {
      const res = await this.plugin.canInstallPackages();
      return !!res.granted;
    } catch (err) {
      return false;
    }
  }

  async openInstallPermissionSettings() {
    if (this.plugin) await this.plugin.openInstallPermissionSettings();
  }

  /**
   * Downloads the APK and hands it to Android's installer.
   * @param {string}   url
   * @param {Function} onProgress  receives 0-100
   */
  async downloadAndInstall(url, onProgress) {
    if (!this.isNative || !this.plugin) {
      // In a browser there is nothing to install; just open the download.
      window.open(url, '_blank');
      return { opened: true };
    }

    let listener = null;
    if (typeof onProgress === 'function') {
      listener = await this.plugin.addListener('downloadProgress', (ev) => {
        onProgress(Math.max(0, Math.min(100, Math.round(ev.percent || 0))));
      });
    }

    try {
      const result = await this.plugin.downloadAndInstall({ url });
      return result;
    } finally {
      if (listener && typeof listener.remove === 'function') listener.remove();
    }
  }

  static formatSize(bytes) {
    if (!bytes) return '';
    const mb = bytes / (1024 * 1024);
    return mb >= 1 ? `${mb.toFixed(1)} MB` : `${Math.round(bytes / 1024)} KB`;
  }
}

window.UpdateManager = UpdateManager;
window.UpdateStorage = UpdateStorage;
window.UPDATE_CONFIG = UPDATE_CONFIG;
