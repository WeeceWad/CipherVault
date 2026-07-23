const { app, BrowserWindow, protocol, net, shell, ipcMain } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');
const { autoUpdater } = require('electron-updater');

/**
 * The renderer is NOT loaded with `win.loadFile()` any more.
 *
 * `loadFile` gives the page a `file://` origin, which browsers treat as opaque.
 * Firebase Auth refuses to run there (it needs a real, secure origin for its
 * IndexedDB session store) and Firestore's requests get rejected because they
 * are sent with `Origin: null`. That is why the desktop build could never log
 * in or sync.
 *
 * Instead we register a private `ciphervault://` scheme as standard + secure
 * and serve the same files over it. The page then has a stable, secure origin
 * (`ciphervault://app`) so localStorage, IndexedDB and Firebase all behave
 * exactly as they do in the browser build. The origin never changes between
 * launches, so a vault saved today is still there tomorrow.
 */
const APP_SCHEME = 'ciphervault';
const APP_HOST = 'app';
const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;
const ROOT = __dirname;

protocol.registerSchemesAsPrivileged([
  {
    scheme: APP_SCHEME,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
      corsEnabled: true,
      stream: true,
    },
  },
]);

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
};

// Everything the app legitimately talks to. Anything else is blocked.
const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' data: https://fonts.gstatic.com",
  "img-src 'self' data: https://www.google.com https://*.gstatic.com",
  [
    "connect-src 'self'",
    'https://identitytoolkit.googleapis.com',
    'https://securetoken.googleapis.com',
    'https://firestore.googleapis.com',
    'https://*.googleapis.com',
    'https://app.simplelogin.io',
    'https://api.pwnedpasswords.com',
  ].join(' '),
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ');

function registerAppProtocol() {
  protocol.handle(APP_SCHEME, async (request) => {
    const requestUrl = new URL(request.url);

    if (requestUrl.host !== APP_HOST) {
      return new Response('Not found', { status: 404 });
    }

    const relativePath = decodeURIComponent(
      requestUrl.pathname === '/' ? '/index.html' : requestUrl.pathname
    );
    const filePath = path.normalize(path.join(ROOT, relativePath));

    // Never serve anything outside the app directory.
    if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
      return new Response('Forbidden', { status: 403 });
    }

    try {
      const fileResponse = await net.fetch(pathToFileURL(filePath).toString());
      if (!fileResponse.ok) {
        return new Response('Not found', { status: 404 });
      }

      const headers = new Headers();
      headers.set(
        'Content-Type',
        MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream'
      );
      headers.set('Content-Security-Policy', CONTENT_SECURITY_POLICY);
      headers.set('X-Content-Type-Options', 'nosniff');

      return new Response(fileResponse.body, { status: 200, headers });
    } catch (err) {
      console.error('Failed to serve', filePath, err);
      return new Response('Not found', { status: 404 });
    }
  });
}

/**
 * Auto-update from GitHub Releases.
 *
 * electron-updater reads `latest.yml` from the release published by the
 * release workflow, checks the installer's hash against it, and hands the NSIS
 * package to Windows. Downloading is never automatic: the renderer asks, so an
 * update can't start pulling ~100 MB while somebody is mid-task, and an
 * unlocked vault is never quit out from under the user.
 */
function setupAutoUpdater() {
  // Registered once for the process: ipcMain.handle throws on a duplicate
  // channel, and createWindow can run again (macOS dock activate).
  if (!app.isPackaged) {
    ipcMain.handle('update:check', async () => ({
      status: 'dev',
      message: 'Updates are only available in the installed app.',
    }));
    ipcMain.handle('update:download', async () => ({ status: 'dev' }));
    ipcMain.handle('update:install', async () => ({ status: 'dev' }));
    return;
  }

  autoUpdater.autoDownload = false;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.logger = null;

  // Resolved at emit time rather than captured, so events still reach the
  // window even if it was recreated after this ran.
  const send = (name, payload) => {
    const target = BrowserWindow.getAllWindows()[0];
    if (target && !target.isDestroyed()) target.webContents.send(`update:${name}`, payload);
  };

  autoUpdater.on('checking-for-update', () => send('checking', {}));
  autoUpdater.on('update-available', (info) => send('available', {
    version: info.version,
    notes: typeof info.releaseNotes === 'string' ? info.releaseNotes : '',
    date: info.releaseDate,
  }));
  autoUpdater.on('update-not-available', (info) => send('not-available', { version: info.version }));
  autoUpdater.on('download-progress', (p) => send('progress', {
    percent: Math.round(p.percent || 0),
    transferred: p.transferred,
    total: p.total,
  }));
  autoUpdater.on('update-downloaded', (info) => send('downloaded', { version: info.version }));
  autoUpdater.on('error', (err) => send('error', {
    message: (err && err.message) || 'Update failed.',
  }));

  ipcMain.handle('update:check', async () => {
    try {
      const result = await autoUpdater.checkForUpdates();
      if (!result || !result.updateInfo) return { status: 'up-to-date' };

      const latest = result.updateInfo.version;
      if (latest === app.getVersion()) return { status: 'up-to-date', version: latest };

      return {
        status: 'available',
        version: latest,
        notes: typeof result.updateInfo.releaseNotes === 'string' ? result.updateInfo.releaseNotes : '',
      };
    } catch (err) {
      return { status: 'error', message: (err && err.message) || 'Could not reach GitHub.' };
    }
  });

  ipcMain.handle('update:download', async () => {
    try {
      await autoUpdater.downloadUpdate();
      return { status: 'downloading' };
    } catch (err) {
      return { status: 'error', message: (err && err.message) || 'Download failed.' };
    }
  });

  ipcMain.handle('update:install', async () => {
    // isSilent false so the user sees the installer; isForceRunAfter true so
    // the app comes back up afterwards.
    setImmediate(() => autoUpdater.quitAndInstall(false, true));
    return { status: 'installing' };
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 940,
    minHeight: 620,
    show: false,
    autoHideMenuBar: true,
    backgroundColor: '#0f172a',
    title: 'CipherVault',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webviewTag: false,
      spellcheck: false,
    },
  });

  win.once('ready-to-show', () => win.show());

  // A blank window with no explanation is the worst possible failure mode for
  // a password manager, so surface load problems on stdout and show the window
  // anyway rather than leaving the user staring at nothing.
  win.webContents.on('did-fail-load', (_e, errorCode, errorDescription, validatedURL) => {
    console.error(`[CipherVault] Failed to load ${validatedURL}: ${errorDescription} (${errorCode})`);
    win.show();
  });

  win.webContents.on('console-message', (_e, level, message, line, sourceId) => {
    if (level >= 2) console.error(`[renderer] ${message} (${sourceId}:${line})`);
  });

  win.webContents.on('render-process-gone', (_e, details) => {
    console.error('[CipherVault] Renderer process gone:', details.reason);
  });

  // Links to the outside world open in the real browser, never in-app.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });

  win.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(APP_ORIGIN)) {
      event.preventDefault();
      if (/^https?:\/\//i.test(url)) shell.openExternal(url);
    }
  });

  win.loadURL(`${APP_ORIGIN}/index.html`);
  return win;
}

// A password manager must not run twice against the same vault storage.
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  let mainWindow = null;

  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  // app.getVersion() reports Electron's own version when running unpackaged,
  // which would show as "v43.2.0" in Settings during development. Prefer the
  // app's declared version and fall back only if that is somehow missing.
  ipcMain.handle('app:get-version', () => {
    try {
      const declared = require('./package.json').version;
      if (declared) return declared;
    } catch (e) { /* packaged asar without package.json access */ }
    return app.getVersion();
  });

  app.whenReady().then(() => {
    registerAppProtocol();
    setupAutoUpdater();
    mainWindow = createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        mainWindow = createWindow();
      }
    });
  });

  app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') app.quit();
  });
}
