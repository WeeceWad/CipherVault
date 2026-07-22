const { app, BrowserWindow, protocol, net, shell } = require('electron');
const path = require('path');
const { pathToFileURL } = require('url');

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

  app.whenReady().then(() => {
    registerAppProtocol();
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
