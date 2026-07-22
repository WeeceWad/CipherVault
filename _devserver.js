/**
 * Tiny static file server for local testing.
 *
 *   node _devserver.js            -> serves the web app  (CipherVault/)  on 5173
 *   node _devserver.js extension  -> serves the popup    (CipherVault-Extension/) on 5174
 *
 * Only needed for development. The Electron app serves its own files and the
 * extension is loaded by the browser, so neither needs this in normal use.
 */
const http = require('http');
const fs = require('fs');
const path = require('path');

const TARGETS = {
  web: { dir: 'CipherVault', port: 5173, index: 'index.html' },
  extension: { dir: 'CipherVault-Extension', port: 5174, index: 'popup.html' },
};

const target = TARGETS[process.argv[2] || 'web'];
if (!target) {
  console.error('Usage: node _devserver.js [web|extension]');
  process.exit(1);
}

const ROOT = path.join(__dirname, target.dir);

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

http
  .createServer((req, res) => {
    const urlPath = decodeURIComponent(req.url.split('?')[0]);
    const rel = urlPath === '/' ? '/' + target.index : urlPath;
    const filePath = path.normalize(path.join(ROOT, rel));

    if (!filePath.startsWith(ROOT)) {
      res.writeHead(403).end('Forbidden');
      return;
    }

    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found: ' + rel);
        return;
      }
      res.writeHead(200, {
        'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
        'Cache-Control': 'no-store',
      });
      res.end(data);
    });
  })
  .listen(target.port, '127.0.0.1', () => {
    console.log(`Serving ${target.dir} on http://localhost:${target.port}`);
  });
