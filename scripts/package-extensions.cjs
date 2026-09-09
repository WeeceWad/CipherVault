// Run on the GitHub Linux runner; packages only public extension files.
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const source = path.join(root, 'CipherVault-Extension');
for (const browser of ['Chromium', 'Firefox']) {
  const dest = path.join(root, 'dist', `extension-${browser}`);
  fs.mkdirSync(dest, { recursive: true });
  for (const file of ['icons', 'js', 'lib', 'css', 'popup.html']) fs.cpSync(path.join(source, file), path.join(dest, file), { recursive: true });
  const manifest = JSON.parse(fs.readFileSync(path.join(source, 'manifest.json'), 'utf8'));
  if (browser === 'Chromium') { delete manifest.browser_specific_settings; delete manifest.background.scripts; }
  else { delete manifest.background.service_worker; }
  fs.writeFileSync(path.join(dest, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  execFileSync('zip', ['-q', '-r', path.join(root, 'dist', `CipherVault-${browser}.zip`), '.'], { cwd: dest });
  console.log(`Packaged ${browser} ${manifest.version}`);
}
