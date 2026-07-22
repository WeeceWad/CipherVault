#!/usr/bin/env node
/**
 * Regenerates the shared engine layer from the single source of truth.
 *
 *   source: ../CipherVault/js/app.js   (everything above "MAIN APPLICATION CONTROLLER")
 *   ->      www/js/core.js                     (Android)
 *   ->      ../CipherVault-Extension/js/crypto.js  (browser extension, crypto only)
 *
 * Why this exists: the vault is encrypted on one device and decrypted on
 * another. If Android's PBKDF2 parameters drift from the desktop's by even one
 * iteration, the phone silently cannot open the vault. Generating instead of
 * copy-pasting makes that class of bug impossible.
 *
 * Run `npm run sync:core` after touching CipherVault/js/app.js.
 * CI runs it with --check and fails the build if anything is stale.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const SOURCE = path.join(ROOT, 'CipherVault', 'js', 'app.js');

const CHECK_ONLY = process.argv.includes('--check');

const BANNER = (what) => `/**
 * ${what}
 *
 * GENERATED FILE - DO NOT EDIT.
 * Source: CipherVault/js/app.js
 * Regenerate: cd CipherVault-Android && npm run sync:core
 *
 * Editing this by hand will be silently overwritten, and any drift from the
 * source means a vault encrypted on one device cannot be opened on another.
 */

`;

/** Pulls an inclusive line range out of the source and removes one indent level. */
function extract(source, startMarker, endMarker) {
  const lines = source.split(/\r?\n/);
  const start = lines.findIndex((l) => l.includes(startMarker));
  const end = lines.findIndex((l) => l.includes(endMarker));

  if (start === -1) throw new Error(`Start marker not found: ${startMarker}`);
  if (end === -1) throw new Error(`End marker not found: ${endMarker}`);
  if (end <= start) throw new Error('End marker appears before start marker');

  return lines
    .slice(start, end)
    .map((l) => (l.startsWith('  ') ? l.slice(2) : l))
    .join('\n')
    .replace(/\s+$/, '') + '\n';
}

function writeIfChanged(target, contents, label) {
  const relative = path.relative(ROOT, target);
  const existing = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : null;

  if (existing === contents) {
    console.log(`  up to date  ${relative}`);
    return false;
  }

  if (CHECK_ONLY) {
    console.error(`  STALE       ${relative}`);
    return true;
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, contents);
  console.log(`  written     ${relative}  (${label})`);
  return true;
}

function main() {
  const source = fs.readFileSync(SOURCE, 'utf8');

  // The whole engine layer: crypto, TOTP, Firebase sync, storage, SimpleLogin,
  // breach scanning, password health. Everything except the desktop UI.
  const engines = extract(
    source,
    '// --- CRYPTOGRAPHIC ENGINE',
    '// --- MAIN APPLICATION CONTROLLER ---'
  );

  // The extension only needs to derive keys and decrypt.
  const cryptoOnly = extract(
    source,
    '// --- CRYPTOGRAPHIC ENGINE',
    '// --- FIREBASE CLOUD SYNC ENGINE ---'
  );

  console.log('Syncing shared engine layer from CipherVault/js/app.js');

  let stale = false;
  stale |= writeIfChanged(
    path.join(__dirname, '..', 'www', 'js', 'core.js'),
    BANNER('CipherVault shared engine layer (Android)') + engines,
    'engines'
  );
  stale |= writeIfChanged(
    path.join(ROOT, 'CipherVault-Extension', 'js', 'crypto.js'),
    BANNER('CipherVault Cryptographic Core Engine (browser extension)') + cryptoOnly,
    'crypto only'
  );

  if (CHECK_ONLY && stale) {
    console.error('\nGenerated files are out of date. Run: cd CipherVault-Android && npm run sync:core');
    process.exit(1);
  }

  console.log('Done.');
}

main();
