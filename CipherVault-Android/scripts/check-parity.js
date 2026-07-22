#!/usr/bin/env node
/**
 * Verifies that every platform derives keys the same way.
 *
 * The desktop, the browser extension and the Android app each ship their own
 * copy of the crypto engine. They are generated from one source, but a bad
 * merge or a hand-edit to a generated file would not necessarily show up as a
 * test failure anywhere else - it would show up as a user unable to open their
 * vault on one device. This asserts the constants agree.
 *
 * Run: node scripts/check-parity.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');

const TARGETS = {
  desktop: 'CipherVault/js/app.js',
  'desktop-build': 'CipherVault-Desktop/js/app.js',
  android: 'CipherVault-Android/www/js/core.js',
  extension: 'CipherVault-Extension/js/crypto.js',
};

// Constants that MUST be identical everywhere.
const CONSTANTS = ['KDF_VERSION', 'DEFAULT_ITERATIONS', 'LEGACY_ITERATIONS'];

// Algorithm choices that must also match, checked as literal substrings.
const INVARIANTS = [
  { name: 'PBKDF2 hash', needle: "hash: \"SHA-256\"" },
  { name: 'AES-GCM cipher', needle: 'name: "AES-GCM"' },
  { name: '512-bit derive', needle: '512' },
];

function readTarget(rel) {
  const full = path.join(ROOT, rel);
  if (!fs.existsSync(full)) throw new Error(`Missing file: ${rel}`);
  return fs.readFileSync(full, 'utf8');
}

function extractConstant(source, name) {
  const match = source.match(new RegExp(`${name}\\s*=\\s*(\\d+)`));
  return match ? match[1] : null;
}

function main() {
  const sources = {};
  for (const [label, rel] of Object.entries(TARGETS)) sources[label] = readTarget(rel);

  let failed = false;

  for (const constant of CONSTANTS) {
    const found = Object.entries(sources).map(([label, src]) => [label, extractConstant(src, constant)]);

    const missing = found.filter(([, v]) => v === null);
    if (missing.length) {
      console.error(`FAIL  ${constant} not found in: ${missing.map(([l]) => l).join(', ')}`);
      failed = true;
      continue;
    }

    const unique = new Set(found.map(([, v]) => v));
    if (unique.size !== 1) {
      console.error(`FAIL  ${constant} differs: ${found.map(([l, v]) => `${l}=${v}`).join('  ')}`);
      failed = true;
    } else {
      console.log(`ok    ${constant} = ${found[0][1]} in all ${found.length} copies`);
    }
  }

  for (const { name, needle } of INVARIANTS) {
    const missing = Object.entries(sources).filter(([, src]) => !src.includes(needle)).map(([l]) => l);
    if (missing.length) {
      console.error(`FAIL  ${name} ("${needle}") missing from: ${missing.join(', ')}`);
      failed = true;
    } else {
      console.log(`ok    ${name} present everywhere`);
    }
  }

  if (failed) {
    console.error('\nKey derivation has diverged between platforms.');
    console.error('A vault encrypted on one device will not open on another.');
    console.error('Fix CipherVault/js/app.js, then: cd CipherVault-Android && npm run sync:core');
    process.exit(1);
  }

  console.log('\nAll platforms derive keys identically.');
}

main();
