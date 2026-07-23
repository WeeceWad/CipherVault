# CipherVault

A zero-knowledge password manager across four platforms, sharing one vault.

**Download:**

| Platform | |
| --- | --- |
| Windows | [CipherVault-Setup.exe](https://github.com/WeeceWad/CipherVault/releases/latest/download/CipherVault-Setup.exe) |
| Android | [CipherVault.apk](https://github.com/WeeceWad/CipherVault/releases/latest/download/CipherVault.apk) |
| Web | https://weecewad.github.io/CipherVault/ |
| Firefox / Chrome | load `CipherVault-Extension/` unpacked (below) |

The desktop and Android apps update themselves from GitHub Releases —
**Settings → Check for Updates**.

---

The four parts:

| Folder | What it is | How you run it |
| --- | --- | --- |
| `CipherVault/` | The web app (deployed to Pages) | `start-web.bat`, or `node _devserver.js web` |
| `CipherVault-Desktop/` | The same app wrapped in Electron | `cd CipherVault-Desktop && npm start` |
| `CipherVault-Extension/` | Firefox/Chrome popup + autofill | Load as a temporary add-on (below) |
| `CipherVault-Android/` | Capacitor app, self-updating from GitHub | See [README-ANDROID.md](README-ANDROID.md) |

## One source of truth

**`CipherVault/js/app.js` is the source of truth for everything
security-relevant.** The other platforms get generated copies, because a vault
encrypted on one device has to decrypt on another byte for byte.

```bash
cd CipherVault-Android
npm run sync:core        # regenerates the Android and extension copies
node scripts/check-parity.js   # asserts every platform derives keys identically
```

That produces:

- `CipherVault-Android/www/js/core.js` — the whole engine layer
- `CipherVault-Extension/js/crypto.js` — crypto only

`CipherVault-Desktop/` is still a manual copy of `CipherVault/` plus `main.js`
and locally bundled Firebase SDKs:

```bash
cp CipherVault/js/app.js CipherVault-Desktop/js/app.js
```

CI runs `sync-core.js --check` and `check-parity.js` on every push and fails
the build if anything has drifted. That check exists because the failure it
prevents is silent: a mismatched iteration count doesn't throw, it just means
your phone can never open your vault again.

---

## 1. Firestore rules

Deployed and verified: unauthenticated reads and writes of `users/{uid}` both
return 403. **Redeploy after any change to `firestore.rules`** — the file in the
repo is not what's live until you publish it.

Paste `firestore.rules` into **Firebase console → Firestore Database → Rules →
Publish**, or:

```bash
firebase deploy --only firestore:rules
```

Then confirm it worked — this should now fail with `permission-denied`:

```bash
curl "https://firestore.googleapis.com/v1/projects/ciphervault-51754/databases/(default)/documents/users/someuid"
```

## 2. Two passwords, and they are not the same thing

This trips everyone up, so the UI now says it explicitly:

- **Account password** — signs you in to Firebase. Resettable by email.
- **Master password** — encrypts the vault. Never leaves your device, never
  sent to any server. **If you lose it, the data is gone.** "Forgot password"
  resets the account password only.

## 3. How a vault gets connected to an account

Storage is namespaced so a vault always belongs to an *account*, not to
whichever browser profile happens to be open:

```
cv:local:*        the offline-only vault ("Continue Locally")
cv:u:<uid>:*      the vault belonging to Firebase user <uid>
```

Flow:

1. Sign in (or create an account).
2. If that account has no vault yet, you're asked to create a master password.
   The salt and verifier are pushed to Firestore **immediately**, so other
   devices can see the vault exists.
3. If you already had an offline vault on this device, you're offered the
   chance to upload it to the account.
4. Every save re-encrypts the whole vault and pushes it up.

Signing out drops the key from memory. Signing in as somebody else switches
namespace, so you are never asked for the wrong account's master password.

## 4. Running the desktop app

```bash
cd CipherVault-Desktop
npm install
npm start
```

To build the Windows installer into `dist/`:

```bash
cd CipherVault-Desktop
npm run build
```

The window is **not** loaded with `file://`. It is served over a private
`ciphervault://app` scheme registered as standard + secure, because Firebase
Auth refuses to run on an opaque `file://` origin — that is why the previous
desktop build could never sign in. The origin is stable across launches, so
localStorage survives.

## 5. Loading the extension in Firefox

1. Go to `about:debugging#/runtime/this-firefox`
2. **Load Temporary Add-on…**
3. Pick `CipherVault-Extension/manifest.json`

(Temporary add-ons are removed when Firefox restarts. For a permanent install
you need a signed `.xpi` from addons.mozilla.org, or Firefox Developer Edition
with `xpinstall.signatures.required` set to `false`.)

In Chrome: `chrome://extensions` → Developer mode → **Load unpacked**.

The extension is a read-only window onto the vault. It signs in to the same
account, downloads the encrypted blob and decrypts it locally. It deliberately
**does not keep your master password between popup sessions** — closing the
popup forgets the key, so you unlock each time you open it.

## 6. Running the tests

```bash
cd CipherVault-Desktop
npm test
```

This boots the real Electron window and drives the real UI: account creation,
master password rules, add/lock/unlock round-trip, wrong-password rejection,
per-account isolation, legacy vault migration, auto-lock, trash filtering, and
the encrypted SimpleLogin key. 61 checks, plus 39 more covering the QR unlock
handshake — including that a captured response cannot be replayed, a different
keypair cannot decrypt it, and tampered ciphertext is rejected.

Cross-platform key derivation:

```bash
cd CipherVault-Android
node scripts/check-parity.js
```

## 7. Security notes

- **Key derivation (v2):** one PBKDF2-SHA256 pass at 600,000 iterations
  produces 512 bits. The first 256 are the AES-256-GCM vault key and are never
  stored; the last 256 are the verifier that gets written to disk and the
  cloud. Checking a guessed master password therefore costs exactly as much as
  deriving the real key.
- **Migration from v1:** older vaults stored a bare `SHA-256(password || salt)`
  — a single unstretched hash, brute-forceable offline at GPU speed by anyone
  who could read the Firestore document (see §1). Those vaults are detected on
  unlock, re-keyed with a fresh salt and re-encrypted automatically. Nothing is
  lost and no action is needed.
- **Auto-lock** defaults to 15 minutes idle (Settings → Security & Automation).
- **What Firebase can see:** your email address, and per vault entry: an opaque
  ciphertext blob, its `type` (login / note / card / …), its favourite and
  trashed flags, and a creation timestamp. Everything with content in it — item
  names, usernames, passwords, notes, card numbers, TOTP secrets, folder names
  and your SimpleLogin key — is inside the encrypted payload.

  So the server can tell **how many** items you have, roughly what kinds, and
  when you created them. It cannot tell what any of them are. Closing that
  metadata gap would mean encrypting the whole vault as one blob, which breaks
  per-item sync; it's a deliberate trade, not an oversight.
- The Firebase `apiKey` in the source is not a secret — it identifies the
  project. Access control is entirely the job of the rules in §1.

### Known limitations

- **Sync is last-write-wins.** Editing the same vault on two devices while both
  are online can lose the earlier edit. There is no merge. This is a data-loss
  risk, not a confidentiality one.
- **Exports are plaintext by design**, so other password managers can read them.
  Both apps say so before writing the file. Delete the file when you're done.
- **The web build is the weakest of the four.** Its code is re-delivered from
  GitHub Pages on every visit, so whoever controls the repo controls the crypto
  running in your browser. The desktop and Android builds are signed artifacts
  you installed once. Prefer them for day-to-day use.
- **`weecewad.github.io` is one origin for all your Pages sites.** Browser
  storage is shared across them, so another project you publish there could read
  CipherVault's stored blob — encrypted, but still. Worth knowing before you
  host something else on that account.
- **Anyone holding your unlocked phone can unlock your computers** via QR.
  Inherent to that feature; the approval prompt is the guard.
- Passkey items store metadata only; they are notes about a passkey, not usable
  WebAuthn credentials.
