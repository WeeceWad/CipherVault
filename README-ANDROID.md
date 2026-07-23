# CipherVault for Android

A Capacitor app wrapping the same web UI, with a mobile layout and a
GitHub-powered self-updater.

## Why Capacitor and not native Kotlin

The vault is encrypted on one device and decrypted on another. Android's
WebView exposes the same WebCrypto API the desktop app uses, so PBKDF2 and
AES-GCM run byte-identically — a vault created on the desktop opens on the
phone with no compatibility layer.

A native rewrite would mean reimplementing the key derivation and hoping it
matched. The failure mode there is "my phone won't open my vault", which is the
worst possible bug in a password manager. This removes that risk by
construction.

Everything security-relevant lives in `www/js/core.js`, which is **generated**
from `CipherVault/js/app.js`. `www/js/mobile.js` is presentation only.

```bash
cd CipherVault-Android
npm run sync:core     # regenerate after editing CipherVault/js/app.js
```

CI runs `node scripts/sync-core.js --check` and fails the build if the
generated files have drifted.

## Layout

```
CipherVault-Android/
  www/                 the web app the WebView loads
    index.html
    css/mobile.css
    js/core.js         GENERATED - crypto, storage, sync, health engines
    js/mobile.js       mobile UI controller
    js/updater.js      GitHub release checking
    js/build.js        version stamp, rewritten at release time
    lib/               vendored Firebase SDKs (committed on purpose)
  android/             generated native project
    app/src/main/java/com/ciphervault/app/
      MainActivity.java
      AppUpdaterPlugin.java   downloads + installs APK updates
  scripts/sync-core.js
```

## Design

Three tabs along the bottom:

- **Vault** — search, horizontally scrolling category chips (All, Favourites,
  Logins, Passkeys, Notes, Cards, Identity, Trash), then your folders, then a
  dashed **＋ Folder** chip. A `+` button adds items. Tapping an item opens a
  full-screen detail sheet; secrets are masked until you tap Show.
- **Tools** — Password Generator, Email Masking (SimpleLogin), Password Health,
  Breach Scanner.
- **Settings** — account, updates, biometrics, auto-lock, clipboard,
  integrations, backup, danger zone.

### Folders

Folder chips sit after the fixed categories, each showing how many items it
holds. **Long-press** a folder chip to rename or delete it — deleting keeps the
items and just moves them back to All.

The item editor has a folder picker with an inline **+ New folder…** option, so
you can file something without leaving the editor. Adding an item while viewing
a folder files it there by default.

### Biometric unlock

Off until you turn it on, either from the prompt after your first unlock or
Settings → Biometric Unlock. Enabling asks for your master password again,
because that is the moment it gets sealed.

The master password is encrypted with an AES key in the AndroidKeyStore created
with `setUserAuthenticationRequired(true)`. The key physically cannot decrypt
anything until a biometric prompt has passed — only the ciphertext and IV go
into SharedPreferences, and on their own they are useless even to somebody with
root.

`setInvalidatedByBiometricEnrollment(true)` means the key is destroyed the
moment a new fingerprint or face is enrolled. Somebody adding their own
biometric to your unlocked phone must not thereby gain access to your vault, so
that case falls back to the master password with an explanation rather than
failing mysteriously.

Signing out, switching account, resetting or destroying the vault all forget
the sealed password — it belongs to one account's vault.

### Backup

**Settings → Backup → Export Vault** writes JSON and hands it to the Android
share sheet, so you choose where it lands. **Import from JSON** opens the system
file picker and merges into your existing vault; nothing is overwritten or
removed. Folders come across too, and any item pointing at a folder that isn't
in the file gets its folder cleared rather than dangling.

The export is deliberately **plaintext** so it can be read by other password
managers, which is why it asks first in blunt terms. Delete the file when
you're done with it.

Same monochrome dark palette as the desktop app, with 48dp touch targets, 16px
inputs (anything smaller makes Android zoom the viewport on focus), and safe-area
insets so nothing hides behind a notch or the gesture bar.

## Building locally

Prerequisites: **JDK 21**, Android SDK with platform 36, Node 20+.

Two environment variables on this machine currently point at the wrong place
and will break Gradle:

```
JAVA_HOME    -> ...\Eclipse Adoptium\jdk-17...   should be jdk-21...
ANDROID_HOME -> ...\Android\Sdk\platform-tools   should be ...\Android\Sdk
```

`android/local.properties` (gitignored) pins the SDK path, so `ANDROID_HOME`
only matters for other tooling. `JAVA_HOME` must be JDK 21 or the build fails
with `invalid source release: 21`.

```bash
cd CipherVault-Android
npm install
npm run sync          # regenerate core.js + copy web assets into android/
cd android
./gradlew assembleDebug
# -> app/build/outputs/apk/debug/app-debug.apk
```

The debug build installs alongside the release build — it uses the applicationId
`com.ciphervault.app.debug`, so you can test without losing your real vault.

## Signing

Every update must be signed with the **same** key, or Android refuses to install
it over the existing app. Losing the key means uninstall/reinstall for every
user, which wipes local app data.

Create it once:

```bash
keytool -genkeypair -v -keystore ciphervault.keystore -alias ciphervault -keyalg RSA -keysize 4096 -validity 10000
```

Keep `ciphervault.keystore` and its passwords somewhere safe and off the repo —
`*.keystore`, `*.jks` and `keystore.properties` are all gitignored.

Then base64-encode it for GitHub:

```bash
base64 -w 0 ciphervault.keystore > keystore.base64.txt
```

Add four repository secrets under **Settings → Secrets and variables → Actions**:

| Secret | Value |
| --- | --- |
| `ANDROID_KEYSTORE_BASE64` | contents of `keystore.base64.txt` |
| `ANDROID_KEYSTORE_PASSWORD` | the keystore password |
| `ANDROID_KEY_ALIAS` | `ciphervault` |
| `ANDROID_KEY_PASSWORD` | the key password |

Delete `keystore.base64.txt` afterwards.

For a local release build, put a `keystore.properties` next to `android/`:

```properties
storeFile=ciphervault.keystore
storePassword=...
keyAlias=ciphervault
keyPassword=...
```

The Gradle config only wires up signing when that file exists, so a fresh clone
can still build debug without any secrets.

## Releasing

```bash
git tag v1.0.0
git push origin v1.0.0
```

`.github/workflows/android-release.yml` then:

1. checks the generated engine layer is in sync
2. stamps the version into `www/js/build.js`
3. runs `cap sync android`
4. builds a signed APK with `versionName=1.0.0`, `versionCode=10203`-style
5. verifies the signature with `apksigner`
6. publishes a GitHub Release with the APK attached as `CipherVault.apk`

The asset name is fixed, which is what makes this URL stable:

```
https://github.com/WeeceWad/CipherVault/releases/latest/download/CipherVault.apk
```

Tags must be `vMAJOR.MINOR.PATCH`. The workflow rejects anything else, because
`versionCode` is derived arithmetically from the parts and Android requires it
to increase on every release.

## How updating works

`www/js/updater.js` calls the GitHub API for the latest release and compares its
tag against the installed `versionName`.

- **On launch** — a silent check, throttled to once every 6 hours. If a newer
  version exists, a dialog appears with the release notes, download size, and
  Download / Later / Skip this version.
- **In Settings → Check for Updates** — an immediate check that ignores both the
  throttle and any previously skipped version.

Accepting hands the URL to `AppUpdaterPlugin`, which streams the APK into
app-private storage with a progress bar and passes it to Android's package
installer via FileProvider.

Android 8+ requires explicit consent before an app may install packages. The
first time, the app explains this and offers to open the right settings screen.

**The repository must be public.** Release assets on a private repo need an
`Authorization` header, and a token shipped inside an APK can be extracted by
anyone holding that APK.

Two safeguards in `AppUpdaterPlugin.java`:

- Download URLs and every redirect are checked against a host allowlist
  (`github.com`, `objects.githubusercontent.com`, …) over HTTPS only. Even if
  the web layer were compromised, it cannot be used to install an arbitrary APK.
- A truncated download is deleted rather than handed to the installer.

Signature verification is Android's job: an APK signed with a different key than
the installed app is rejected by the system.

## Security choices specific to Android

- **`FLAG_SECURE`** on the main activity — no screenshots, no screen recording,
  and the app's thumbnail in the recents switcher is blanked. An unlocked vault
  sitting in the app switcher is a real exposure.
- **`allowBackup=false`** plus explicit data-extraction rules. The vault blob is
  encrypted, but Android auto-backup would still copy the salt and master
  password verifier into the user's Google account, weakening an offline attack
  for no benefit — a signed-in vault restores from Firestore anyway.
- **Lock when backgrounded** (Settings, off by default) and idle auto-lock
  (15 minutes by default). Returning from the background after longer than the
  auto-lock window locks immediately.
- **`androidScheme: https`** so the WebView origin is a secure context, which
  WebCrypto requires.

## Not built yet

- **System-wide autofill.** Filling passwords into *other* Android apps needs a
  native `AutofillService`, which is a separate Kotlin component with its own
  bridge to the decrypted vault. Copy-to-clipboard works now, with the same
  auto-clear timer as the desktop.
