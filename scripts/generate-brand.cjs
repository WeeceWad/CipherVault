// Rebuild the approved shield/keyhole artwork. Requires sharp (npm install --no-save sharp).
const fs = require('node:fs');
const path = require('node:path');
const sharp = require('sharp');
const root = path.resolve(__dirname, '..');
const mark = 'M12 2C9.5 3.8 6.5 4.7 3 5.5V12C3 17 6.6 20.2 12 23C17.4 20.2 21 17 21 12V5.5C17.5 4.7 14.5 3.8 12 2Z M12 8A2.4 2.4 0 0 0 10.8 12.48L10 17H14L13.2 12.48A2.4 2.4 0 0 0 12 8Z';
const shape = `<path fill="#F8FAFC" fill-rule="evenodd" d="${mark}"/>`;
function svg(background = true, adaptive = false, round = false) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 108 108">${background ? (round ? '<circle cx="54" cy="54" r="54" fill="#1B1E2C"/>' : '<rect width="108" height="108" rx="23" fill="#1B1E2C"/>') : ''}<g transform="translate(${adaptive ? '27 25' : '19 16'}) scale(${adaptive ? '2.25' : '2.9'})">${shape}</g></svg>`;
}
function write(file, data) { const dest = path.join(root, file); fs.mkdirSync(path.dirname(dest), { recursive: true }); fs.writeFileSync(dest, data); }
async function png(file, size, source = svg()) { write(file, await sharp(Buffer.from(source)).resize(size, size).png().toBuffer()); }
(async () => {
  for (const dir of ['CipherVault/icons', 'CipherVault-Desktop/icons', 'CipherVault-Android/www/icons', 'CipherVault-Extension/icons']) {
    write(`${dir}/icon.svg`, svg());
    for (const size of [16, 32, 48, 128, 192, 512]) await png(`${dir}/icon-${size}.png`, size);
  }
  // Windows ICO directory with PNG frames, including the 256px installer frame.
  const sizes = [16, 32, 48, 64, 128, 256];
  const frames = await Promise.all(sizes.map(size => sharp(Buffer.from(svg())).resize(size).png().toBuffer()));
  const header = Buffer.alloc(6 + sizes.length * 16); header.writeUInt16LE(1, 2); header.writeUInt16LE(sizes.length, 4);
  let offset = header.length;
  frames.forEach((frame, i) => { const at = 6 + i * 16; header[at] = header[at + 1] = sizes[i] % 256; header.writeUInt16LE(1, at + 4); header.writeUInt16LE(32, at + 6); header.writeUInt32LE(frame.length, at + 8); header.writeUInt32LE(offset, at + 12); offset += frame.length; });
  write('CipherVault-Desktop/icons/icon.ico', Buffer.concat([header, ...frames]));
  const res = 'CipherVault-Android/android/app/src/main/res';
  for (const [density, size] of Object.entries({mdpi:48, hdpi:72, xhdpi:96, xxhdpi:144, xxxhdpi:192})) {
    await png(`${res}/mipmap-${density}/ic_launcher.png`, size);
    await png(`${res}/mipmap-${density}/ic_launcher_round.png`, size, svg(true, false, true));
    await png(`${res}/mipmap-${density}/ic_launcher_foreground.png`, Math.round(size * 108 / 48), svg(false, true));
  }
  const vector = `<?xml version="1.0" encoding="utf-8"?>\n<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="108dp" android:height="108dp" android:viewportWidth="108" android:viewportHeight="108"><group android:translateX="27" android:translateY="25" android:scaleX="2.25" android:scaleY="2.25"><path android:fillColor="#F8FAFC" android:fillType="evenOdd" android:pathData="${mark}"/></group></vector>\n`;
  for (const dir of ['drawable', 'drawable-v24']) write(`${res}/${dir}/ic_launcher_foreground.xml`, vector);
  // Replace only the old split-shield artwork; field/action icons are untouched.
  for (const file of ['CipherVault/index.html', 'CipherVault-Desktop/index.html', 'CipherVault-Android/www/index.html', 'CipherVault-Android/www/js/mobile.js', 'CipherVault-Extension/popup.html']) {
    const src = fs.readFileSync(path.join(root, file), 'utf8');
    write(file, src.replace(/d="M12 1L3 5v6c0 5\.55[^"\n]*?v8\.8z"/g, `fill-rule="evenodd" d="${mark}"`));
  }
  console.log('Generated shield/keyhole icons for web, desktop, Android and extensions.');
})().catch(error => { console.error(error); process.exitCode = 1; });
