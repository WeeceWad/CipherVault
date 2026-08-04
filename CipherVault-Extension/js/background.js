// CipherVault background worker.
//
// Its only job is the auto-lock alarm. When the popup unlocks the vault it
// stashes the master password in storage.session (in-memory only, never on
// disk) with a 15-minute deadline and sets an alarm for that moment. This
// worker wakes on the alarm and wipes that stash, so the vault re-locks after
// the idle window even if the popup is never opened again.
//
// storage.session is cleared automatically when the browser closes, so a
// closed browser is always locked regardless of the timer.

const ext = typeof chrome !== "undefined" ? chrome : browser;

const AUTOLOCK_ALARM = "cv-autolock";
const SESSION_KEY = "cvUnlock";

ext.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== AUTOLOCK_ALARM) return;
  if (ext.storage && ext.storage.session) {
    ext.storage.session.remove(SESSION_KEY).catch(() => {});
  }
});

// If the worker restarts (MV3 can recycle it), re-arm the alarm from whatever
// deadline is currently stored, so a pending lock is never lost.
if (ext.runtime && ext.runtime.onStartup) {
  ext.runtime.onStartup.addListener(reArm);
}
if (ext.runtime && ext.runtime.onInstalled) {
  ext.runtime.onInstalled.addListener(reArm);
}

async function reArm() {
  try {
    if (!ext.storage || !ext.storage.session) return;
    const { [SESSION_KEY]: unlock } = await ext.storage.session.get(SESSION_KEY);
    if (!unlock || !unlock.until) return;
    if (Date.now() >= unlock.until) {
      await ext.storage.session.remove(SESSION_KEY);
      return;
    }
    ext.alarms.create(AUTOLOCK_ALARM, { when: unlock.until });
  } catch (e) {
    // Nothing actionable; the popup re-checks the deadline on open anyway.
  }
}
