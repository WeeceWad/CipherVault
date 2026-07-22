// CipherVault autofill content script.

const cvExt = typeof chrome !== "undefined" ? chrome : browser;

cvExt.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request && request.action === "FILL_CREDENTIALS") {
    const result = fillCredentials(request.username, request.password);
    sendResponse(result);
  }
  // Synchronous response; no need to keep the channel open.
  return false;
});

/** An input the user could actually type into right now. */
function isFillable(el) {
  if (!el || el.disabled || el.readOnly) return false;
  if (el.type === "hidden") return false;
  const rect = el.getBoundingClientRect();
  if (rect.width === 0 && rect.height === 0) return false;
  const style = window.getComputedStyle(el);
  return style.visibility !== "hidden" && style.display !== "none";
}

function findPasswordField() {
  return Array.from(document.querySelectorAll('input[type="password"]')).find(isFillable) || null;
}

function findUsernameField(pwdField) {
  const candidates = Array.from(
    document.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')
  ).filter(isFillable);

  if (candidates.length === 0) return null;

  // Strongest signal: the page told us outright.
  const declared = candidates.find((el) => {
    const ac = (el.autocomplete || "").toLowerCase();
    return ac === "username" || ac === "email";
  });
  if (declared) return declared;

  // Otherwise the last fillable text input that sits before the password box.
  if (pwdField) {
    let best = null;
    for (const el of candidates) {
      if (el.compareDocumentPosition(pwdField) & Node.DOCUMENT_POSITION_FOLLOWING) best = el;
    }
    if (best) return best;
  }

  // Multi-step logins show the username page first, with no password field.
  const byName = candidates.find((el) => {
    const hint = `${el.name || ""} ${el.id || ""} ${el.placeholder || ""}`.toLowerCase();
    return /user|email|login|account|identifier/.test(hint);
  });
  return byName || candidates[0];
}

/** Sets a value the way a real keystroke would, so React/Vue/Angular notice. */
function setFieldValue(el, value) {
  const proto = el instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype
    : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;

  el.focus();
  // React installs its own value setter on the element instance and diffs
  // against it; assigning through the prototype setter is what makes the
  // synthetic input event land.
  if (setter) setter.call(el, value);
  else el.value = value;

  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
  el.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
}

function fillCredentials(username, password) {
  const pwdField = findPasswordField();
  const userField = findUsernameField(pwdField);

  let filled = 0;

  if (userField && username) {
    setFieldValue(userField, username);
    highlightField(userField);
    filled++;
  }

  if (pwdField && password) {
    setFieldValue(pwdField, password);
    highlightField(pwdField);
    filled++;
  }

  if (pwdField) pwdField.blur();

  return { filled, foundUsernameField: !!userField, foundPasswordField: !!pwdField };
}

function highlightField(el) {
  const originalOutline = el.style.outline;
  const originalTransition = el.style.transition;

  el.style.transition = "outline 0.2s";
  el.style.outline = "2px solid #3b82f6";

  setTimeout(() => {
    el.style.outline = originalOutline;
    setTimeout(() => {
      el.style.transition = originalTransition;
    }, 200);
  }, 1000);
}
