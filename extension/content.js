// Passvault content script — runs on every http(s) page (ISOLATED world,
// the default: it can read/write the page's DOM but shares none of the
// page's own JS scope, which is exactly the isolation a password manager
// wants here). It never talks to the Passvault server directly — every
// server call goes through the background service worker via
// chrome.runtime.sendMessage, so vaultKey never has to exist in a context
// that arbitrary page JS could ever reach.
//
// Two jobs: (1) offer to autofill a detected login form from matching
// saved items, (2) after a form with a password field is submitted, offer
// to save it if nothing already matches. Both are deliberately simple
// heuristics, not a full password-manager-grade form-detection engine —
// see findLoginForm below for exactly what's covered and what isn't.

function sendMessage(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!resp || !resp.ok) return reject(new Error((resp && resp.error) || "extension error"));
      resolve(resp.result);
    });
  });
}

// Finds the single most likely login form on the page: a password input,
// its enclosing <form> (or the whole document if the field isn't inside
// one — some sites don't use a real <form> element), and a preceding
// text/email input as the username field. Only handles the FIRST password
// field found — a page with multiple independent login forms (rare) only
// gets the first one autofill-enabled. Doesn't attempt to distinguish a
// login form from a signup/change-password form; that's a known,
// acceptable false-positive for a v1 heuristic.
function findLoginForm() {
  const passwordInput = document.querySelector('input[type="password"]:not([disabled])');
  if (!passwordInput) return null;
  const container = passwordInput.closest("form") || document;
  const candidates = Array.from(
    container.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'),
  );
  // The username field is almost always the last text/email input BEFORE
  // the password field in document order — walk candidates and keep the
  // last one that precedes passwordInput.
  let usernameInput = null;
  for (const el of candidates) {
    if (el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING) {
      usernameInput = el;
    }
  }
  return { form: container, passwordInput, usernameInput };
}

function fillField(el, value) {
  if (!el) return;
  const proto = el instanceof HTMLTextAreaElement ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(proto, "value").set;
  // Framework-bound inputs (React/Vue/etc.) track their own state and
  // ignore a plain `el.value = x` assignment's native setter because
  // frameworks override the property descriptor on the DOM node itself —
  // calling the PROTOTYPE's setter bypasses that override, then the
  // dispatched events below are what actually notifies the framework.
  setter.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// --- Autofill suggestion UI ---------------------------------------------
// A minimal floating badge near the password field, not a full styled
// dropdown — clicking it fills the top match immediately if there's
// exactly one, or cycles through matches on repeated clicks if there's
// more than one. Kept deliberately small: the popup (click the toolbar
// icon) is the real "pick from a list" UI; this is just a fast path.

let badgeEl = null;
let matches = [];
let matchIndex = 0;

function removeBadge() {
  if (badgeEl) badgeEl.remove();
  badgeEl = null;
}

function showBadge(passwordInput, onClick) {
  removeBadge();
  const rect = passwordInput.getBoundingClientRect();
  badgeEl = document.createElement("button");
  badgeEl.textContent = "🔑";
  badgeEl.title = "Fill from Passvault";
  badgeEl.type = "button";
  Object.assign(badgeEl.style, {
    position: "fixed",
    left: `${rect.right - 28}px`,
    top: `${rect.top + rect.height / 2 - 12}px`,
    width: "24px",
    height: "24px",
    zIndex: 2147483647,
    border: "1px solid #ddd7c9",
    borderRadius: "4px",
    background: "#fff",
    cursor: "pointer",
    fontSize: "13px",
    lineHeight: "1",
    padding: "0",
    boxShadow: "0 1px 3px rgba(0,0,0,.15)",
  });
  badgeEl.addEventListener("mousedown", (e) => e.preventDefault()); // don't steal focus from the field
  badgeEl.addEventListener("click", onClick);
  document.documentElement.appendChild(badgeEl);
}

let repositionTarget = null; // the passwordInput the current badge is pinned to, if any

function repositionBadge() {
  if (!badgeEl || !repositionTarget || !repositionTarget.isConnected) return;
  const rect = repositionTarget.getBoundingClientRect();
  badgeEl.style.left = `${rect.right - 28}px`;
  badgeEl.style.top = `${rect.top + rect.height / 2 - 12}px`;
}
window.addEventListener("scroll", repositionBadge, { passive: true, capture: true });
window.addEventListener("resize", repositionBadge, { passive: true });

async function checkAndOfferAutofill() {
  const loginForm = findLoginForm();
  if (!loginForm) return;
  let result;
  try {
    result = await sendMessage({ type: "PV_GET_MATCHES", host: location.hostname });
  } catch {
    return; // extension not set up / locked / unreachable — fail silent, never block the page
  }
  if (result.locked || result.items.length === 0) return;
  matches = result.items;
  matchIndex = 0;
  repositionTarget = loginForm.passwordInput;
  showBadge(loginForm.passwordInput, () => {
    const m = matches[matchIndex % matches.length];
    fillField(loginForm.usernameInput, m.username);
    fillField(loginForm.passwordInput, m.password);
    matchIndex++;
  });
}

// --- Save-new-login capture ----------------------------------------------
// On a real form submit (not just any click) with a non-empty password
// field, ask the background worker whether this is already saved; if not,
// show a small prompt. No auto-save — the user always confirms.

// Shadow DOM, not a plain injected <div>: the host page's own CSS can
// never leak in and mangle this (a page-wide `button { all: unset }` or
// similar reset would otherwise silently break it), and this element's
// styles can never leak out and affect the host page either — a real
// isolation boundary, not just "hope nothing collides."
function showSavePrompt(candidate) {
  const host = document.createElement("div");
  host.setAttribute("data-passvault-save-prompt", "1");
  Object.assign(host.style, { all: "initial", position: "fixed", top: "16px", right: "16px", zIndex: 2147483647 });
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      .card {
        font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        -webkit-font-smoothing: antialiased;
        width: 300px; background: #fff; color: #14161f;
        border: 1px solid #e5e7f0; border-radius: 12px;
        box-shadow: 0 8px 24px rgba(20,22,31,.14), 0 1px 3px rgba(20,22,31,.08);
        padding: 16px; animation: pv-in .16s ease-out;
      }
      @keyframes pv-in { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
      .head { display: flex; align-items: center; gap: 9px; margin-bottom: 10px; }
      .head svg { width: 20px; height: 20px; flex: none; color: #4f46e5; }
      .head span { font-weight: 700; font-size: 14px; }
      .detail { font-size: 12.5px; color: #6b7080; margin: 0 0 14px; line-height: 1.4; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .detail strong { color: #14161f; font-weight: 600; }
      .row { display: flex; gap: 8px; }
      button {
        border: none; border-radius: 8px; padding: 8px 14px; font-size: 13px; font-weight: 600;
        cursor: pointer; font-family: inherit;
      }
      button[data-action="save"] { background: #4f46e5; color: #fff; flex: 1; }
      button[data-action="save"]:hover { background: #4338ca; }
      button[data-action="dismiss"] { background: #f7f7fb; color: #14161f; border: 1px solid #e5e7f0; }
      button[data-action="dismiss"]:hover { background: #eef0f7; }
      .status { font-size: 13px; font-weight: 600; }
      .status.ok { color: #16a34a; }
      .status.error { color: #dc2626; font-weight: 400; }
    </style>
    <div class="card">
      <div class="head">
        <svg viewBox="0 0 24 24" fill="none"><path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/></svg>
        <span>Save to Passvault?</span>
      </div>
      <div class="detail"><strong>${candidate.uri}</strong> &middot; ${candidate.username || "(no username)"}</div>
      <div class="row">
        <button data-action="save" type="button">Save</button>
        <button data-action="dismiss" type="button">Not now</button>
      </div>
    </div>
  `;
  root.querySelector('[data-action="dismiss"]').addEventListener("click", () => host.remove());
  root.querySelector('[data-action="save"]').addEventListener("click", async () => {
    const card = root.querySelector(".card");
    try {
      await sendMessage({ type: "PV_SAVE_LOGIN", item: candidate });
      card.innerHTML = '<div class="status ok">✓ Saved to Passvault</div>';
      setTimeout(() => host.remove(), 1400);
    } catch (err) {
      card.innerHTML = `<div class="status error">Couldn't save: ${err.message}</div>`;
    }
  });
  document.documentElement.appendChild(host);
}

// A REAL (non-SPA) login form navigates the tab the instant it's
// submitted — the default action proceeds concurrently with this handler,
// and this content script's entire execution context is torn down as
// soon as the new document starts loading. That means anything async
// here (a round-trip to the background worker to check "is this already
// saved," then inserting a prompt into THIS page) can't be relied on to
// finish, let alone be seen — confirmed live: the prompt never had a
// chance to render before the page navigated away. So this handler does
// the absolute minimum before returning: capture the field values
// synchronously and fire a stash message. chrome.runtime.sendMessage
// doesn't need its SENDING tab to survive for the message itself to be
// delivered and processed (only a response callback would be lost, which
// nothing here waits for) — the background worker receives and stores it
// regardless of what happens to this page a moment later. The actual
// "is this new, should we offer to save it" decision and prompt happen
// on the NEXT page load instead — see checkPendingCapture below — which
// is a normal content-script run with the time to do both properly.
function onFormSubmit(e) {
  const form = e.target;
  if (!(form instanceof HTMLFormElement)) return;
  const passwordInput = form.querySelector('input[type="password"]:not([disabled])');
  if (!passwordInput || !passwordInput.value) return;
  const loginForm = findLoginForm();
  const candidate = {
    name: document.title || location.hostname,
    uri: location.hostname,
    username: loginForm && loginForm.usernameInput ? loginForm.usernameInput.value : "",
    password: passwordInput.value,
  };
  sendMessage({ type: "PV_STASH_CAPTURE", item: candidate }).catch(() => {
    // Not set up / unreachable — nothing to stash, fail silent as usual.
  });
  // Covers the OTHER case: a login form that submits via fetch/XHR and
  // never navigates at all (SPA-style). There, this exact script instance
  // is still alive a moment later, so it can pick its own stash back up
  // directly — nothing else would ever re-check it on this page otherwise.
  // If a real navigation DOES happen instead, this callback simply never
  // fires (the whole context is gone), and the fresh content script the
  // new page gets already checks on its own via the top-level call below.
  setTimeout(checkPendingCapture, 800);
}

document.addEventListener("submit", onFormSubmit, true);

// Runs once per content-script load (i.e. once per navigation): checks
// whether the PREVIOUS page's submit stashed a capture, and — only if
// it's genuinely not already saved — offers it here. Also covers the
// same-page (SPA/AJAX) login case, where no navigation happens at all
// and this same script instance is still alive; checkAndOfferAutofill's
// own MutationObserver-triggered reruns will pick it up incidentally
// since this function is independent of that flow.
async function checkPendingCapture() {
  let taken;
  try {
    taken = await sendMessage({ type: "PV_TAKE_PENDING_CAPTURE" });
  } catch {
    return;
  }
  const candidate = taken.item;
  if (!candidate) return;
  let result;
  try {
    result = await sendMessage({ type: "PV_GET_MATCHES", host: candidate.uri });
  } catch {
    return;
  }
  if (result.locked) return;
  const alreadySaved = result.items.some((it) => it.username === candidate.username && it.password === candidate.password);
  if (alreadySaved) return;
  showSavePrompt(candidate);
}
checkPendingCapture();

// Lets the popup ("Fill" button next to a specific match) trigger a fill
// directly, in addition to the in-page badge's own click handler.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type !== "PV_FILL") return;
  const loginForm = findLoginForm();
  if (loginForm) {
    fillField(loginForm.usernameInput, msg.item.username);
    fillField(loginForm.passwordInput, msg.item.password);
  }
  sendResponse({ ok: true });
});

// Re-check for a login form whenever the page settles (initial load, and
// after any DOM mutation — many login pages render the form after an
// async fetch). Debounced so a busy page doesn't re-run this constantly.
let debounceTimer = null;
function scheduleCheck() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(checkAndOfferAutofill, 400);
}
new MutationObserver(scheduleCheck).observe(document.documentElement, { childList: true, subtree: true });
scheduleCheck();
