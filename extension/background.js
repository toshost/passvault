// Passvault extension background service worker (MV3, classic script —
// NOT type:"module", because hash-wasm's UMD build needs importScripts()
// and there's no ES module equivalent of that). This is the ONLY place in
// the extension that ever holds vaultKey or talks to the Passvault server:
// the popup and content scripts never call the API directly, they send a
// runtime message here and get a result back. That keeps the "where does
// the key live" answer to exactly one place, same as web/app.js's
// module-level `session` object.
//
// crypto.js is loaded from lib/ (a generated copy — see
// scripts/sync-extension-libs.sh — never edit lib/crypto.js by hand) with
// its `export` keywords stripped, since a classic script has no module
// system: every function it declares becomes an ambient global in this
// worker's scope, which is all importScripts() needs.
importScripts("lib/vendor/hash-wasm/argon2.umd.min.js", "lib/crypto.js");

// --- Session persistence ---------------------------------------------------
// MV3 service workers are non-persistent — Chrome can unload this worker
// after ~30s idle, wiping any plain `let`/`const` state. chrome.storage.
// session is the MV3-native fix: RAM-only, never written to disk, cleared
// when the browser closes, but — unlike a bare JS variable here — it
// SURVIVES a service-worker restart within the same browser session. This
// is where accessToken/refreshToken/vaultKey live; nothing secret is ever
// written to chrome.storage.local, which IS disk-backed.
//
// The server URL is the one thing that DOES belong in chrome.storage.local
// — it's not a secret, and losing it on every browser restart (forcing the
// user to re-enter their self-hosted instance's URL) would be a real
// papercut for no security benefit.

const SESSION_KEYS = [
  "accessToken", "refreshToken", "vaultKeyB64", "email", "items",
  // Bridges the two-phase 2FA login (see login()/loginTOTP() below). This
  // has to live here, not in a plain module-level variable: a user
  // fetching their 2FA code from their phone can easily take longer than
  // the ~30s Chrome allows before unloading an idle service worker, which
  // would otherwise silently wipe it mid-login.
  "pendingLoginChallenge", "pendingLoginWrapKeyB64",
  // A captured (not-yet-offered) save-this-login candidate — see
  // PV_STASH_CAPTURE below for why this can't just be shown immediately
  // from within the submit handler that captured it.
  "pendingCapture",
];

async function getSession() {
  const stored = await chrome.storage.session.get(SESSION_KEYS);
  return {
    accessToken: stored.accessToken || null,
    refreshToken: stored.refreshToken || null,
    vaultKeyB64: stored.vaultKeyB64 || null,
    email: stored.email || null,
    items: stored.items || [], // decrypted login items: [{id, name, uri, username, password, totp, notes, folderId}]
    pendingLoginChallenge: stored.pendingLoginChallenge || null,
    pendingLoginWrapKeyB64: stored.pendingLoginWrapKeyB64 || null,
    pendingCapture: stored.pendingCapture || null,
  };
}

async function setSession(patch) {
  await chrome.storage.session.set(patch);
}

async function clearSession() {
  await chrome.storage.session.remove(SESSION_KEYS);
}

async function getServerUrl() {
  const { serverUrl } = await chrome.storage.local.get("serverUrl");
  return serverUrl || null;
}

// --- API -------------------------------------------------------------------

class PVError extends Error {}

async function apiFetch(path, opts = {}) {
  const serverUrl = await getServerUrl();
  if (!serverUrl) throw new PVError("Set your Passvault server URL in the extension options first.");
  const session = await getSession();
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (session.accessToken) headers.Authorization = "Bearer " + session.accessToken;
  const res = await fetch(serverUrl.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, ""), { ...opts, headers });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new PVError(body.error || res.statusText);
  return body;
}

// --- Domain matching ---------------------------------------------------
// Deliberately simple for v1: exact hostname match, with a leading "www."
// stripped from both sides before comparing (the single most common
// mismatch — a login saved on "example.com" should still match
// "www.example.com"). This is NOT a public-suffix-list-aware registrable-
// domain matcher — "sub.example.com" will not match an "example.com" item,
// and that's intentional: a naive last-two-labels fallback would wrongly
// treat "example.co.uk" and "other.co.uk" as the same site. Getting this
// wrong in the permissive direction is a real security bug (suggesting a
// credential on the wrong site); getting it wrong in the strict direction
// is just an occasional missed autofill. Correcting this properly needs a
// real PSL, which is future work, not a silent guess now.
function normalizeHost(host) {
  return (host || "").toLowerCase().replace(/^www\./, "");
}

function hostFromUri(uri) {
  try {
    return normalizeHost(new URL(/^https?:\/\//i.test(uri) ? uri : "https://" + uri).hostname);
  } catch {
    return normalizeHost(uri);
  }
}

function matchesForHost(items, host) {
  const target = normalizeHost(host);
  if (!target) return [];
  return items.filter((it) => it.uri && hostFromUri(it.uri) === target);
}

// --- Vault sync/decrypt --------------------------------------------------
// Mirrors web/app.js's refreshItems(), but scoped to just what autofill
// needs: login items only (folders/notes/cards/identities/ssh_key/totp
// items are irrelevant here and stay web-app-only), and no offline cache —
// a service worker has no "keep working while offline" UX to serve.
async function syncItems(vaultKeyBytes) {
  const data = await apiFetch("v1/sync?since=0");
  const items = [];
  for (const cipher of data.ciphers || []) {
    if (cipher.deleted_at || cipher.type !== "login") continue;
    try {
      const itemKey = await unwrapKeyBytes(cipher.wrapped_item_key, vaultKeyBytes);
      const item = await decryptJSON(cipher.encrypted_blob, itemKey);
      items.push({
        id: cipher.id,
        name: item.name || "",
        uri: item.uri || "",
        username: item.username || "",
        password: item.password || "",
        folderId: cipher.folder_id ?? null,
      });
    } catch {
      // Undecryptable row (stale/tampered) — skip it, same as app.js does
      // for shared ciphers, rather than aborting the whole sync.
    }
  }
  return items;
}

// --- Login flow (mirrors web/app.js's prelogin -> deriveKeys -> login ->
// completeLogin, against the identical /v1/auth/* endpoints) -------------

async function login(email, password) {
  const kdf = await apiFetch("v1/auth/prelogin?email=" + encodeURIComponent(email));
  const { authKeyB64, wrapKey } = await deriveKeys(password, kdf);
  const resp = await apiFetch("v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, auth_key: authKeyB64 }),
  });
  if (resp.requires_2fa) {
    await setSession({ pendingLoginChallenge: resp.login_challenge, pendingLoginWrapKeyB64: toB64(wrapKey) });
    return { requires2fa: true };
  }
  await completeLogin(resp, wrapKey);
  return { requires2fa: false };
}

async function loginTOTP(code) {
  const { pendingLoginChallenge, pendingLoginWrapKeyB64 } = await getSession();
  if (!pendingLoginChallenge) throw new PVError("No login in progress — start over.");
  const resp = await apiFetch("v1/auth/login/2fa", {
    method: "POST",
    body: JSON.stringify({ login_challenge: pendingLoginChallenge, code }),
  });
  await chrome.storage.session.remove(["pendingLoginChallenge", "pendingLoginWrapKeyB64"]);
  await completeLogin(resp, fromB64(pendingLoginWrapKeyB64));
}

async function completeLogin(resp, wrapKey) {
  const vaultKeyBytes = await unwrapKeyBytes(resp.user.wrapped_vault_key, wrapKey);
  await setSession({
    accessToken: resp.tokens.access_token,
    refreshToken: resp.tokens.refresh_token,
    vaultKeyB64: toB64(vaultKeyBytes),
    email: resp.user.email,
  });
  const items = await syncItems(vaultKeyBytes);
  await setSession({ items });
}

async function saveLogin({ name, uri, username, password }) {
  const session = await getSession();
  if (!session.vaultKeyB64) throw new PVError("Unlock the vault first.");
  const vaultKeyBytes = fromB64(session.vaultKeyB64);
  const itemKey = generateKey();
  const wrappedItemKey = await wrapKeyBytes(itemKey, vaultKeyBytes);
  const encryptedBlob = await encryptJSON({ name, uri, username, password, totp: "", notes: "" }, itemKey);
  await apiFetch("v1/ciphers", {
    method: "POST",
    body: JSON.stringify({ type: "login", folder_id: null, wrapped_item_key: wrappedItemKey, encrypted_blob: encryptedBlob }),
  });
  const items = await syncItems(vaultKeyBytes);
  await setSession({ items });
}

// --- Message handling --------------------------------------------------
// The popup and content scripts talk to this worker ONLY through these
// messages — see the file header for why. Every handler returns a plain
// JSON-serializable value or throws; sendResponse always gets {ok:true,
// result} or {ok:false, error} so callers never have to special-case
// chrome.runtime.lastError.

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  handleMessage(msg)
    .then((result) => sendResponse({ ok: true, result }))
    .catch((err) => sendResponse({ ok: false, error: err.message || String(err) }));
  return true; // keep the message channel open for the async response
});

async function handleMessage(msg) {
  switch (msg.type) {
    case "PV_GET_STATE": {
      const serverUrl = await getServerUrl();
      const session = await getSession();
      return {
        configured: !!serverUrl,
        locked: !session.vaultKeyB64,
        email: session.email,
        itemCount: (session.items || []).length,
      };
    }
    case "PV_GET_SERVER_URL":
      return { serverUrl: await getServerUrl() };
    case "PV_SET_SERVER_URL": {
      const url = String(msg.url || "").trim().replace(/\/+$/, "");
      if (!/^https?:\/\//i.test(url)) throw new PVError("Enter a full URL, including https://");
      await chrome.storage.local.set({ serverUrl: url });
      return { serverUrl: url };
    }
    case "PV_LOGIN":
      return login(msg.email, msg.password);
    case "PV_LOGIN_2FA":
      await loginTOTP(msg.code);
      return { ok: true };
    case "PV_LOCK":
      await clearSession();
      return { ok: true };
    case "PV_LOGOUT":
      try {
        await apiFetch("v1/auth/logout", { method: "POST" });
      } catch {
        // best-effort, same as web/app.js's logout handler
      }
      await clearSession();
      return { ok: true };
    case "PV_GET_MATCHES": {
      const session = await getSession();
      if (!session.vaultKeyB64) return { locked: true, items: [] };
      return { locked: false, items: matchesForHost(session.items, msg.host) };
    }
    case "PV_GET_ALL_ITEMS": {
      const session = await getSession();
      if (!session.vaultKeyB64) return { locked: true, items: [] };
      const items = [...(session.items || [])].sort((a, b) =>
        (a.name || a.uri).localeCompare(b.name || b.uri)
      );
      return { locked: false, items };
    }
    case "PV_SAVE_LOGIN":
      await saveLogin(msg.item);
      return { ok: true };
    // A form submit that looks like a login (see content.js's onFormSubmit)
    // is stashed here rather than shown as a prompt right away: a real
    // (non-SPA) login form navigates the tab immediately on submit, which
    // tears down the content script's whole execution context before an
    // async round-trip + DOM-inserted prompt could ever render. Sending
    // this message doesn't need to be awaited by the caller for the
    // message ITSELF to be delivered — chrome.runtime.sendMessage doesn't
    // require the sending tab to still exist for that part — only a
    // response callback would fail to fire, which content.js doesn't wait
    // for here. The NEXT page load (the post-login page, still governed by
    // the same content script running fresh on the new document) is what
    // actually asks for and shows the prompt — see PV_TAKE_PENDING_CAPTURE.
    case "PV_STASH_CAPTURE":
      await setSession({ pendingCapture: msg.item });
      return { ok: true };
    // Reads AND clears the stash in one step, so a save-prompt is only
    // ever offered once — a page the user merely revisits later (no new
    // submit happened) must not keep re-showing a stale capture.
    case "PV_TAKE_PENDING_CAPTURE": {
      const session = await getSession();
      if (session.pendingCapture) await chrome.storage.session.remove("pendingCapture");
      return { item: session.pendingCapture };
    }
    default:
      throw new PVError("Unknown message type: " + msg.type);
  }
}
