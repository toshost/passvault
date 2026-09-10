# Passvault browser extension (Chromium, Manifest V3)

Login + password autofill for a self-hosted Passvault instance. This is
Phase 1 of the browser extension roadmap item: it unlocks the vault,
autofills/saves logins on other sites, and sets up the plumbing (a
background service worker holding the session, a message-passing contract
between it and the popup/content scripts) that passkey storage/autofill —
the originally-cited reason for needing an extension at all — will build on
next. Passkeys aren't implemented yet; see `docs/PROTOCOL.md`.

## Load it (development)

1. Run `../scripts/sync-extension-libs.sh` from this directory (or
   `scripts/sync-extension-libs.sh` from the repo root) any time
   `web/crypto.js` changes — `extension/lib/crypto.js` is a generated copy,
   never hand-edited.
2. Chrome/Edge/Brave → `chrome://extensions` → enable **Developer mode** →
   **Load unpacked** → select this `extension/` directory.
3. Click the Passvault toolbar icon → **Set up your server** → enter your
   instance's URL (e.g. `https://your-domain.example.com/tpass`) → the
   browser will ask you to confirm access to that one origin.
4. Click the toolbar icon again and log in with your master password.

## Why a service worker, not a module

The background script is a **classic** (non-module) service worker
specifically so it can `importScripts()` the vendored Argon2id WASM build
(`lib/vendor/hash-wasm/argon2.umd.min.js`) — there's no ES-module
equivalent of `importScripts()`. `lib/crypto.js` is generated from
`web/crypto.js` with its `export` keywords stripped for the same reason:
a classic script has no module system, so each function becomes an
ambient global within the worker's scope instead, which is all
`importScripts()`'d files need to see each other.

## Where the vault key lives

`background.js` is the *only* place in the extension that ever holds
`vaultKey` or talks to the Passvault server. The popup and content script
only ever send it a `chrome.runtime.sendMessage` and get a result back —
see `background.js`'s message handler for the full list of message types.
Session state (`accessToken`/`refreshToken`/`vaultKey`/decrypted item
cache) lives in `chrome.storage.session` — RAM-only, never written to
disk, cleared when the browser closes, and (unlike a plain JS variable in
the worker) it survives the service worker being unloaded and restarted
by the browser, which MV3 does aggressively after ~30s idle.

## What's NOT here yet

- Passkey storage/autofill for other sites (a real software WebAuthn
  authenticator — its own future project).
- Firefox (`browser.*` API differences from Chrome's `chrome.*`).
- A standalone TOTP-authenticator view.
- Full vault management (add/edit any item type, generator, security
  check, Send, emergency access, folders) — the popup deliberately only
  does login + autofill; everything else stays in the full web app, one
  click away via "Open full vault."
