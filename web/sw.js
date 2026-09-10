// Passvault's service worker: makes the app shell load offline and
// installable as a PWA. Deliberately network-first for the shell (not
// pure cache-first) so a redeploy reaches an already-open tab on its next
// navigation instead of being stuck on stale cached JS indefinitely —
// the cache is only consulted when the network genuinely fails.
//
// This file NEVER touches API requests (/v1/*, /public/*) — they pass
// straight through to the network, unconditionally, every time. Any
// offline resilience for actual vault DATA (as opposed to the static app
// shell) is handled explicitly in app.js, via a localStorage cache of the
// last sync response — which is still opaque ciphertext, same as every
// other persisted blob in this app. This file has no opinion about that
// and caches nothing dynamic itself, so "what persists offline" stays
// auditable in exactly one place per concern rather than split across a
// service worker's implicit HTTP cache and the app's own explicit one.

const CACHE_VERSION = "passvault-shell-v2";

const SHELL_FILES = [
  "./",
  "index.html",
  "app.js",
  "crypto.js",
  "generator.js",
  "totp.js",
  "strength.js",
  "hibp.js",
  "passkey.js",
  "importexport.js",
  "vendor/hash-wasm/argon2.umd.min.js",
  "send.html",
  "send.js",
  "admin.html",
  "admin.js",
  "manifest.json",
  "icons/icon-192.png",
  "icons/icon-512.png",
  "icons/icon-maskable-192.png",
  "icons/icon-maskable-512.png",
  "icons/apple-touch-icon.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((cache) => cache.addAll(SHELL_FILES))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE_VERSION).map((n) => caches.delete(n))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Explicit allowlist (same-origin GETs only), not a denylist — a new
  // API route added later is safe-by-default (passes through untouched)
  // rather than accidentally getting cached because nobody remembered to
  // list it here.
  if (event.request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.includes("/v1/") || url.pathname.includes("/public/")) return;

  event.respondWith(
    fetch(event.request)
      .then((res) => {
        // Only cache a genuinely successful, same-origin response — never
        // a 404/500 or an opaque/redirected one. Without this check, a
        // single bad response (a misconfigured/mid-deploy proxy, or in
        // the worst case a one-time MITM injecting a malicious body for
        // app.js/crypto.js over a compromised connection) would get
        // written into persistent Cache Storage and then get served back
        // as if it were the real file on every later offline fallback —
        // outliving the window that produced it.
        if (res.ok && res.type === "basic") {
          const copy = res.clone();
          caches.open(CACHE_VERSION).then((cache) => cache.put(event.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(event.request).then((cached) => cached || caches.match("index.html"))),
  );
});
