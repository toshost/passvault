Vendored from hash-wasm v4.12.0 (MIT), https://www.npmjs.com/package/hash-wasm
File: dist/argon2.umd.min.js — self-contained UMD build (WASM embedded as
base64), only the Argon2id module. Everything else Passvault's client
needs (AES-256-GCM, HKDF, random bytes) uses the browser's native
SubtleCrypto — this is the one primitive with no Web Crypto equivalent.

Vendored rather than loaded from a CDN at runtime: the web app's own crypto
code should not depend on a third party being reachable/uncompromised on
every page load. To update, re-run:
  npm install hash-wasm@<version> --no-save
  cp node_modules/hash-wasm/dist/argon2.umd.min.js .
and re-verify the version/license here.
