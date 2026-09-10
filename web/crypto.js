// Passvault client-side crypto. This is the entire trust boundary: the
// server (see ../internal/crypto, ../internal/auth) never sees a master
// password, wrapKey, vaultKey, itemKey, or X25519 private key — only
// authKey and the opaque blobs this module produces. Every operation here
// must match internal/crypto's expectations exactly (same KDF params
// shape, same AES-256-GCM framing, same HKDF info strings).
//
// Argon2id has no Web Crypto equivalent, so it comes from vendored
// hash-wasm (vendor/hash-wasm/argon2.umd.min.js, loaded as a classic
// script before this module — see index.html). Everything else (AES-GCM,
// HKDF, X25519, secure random) uses the browser's native SubtleCrypto.

const enc = new TextEncoder();

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// URL-safe base64 (RFC 4648 §5: '-'/'_', no padding) — for a Send's
// content key, which travels only in a URL fragment (web/send.html's
// location.hash). A fragment can technically carry '+'/'/'/'=' too, but
// URL-safe encoding sidesteps any tool/proxy/chat-app that mangles those
// when a link is pasted elsewhere, same reasoning as a JWT using it.
export function toURLSafeB64(bytes) {
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromURLSafeB64(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  return fromB64(padded);
}

export function toB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function fromB64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- Argon2id (master password -> masterKey) ---------------------------

// Must match internal/crypto.DefaultKDFParams()'s defaults (memory 64 MiB,
// iterations 3, parallelism 4) — the server returns whatever params it has
// stored for the account (via /v1/auth/prelogin), so the client always
// follows the server-supplied params rather than hardcoding them, except
// at registration time when this client is the one choosing them.
export function defaultKDFParams() {
  return { memory_kib: 64 * 1024, iterations: 3, parallelism: 4, salt: toB64(randomBytes(16)) };
}

async function argon2id(passwordBytes, kdf) {
  const raw = await hashwasm.argon2id({
    password: passwordBytes,
    salt: fromB64(kdf.salt),
    parallelism: kdf.parallelism,
    iterations: kdf.iterations,
    memorySize: kdf.memory_kib,
    hashLength: 32,
    outputType: "binary",
  });
  return new Uint8Array(raw);
}

// --- HKDF-SHA256 (masterKey -> authKey / wrapKey), distinct info strings ---
// Full HKDF with an empty salt (RFC 5869 permits this) rather than
// HKDF-Expand alone, since masterKey already has full entropy from Argon2id
// — this still gives clean domain separation between authKey and wrapKey,
// which is the property that matters here.
async function hkdf(masterKeyBytes, info, lengthBytes) {
  const key = await crypto.subtle.importKey("raw", masterKeyBytes, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
    key,
    lengthBytes * 8,
  );
  return new Uint8Array(bits);
}

// deriveKeys is the one function that touches the master password. Returns
// authKey (send to server) and wrapKey (never leaves the client).
export async function deriveKeys(masterPassword, kdf) {
  const masterKey = await argon2id(enc.encode(masterPassword), kdf);
  const authKey = await hkdf(masterKey, "passvault-auth-v1", 32);
  const wrapKey = await hkdf(masterKey, "passvault-wrap-v1", 32);
  return { authKeyB64: toB64(authKey), wrapKey };
}

// --- Account recovery kit --------------------------------------------
// A one-time-generated, print-and-store-offline recovery code — the
// mitigation for "forgot the master password" that a zero-knowledge
// design can't otherwise offer (there is no server-side reset). The
// 256-bit code itself never leaves the browser; two distinct values are
// HKDF'd from it, mirroring deriveKeys' own authKey/wrapKey split:
// recoveryAuthKey (sent to the server as a verifier, so a "forgot
// password" flow can be gated instead of being a free-for-all "reset
// anyone's password" endpoint) and recoveryWrapKey (wraps vaultKey,
// never leaves the client). See docs/PROTOCOL.md.

export function generateRecoveryCode() {
  return randomBytes(32); // client-only, shown to the user exactly once
}

// Lowercase hex, grouped for readability/transcription — no case-folding
// ambiguity to worry about (unlike base32's easily-confused characters),
// which matters more here than compactness since this is printed and
// retyped rarely, under a "I'm locked out" level of stress.
export function formatRecoveryCode(bytes) {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hex.match(/.{1,4}/g).join("-");
}

export function parseRecoveryCode(input) {
  const hex = (input || "").toLowerCase().replace(/[^0-9a-f]/g, "");
  if (hex.length !== 64) return null;
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export async function deriveRecoveryKeys(recoveryCodeBytes) {
  const recoveryAuthKey = await hkdf(recoveryCodeBytes, "passvault-recovery-auth-v1", 32);
  const recoveryWrapKey = await hkdf(recoveryCodeBytes, "passvault-recovery-wrap-v1", 32);
  return { recoveryAuthKeyB64: toB64(recoveryAuthKey), recoveryWrapKey };
}

// --- AES-256-GCM envelope (wrapKey/vaultKey/orgKey -> wrapped blob) -------
// Wire format: base64(12-byte IV || GCM ciphertext+tag). Symmetric for
// wrapping a key and for encrypting a cipher's field blob — same primitive,
// different key, per docs/PROTOCOL.md's envelope design.

async function aesGcmEncrypt(keyBytes, plaintextBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toB64(out);
}

async function aesGcmDecrypt(keyBytes, blobB64) {
  const raw = fromB64(blobB64);
  const iv = raw.slice(0, 12);
  const ct = raw.slice(12);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

export function generateKey() {
  return randomBytes(32); // 256-bit vaultKey / itemKey / folderKey
}

export async function wrapKeyBytes(rawKey, wrappingKey) {
  return aesGcmEncrypt(wrappingKey, rawKey);
}

export async function unwrapKeyBytes(wrappedB64, wrappingKey) {
  return aesGcmDecrypt(wrappingKey, wrappedB64);
}

export async function encryptJSON(obj, itemKey) {
  return aesGcmEncrypt(itemKey, enc.encode(JSON.stringify(obj)));
}

export async function decryptJSON(blobB64, itemKey) {
  const pt = await aesGcmDecrypt(itemKey, blobB64);
  return JSON.parse(new TextDecoder().decode(pt));
}

// --- Raw-bytes envelope (attachments) -------------------------------------
// Same AES-256-GCM framing as above (12-byte IV || ciphertext+tag), but
// left as raw bytes rather than base64 — a file's ciphertext goes straight
// into a multipart upload as a Blob, so base64's ~33% size overhead never
// applies to attachment content (only to the small metadata fields, which
// still go through the JSON/base64 helpers above).
export async function encryptBytes(keyBytes, plaintextBytes) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return out;
}

export async function decryptBytes(keyBytes, ciphertextBytes) {
  const iv = ciphertextBytes.slice(0, 12);
  const ct = ciphertextBytes.slice(12);
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new Uint8Array(pt);
}

// --- X25519 (generated at every signup so an account never needs a
// disruptive later migration to add it; used for item sharing — see
// deriveSharedWrapKey below). Feature-detected rather than silently faked:
// a placeholder keypair that doesn't correspond to real Diffie-Hellman math
// would be actively wrong to store, so this throws instead of degrading
// quietly.
export async function generateX25519KeyPair() {
  try {
    const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const rawPriv = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    return { publicKeyB64: toB64(rawPub), privateKeyBytes: rawPriv };
  } catch (e) {
    throw new Error(
      "This browser does not support X25519 in SubtleCrypto — update to a current browser. (" + e.message + ")",
    );
  }
}

// --- ECDH-derived wrap keys ----------------------------------------------
// Shared machinery behind every "two accounts, no server-transmitted key"
// feature: ECDH(myPriv, theirPub) === ECDH(theirPriv, myPub) is what lets
// both sides independently reach the same secret. Each *use* of that
// secret gets its own HKDF info string for domain separation — the same
// two accounts' raw ECDH output must derive to a DIFFERENT key for item
// sharing than for emergency access, so one feature's key material is
// never reusable as the other's, even between the same pair of people.
async function deriveECDHWrapKey(myPrivateKeyBytes, theirPublicKeyB64, info) {
  const myPrivKey = await crypto.subtle.importKey("pkcs8", myPrivateKeyBytes, { name: "X25519" }, false, ["deriveBits"]);
  const theirPubKey = await crypto.subtle.importKey("raw", fromB64(theirPublicKeyB64), { name: "X25519" }, false, []);
  const sharedBits = await crypto.subtle.deriveBits({ name: "X25519", public: theirPubKey }, myPrivKey, 256);
  return hkdf(new Uint8Array(sharedBits), info, 32);
}

// Simple, one-item-at-a-time sharing: no orgs, no collections. See
// docs/PROTOCOL.md and internal/db/db.go's cipher_shares table comment.
export async function deriveSharedWrapKey(myPrivateKeyBytes, theirPublicKeyB64) {
  return deriveECDHWrapKey(myPrivateKeyBytes, theirPublicKeyB64, "passvault-share-v1");
}

// Emergency access: wraps the GRANTOR's vaultKey for a trusted contact.
// See docs/PROTOCOL.md's Emergency access section and internal/db/db.go's
// emergency_access table comment.
export async function deriveEmergencyAccessWrapKey(myPrivateKeyBytes, theirPublicKeyB64) {
  return deriveECDHWrapKey(myPrivateKeyBytes, theirPublicKeyB64, "passvault-emergency-v1");
}

// --- Passkey device-unlock (WebAuthn PRF-derived wrap key) ---------------
// A device-local convenience only — see web/passkey.js for the WebAuthn
// ceremony that produces prfSecretBytes. It is HKDF'd into an AES-256-GCM
// key exactly like every other derived key in this file (domain separation
// via a distinct info string), rather than using the raw PRF output
// directly. This key wraps a small JSON blob (vaultKey, the X25519 private
// key, a refresh token) that app.js stores in localStorage; nothing here
// is sent to, or trusted by, the server. See docs/PROTOCOL.md.
export async function derivePasskeyWrapKey(prfSecretBytes) {
  return hkdf(prfSecretBytes, "passvault-passkey-unlock-v1", 32);
}
