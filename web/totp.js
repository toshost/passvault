// RFC 6238 TOTP code generation. Deliberately separate from crypto.js —
// that module is the zero-knowledge trust boundary (protecting server-
// stored data); this one generates one-time codes from a secret the user
// already holds, an unrelated concern. Uses native SubtleCrypto HMAC, no
// vendored dependency needed (unlike Argon2id).

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const c of clean) {
    const val = BASE32_ALPHABET.indexOf(c);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return new Uint8Array(bytes);
}

const HASH_NAMES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

// Accepts either a raw base32 secret (the common case — most sites just
// show you the base32 string) or a full otpauth://totp/... URI (what a QR
// code decodes to, and what GitHub/Google/etc. offer as a "can't scan"
// fallback). Returns null for empty/unparseable input rather than
// throwing, since this is called on every keystroke of an optional field.
export function parseTOTPInput(input) {
  const trimmed = (input || "").trim();
  if (!trimmed) return null;
  if (trimmed.toLowerCase().startsWith("otpauth://")) {
    try {
      const url = new URL(trimmed);
      const secret = url.searchParams.get("secret");
      if (!secret) return null;
      return {
        secret,
        digits: parseInt(url.searchParams.get("digits") || "6", 10),
        period: parseInt(url.searchParams.get("period") || "30", 10),
        algorithm: (url.searchParams.get("algorithm") || "SHA1").toUpperCase(),
      };
    } catch {
      return null;
    }
  }
  return { secret: trimmed, digits: 6, period: 30, algorithm: "SHA1" };
}

async function hmac(keyBytes, msgBytes, hashName) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: hashName }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, msgBytes));
}

// Generates the current code for a parsed TOTP config (see parseTOTPInput).
// now is epoch milliseconds, overridable for testing. Returns null if the
// secret doesn't decode to any bytes (e.g. garbage input).
export async function generateTOTP({ secret, digits = 6, period = 30, algorithm = "SHA1" }, now = Date.now()) {
  const keyBytes = base32Decode(secret);
  if (keyBytes.length === 0) return null;

  const counter = Math.floor(now / 1000 / period);
  const counterBytes = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const hash = await hmac(keyBytes, counterBytes, HASH_NAMES[algorithm] || "SHA-1");
  const offset = hash[hash.length - 1] & 0x0f;
  const binCode =
    ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
  const code = (binCode % 10 ** digits).toString().padStart(digits, "0");
  const secondsRemaining = period - (Math.floor(now / 1000) % period);
  return { code, period, secondsRemaining };
}
