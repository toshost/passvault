// Password generator. Pure client-side, no server involvement at all —
// the generated string is just typed into the item-password field like
// anything the user would've typed themselves.

const CHARSETS = {
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  lower: "abcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  // Excludes quote/backslash characters that are common sources of
  // copy-paste and shell-escaping breakage in the sites people paste
  // generated passwords into.
  symbols: "!@#$%^&*()-_=+[]{};:,.<>/?",
};

// Uses crypto.getRandomValues with rejection sampling (not `% length`
// alone) so every character in the chosen charset has exactly equal
// probability — a plain modulo would bias toward low character-code
// values whenever 256 isn't a multiple of the charset length.
export function generatePassword({ length = 16, upper = true, lower = true, digits = true, symbols = true } = {}) {
  let charset = "";
  if (upper) charset += CHARSETS.upper;
  if (lower) charset += CHARSETS.lower;
  if (digits) charset += CHARSETS.digits;
  if (symbols) charset += CHARSETS.symbols;
  if (!charset) charset = CHARSETS.lower + CHARSETS.digits; // never generate from an empty set

  const max = Math.floor(256 / charset.length) * charset.length;
  const buf = new Uint8Array(1);
  let out = "";
  while (out.length < length) {
    crypto.getRandomValues(buf);
    if (buf[0] < max) out += charset[buf[0] % charset.length];
  }
  return out;
}
