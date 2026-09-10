// Simplified entropy-based password strength estimate. This is NOT a
// crack-time model like zxcvbn (no dictionary/pattern awareness — it
// won't catch "P@ssw0rd1" being a well-known guessable pattern despite
// looking varied); it's a keyspace-size estimate: bits = length *
// log2(size of character classes actually used). Good enough to flag
// "too short/too simple", which is most of what matters here — the
// breach check (hibp.js) is what catches known-bad passwords this
// wouldn't.
export function estimateStrength(password) {
  if (!password) return { bits: 0, label: "Empty", score: 0 };
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;

  const bits = password.length * Math.log2(charsetSize || 1);
  let label, score;
  if (bits < 28) {
    label = "Weak";
    score = 1;
  } else if (bits < 45) {
    label = "Fair";
    score = 2;
  } else if (bits < 65) {
    label = "Strong";
    score = 3;
  } else {
    label = "Very strong";
    score = 4;
  }
  return { bits: Math.round(bits), label, score };
}
