// Have I Been Pwned "Pwned Passwords" range API — the k-anonymity pattern
// also used by Firefox Monitor, Chrome's Password Checkup, 1Password, and
// Bitwarden's own breach report. Only the first 5 hex characters of a
// SHA-1 hash of the password ever leave the browser; the full password —
// and even the full hash — never does, and HIBP has no way to know which
// specific password (of the ~1M sharing that prefix) was being checked.
//
// This is the ONE feature in Passvault that makes an external network
// request. It only runs when the user explicitly triggers a check (see
// app.js's "Check for breaches" button) — never automatically, and never
// on page load or on a timer.
export async function checkPasswordBreach(password) {
  const bytes = new TextEncoder().encode(password);
  const hashBuf = await crypto.subtle.digest("SHA-1", bytes);
  const hashHex = [...new Uint8Array(hashBuf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  const prefix = hashHex.slice(0, 5);
  const suffix = hashHex.slice(5);

  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) throw new Error(`Have I Been Pwned request failed (${res.status})`);
  const text = await res.text();

  for (const line of text.split("\n")) {
    const [lineSuffix, countStr] = line.trim().split(":");
    if (lineSuffix === suffix) return { breached: true, count: parseInt(countStr, 10) || 0 };
  }
  return { breached: false, count: 0 };
}
