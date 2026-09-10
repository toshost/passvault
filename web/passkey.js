// WebAuthn PRF extension, used as a real KDF for a device-local "unlock
// without retyping the master password" convenience — NOT an alternate
// authentication path. The platform authenticator (Touch ID, Windows
// Hello, a security key) derives a secret tied to (credential, salt) that
// is only ever used, via crypto.js's derivePasskeyWrapKey, to wrap/unwrap
// material Passvault already obtained locally after a normal password
// login. The credential itself is never registered with the server and
// never asserts identity to it — app.js still authenticates every request
// with the same access/refresh tokens a password login would produce.
//
// Cross-browser note: PRF `eval` results are not reliably available from
// the clientExtensionResults of navigator.credentials.create() itself, so
// this always follows a create() with an immediate get() to evaluate PRF —
// the documented, widely-compatible pattern for this extension.

const PRF_SALT = new TextEncoder().encode("passvault-passkey-unlock-v1");

export function isPasskeySupported() {
  return typeof PublicKeyCredential !== "undefined" && typeof navigator.credentials?.create === "function";
}

// Creates a new platform passkey for `email` and confirms the authenticator
// actually supports PRF (not just WebAuthn in general) by evaluating it
// once. Throws — rather than silently degrading to "no encryption" — if
// creation is cancelled or PRF isn't available, same principle as
// generateX25519KeyPair in crypto.js.
export async function registerPasskey(email) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const cred = await navigator.credentials.create({
    publicKey: {
      rp: { name: "Passvault" },
      user: { id: userId, name: email, displayName: email },
      challenge,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 }, // ES256
        { type: "public-key", alg: -257 }, // RS256, for authenticators without ES256
      ],
      authenticatorSelection: { userVerification: "required" },
      extensions: { prf: {} },
    },
  });
  if (!cred) throw new Error("Passkey creation was cancelled.");

  const prfSecret = await evalPRF(new Uint8Array(cred.rawId));
  if (!prfSecret) {
    throw new Error(
      "This authenticator doesn't support the PRF extension, which passkey unlock requires. " +
        "(A passkey was created but can't be used here — you may want to remove it from your browser/OS passkey settings.)",
    );
  }
  return { credentialIdBytes: new Uint8Array(cred.rawId), prfSecret };
}

// Re-derives the SAME PRF secret from an existing credential — this is
// what makes it usable as a symmetric key: the authenticator returns an
// identical output for the identical (credential, salt) pair every time,
// with no state stored anywhere Passvault controls. Returns null (not a
// throw) when the authenticator/browser doesn't support PRF, so callers
// can distinguish "no PRF support" from "user cancelled".
export async function evalPRF(credentialIdBytes) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: credentialIdBytes, type: "public-key" }],
      userVerification: "required",
      extensions: { prf: { eval: { first: PRF_SALT } } },
    },
  });
  const results = assertion?.getClientExtensionResults()?.prf?.results;
  if (!results?.first) return null;
  return new Uint8Array(results.first);
}
