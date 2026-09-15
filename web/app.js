import {
  defaultKDFParams, deriveKeys, generateKey, wrapKeyBytes, unwrapKeyBytes,
  encryptJSON, decryptJSON, generateX25519KeyPair, encryptBytes, decryptBytes,
  deriveSharedWrapKey, toB64, fromB64, derivePasskeyWrapKey, toURLSafeB64,
  deriveEmergencyAccessWrapKey, generateRecoveryCode, formatRecoveryCode,
  parseRecoveryCode, deriveRecoveryKeys,
} from "./crypto.js";
import { generatePassword } from "./generator.js";
import { parseTOTPInput, generateTOTP } from "./totp.js";
import { estimateStrength } from "./strength.js";
import { checkPasswordBreach } from "./hibp.js";
import { isPasskeySupported, registerPasskey, evalPRF } from "./passkey.js";
import { buildPassvaultExport, IMPORT_FORMATS } from "./importexport.js";

// Session state lives in memory only — never localStorage/sessionStorage —
// matching the "keys live in memory only, never persisted unencrypted
// anywhere" rule from docs/PROTOCOL.md. A page reload means logging back
// in; that's an intentional consequence of zero-knowledge, not an oversight.
// There are two opt-in exceptions, neither of which breaks that rule: (1)
// passkey unlock (see the "Passkey unlock" section below), where the cached
// material is AES-256-GCM-wrapped under a key that never leaves the platform
// authenticator without a fresh biometric/PIN ceremony; (2) the offline
// sync cache (see "Offline support" below), which stores nothing but the
// last /v1/sync response verbatim — the exact same opaque ciphertext the
// server already sent over the wire, not a new decryption or export.
const session = { accessToken: null, refreshToken: null, vaultKey: null, user: null, x25519PrivateKeyBytes: null };

const $ = (sel) => document.querySelector(sel);
const authView = $("#auth-view");
const vaultView = $("#vault-view");
const authError = $("#auth-error");
const itemsEl = $("#items");
const emptyState = $("#empty-state");
const emptyStateText = $("#empty-state-text");
const authEl = $("#authenticator-list");
const authEmpty = $("#authenticator-empty");

// --- Offline support (PWA) -------------------------------------------------
// Two independent pieces: a service worker caches the static app SHELL
// (JS/HTML/icons) so the app loads at all without network — see web/sw.js,
// which never touches API requests itself — and a small localStorage cache
// of the last /v1/sync response so an ALREADY-unlocked session can keep
// showing the vault after the network drops mid-session (refreshItems()
// below falls back to it). Neither survives a full page reload while
// offline: session.vaultKey is memory-only by design (see the comment
// above), so a reload always requires a fresh login regardless of what's
// cached.

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js").catch(() => {
      // Not fatal — the app still works fully online without it, this only
      // affects offline/installability.
    });
  });
}

const SYNC_CACHE_KEY = "passvault_sync_cache_v1";

function cacheSyncResponse(email, data) {
  try {
    localStorage.setItem(SYNC_CACHE_KEY, JSON.stringify({ email, data }));
  } catch {
    // localStorage can throw (private browsing, quota) — offline viewing
    // just won't work this session; not worth surfacing as an error for
    // what's already a best-effort convenience feature.
  }
}

function loadCachedSyncResponse(email) {
  try {
    const raw = localStorage.getItem(SYNC_CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return parsed.email === email ? parsed.data : null;
  } catch {
    return null;
  }
}

function setOfflineBannerVisible(visible) {
  const banner = $("#offline-banner");
  if (banner) banner.hidden = !visible;
}

window.addEventListener("online", () => setOfflineBannerVisible(false));
window.addEventListener("offline", () => setOfflineBannerVisible(true));

function showError(msg) {
  authError.textContent = msg;
  authError.hidden = !msg;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false; // clipboard permission denied/unavailable — caller decides how to surface this
  }
}

// --- Password generator ------------------------------------------------

$("#gen-password-btn").addEventListener("click", () => {
  const pw = generatePassword({
    length: parseInt($("#gen-length").value, 10) || 16,
    upper: $("#gen-upper").checked,
    lower: $("#gen-lower").checked,
    digits: $("#gen-digits").checked,
    symbols: $("#gen-symbols").checked,
  });
  $("#item-password").value = pw;
});

// --- Standalone generator view ---------------------------------------------
// Same generatePassword() as the inline one above, independent target and
// options (gen2-*) so the two don't fight over the same fields.

function regenerateStandalonePassword() {
  const pw = generatePassword({
    length: parseInt($("#gen2-length").value, 10) || 16,
    upper: $("#gen2-upper").checked,
    lower: $("#gen2-lower").checked,
    digits: $("#gen2-digits").checked,
    symbols: $("#gen2-symbols").checked,
  });
  $("#generator-output").textContent = pw;
  const { label, bits } = estimateStrength(pw);
  $("#generator-strength").textContent = `${label} — ~${bits} bits of entropy`;
}
$("#generator-regenerate-btn").addEventListener("click", regenerateStandalonePassword);
for (const id of ["#gen2-length", "#gen2-upper", "#gen2-lower", "#gen2-digits", "#gen2-symbols"]) {
  $(id).addEventListener("change", regenerateStandalonePassword);
}
$("#generator-copy-btn").addEventListener("click", async () => {
  const btn = $("#generator-copy-btn");
  const ok = await copyToClipboard($("#generator-output").textContent);
  flashCopied(btn, ok);
});

// --- Item type toggle ----------------------------------------------------
// Each .type-fields block's data-type is a space-separated list of the
// item types it applies to (the common Notes field applies to three of
// the four types, everything else applies to exactly one).

function syncTypeFields() {
  const type = $("#item-type").value;
  for (const el of document.querySelectorAll(".type-fields")) {
    el.hidden = !el.dataset.type.split(" ").includes(type);
  }
}
$("#item-type").addEventListener("change", syncTypeFields);

// --- Add / edit item modal -------------------------------------------------
// The same modal and form serve both: editingCipher is null for a fresh
// "Add item", or {id, itemKey} while editing an existing one, in which
// case submit re-wraps the SAME itemKey (no rotation needed for a normal
// content edit) and sends it back with `id` set — the server already
// treats a POST /v1/ciphers with `id` as an update (see
// internal/api/cipher_handlers.go), this just wires the client up to it.

const addItemModal = $("#add-item-modal");
let editingCipher = null; // { id, itemKey } | null

function openAddItemModal() {
  addItemModal.hidden = false;
  $("#item-type").disabled = false;
  $("#add-item-modal-title").textContent = "Add item";
  editingCipher = null;
  // Fire-and-forget: only toggles whether the alias-generation button is
  // visible, not required for the modal to be usable.
  api("v1/settings/email-alias")
    .then((s) => {
      $("#gen-alias-btn").hidden = !(s.provider && s.wrapped_api_key);
    })
    .catch(() => {});
}

// TOTP-only ciphers are managed from the Authenticator tab (add-totp-form)
// and have no representation in this form's type list, so editing one
// here isn't offered — see the "totp" guard on the Edit button itself.
function openEditItemModal(id, type, item, itemKey, folderId) {
  addItemModal.hidden = false;
  $("#add-item-modal-title").textContent = "Edit item";
  editingCipher = { id, itemKey };
  $("#item-type").value = type;
  $("#item-type").disabled = true; // changing type mid-edit would leave the old fields orphaned in a shape they don't belong to
  syncTypeFields();
  $("#item-name").value = item.name || "";
  $("#item-folder").value = folderId != null ? String(folderId) : "";
  switch (type) {
    case "login":
      $("#item-uri").value = item.uri || "";
      $("#item-username").value = item.username || "";
      $("#item-password").value = item.password || "";
      $("#item-totp").value = item.totp || "";
      $("#item-notes").value = item.notes || "";
      break;
    case "note":
      $("#note-content").value = item.notes || "";
      break;
    case "card":
      $("#card-holder").value = item.cardholderName || "";
      $("#card-brand").value = item.brand || "";
      $("#card-number").value = item.number || "";
      $("#card-cvv").value = item.cvv || "";
      $("#card-exp-month").value = item.expMonth || "";
      $("#card-exp-year").value = item.expYear || "";
      $("#item-notes").value = item.notes || "";
      break;
    case "identity":
      $("#id-first-name").value = item.firstName || "";
      $("#id-last-name").value = item.lastName || "";
      $("#id-email").value = item.email || "";
      $("#id-phone").value = item.phone || "";
      $("#id-address").value = item.address || "";
      $("#id-city").value = item.city || "";
      $("#id-state").value = item.state || "";
      $("#id-postal").value = item.postalCode || "";
      $("#id-country").value = item.country || "";
      $("#item-notes").value = item.notes || "";
      break;
    case "ssh_key":
      $("#ssh-key-type").value = item.keyType || "Ed25519";
      $("#ssh-public-key").value = item.publicKey || "";
      $("#ssh-private-key").value = item.privateKey || "";
      $("#ssh-passphrase").value = item.passphrase || "";
      $("#ssh-fingerprint").value = item.fingerprint || "";
      $("#item-notes").value = item.notes || "";
      break;
  }
  $("#item-username")?.focus();
}

function closeAddItemModal() {
  addItemModal.hidden = true;
  $("#item-type").disabled = false;
  editingCipher = null;
  $("#add-item-form").reset();
  syncTypeFields(); // reset() puts the type <select> back on "login" — resync which field groups show
}
$("#gen-alias-btn").addEventListener("click", async () => {
  const btn = $("#gen-alias-btn");
  try {
    const hostname = $("#item-name").value.trim() || undefined;
    const alias = await generateEmailAlias(hostname);
    if (alias) $("#item-username").value = alias;
  } catch (err) {
    flashMessage(btn, err.message || "Alias generation failed", false);
  }
});

$("#open-add-item-btn").addEventListener("click", openAddItemModal);
$("#empty-state-add-btn").addEventListener("click", openAddItemModal);
$("#close-add-item-modal").addEventListener("click", closeAddItemModal);
addItemModal.addEventListener("click", (e) => {
  if (e.target === addItemModal) closeAddItemModal(); // click on the backdrop itself, not its content
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !addItemModal.hidden) closeAddItemModal();
});

// --- Sidebar navigation (Vault / Authenticator / Folders / Generator / Security) ---

for (const navBtn of document.querySelectorAll(".nav-item[data-nav]")) {
  navBtn.addEventListener("click", () => {
    const target = navBtn.dataset.nav;
    for (const b of document.querySelectorAll(".nav-item[data-nav]")) b.classList.toggle("active", b === navBtn);
    for (const view of document.querySelectorAll(".view")) view.hidden = view.id !== `view-${target}`;
    // The search box only makes sense against the vault grid — hide it
    // elsewhere rather than leaving it visibly inert.
    $("#vault-search").hidden = target !== "vault";
    if (target === "generator") regenerateStandalonePassword(); // fresh suggestion each time the tool is opened
    if (target === "security") {
      renderSecurityView();
      updatePasskeyUI();
      update2FAUI();
      updateEmailAliasUI();
      updateRecoveryKitUI();
      renderAuditLog();
    }
    if (target === "send") renderSendList();
    if (target === "emergency") renderEmergencyAccessLists();
    if (target === "importexport") resetImportExportView();
  });
}

// --- Auth tabs (Log in / Sign up) ------------------------------------------

const AUTH_HERO_COPY = {
  login: ["Welcome back", "Your master password unlocks everything — it's never sent to this server, encrypted or otherwise."],
  register: ["Create your vault", "Pick a master password only you will ever know. Everything else — every login, note, and key you save — is encrypted under it before it leaves your browser."],
};

for (const tab of document.querySelectorAll(".tab")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t === tab);
    $("#login-form").hidden = tab.id !== "tab-login";
    $("#register-form").hidden = tab.id !== "tab-register";
    const [title, sub] = AUTH_HERO_COPY[tab.id === "tab-login" ? "login" : "register"];
    $("#auth-hero-title").textContent = title;
    $("#auth-hero-sub").textContent = sub;
    showError("");
  });
}

// --- Account 2FA (TOTP) -----------------------------------------------
// Separate from passkey unlock below: this gates the MASTER-PASSWORD
// login path itself (see the two-phase login flow above the auth tabs
// section), not a convenience layer on top of an already-authenticated
// session. The secret lives server-side by necessity — see
// internal/db/db.go's totp_2fa_secret comment for why that one field was
// never going to be zero-knowledge, same as for any password manager.

async function update2FAUI() {
  let status;
  try {
    status = await api("v1/auth/2fa/status");
  } catch {
    return;
  }
  $("#twofa-disabled-state").hidden = status.enabled;
  $("#twofa-enabled-state").hidden = !status.enabled;
  $("#twofa-recovery-codes-remaining").textContent = status.enabled
    ? `${status.recovery_codes_remaining} recovery code(s) remaining.`
    : "";
  $("#twofa-setup-panel").hidden = true;
  $("#twofa-disable-panel").hidden = true;
  $("#twofa-regenerate-panel").hidden = true;
}

$("#enable-2fa-btn").addEventListener("click", async () => {
  const errorEl = $("#twofa-setup-error");
  errorEl.hidden = true;
  try {
    const { secret, otpauth_url } = await api("v1/auth/2fa/setup", { method: "POST" });
    $("#twofa-setup-secret").textContent = secret;
    $("#twofa-setup-otpauth-link").href = otpauth_url;
    $("#twofa-setup-code").value = "";
    $("#twofa-setup-panel").dataset.secret = secret;
    $("#twofa-setup-panel").hidden = false;
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

function showRecoveryCodes(codes) {
  $("#twofa-recovery-codes-list").innerHTML = codes.map((c) => escapeHTML(c)).join("<br>");
  $("#twofa-recovery-codes-panel").hidden = false;
}

$("#twofa-setup-confirm-btn").addEventListener("click", async () => {
  const errorEl = $("#twofa-setup-error");
  errorEl.hidden = true;
  try {
    const secret = $("#twofa-setup-panel").dataset.secret;
    const resp = await api("v1/auth/2fa/enable", {
      method: "POST",
      body: JSON.stringify({ secret, code: $("#twofa-setup-code").value.trim() }),
    });
    $("#twofa-setup-panel").hidden = true;
    showRecoveryCodes(resp.recovery_codes);
    await update2FAUI();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#twofa-recovery-codes-done-btn").addEventListener("click", () => {
  $("#twofa-recovery-codes-panel").hidden = true;
  $("#twofa-recovery-codes-list").innerHTML = "";
});

$("#disable-2fa-btn").addEventListener("click", () => {
  $("#twofa-disable-code").value = "";
  $("#twofa-disable-error").hidden = true;
  $("#twofa-disable-panel").hidden = false;
});

$("#twofa-disable-confirm-btn").addEventListener("click", async () => {
  const errorEl = $("#twofa-disable-error");
  errorEl.hidden = true;
  try {
    await api("v1/auth/2fa/disable", {
      method: "POST",
      body: JSON.stringify({ code: $("#twofa-disable-code").value.trim() }),
    });
    $("#twofa-disable-panel").hidden = true;
    await update2FAUI();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#regenerate-recovery-codes-btn").addEventListener("click", () => {
  $("#twofa-regenerate-code").value = "";
  $("#twofa-regenerate-error").hidden = true;
  $("#twofa-regenerate-panel").hidden = false;
});

$("#twofa-regenerate-confirm-btn").addEventListener("click", async () => {
  const errorEl = $("#twofa-regenerate-error");
  errorEl.hidden = true;
  try {
    const resp = await api("v1/auth/2fa/recovery-codes/regenerate", {
      method: "POST",
      body: JSON.stringify({ code: $("#twofa-regenerate-code").value.trim() }),
    });
    $("#twofa-regenerate-panel").hidden = true;
    showRecoveryCodes(resp.recovery_codes);
    await update2FAUI();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

// --- Email alias generation (SimpleLogin integration) ----------------------
// The API key is encrypted under this account's own vaultKey (like every
// other opaque blob) and stored server-side so it syncs across devices —
// it's decrypted client-side only in memory, right before a generate
// call, and sent to the server just for that one proxied request (see
// internal/api/email_alias_handlers.go for why a proxy is needed at all:
// SimpleLogin's API doesn't set CORS headers permitting a browser to call
// it directly — confirmed empirically, not assumed).

async function updateEmailAliasUI() {
  let settings;
  try {
    settings = await api("v1/settings/email-alias");
  } catch {
    return;
  }
  const configured = Boolean(settings.provider && settings.wrapped_api_key);
  $("#email-alias-configured-state").hidden = !configured;
  $("#email-alias-setup-state").hidden = configured;
  if (configured) $("#email-alias-provider-label").textContent = settings.provider === "simplelogin" ? "SimpleLogin" : settings.provider;
}

$("#save-email-alias-btn").addEventListener("click", async () => {
  const errorEl = $("#email-alias-error");
  errorEl.hidden = true;
  const apiKey = $("#email-alias-api-key").value.trim();
  if (!apiKey) return;
  try {
    const wrappedAPIKey = await encryptJSON({ api_key: apiKey }, session.vaultKey);
    await api("v1/settings/email-alias", {
      method: "PUT",
      body: JSON.stringify({ provider: "simplelogin", wrapped_api_key: wrappedAPIKey }),
    });
    $("#email-alias-api-key").value = "";
    await updateEmailAliasUI();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#remove-email-alias-btn").addEventListener("click", async () => {
  await api("v1/settings/email-alias", { method: "DELETE" });
  await updateEmailAliasUI();
});

// Generates a fresh alias and returns it, or null if email-alias isn't
// configured — called from the Add Item modal's "Generate alias" button
// (wired further down, alongside the rest of that form's handlers).
async function generateEmailAlias(hostname) {
  const settings = await api("v1/settings/email-alias");
  if (!settings.provider || !settings.wrapped_api_key) return null;
  const { api_key: apiKey } = await decryptJSON(settings.wrapped_api_key, session.vaultKey);
  const resp = await api("v1/email-alias/generate", {
    method: "POST",
    body: JSON.stringify({ provider: settings.provider, api_key: apiKey, hostname }),
  });
  return resp.email;
}

// --- Account recovery kit (settings side) ---------------------------------
// Creating/regenerating a kit runs entirely client-side except for the
// final upload: generate a random code, derive recoveryAuthKey (sent to
// the server as a verifier) and recoveryWrapKey (wraps vaultKey, never
// sent), and show the formatted code exactly once. See the login-screen
// recovery flow above for the other half of this feature and
// docs/PROTOCOL.md for the full design.

async function updateRecoveryKitUI() {
  let status;
  try {
    status = await api("v1/auth/recovery-kit/status");
  } catch {
    return;
  }
  $("#recovery-kit-unconfigured-state").hidden = status.configured;
  $("#recovery-kit-configured-state").hidden = !status.configured;
  $("#recovery-kit-reveal-panel").hidden = true;
}

// Creating, regenerating, or removing the recovery kit all write the
// exact credential pair the public login-screen recovery flow later
// accepts as sufficient to reset the master password — see
// HandleSetRecoveryKit/HandleDeleteRecoveryKit's server-side comments.
// So all three are gated behind confirming the CURRENT master password
// (and a live 2FA code, if enabled) first, the same re-auth panel either
// way — a bearer token alone must never be enough to touch this.
let recoveryKitReauthAction = null; // "set" | "delete" | null

function openRecoveryKitReauth(action) {
  recoveryKitReauthAction = action;
  $("#recovery-kit-reauth-password").value = "";
  $("#recovery-kit-reauth-code").value = "";
  $("#recovery-kit-reauth-2fa-row").hidden = !session.user.totp_2fa_enabled;
  $("#recovery-kit-reauth-error").hidden = true;
  $("#recovery-kit-reauth-panel").hidden = false;
}

async function createOrRegenerateRecoveryKit(currentAuthKeyB64, code) {
  const recoveryCode = generateRecoveryCode();
  const { recoveryAuthKeyB64, recoveryWrapKey } = await deriveRecoveryKeys(recoveryCode);
  const wrappedVaultKeyForRecovery = await wrapKeyBytes(session.vaultKey, recoveryWrapKey);
  await api("v1/auth/recovery-kit", {
    method: "POST",
    body: JSON.stringify({
      current_auth_key: currentAuthKeyB64,
      code,
      recovery_auth_key: recoveryAuthKeyB64,
      wrapped_vault_key_for_recovery: wrappedVaultKeyForRecovery,
    }),
  });
  $("#recovery-kit-unconfigured-state").hidden = true;
  $("#recovery-kit-configured-state").hidden = false;
  $("#recovery-kit-code").textContent = formatRecoveryCode(recoveryCode);
  $("#recovery-kit-reveal-panel").hidden = false;
}

$("#create-recovery-kit-btn").addEventListener("click", () => openRecoveryKitReauth("set"));
$("#regenerate-recovery-kit-btn").addEventListener("click", () => openRecoveryKitReauth("set"));
$("#remove-recovery-kit-btn").addEventListener("click", () => openRecoveryKitReauth("delete"));

$("#recovery-kit-done-btn").addEventListener("click", () => {
  $("#recovery-kit-reveal-panel").hidden = true;
  $("#recovery-kit-code").textContent = "";
});

$("#recovery-kit-reauth-cancel-btn").addEventListener("click", () => {
  $("#recovery-kit-reauth-panel").hidden = true;
  recoveryKitReauthAction = null;
});

$("#recovery-kit-reauth-confirm-btn").addEventListener("click", async () => {
  const errorEl = $("#recovery-kit-reauth-error");
  errorEl.hidden = true;
  const password = $("#recovery-kit-reauth-password").value;
  const code = $("#recovery-kit-reauth-code").value.trim();
  if (!password) return;
  try {
    const kdf = {
      memory_kib: session.user.kdf_memory_kib,
      iterations: session.user.kdf_iterations,
      parallelism: session.user.kdf_parallelism,
      salt: session.user.kdf_salt,
    };
    const { authKeyB64 } = await deriveKeys(password, kdf);
    if (recoveryKitReauthAction === "set") {
      await createOrRegenerateRecoveryKit(authKeyB64, code);
    } else if (recoveryKitReauthAction === "delete") {
      await api("v1/auth/recovery-kit", {
        method: "DELETE",
        body: JSON.stringify({ current_auth_key: authKeyB64, code }),
      });
      await updateRecoveryKitUI();
    }
    $("#recovery-kit-reauth-panel").hidden = true;
    recoveryKitReauthAction = null;
  } catch (err) {
    errorEl.textContent = err.message || "Something went wrong. Please try again.";
    errorEl.hidden = false;
  }
});

// --- Recent activity (audit log) -------------------------------------
// Read-only view of internal/api's audit() call sites, scoped server-side
// to the caller's own events only.

const AUDIT_EVENT_LABELS = {
  "user.registered": "Account created",
  "user.login": "Logged in",
  "user.login_failed": "Failed login attempt",
  "user.login_2fa_pending": "Password correct, 2FA required",
  "user.login_2fa_failed": "Failed 2FA code at login",
  "user.login_2fa_recovery_code_used": "Logged in using a 2FA recovery code",
  "user.logout": "Logged out",
  "user.password_changed": "Master password changed",
  "user.2fa_enabled": "Two-factor authentication enabled",
  "user.2fa_disabled": "Two-factor authentication disabled",
  "user.2fa_recovery_codes_regenerated": "2FA recovery codes regenerated",
  "user.recovery_kit_created": "Account recovery kit created",
  "user.recovery_kit_removed": "Account recovery kit removed",
  "user.recovery_verified": "Recovery code verified (password not yet changed)",
  "user.recovery_2fa_failed": "Failed 2FA code during account recovery",
  "user.recovery_completed": "Account recovered — master password reset",
  "user.recovery_failed": "Failed account recovery attempt",
  "device.revoked": "Device signed out",
  "cipher.shared": "Shared an item",
  "send.created": "Created a Send",
  "send.revoked": "Revoked a Send",
  "send.accessed": "A Send was opened by its recipient",
  "send.access_attempt": "Someone attempted to open a password-protected Send",
  "email_alias.configured": "Email alias provider connected",
  "emergency_access.invited": "Invited an emergency contact",
  "emergency_access.confirmed": "Confirmed an emergency contact",
  "emergency_access.requested": "Requested emergency access",
  "emergency_access.approved": "Approved an emergency access request",
  "emergency_access.rejected": "Rejected an emergency access request",
  "emergency_access.auto_granted": "Emergency access auto-granted (wait period elapsed)",
  "emergency_access.removed": "Removed an emergency access relationship",
  "emergency_access.vault_viewed": "An emergency contact viewed your vault",
  "emergency_access.takeover": "Emergency access takeover performed",
};

async function renderAuditLog() {
  const list = $("#audit-log-list");
  const empty = $("#audit-log-empty");
  let events;
  try {
    events = await api("v1/audit-log");
  } catch {
    return;
  }
  list.innerHTML = "";
  empty.hidden = events.length > 0;
  for (const e of events) {
    const li = document.createElement("li");
    li.className = "audit-row";
    const label = AUDIT_EVENT_LABELS[e.event] || e.event;
    const target = e.target ? ` — ${escapeHTML(e.target)}` : "";
    li.innerHTML = `
      <span>${escapeHTML(label)}${target}</span>
      <span class="audit-meta">${escapeHTML(new Date(e.created_at).toLocaleString())}${e.ip ? `<br>${escapeHTML(e.ip)}` : ""}</span>
    `;
    list.appendChild(li);
  }
}

// --- Passkey unlock (device-local, opt-in) ---------------------------------
// Lets a device skip retyping the master password using Touch ID/Windows
// Hello/a security key, via the WebAuthn PRF extension (see passkey.js).
// What's cached is a small JSON blob {vault_key, x25519_private_key,
// refresh_token}, AES-256-GCM-wrapped (crypto.js's derivePasskeyWrapKey)
// under a key that only the platform authenticator can reproduce — nothing
// server-side changes, and nothing here is synced across devices/browsers,
// same as Bitwarden's own local biometric-unlock design. Keyed by email
// (an object, not a single slot) so two accounts on the same shared browser
// don't silently clobber each other's enrollment.
const PASSKEY_STORAGE_KEY = "passvault_passkey_unlock_v1";

function loadPasskeyRecords() {
  try {
    return JSON.parse(localStorage.getItem(PASSKEY_STORAGE_KEY) || "{}");
  } catch {
    return {};
  }
}

function savePasskeyRecord(email, record) {
  const all = loadPasskeyRecords();
  all[email] = record;
  localStorage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(all));
}

function clearPasskeyRecord(email) {
  const all = loadPasskeyRecords();
  delete all[email];
  localStorage.setItem(PASSKEY_STORAGE_KEY, JSON.stringify(all));
}

// Which enrolled account to offer on the lock screen: whichever one was
// enrolled/unlocked most recently, tracked separately since object key
// order isn't a safe thing to rely on for that.
function mostRecentPasskeyEmail() {
  const all = loadPasskeyRecords();
  const last = localStorage.getItem("passvault_passkey_last_email");
  if (last && all[last]) return last;
  const keys = Object.keys(all);
  return keys.length ? keys[0] : null;
}

function rememberPasskeyEmail(email) {
  localStorage.setItem("passvault_passkey_last_email", email);
}

function initPasskeyLoginUI() {
  const email = mostRecentPasskeyEmail();
  const row = $("#passkey-unlock-row");
  if (!email) {
    row.hidden = true;
    return;
  }
  $("#passkey-unlock-email").textContent = email;
  row.hidden = false;
  $(".tabs").hidden = true;
  $("#login-form").hidden = true;
  $("#register-form").hidden = true;
}

function showPasswordLoginInstead(prefillEmail) {
  $("#passkey-unlock-row").hidden = true;
  $(".tabs").hidden = false;
  $("#login-form").hidden = false;
  if (prefillEmail) $("#login-email").value = prefillEmail;
}

$("#passkey-use-password-link").addEventListener("click", (e) => {
  e.preventDefault();
  showPasswordLoginInstead(mostRecentPasskeyEmail());
});

$("#passkey-unlock-btn").addEventListener("click", async () => {
  showError("");
  const email = mostRecentPasskeyEmail();
  const record = email && loadPasskeyRecords()[email];
  if (!record) return;
  try {
    const prfSecret = await evalPRF(fromB64(record.credentialId));
    if (!prfSecret) {
      throw new Error("Passkey unlock isn't available for this account on this browser anymore.");
    }
    const wrapKey = await derivePasskeyWrapKey(prfSecret);
    const payload = await decryptJSON(record.wrappedBlob, wrapKey);

    const tokens = await api("v1/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token: payload.refresh_token }),
    });

    // The refresh token is single-use (server rotates it on every call) —
    // immediately re-wrap and persist the NEW one, or the next unlock
    // attempt on this device would fail with a dead token.
    savePasskeyRecord(email, {
      ...record,
      wrappedBlob: await encryptJSON({ ...payload, refresh_token: tokens.refresh_token }, wrapKey),
    });

    session.accessToken = tokens.access_token;
    session.refreshToken = tokens.refresh_token;
    session.vaultKey = fromB64(payload.vault_key);
    session.x25519PrivateKeyBytes = fromB64(payload.x25519_private_key);
    session.user = { email };
    await enterVault();
  } catch (err) {
    showError("Passkey unlock failed: " + err.message);
    showPasswordLoginInstead(email);
  }
});

// Reflects current enrollment state in the Security Check view; called
// whenever that view is opened and right after enable/disable.
async function updatePasskeyUI() {
  const statusEl = $("#passkey-status");
  const enableBtn = $("#enable-passkey-btn");
  const disableBtn = $("#disable-passkey-btn");
  if (!session.user) return;
  if (!isPasskeySupported()) {
    enableBtn.hidden = true;
    disableBtn.hidden = true;
    statusEl.textContent = "This browser doesn't support passkeys.";
    return;
  }
  const enrolled = Boolean(loadPasskeyRecords()[session.user.email]);
  enableBtn.hidden = enrolled;
  disableBtn.hidden = !enrolled;
  statusEl.textContent = enrolled ? "Passkey unlock is enabled on this device." : "";
}

$("#enable-passkey-btn").addEventListener("click", async () => {
  const statusEl = $("#passkey-status");
  statusEl.textContent = "";
  try {
    const { credentialIdBytes, prfSecret } = await registerPasskey(session.user.email);
    const wrapKey = await derivePasskeyWrapKey(prfSecret);
    const payload = {
      vault_key: toB64(session.vaultKey),
      x25519_private_key: toB64(session.x25519PrivateKeyBytes),
      refresh_token: session.refreshToken,
    };
    savePasskeyRecord(session.user.email, {
      credentialId: toB64(credentialIdBytes),
      wrappedBlob: await encryptJSON(payload, wrapKey),
    });
    rememberPasskeyEmail(session.user.email);
    await updatePasskeyUI();
  } catch (err) {
    statusEl.textContent = "Couldn't enable passkey unlock: " + err.message;
  }
});

$("#disable-passkey-btn").addEventListener("click", async () => {
  if (!session.user) return;
  clearPasskeyRecord(session.user.email);
  await updatePasskeyUI();
});

initPasskeyLoginUI();

async function api(path, opts = {}) {
  // Fail fast with a clear message instead of a slow, confusing generic
  // "Failed to fetch" — every caller already surfaces err.message as-is,
  // so this reaches the user directly, whether the call is a normal
  // request or refreshItems()'s own sync (which specifically catches
  // this to fall back to its offline cache — see below).
  if (!navigator.onLine) throw new Error("You're offline — this needs a connection.");
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (session.accessToken) headers["Authorization"] = "Bearer " + session.accessToken;
  const res = await fetch(path, { ...opts, headers });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

// --- Registration ---------------------------------------------------------

$("#register-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError("");
  const inviteToken = $("#reg-invite-token").value.trim();
  const email = $("#reg-email").value.trim();
  const password = $("#reg-password").value;
  if ($("#reg-password-confirm").value !== password) {
    showError("Passwords don't match");
    return;
  }
  try {
    const kdf = defaultKDFParams();
    const { authKeyB64, wrapKey } = await deriveKeys(password, kdf);
    const vaultKey = generateKey();
    const wrappedVaultKey = await wrapKeyBytes(vaultKey, wrapKey);
    const { publicKeyB64, privateKeyBytes } = await generateX25519KeyPair();
    const wrappedX25519PrivateKey = await wrapKeyBytes(privateKeyBytes, vaultKey);

    const resp = await api("v1/auth/register", {
      method: "POST",
      body: JSON.stringify({
        invite_token: inviteToken,
        email,
        kdf,
        auth_key: authKeyB64,
        wrapped_vault_key: wrappedVaultKey,
        x25519_public_key: publicKeyB64,
        wrapped_x25519_private_key: wrappedX25519PrivateKey,
      }),
    });

    session.accessToken = resp.tokens.access_token;
    session.refreshToken = resp.tokens.refresh_token;
    session.vaultKey = vaultKey;
    session.x25519PrivateKeyBytes = privateKeyBytes; // already unwrapped — we just generated it
    session.user = resp.user;
    await enterVault();
  } catch (err) {
    showError(err.message);
  }
});

// --- Login -----------------------------------------------------------------

// Bridges the two-phase 2FA login: phase one (authKey check) already
// derived wrapKey from the master password, but the vault can't be
// unwrapped until phase two (the TOTP/recovery code) also succeeds — so
// wrapKey has to survive in memory between the two form submissions
// rather than being a local var scoped to just the first handler.
let pendingLogin = null; // { loginChallenge, wrapKey } | null

async function completeLogin(resp, wrapKey) {
  session.vaultKey = await unwrapKeyBytes(resp.user.wrapped_vault_key, wrapKey);
  session.x25519PrivateKeyBytes = await unwrapKeyBytes(resp.user.wrapped_x25519_private_key, session.vaultKey);
  session.accessToken = resp.tokens.access_token;
  session.refreshToken = resp.tokens.refresh_token;
  session.user = resp.user;
  await enterVault();
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError("");
  const email = $("#login-email").value.trim();
  const password = $("#login-password").value;
  try {
    const kdf = await api("v1/auth/prelogin?email=" + encodeURIComponent(email));
    const { authKeyB64, wrapKey } = await deriveKeys(password, kdf);
    const resp = await api("v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, auth_key: authKeyB64 }),
    });

    if (resp.requires_2fa) {
      pendingLogin = { loginChallenge: resp.login_challenge, wrapKey };
      $("#login-form").hidden = true;
      $("#login-2fa-form").hidden = false;
      $("#login-2fa-code").value = "";
      $("#login-2fa-code").focus();
      return;
    }
    await completeLogin(resp, wrapKey);
  } catch (err) {
    // Deliberately generic per the server's own error message — this UI
    // must not add back a distinction the server chose not to make.
    showError(err.message);
  }
});

$("#login-2fa-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  showError("");
  if (!pendingLogin) return;
  try {
    const resp = await api("v1/auth/login/2fa", {
      method: "POST",
      body: JSON.stringify({ login_challenge: pendingLogin.loginChallenge, code: $("#login-2fa-code").value.trim() }),
    });
    await completeLogin(resp, pendingLogin.wrapKey);
    pendingLogin = null;
  } catch (err) {
    showError(err.message);
  }
});

$("#login-2fa-cancel-link").addEventListener("click", (e) => {
  e.preventDefault();
  pendingLogin = null;
  showError("");
  $("#login-2fa-form").hidden = true;
  $("#login-form").hidden = false;
  $("#login-password").value = "";
});

// --- Account recovery (forgot master password) ------------------------
// Uses the recovery kit set up under Security Check (see crypto.js's
// deriveRecoveryKeys): recoveryWrapKey unwraps the SAME vaultKey the
// account already has, so setting a new master password here is exactly
// auth.ChangePassword's re-wrap trick — no data is lost, nothing about
// the vault's contents changes.

let pendingRecovery = null; // { challenge, wrapKey: recoveryWrapKey, wrappedVaultKeyForRecovery } | null

function showRecoveryFlow() {
  $("#passkey-unlock-row").hidden = true;
  $(".tabs").hidden = true;
  $("#login-form").hidden = true;
  $("#login-2fa-form").hidden = true;
  $("#recovery-flow").hidden = false;
  $("#recovery-step-verify").hidden = false;
  $("#recovery-step-finish").hidden = true;
  $("#recovery-verify-error").hidden = true;
  $("#recovery-finish-error").hidden = true;
  $("#auth-hero-title").textContent = "Recover your vault";
  $("#auth-hero-sub").textContent = "Your recovery kit unwraps the same vault key you already have — nothing is lost, and no one but you can do this step.";
  showError("");
}

function hideRecoveryFlow() {
  pendingRecovery = null;
  $("#recovery-flow").hidden = true;
  $(".tabs").hidden = false;
  $("#login-form").hidden = false;
  const [title, sub] = AUTH_HERO_COPY.login;
  $("#auth-hero-title").textContent = title;
  $("#auth-hero-sub").textContent = sub;
  showError("");
}

$("#forgot-password-link").addEventListener("click", (e) => {
  e.preventDefault();
  showRecoveryFlow();
});

$("#recovery-cancel-link").addEventListener("click", (e) => {
  e.preventDefault();
  hideRecoveryFlow();
});

$("#recovery-verify-btn").addEventListener("click", async () => {
  const errorEl = $("#recovery-verify-error");
  errorEl.hidden = true;
  const email = $("#recovery-email").value.trim();
  const codeBytes = parseRecoveryCode($("#recovery-code-input").value);
  if (!codeBytes) {
    errorEl.textContent = "That doesn't look like a valid recovery code.";
    errorEl.hidden = false;
    return;
  }
  try {
    const { recoveryAuthKeyB64, recoveryWrapKey } = await deriveRecoveryKeys(codeBytes);
    const resp = await api("v1/auth/recovery/verify", {
      method: "POST",
      body: JSON.stringify({ email, recovery_auth_key: recoveryAuthKeyB64 }),
    });
    pendingRecovery = {
      challenge: resp.recovery_challenge,
      wrapKey: recoveryWrapKey,
      wrappedVaultKeyForRecovery: resp.wrapped_vault_key_for_recovery,
    };
    $("#recovery-2fa-row").hidden = !resp.requires_2fa;
    $("#recovery-new-password").value = "";
    $("#recovery-new-password-confirm").value = "";
    $("#recovery-2fa-code").value = "";
    $("#recovery-step-verify").hidden = true;
    $("#recovery-step-finish").hidden = false;
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#recovery-finish-btn").addEventListener("click", async () => {
  const errorEl = $("#recovery-finish-error");
  errorEl.hidden = true;
  if (!pendingRecovery) return;
  const newPassword = $("#recovery-new-password").value;
  if (!newPassword || newPassword !== $("#recovery-new-password-confirm").value) {
    errorEl.textContent = "Passwords don't match.";
    errorEl.hidden = false;
    return;
  }
  try {
    const vaultKey = await unwrapKeyBytes(pendingRecovery.wrappedVaultKeyForRecovery, pendingRecovery.wrapKey);
    const kdf = defaultKDFParams();
    const { authKeyB64, wrapKey: newWrapKey } = await deriveKeys(newPassword, kdf);
    const newWrappedVaultKey = await wrapKeyBytes(vaultKey, newWrapKey);

    const resp = await api("v1/auth/recovery/finish", {
      method: "POST",
      body: JSON.stringify({
        recovery_challenge: pendingRecovery.challenge,
        code: $("#recovery-2fa-code").value.trim(),
        kdf,
        new_auth_key: authKeyB64,
        new_wrapped_vault_key: newWrappedVaultKey,
      }),
    });
    pendingRecovery = null;
    // Only hide the recovery form once completeLogin actually succeeds —
    // if it throws (it shouldn't, but see the empty-message fallback
    // below for why that's worth guarding), the user stays on a form
    // that still shows a real error instead of a blank screen.
    await completeLogin(resp, newWrapKey);
    $("#recovery-flow").hidden = true;
  } catch (err) {
    // AES-GCM decrypt failures throw a DOMException with an EMPTY
    // message ("OperationError") — without this fallback, a real failure
    // here silently shows nothing, which is exactly how a genuine server
    // bug (stale wrapped_vault_key in the response) went unnoticed
    // during testing until console logging exposed it.
    errorEl.textContent = err.message || "Something went wrong finishing recovery. Please try again.";
    errorEl.hidden = false;
  }
});

// --- Vault -------------------------------------------------------------

function timeOfDayGreeting() {
  const h = new Date().getHours();
  return h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
}

async function enterVault() {
  authView.hidden = true;
  vaultView.hidden = false;
  setOfflineBannerVisible(!navigator.onLine);
  $("#vault-email").textContent = session.user.email;
  $("#vault-avatar").textContent = session.user.email[0]?.toUpperCase() || "?";
  // Just the local part of the email as a stand-in name — there's no
  // separate display-name field in the data model, and fabricating one
  // would be worse than using what's actually there.
  const localPart = session.user.email.split("@")[0];
  $("#greeting-text").textContent = `${timeOfDayGreeting()}, ${localPart}`;
  $("#greeting-sub").textContent = new Date().toLocaleDateString(undefined, {
    weekday: "long", year: "numeric", month: "long", day: "numeric",
  });
  await refreshItems();
  startTotpTimer();
}

// itemsById backs the TOTP refresh timer: it needs the decrypted item
// (for the secret) without re-decrypting every tick, keyed by cipher id
// so the timer can find the right DOM nodes to update.
const itemsById = new Map();
// Items someone ELSE owns and shared with this account — kept separate
// from itemsById rather than merged in with an "owned" flag, since so much
// else (stats, folder/type filters, the TOTP timer) is written assuming
// itemsById == "my own vault".
const sharedWithMeById = new Map();
let totpTimer = null;

function startTotpTimer() {
  if (totpTimer) return;
  updateAllTotpCodes();
  totpTimer = setInterval(updateAllTotpCodes, 1000);
}

function stopTotpTimer() {
  clearInterval(totpTimer);
  totpTimer = null;
  itemsById.clear();
}

// An item with a TOTP secret can now be rendered twice at once — once in
// the main vault list, once in the Authenticator panel (see
// renderAuthenticatorPanel) — so this updates every matching node
// (querySelectorAll, not querySelector) across the whole document, not
// just one list.
async function updateAllTotpCodes() {
  for (const [id, { item }] of itemsById) {
    const parsed = parseTOTPInput(item.totp);
    if (!parsed) continue;
    const result = await generateTOTP(parsed);
    if (!result) continue;
    for (const codeEl of document.querySelectorAll(`.totp-code[data-id="${id}"]`)) {
      codeEl.textContent = result.code.slice(0, 3) + " " + result.code.slice(3);
    }
    for (const barEl of document.querySelectorAll(`.totp-bar[data-id="${id}"]`)) {
      barEl.style.width = (result.secondsRemaining / result.period) * 100 + "%";
    }
  }
}

// folders: decrypted {id, name}[], rebuilt on every refresh — small enough
// (one per real-world folder, not per item) that there's no need to cache
// across refreshes the way itemsById does for the TOTP timer.
let folders = [];
// "all" | "unfiled" | <folder id number> — client-side filter only, no
// re-fetch needed since refreshItems already decrypted everything.
let currentFolderFilter = "all";
// "all" | "login" | "note" | "card" | "identity" | "totp"
let currentTypeFilter = "all";
// Lowercased substring match against item.name — also client-side only.
let currentSearchQuery = "";

// The type-filter pills are static markup (unlike folder pills, which are
// generated per-folder), so they're wired once here rather than re-bound
// on every render.
for (const pill of document.querySelectorAll("#type-filters .pill")) {
  pill.addEventListener("click", () => {
    currentTypeFilter = pill.dataset.typeKey;
    for (const p of document.querySelectorAll("#type-filters .pill")) p.classList.toggle("active", p === pill);
    renderVisibleItems();
  });
}

$("#vault-search").addEventListener("input", () => {
  currentSearchQuery = $("#vault-search").value.trim().toLowerCase();
  renderVisibleItems();
});

async function refreshItems() {
  let data;
  let usingCachedData = false;
  try {
    data = await api("v1/sync?since=0");
    cacheSyncResponse(session.user.email, data);
  } catch (err) {
    // Offline (or the server's genuinely unreachable): fall back to the
    // last successful sync response, still exactly as opaque as it was
    // over the wire — nothing extra gets decrypted or persisted here,
    // this is the SAME ciphertext the server already sent us once. Only
    // useful within an already-unlocked session (session.vaultKey is
    // still in memory); a reload while offline is unaffected by this —
    // see the memory-only session comment at the top of this file.
    const cached = loadCachedSyncResponse(session.user.email);
    if (!cached) throw err; // nothing to fall back to — let the real error surface
    data = cached;
    usingCachedData = true;
  }
  setOfflineBannerVisible(usingCachedData || !navigator.onLine);
  itemsById.clear();

  folders = [];
  for (const f of data.folders || []) {
    if (f.deleted_at) continue;
    const folderKey = await unwrapKeyBytes(f.wrapped_folder_key, session.vaultKey);
    const { name } = await decryptJSON(f.encrypted_name, folderKey);
    folders.push({ id: f.id, name });
  }
  // A filter pointing at a folder that no longer exists (deleted from
  // another device, or by this one) falls back to "all" rather than
  // silently rendering an empty list with no explanation.
  if (typeof currentFolderFilter === "number" && !folders.some((f) => f.id === currentFolderFilter)) {
    currentFolderFilter = "all";
  }

  for (const cipher of data.ciphers || []) {
    if (cipher.deleted_at) continue;
    const itemKey = await unwrapKeyBytes(cipher.wrapped_item_key, session.vaultKey);
    const item = await decryptJSON(cipher.encrypted_blob, itemKey);
    itemsById.set(cipher.id, { type: cipher.type, item, itemKey, folderId: cipher.folder_id ?? null });
  }

  sharedWithMeById.clear();
  for (const sc of data.shared_ciphers || []) {
    try {
      const shareWrapKey = await deriveSharedWrapKey(session.x25519PrivateKeyBytes, sc.owner_x25519_public_key);
      const itemKey = await unwrapKeyBytes(sc.wrapped_item_key, shareWrapKey);
      const item = await decryptJSON(sc.encrypted_blob, itemKey);
      sharedWithMeById.set(sc.id, { type: sc.type, item, itemKey, ownerEmail: sc.owner_email });
    } catch {
      // Undecryptable share (stale key, tampered row) is skipped rather
      // than aborting the whole sync — it just doesn't appear.
    }
  }

  renderFolderUI();
  renderStats();
  renderVisibleItems();
  renderAuthenticatorPanel();
  renderSharedWithMe();
  renderSecurityView();
  await updateAllTotpCodes();
}

function renderSharedWithMe() {
  const section = $("#shared-with-me-section");
  const list = $("#shared-with-me-list");
  list.innerHTML = "";
  for (const [id, entry] of sharedWithMeById) {
    list.appendChild(renderSharedItem(id, entry.type, entry.item, entry.itemKey, entry.ownerEmail));
  }
  section.hidden = sharedWithMeById.size === 0;
}

// --- Security check (strength + reuse are instant/local; breach check is
// opt-in and hits an external API — see hibp.js) --------------------------

// Scoped to Login passwords only: card numbers/CVVs and identity fields
// aren't "passwords" in the sense strength/reuse/breach checking applies
// to, matching how Bitwarden's own Password Health report is scoped.
let securityEntries = [];

function collectLoginPasswords() {
  const out = [];
  for (const [id, entry] of itemsById) {
    if (entry.type === "login" && entry.item.password) {
      out.push({ id, name: entry.item.name || "(untitled)", password: entry.item.password });
    }
  }
  return out;
}

function renderSecurityView() {
  securityEntries = collectLoginPasswords();

  const byPassword = new Map();
  for (const e of securityEntries) {
    if (!byPassword.has(e.password)) byPassword.set(e.password, []);
    byPassword.get(e.password).push(e);
  }
  const reusedGroups = [...byPassword.values()].filter((g) => g.length > 1);
  const reusedIds = new Set(reusedGroups.flat().map((e) => e.id));

  const weak = securityEntries.filter((e) => estimateStrength(e.password).score <= 2);
  const weakIds = new Set(weak.map((e) => e.id));

  $("#stat-sec-total").textContent = securityEntries.length;
  $("#stat-sec-weak").textContent = weakIds.size;
  $("#stat-sec-reused").textContent = reusedIds.size;
  $("#stat-sec-secure").textContent = securityEntries.length - new Set([...weakIds, ...reusedIds]).size;

  const weakEl = $("#security-weak-list");
  weakEl.innerHTML = weak
    .map((e) => {
      const { label } = estimateStrength(e.password);
      return `<li class="folder-row"><span>${escapeHTML(e.name)}</span><span class="hint-inline">${escapeHTML(label)}</span></li>`;
    })
    .join("");

  const reusedEl = $("#security-reused-list");
  reusedEl.innerHTML = reusedGroups
    .map(
      (g) =>
        `<li class="folder-row"><span>${g.map((e) => escapeHTML(e.name)).join(", ")}</span><span class="hint-inline">shared by ${g.length}</span></li>`,
    )
    .join("");

  // A previous breach-check result no longer describes the current
  // password set once it's changed — reset rather than show a stale
  // "Compromised: N" that might not match what's actually in the vault now.
  $("#stat-sec-compromised").textContent = "0";
  $("#security-compromised-list").innerHTML = "";
  $("#breach-check-status").textContent = securityEntries.length ? "" : "No login passwords to check yet.";
}

$("#check-breaches-btn").addEventListener("click", async () => {
  const btn = $("#check-breaches-btn");
  const statusEl = $("#breach-check-status");
  if (!securityEntries.length) {
    statusEl.textContent = "No login passwords to check.";
    return;
  }

  btn.disabled = true;
  const uniquePasswords = [...new Set(securityEntries.map((e) => e.password))];
  const breachedPasswords = new Map(); // password -> times-seen count from HIBP
  for (let i = 0; i < uniquePasswords.length; i++) {
    statusEl.textContent = `Checking ${i + 1} of ${uniquePasswords.length} unique password(s)…`;
    try {
      const result = await checkPasswordBreach(uniquePasswords[i]);
      if (result.breached) breachedPasswords.set(uniquePasswords[i], result.count);
    } catch (err) {
      statusEl.textContent = `Breach check failed: ${err.message}`;
      btn.disabled = false;
      return;
    }
  }

  const compromised = securityEntries.filter((e) => breachedPasswords.has(e.password));
  $("#stat-sec-compromised").textContent = compromised.length;
  $("#security-compromised-list").innerHTML = compromised
    .map(
      (e) =>
        `<li class="folder-row"><span>${escapeHTML(e.name)}</span><span class="hint-inline" style="color:var(--danger)">Seen ${breachedPasswords.get(e.password).toLocaleString()} times in known breaches</span></li>`,
    )
    .join("");
  statusEl.textContent = compromised.length
    ? `Checked ${uniquePasswords.length} unique password(s) — ${compromised.length} item(s) use a breached password.`
    : `Checked ${uniquePasswords.length} unique password(s) against Have I Been Pwned — none were found in known breaches.`;
  btn.disabled = false;
});

// Real counts from the actual decrypted data — no fabricated "security
// score" or breach-check numbers, since this app doesn't have those
// features yet (see README roadmap). Only what's genuinely known.
let statIconsPainted = false;

function renderStats() {
  const counts = { login: 0, note: 0, card: 0, identity: 0, ssh_key: 0 };
  let total = 0;
  // "TOTP codes" counts anything with a secret set, not just type==="totp"
  // — a Login item with a TOTP secret has one too, and the Authenticator
  // panel already treats both the same way.
  let totpCount = 0;
  for (const [, entry] of itemsById) {
    total++;
    if (counts[entry.type] !== undefined) counts[entry.type]++;
    if (entry.item.totp) totpCount++;
  }
  $("#stat-total").textContent = total;
  $("#stat-login").textContent = counts.login;
  $("#stat-note").textContent = counts.note;
  $("#stat-card").textContent = counts.card;
  $("#stat-identity").textContent = counts.identity;
  $("#stat-totp").textContent = totpCount;
  $("#stat-ssh_key").textContent = counts.ssh_key;

  // Dim whichever breakdown boxes are empty, so the eye lands on the
  // categories that actually have something in them instead of scanning
  // seven identically-weighted "0"s.
  const byType = { login: counts.login, note: counts.note, card: counts.card, identity: counts.identity, totp: totpCount, ssh_key: counts.ssh_key };
  for (const [type, count] of Object.entries(byType)) {
    $(`#stat-box-${type}`)?.classList.toggle("zero", count === 0);
  }
  if (!statIconsPainted) {
    for (const type of Object.keys(byType)) {
      const el = $(`#stat-icon-${type}`);
      if (el) el.innerHTML = TYPE_ICONS[type] || "";
    }
    statIconsPainted = true;
  }
}

// The Authenticator panel is a dedicated view of every item that carries a
// TOTP secret, regardless of how it got one — a bare code added here, or
// any Login item with a TOTP secret set. It reuses renderItem verbatim
// (same card, same reveal/copy/delete behavior) so a "totp" item looks and
// behaves identically whether it's showing in the main vault list or here;
// this is purely a filtered second view, not a different data model.
function renderAuthenticatorPanel() {
  authEl.innerHTML = "";
  let count = 0;
  for (const [id, entry] of itemsById) {
    if (!entry.item.totp) continue;
    authEl.appendChild(renderItem(id, entry.type, entry.item, entry.itemKey, entry.folderId));
    count++;
  }
  authEmpty.hidden = count > 0;
}

function renderVisibleItems() {
  itemsEl.innerHTML = "";
  let count = 0;
  for (const [id, entry] of itemsById) {
    if (currentFolderFilter === "unfiled" && entry.folderId != null) continue;
    if (typeof currentFolderFilter === "number" && entry.folderId !== currentFolderFilter) continue;
    if (currentTypeFilter !== "all" && entry.type !== currentTypeFilter) continue;
    if (currentSearchQuery && !(entry.item.name || "").toLowerCase().includes(currentSearchQuery)) continue;
    itemsEl.appendChild(renderItem(id, entry.type, entry.item, entry.itemKey, entry.folderId));
    count++;
  }
  emptyState.hidden = count > 0;
  const trulyEmpty = currentFolderFilter === "all" && currentTypeFilter === "all" && !currentSearchQuery;
  emptyStateText.textContent = trulyEmpty
    ? "Nothing saved yet — add your first login, note, or key and it's encrypted before it ever leaves your browser."
    : "No items match this view — try a different filter or search term.";
  $("#empty-state-add-btn").hidden = !trulyEmpty;
}

function renderFolderUI() {
  const filterBar = $("#folder-filters");
  const pills = [
    { key: "all", label: "All" },
    { key: "unfiled", label: "Unfiled" },
    ...folders.map((f) => ({ key: f.id, label: f.name })),
  ];
  filterBar.innerHTML = pills
    .map(
      (p) =>
        `<button type="button" class="pill${p.key === currentFolderFilter ? " active" : ""}" data-key="${escapeHTML(String(p.key))}">${escapeHTML(p.label)}</button>`,
    )
    .join("");
  for (const btn of filterBar.querySelectorAll(".pill")) {
    btn.addEventListener("click", () => {
      const key = btn.dataset.key;
      currentFolderFilter = key === "all" || key === "unfiled" ? key : parseInt(key, 10);
      renderFolderUI();
      renderVisibleItems();
    });
  }

  const list = $("#folder-list");
  list.innerHTML = folders
    .map(
      (f) =>
        `<li class="folder-row"><span>${escapeHTML(f.name)}</span><button type="button" class="btn-icon danger" data-folder-id="${f.id}" aria-label="Delete folder" data-tip="Delete folder">${TRASH_ICON}</button></li>`,
    )
    .join("");
  for (const btn of list.querySelectorAll("[data-folder-id]")) {
    btn.addEventListener("click", async () => {
      await api(`v1/folders/${btn.dataset.folderId}`, { method: "DELETE" });
      await refreshItems();
    });
  }

  const select = $("#item-folder");
  const prevValue = select.value;
  select.innerHTML =
    '<option value="">No folder</option>' +
    folders.map((f) => `<option value="${f.id}">${escapeHTML(f.name)}</option>`).join("");
  select.value = folders.some((f) => String(f.id) === prevValue) ? prevValue : "";
}

// Shared by the folder form below and the importer (which creates any
// folder named in the import file that doesn't already exist here).
// Returns the new folder's id.
async function createFolder(name) {
  const folderKey = generateKey();
  const wrappedFolderKey = await wrapKeyBytes(folderKey, session.vaultKey);
  const encryptedName = await encryptJSON({ name }, folderKey);
  const resp = await api("v1/folders", {
    method: "POST",
    body: JSON.stringify({ wrapped_folder_key: wrappedFolderKey, encrypted_name: encryptedName }),
  });
  return resp.id;
}

$("#add-folder-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#new-folder-name").value.trim();
  if (!name) return;
  await createFolder(name);
  e.target.reset();
  await refreshItems();
});

// --- Import / Export --------------------------------------------------
// Export decrypts everything already held in memory (itemsById/folders —
// no extra network round trip needed) and triggers a plaintext download;
// import parses a file entirely client-side (web/importexport.js, which
// never touches crypto or the network) then encrypts and uploads each
// item the same way the "Add item" form already does, one
// POST /v1/ciphers per item.

let pendingImport = null; // { items: [{type, folder, fields}] } | null

function resetImportExportView() {
  $("#export-password").value = "";
  $("#export-error").hidden = true;
  $("#export-status").textContent = "";
  $("#import-file").value = "";
  $("#import-error").hidden = true;
  $("#import-preview").hidden = true;
  $("#import-progress").hidden = true;
  pendingImport = null;
}

$("#export-btn").addEventListener("click", async () => {
  const errorEl = $("#export-error");
  errorEl.hidden = true;
  const password = $("#export-password").value;
  if (!password) return;
  try {
    // Re-auth gate: proves the CURRENT session still actually knows the
    // master password before dumping the whole vault to plaintext — a
    // hijacked-but-unlocked session shouldn't be able to silently
    // exfiltrate everything just because it's logged in. Verified
    // entirely locally (no server round trip needed): re-derive wrapKey
    // from the typed password and confirm it actually unwraps this
    // account's own wrapped_vault_key — a wrong password fails the
    // AES-GCM auth tag check inside unwrapKeyBytes.
    const kdf = {
      memory_kib: session.user.kdf_memory_kib,
      iterations: session.user.kdf_iterations,
      parallelism: session.user.kdf_parallelism,
      salt: session.user.kdf_salt,
    };
    const { wrapKey } = await deriveKeys(password, kdf);
    await unwrapKeyBytes(session.user.wrapped_vault_key, wrapKey);

    const items = [];
    for (const entry of itemsById.values()) {
      const folderName = entry.folderId ? folders.find((f) => f.id === entry.folderId)?.name || null : null;
      items.push({ type: entry.type, folder: folderName, fields: entry.item });
    }
    const exportData = buildPassvaultExport(items);
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `passvault-export-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    $("#export-password").value = "";
    $("#export-status").textContent = `Exported ${items.length} item(s).`;
  } catch {
    errorEl.textContent = "Wrong master password.";
    errorEl.hidden = false;
  }
});

$("#import-file").addEventListener("change", async () => {
  const errorEl = $("#import-error");
  errorEl.hidden = true;
  $("#import-preview").hidden = true;
  pendingImport = null;
  const file = $("#import-file").files[0];
  if (!file) return;
  const format = IMPORT_FORMATS[$("#import-format").value];
  try {
    const text = await file.text();
    const { items, warnings } = format.parse(text);
    if (!items.length) throw new Error("No importable items found in this file.");
    pendingImport = { items };

    const counts = {};
    for (const it of items) counts[it.type] = (counts[it.type] || 0) + 1;
    const summary = Object.entries(counts)
      .map(([t, n]) => `${n} ${t}${n === 1 ? "" : "s"}`)
      .join(", ");
    $("#import-summary").textContent = `Found ${items.length} item(s): ${summary}.`;
    $("#import-warnings").innerHTML = warnings.map((w) => `<li>${escapeHTML(w)}</li>`).join("");
    $("#import-preview").hidden = false;
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#import-confirm-btn").addEventListener("click", async () => {
  if (!pendingImport) return;
  const items = pendingImport.items;
  pendingImport = null;
  $("#import-preview").hidden = true;
  $("#import-progress").hidden = false;
  const progressEl = $("#import-progress-text");

  // Reuses an existing folder by name if one already matches, otherwise
  // creates it — and only ever creates each named folder once per import,
  // even if many items share it.
  const folderIdByName = new Map(folders.map((f) => [f.name, f.id]));
  let done = 0;
  let failed = 0;
  for (const it of items) {
    progressEl.textContent = `Importing ${done + failed + 1} of ${items.length}…`;
    try {
      let folderId = null;
      if (it.folder) {
        if (!folderIdByName.has(it.folder)) {
          folderIdByName.set(it.folder, await createFolder(it.folder));
        }
        folderId = folderIdByName.get(it.folder);
      }
      const itemKey = generateKey();
      const wrappedItemKey = await wrapKeyBytes(itemKey, session.vaultKey);
      const encryptedBlob = await encryptJSON(it.fields, itemKey);
      await api("v1/ciphers", {
        method: "POST",
        body: JSON.stringify({ type: it.type, folder_id: folderId, wrapped_item_key: wrappedItemKey, encrypted_blob: encryptedBlob }),
      });
      done++;
    } catch {
      failed++;
    }
  }
  progressEl.textContent = `Done — imported ${done} item(s)${failed ? `, ${failed} failed` : ""}.`;
  $("#import-file").value = "";
  await refreshItems();
});

// --- Authenticator (dedicated TOTP-only items) ----------------------------

$("#add-totp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#totp-form-error");
  errorEl.hidden = true;

  const name = $("#totp-name").value.trim();
  const secretInput = $("#totp-secret").value.trim();

  // Validate by actually generating a code, not just checking the string
  // looks base32-ish — parseTOTPInput accepts syntactically-fine garbage
  // that decodes to zero key bytes, and a saved-but-broken code would sit
  // silently wrong until someone tried to use it to log in.
  const parsed = parseTOTPInput(secretInput);
  const testCode = parsed && (await generateTOTP(parsed));
  if (!testCode) {
    errorEl.textContent = "That doesn't look like a valid TOTP secret or otpauth:// URI.";
    errorEl.hidden = false;
    return;
  }

  const item = { name, totp: secretInput };
  const itemKey = generateKey();
  const wrappedItemKey = await wrapKeyBytes(itemKey, session.vaultKey);
  const encryptedBlob = await encryptJSON(item, itemKey);
  await api("v1/ciphers", {
    method: "POST",
    body: JSON.stringify({ type: "totp", folder_id: null, wrapped_item_key: wrappedItemKey, encrypted_blob: encryptedBlob }),
  });
  e.target.reset();
  await refreshItems();
});

const TYPE_ICONS = {
  login: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="8" cy="15" r="4" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="m11 12 8-8m0 0h-5m5 0v5"/></svg>',
  note: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5Z"/><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3v5h5"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M8 13h8M8 17h5"/></svg>',
  card: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="2" y="5" width="20" height="14" rx="2" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" d="M2 10h20"/></svg>',
  identity: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="4" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M4 21c0-4.4 3.6-7 8-7s8 2.6 8 7"/></svg>',
  totp: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M12 7v5l3.5 2"/></svg>',
  ssh_key: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="7" cy="15" r="4" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="m10 12 10-10m0 0h-5m5 0v5m-8 3 2 2m-5 1 2 2"/></svg>',
  text: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3H6a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8l-5-5Z"/><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3v5h5"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M8 13h8M8 17h5"/></svg>',
  file: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path stroke="currentColor" stroke-width="2" stroke-linejoin="round" d="M14 3v5h5"/></svg>',
};

function itemSubtitle(type, item) {
  switch (type) {
    case "login": {
      let hostname = "";
      if (item.uri) {
        try {
          hostname = new URL(item.uri).hostname;
        } catch {
          hostname = item.uri; // not a fully-qualified URL (e.g. imported as a bare domain) — show it verbatim rather than hide it
        }
      }
      return [item.username, hostname].filter(Boolean).join(" · ");
    }
    case "note":
      return (item.notes || "").replace(/\s+/g, " ").slice(0, 60);
    case "card": {
      const last4 = (item.number || "").replace(/\s+/g, "").slice(-4);
      return [item.brand, last4 && `•••• ${last4}`].filter(Boolean).join(" ");
    }
    case "identity":
      return item.email || [item.firstName, item.lastName].filter(Boolean).join(" ");
    case "totp":
      return "One-time code"; // the code itself is already visible in the totp-box, no need to repeat it
    case "ssh_key":
      return [item.keyType, item.fingerprint].filter(Boolean).join(" · ");
    default:
      return "";
  }
}

// Text shown when "reveal" is clicked — the one place actual secret
// content becomes visible in the DOM, same as the password reveal used to
// be login-only. Identity/card also count as sensitive (a card number+CVV
// or a full address is exactly what this app exists to protect).
function itemDetailText(type, item) {
  switch (type) {
    case "login":
      return item.password || "(no password set)";
    case "note":
      return item.notes || "(empty note)";
    case "card":
      return `Number: ${item.number || "—"}\nCVV: ${item.cvv || "—"}\nExpires: ${item.expMonth || "--"}/${item.expYear || "----"}`;
    case "identity":
      return (
        [
          [item.firstName, item.lastName].filter(Boolean).join(" "),
          item.email,
          item.phone,
          [item.address, item.city, item.state, item.postalCode, item.country].filter(Boolean).join(", "),
        ]
          .filter(Boolean)
          .join("\n") || "(no details)"
      );
    case "totp":
      // The raw secret, not the current code — useful if someone needs to
      // re-import it into another authenticator, e.g. before deleting the
      // entry here. The live code has its own copy affordance (click the
      // totp-box itself), so it doesn't need to be duplicated here too.
      return item.totp || "(no secret set)";
    case "ssh_key":
      return (
        [
          item.privateKey && `Private key:\n${item.privateKey}`,
          item.passphrase && `Passphrase: ${item.passphrase}`,
          item.publicKey && `Public key:\n${item.publicKey}`,
        ]
          .filter(Boolean)
          .join("\n\n") || "(no key material set)"
      );
    default:
      return "";
  }
}

// The single field the "copy" quick-action copies — whatever someone
// reaches for this item type most often. null means no copy button at
// all: a note has no one obvious field (and a totp item's code already has
// its own click-to-copy on the totp-box), so those only get "reveal".
function itemCopyValue(type, item) {
  switch (type) {
    case "login":
      return item.password || "";
    case "card":
      return item.number || "";
    case "identity":
      return item.email || "";
    case "ssh_key":
      return item.publicKey || ""; // the field reached for day-to-day (authorized_keys, deploy keys); the private key is still fully visible via "reveal"
    default:
      return null;
  }
}

const EYE_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg>';
const PENCIL_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12.5 5.5 18 11 8 21H3v-5l9.5-10.5Z"/><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="m15 3 3.5 3.5"/></svg>';
const TRASH_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linecap="round" d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13"/></svg>';
const COPY_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="12" height="12" rx="2" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1"/></svg>';
const PAPERCLIP_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="m21 12.5-8.5 8.5a5 5 0 0 1-7-7L14 5.5a3.5 3.5 0 0 1 5 5L10.5 19a2 2 0 0 1-3-3L15 8.5"/></svg>';
const DOWNLOAD_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M12 3v12m0 0 4-4m-4 4-4-4M4 21h16"/></svg>';
const SHARE_ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none"><circle cx="6" cy="12" r="3" stroke="currentColor" stroke-width="2"/><circle cx="18" cy="6" r="3" stroke="currentColor" stroke-width="2"/><circle cx="18" cy="18" r="3" stroke="currentColor" stroke-width="2"/><path stroke="currentColor" stroke-width="2" d="m8.5 10.5 7-3M8.5 13.5l7 3"/></svg>';

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

// Types the add/edit modal actually has a form for — a bare TOTP-only
// cipher (added via the Authenticator tab's own form) has no field group
// here, so it gets no Edit button rather than opening a modal that can't
// represent it.
const EDITABLE_TYPES = new Set(["login", "note", "card", "identity", "ssh_key"]);

function renderItem(id, type, item, itemKey, folderId) {
  const li = document.createElement("li");
  li.className = "item card";
  const totpHTML = item.totp
    ? `<div class="totp-box" data-id="${id}" title="Click to copy code">
         <div class="totp-code" data-id="${id}">------</div>
         <div class="totp-track"><div class="totp-bar" data-id="${id}"></div></div>
       </div>`
    : "";
  const copyValue = itemCopyValue(type, item);
  const copyLabel =
    type === "card" ? "Copy card number" : type === "identity" ? "Copy email" : type === "ssh_key" ? "Copy public key" : "Copy password";
  const copyBtnHTML =
    copyValue !== null
      ? `<button class="btn-icon" data-action="copy" aria-label="${copyLabel}" data-tip="${copyLabel}" type="button">${COPY_ICON}</button>`
      : "";
  const editBtnHTML = EDITABLE_TYPES.has(type)
    ? `<button class="btn-icon" data-action="edit" aria-label="Edit" data-tip="Edit" type="button">${PENCIL_ICON}</button>`
    : "";
  li.innerHTML = `
    <div class="item-icon type-${type}">${TYPE_ICONS[type] || ""}</div>
    <div class="item-main">
      <div class="item-name">${escapeHTML(item.name || "(untitled)")}</div>
      <div class="item-username">${escapeHTML(itemSubtitle(type, item))}</div>
    </div>
    ${totpHTML}
    <div class="item-actions">
      ${copyBtnHTML}
      ${editBtnHTML}
      <button class="btn-icon" data-action="attachments" aria-label="Attachments" data-tip="Attachments" type="button">${PAPERCLIP_ICON}</button>
      <button class="btn-icon" data-action="share" aria-label="Share" data-tip="Share" type="button">${SHARE_ICON}</button>
      <button class="btn-icon" data-action="reveal" aria-label="Show details" data-tip="Show details" type="button">${EYE_ICON}</button>
      <button class="btn-icon danger" data-action="delete" aria-label="Delete" data-tip="Delete" type="button">${TRASH_ICON}</button>
    </div>
    <div class="item-detail" hidden></div>
    <div class="attachments-panel" hidden>
      <div class="attachments-list"></div>
      <label class="attach-upload-btn">
        <input type="file" hidden>
        + Add file (max 25MB)
      </label>
    </div>
    <div class="share-panel" hidden>
      <div class="share-list"></div>
      <div class="share-add-row">
        <input type="email" class="share-email-input" placeholder="Share with email">
        <button type="button" class="btn btn-primary share-add-btn">Share</button>
      </div>
      <p class="share-error hint-inline" style="color:var(--danger)" hidden></p>
    </div>
  `;
  li.querySelector('[data-action="reveal"]').addEventListener("click", () => {
    const detailEl = li.querySelector(".item-detail");
    detailEl.hidden = !detailEl.hidden;
    detailEl.textContent = detailEl.hidden ? "" : itemDetailText(type, item);
  });
  const copyBtn = li.querySelector('[data-action="copy"]');
  if (copyBtn) {
    // Capture the button in this closure rather than reading e.currentTarget
    // after the await below — the DOM spec nulls currentTarget out once
    // event dispatch finishes, which happens well before an async handler's
    // first await resolves, so that pattern throws on every click.
    copyBtn.addEventListener("click", async () => {
      const ok = await copyToClipboard(copyValue || "");
      flashCopied(copyBtn, ok);
    });
  }
  li.querySelector('[data-action="delete"]').addEventListener("click", async () => {
    await api(`v1/ciphers/${id}`, { method: "DELETE" });
    await refreshItems();
  });
  li.querySelector('[data-action="edit"]')?.addEventListener("click", () => {
    openEditItemModal(id, type, item, itemKey, folderId);
  });
  const totpBox = li.querySelector(".totp-box");
  if (totpBox) {
    totpBox.addEventListener("click", async () => {
      const code = li.querySelector(".totp-code").textContent.replace(/\s/g, "");
      const ok = await copyToClipboard(code);
      flashCopied(totpBox, ok);
    });
  }

  wireAttachments(li, id, itemKey);
  wireSharing(li, id, itemKey);
  return li;
}

// Wraps a normal owned-item card into a read-only view for something
// SOMEONE ELSE shared with the caller: no delete, no attachments (those
// belong to the owner's cipher — out of scope for "simple sharing"), no
// re-sharing. Copy/reveal stay, since being able to actually use a shared
// login is the entire point.
function renderSharedItem(id, type, item, itemKey, ownerEmail) {
  const li = renderItem(id, type, item, itemKey);
  li.querySelector('[data-action="delete"]')?.remove();
  li.querySelector('[data-action="edit"]')?.remove(); // edits belong to the owner's cipher, not the recipient's read-only view
  li.querySelector('[data-action="attachments"]')?.remove();
  li.querySelector('[data-action="share"]')?.remove();
  li.querySelector(".attachments-panel")?.remove();
  li.querySelector(".share-panel")?.remove();
  const badge = document.createElement("div");
  badge.className = "item-username";
  badge.textContent = `Shared by ${ownerEmail}`;
  li.querySelector(".item-main").appendChild(badge);
  return li;
}

// --- Attachments (per-item, lazily loaded on first expand) ----------------
// Each attachment gets its own random key, wrapped under the parent item's
// key — the same envelope shape as everything else. The server only ever
// handles ciphertext bytes and an opaque encrypted filename.

function wireAttachments(li, cipherId, itemKey) {
  const btn = li.querySelector('[data-action="attachments"]');
  const panel = li.querySelector(".attachments-panel");
  const list = li.querySelector(".attachments-list");
  const fileInput = li.querySelector('input[type="file"]');
  let loaded = false;

  async function loadAttachments() {
    list.innerHTML = '<span class="hint-inline">Loading…</span>';
    const rows = await api(`v1/ciphers/${cipherId}/attachments`);
    list.innerHTML = "";
    if (!rows.length) {
      list.innerHTML = '<span class="hint-inline">No files attached.</span>';
      return;
    }
    for (const a of rows) {
      const attachmentKey = await unwrapKeyBytes(a.wrapped_attachment_key, itemKey);
      const { name } = await decryptJSON(a.encrypted_filename, attachmentKey);
      const row = document.createElement("div");
      row.className = "attachment-row";
      row.innerHTML = `
        <span>${escapeHTML(name)} <span class="hint-inline">(${formatBytes(a.size_bytes)})</span></span>
        <span style="display:flex;gap:4px">
          <button type="button" class="btn-icon" data-dl aria-label="Download" data-tip="Download">${DOWNLOAD_ICON}</button>
          <button type="button" class="btn-icon danger" data-del aria-label="Delete" data-tip="Delete">${TRASH_ICON}</button>
        </span>
      `;
      row.querySelector("[data-dl]").addEventListener("click", async () => {
        const res = await fetch(`v1/attachments/${a.id}`, {
          headers: { Authorization: "Bearer " + session.accessToken },
        });
        if (!res.ok) return;
        const encryptedBytes = new Uint8Array(await res.arrayBuffer());
        const plainBytes = await decryptBytes(attachmentKey, encryptedBytes);
        const blobUrl = URL.createObjectURL(new Blob([plainBytes]));
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = name;
        link.click();
        URL.revokeObjectURL(blobUrl);
      });
      row.querySelector("[data-del]").addEventListener("click", async () => {
        await api(`v1/attachments/${a.id}`, { method: "DELETE" });
        await loadAttachments();
      });
      list.appendChild(row);
    }
  }

  btn.addEventListener("click", async () => {
    panel.hidden = !panel.hidden;
    if (!panel.hidden && !loaded) {
      loaded = true;
      await loadAttachments();
    }
  });

  fileInput.addEventListener("change", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    const attachmentKey = generateKey();
    const wrappedAttachmentKey = await wrapKeyBytes(attachmentKey, itemKey);
    const encryptedFilename = await encryptJSON({ name: file.name }, attachmentKey);
    const encryptedBytes = await encryptBytes(attachmentKey, new Uint8Array(await file.arrayBuffer()));

    const form = new FormData();
    form.set("wrapped_attachment_key", wrappedAttachmentKey);
    form.set("encrypted_filename", encryptedFilename);
    form.set("file", new Blob([encryptedBytes]), "encrypted"); // the part filename is opaque/unused server-side

    await fetch(`v1/ciphers/${cipherId}/attachments`, {
      method: "POST",
      headers: { Authorization: "Bearer " + session.accessToken },
      body: form,
    });
    fileInput.value = "";
    loaded = true;
    await loadAttachments();
  });
}

// --- Item sharing (per-item, lazily loaded on first expand) ---------------
// Sharing computes an ECDH-derived wrap key from the owner's private key
// and the recipient's public key (deriveSharedWrapKey) and wraps THIS
// item's existing itemKey with it — the item's own encryption never
// changes, only who else can unwrap the key to it. See crypto.js and
// internal/db/db.go's cipher_shares table comment.

function wireSharing(li, cipherId, itemKey) {
  const btn = li.querySelector('[data-action="share"]');
  const panel = li.querySelector(".share-panel");
  const list = li.querySelector(".share-list");
  const emailInput = li.querySelector(".share-email-input");
  const shareBtn = li.querySelector(".share-add-btn");
  const errorEl = li.querySelector(".share-error");
  let loaded = false;

  async function loadShares() {
    list.innerHTML = '<span class="hint-inline">Loading…</span>';
    const rows = await api(`v1/ciphers/${cipherId}/shares`);
    list.innerHTML = "";
    if (!rows.length) {
      list.innerHTML = '<span class="hint-inline">Not shared with anyone yet.</span>';
      return;
    }
    for (const s of rows) {
      const row = document.createElement("div");
      row.className = "attachment-row";
      row.innerHTML = `<span>${escapeHTML(s.email)}</span><button type="button" class="btn-icon danger" aria-label="Unshare" data-tip="Unshare">${TRASH_ICON}</button>`;
      row.querySelector("button").addEventListener("click", async () => {
        await api(`v1/shares/${s.id}`, { method: "DELETE" });
        await loadShares();
      });
      list.appendChild(row);
    }
  }

  btn.addEventListener("click", async () => {
    panel.hidden = !panel.hidden;
    if (!panel.hidden && !loaded) {
      loaded = true;
      await loadShares();
    }
  });

  shareBtn.addEventListener("click", async () => {
    errorEl.hidden = true;
    const email = emailInput.value.trim();
    if (!email) return;
    try {
      if (!session.x25519PrivateKeyBytes) {
        throw new Error("Your session is missing its sharing key — log out and back in.");
      }
      const target = await api(`v1/users/lookup?email=${encodeURIComponent(email)}`);
      const shareWrapKey = await deriveSharedWrapKey(session.x25519PrivateKeyBytes, target.x25519_public_key);
      const wrappedItemKey = await wrapKeyBytes(itemKey, shareWrapKey);
      await api(`v1/ciphers/${cipherId}/shares`, {
        method: "POST",
        body: JSON.stringify({ shared_with_user_id: target.id, wrapped_item_key: wrappedItemKey }),
      });
      emailInput.value = "";
      loaded = true;
      await loadShares();
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.hidden = false;
    }
  });
}

// --- Send (one-time anonymous encrypted links) -----------------------------
// A Send is encrypted under its OWN random key (sendKey) — not vaultKey,
// not an itemKey — because the recipient has no Passvault account at all.
// sendKey is wrapped twice: once for the anonymous recipient (embedded only
// in the share URL's fragment, via web/send.html/send.js — never sent to
// the server in any request) and once under this account's own vaultKey
// (wrapped_send_key), which is what lets "My Sends" below re-derive the
// link, and re-view/re-download content, without the one-time URL. See
// docs/PROTOCOL.md and internal/api/send_handlers.go.

$("#send-type").addEventListener("change", () => {
  const isFile = $("#send-type").value === "file";
  $("#send-text-field").hidden = isFile;
  $("#send-file-field").hidden = !isFile;
});

function sendShareURL(id, sendKeyBytes) {
  // Everything after '#' never leaves the browser in an HTTP request — that
  // property is what makes a URL fragment the right place for a raw key.
  const basePath = location.pathname.replace(/[^/]*$/, "");
  return `${location.origin}${basePath}send.html#${id}.${toURLSafeB64(sendKeyBytes)}`;
}

$("#send-create-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#send-create-error");
  errorEl.hidden = true;
  const type = $("#send-type").value;
  const label = $("#send-label").value.trim();

  try {
    const sendKey = generateKey();
    const wrappedSendKey = await wrapKeyBytes(sendKey, session.vaultKey);
    const encryptedLabel = await encryptJSON({ label }, session.vaultKey);

    const form = new FormData();
    form.set("type", type);
    form.set("wrapped_send_key", wrappedSendKey);
    form.set("encrypted_label", encryptedLabel);
    form.set("expires_in_seconds", $("#send-expires").value);
    const maxViews = $("#send-max-views").value.trim();
    if (maxViews) form.set("max_views", maxViews);
    const availableInSeconds = $("#send-available").value;
    if (availableInSeconds) form.set("available_in_seconds", availableInSeconds);
    const password = $("#send-password").value;
    if (password) form.set("password", password);

    if (type === "text") {
      const text = $("#send-text-content").value;
      if (!text) throw new Error("Enter some text to share.");
      form.set("encrypted_content", await encryptJSON({ text }, sendKey));
    } else {
      const file = $("#send-file-input").files[0];
      if (!file) throw new Error("Choose a file to share.");
      form.set("encrypted_filename", await encryptJSON({ name: file.name }, sendKey));
      const encryptedBytes = await encryptBytes(sendKey, new Uint8Array(await file.arrayBuffer()));
      form.set("file", new Blob([encryptedBytes]), "encrypted");
    }

    const res = await fetch("v1/sends", {
      method: "POST",
      headers: { Authorization: "Bearer " + session.accessToken },
      body: form,
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error || res.statusText);

    $("#send-result-link").value = sendShareURL(body.id, sendKey);
    $("#send-create-form").hidden = true;
    $("#send-result").hidden = false;
    await renderSendList();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#send-create-another-btn").addEventListener("click", () => {
  $("#send-create-form").reset();
  $("#send-type").dispatchEvent(new Event("change"));
  $("#send-create-form").hidden = false;
  $("#send-result").hidden = true;
});

const sendCopyLinkBtn = $("#send-copy-link-btn");
sendCopyLinkBtn.addEventListener("click", async () => {
  const ok = await copyToClipboard($("#send-result-link").value);
  flashCopied(sendCopyLinkBtn, ok);
});

function formatExpiry(expiresAtISO) {
  const d = new Date(expiresAtISO);
  return d < new Date() ? "Expired" : `Expires ${d.toLocaleString()}`;
}

async function renderSendList() {
  const list = $("#send-list");
  const empty = $("#send-list-empty");
  let sends;
  try {
    sends = await api("v1/sends");
  } catch {
    return;
  }
  list.innerHTML = "";
  empty.hidden = sends.length > 0;
  for (const send of sends) {
    list.appendChild(await renderSendRow(send));
  }
}

async function renderSendRow(send) {
  const li = document.createElement("li");
  li.className = "item card";
  let label = "(untitled)";
  try {
    ({ label } = await decryptJSON(send.encrypted_label, session.vaultKey));
  } catch {
    // Leave the fallback label rather than let one bad row break the list.
  }
  const viewsText = send.max_views ? `${send.view_count}/${send.max_views} views` : `${send.view_count} views`;
  const viewIcon = send.type === "text" ? EYE_ICON : DOWNLOAD_ICON;
  const viewTitle = send.type === "text" ? "View" : "Download and decrypt";
  const notYetAvailable = send.available_at && new Date(send.available_at) > new Date();
  const availableText = notYetAvailable ? ` &middot; unlocks ${new Date(send.available_at).toLocaleString()}` : "";
  li.innerHTML = `
    <div class="item-icon">${TYPE_ICONS[send.type] || ""}</div>
    <div class="item-main">
      <div class="item-name">${escapeHTML(label)}</div>
      <div class="item-username">${formatExpiry(send.expires_at)} &middot; ${viewsText}${send.has_password ? " &middot; password-protected" : ""}${availableText}</div>
    </div>
    <div class="item-actions">
      <button class="btn-icon" data-action="view" aria-label="${viewTitle}" data-tip="${viewTitle}" type="button">${viewIcon}</button>
      <button class="btn-icon" data-action="copy-link" aria-label="Copy link" data-tip="Copy link" type="button">${COPY_ICON}</button>
      <button class="btn-icon danger" data-action="revoke" aria-label="Revoke" data-tip="Revoke" type="button">${TRASH_ICON}</button>
    </div>
    <div class="item-detail" hidden></div>
  `;

  const viewBtn = li.querySelector('[data-action="view"]');
  const detailEl = li.querySelector(".item-detail");
  viewBtn.addEventListener("click", async () => {
    try {
      const sendKey = await unwrapKeyBytes(send.wrapped_send_key, session.vaultKey);
      if (send.type === "text") {
        if (!detailEl.hidden) {
          detailEl.hidden = true;
          return;
        }
        const { text } = await decryptJSON(send.encrypted_content, sendKey);
        detailEl.textContent = text;
        detailEl.hidden = false;
      } else {
        const res = await fetch(`v1/sends/${send.id}/content`, {
          headers: { Authorization: "Bearer " + session.accessToken },
        });
        if (!res.ok) throw new Error("download failed");
        const encryptedBytes = new Uint8Array(await res.arrayBuffer());
        const plainBytes = await decryptBytes(sendKey, encryptedBytes);
        const { name } = await decryptJSON(send.encrypted_filename, sendKey);
        const blobUrl = URL.createObjectURL(new Blob([plainBytes]));
        const link = document.createElement("a");
        link.href = blobUrl;
        link.download = name;
        link.click();
        URL.revokeObjectURL(blobUrl);
      }
    } catch {
      flashCopied(viewBtn, false);
    }
  });

  const copyLinkBtn = li.querySelector('[data-action="copy-link"]');
  copyLinkBtn.addEventListener("click", async () => {
    try {
      const sendKey = await unwrapKeyBytes(send.wrapped_send_key, session.vaultKey);
      const ok = await copyToClipboard(sendShareURL(send.id, sendKey));
      flashCopied(copyLinkBtn, ok);
    } catch {
      flashCopied(copyLinkBtn, false);
    }
  });

  li.querySelector('[data-action="revoke"]').addEventListener("click", async () => {
    await api(`v1/sends/${send.id}`, { method: "DELETE" });
    await renderSendList();
  });

  return li;
}

// --- Emergency access -------------------------------------------------
// Bitwarden-style: a grantor designates a trusted contact who can request
// access if the grantor ever goes unreachable. State machine lives
// server-side (internal/api/emergency_access_handlers.go); this is purely
// the client half of each transition. The only step that touches key
// material is "confirm" — wrapping the GRANTOR's own vaultKey under an
// ECDH key shared with the grantee (deriveEmergencyAccessWrapKey, a
// sibling of deriveSharedWrapKey used for item sharing, with its own HKDF
// info string) — every other transition is a plain status change. See
// docs/PROTOCOL.md.

function showRowMessage(li, text, isError) {
  const el = li.querySelector(".item-detail");
  el.textContent = text;
  el.style.color = isError ? "var(--danger)" : "";
  el.hidden = false;
}

async function renderEmergencyAccessLists() {
  await Promise.all([renderEmergencyByMe(), renderEmergencyToMe()]);
}

async function renderEmergencyByMe() {
  const list = $("#emergency-by-me-list");
  const empty = $("#emergency-by-me-empty");
  let rows;
  try {
    rows = await api("v1/emergency-access/granted-by-me");
  } catch {
    return;
  }
  list.innerHTML = "";
  empty.hidden = rows.length > 0;
  for (const ea of rows) list.appendChild(renderEmergencyByMeRow(ea));
}

async function renderEmergencyToMe() {
  const list = $("#emergency-to-me-list");
  const empty = $("#emergency-to-me-empty");
  let rows;
  try {
    rows = await api("v1/emergency-access/granted-to-me");
  } catch {
    return;
  }
  list.innerHTML = "";
  empty.hidden = rows.length > 0;
  for (const ea of rows) list.appendChild(renderEmergencyToMeRow(ea));
}

function formatEmergencyStatus(ea, iAmGrantor) {
  const other = iAmGrantor ? ea.grantee_email : ea.grantor_email;
  switch (ea.status) {
    case "invited":
      return iAmGrantor ? `Invitation sent — waiting for ${other} to accept.` : `${other} invited you to be their emergency contact.`;
    case "accepted":
      return iAmGrantor ? `${other} accepted — confirm to finish setup.` : `Accepted — waiting for ${other} to confirm.`;
    case "confirmed":
      return iAmGrantor
        ? `${other} is your emergency contact (${ea.access_type}, ${ea.wait_days}-day wait).`
        : `You're ${other}'s emergency contact (${ea.access_type}, ${ea.wait_days}-day wait).`;
    case "requested": {
      const when = new Date(ea.access_at).toLocaleString();
      return iAmGrantor
        ? `${other} requested access — auto-grants ${when} unless you reject it.`
        : `Requested — access opens ${when} unless rejected.`;
    }
    case "granted":
      return iAmGrantor ? `${other} has ${ea.access_type} access to your vault.` : `You have ${ea.access_type} access to ${other}'s vault.`;
    default:
      return ea.status;
  }
}

$("#emergency-invite-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#emergency-invite-error");
  errorEl.hidden = true;
  try {
    await api("v1/emergency-access", {
      method: "POST",
      body: JSON.stringify({
        grantee_email: $("#emergency-invite-email").value.trim(),
        access_type: $("#emergency-invite-type").value,
        wait_days: parseInt($("#emergency-invite-wait").value, 10),
      }),
    });
    e.target.reset();
    await renderEmergencyByMe();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

function renderEmergencyByMeRow(ea) {
  const li = document.createElement("li");
  li.className = "item card";
  const actions = {
    invited: [["cancel", "Cancel invite", "btn-sm"]],
    accepted: [
      ["confirm", "Confirm", "btn-sm btn-primary"],
      ["cancel", "Cancel", "btn-sm"],
    ],
    confirmed: [["cancel", "Remove", "btn-sm"]],
    requested: [
      ["approve", "Approve now", "btn-sm btn-primary"],
      ["reject", "Reject", "btn-sm btn-danger"],
    ],
    granted: [["cancel", "Remove", "btn-sm"]],
  }[ea.status] || [];
  li.innerHTML = `
    <div class="item-icon">${escapeHTML((ea.grantee_email || "?")[0]?.toUpperCase() || "?")}</div>
    <div class="item-main">
      <div class="item-name">${escapeHTML(ea.grantee_email)}</div>
      <div class="item-username">${escapeHTML(formatEmergencyStatus(ea, true))}</div>
    </div>
    <div class="item-actions">
      ${actions.map(([action, label, cls]) => `<button class="btn ${cls}" data-action="${action}" type="button">${label}</button>`).join("")}
    </div>
    <div class="item-detail" hidden></div>
  `;

  li.querySelector('[data-action="cancel"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}`, { method: "DELETE" });
    await renderEmergencyByMe();
  });
  li.querySelector('[data-action="reject"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}/reject`, { method: "POST" });
    await renderEmergencyByMe();
  });
  li.querySelector('[data-action="approve"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}/approve`, { method: "POST" });
    await renderEmergencyByMe();
  });
  li.querySelector('[data-action="confirm"]')?.addEventListener("click", async () => {
    try {
      const wrapKey = await deriveEmergencyAccessWrapKey(session.x25519PrivateKeyBytes, ea.grantee_x25519_public_key);
      const wrappedVaultKeyForGrantee = await wrapKeyBytes(session.vaultKey, wrapKey);
      await api(`v1/emergency-access/${ea.id}/confirm`, {
        method: "POST",
        body: JSON.stringify({ wrapped_vault_key_for_grantee: wrappedVaultKeyForGrantee }),
      });
      await renderEmergencyByMe();
    } catch (err) {
      showRowMessage(li, err.message, true);
    }
  });

  return li;
}

function renderEmergencyToMeRow(ea) {
  const li = document.createElement("li");
  li.className = "item card";
  const actions = {
    invited: [
      ["accept", "Accept", "btn-sm btn-primary"],
      ["cancel", "Decline", "btn-sm"],
    ],
    accepted: [["cancel", "Cancel", "btn-sm"]],
    confirmed: [
      ["request", "Request access", "btn-sm btn-primary"],
      ["cancel", "Remove", "btn-sm"],
    ],
    requested: [["cancel", "Cancel request", "btn-sm"]],
    granted: [
      [ea.access_type === "view" ? "view" : "takeover", ea.access_type === "view" ? "View vault" : "Take over account", "btn-sm btn-primary"],
      ["cancel", "Remove", "btn-sm"],
    ],
  }[ea.status] || [];
  li.innerHTML = `
    <div class="item-icon">${escapeHTML((ea.grantor_email || "?")[0]?.toUpperCase() || "?")}</div>
    <div class="item-main">
      <div class="item-name">${escapeHTML(ea.grantor_email)}</div>
      <div class="item-username">${escapeHTML(formatEmergencyStatus(ea, false))}</div>
    </div>
    <div class="item-actions">
      ${actions.map(([action, label, cls]) => `<button class="btn ${cls}" data-action="${action}" type="button">${label}</button>`).join("")}
    </div>
    <div class="item-detail" hidden></div>
    <div class="emergency-panel" hidden></div>
  `;

  li.querySelector('[data-action="cancel"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}`, { method: "DELETE" });
    await renderEmergencyToMe();
  });
  li.querySelector('[data-action="accept"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}/accept`, { method: "POST" });
    await renderEmergencyToMe();
  });
  li.querySelector('[data-action="request"]')?.addEventListener("click", async () => {
    await api(`v1/emergency-access/${ea.id}/request`, { method: "POST" });
    await renderEmergencyToMe();
  });
  li.querySelector('[data-action="view"]')?.addEventListener("click", () => wireEmergencyVaultView(li, ea));
  li.querySelector('[data-action="takeover"]')?.addEventListener("click", () => wireEmergencyTakeover(li, ea));

  return li;
}

// "View" access: fetches the grantor's current folders/ciphers, recovers
// their vaultKey via ECDH (deriveEmergencyAccessWrapKey + the grantor's
// wrapped_vault_key_for_grantee), and renders each item read-only by
// reusing renderSharedItem — the exact same "someone else's item,
// display-only" shape item sharing already built, just sourced from an
// emergency grant instead of a cipher_shares row.
async function wireEmergencyVaultView(li, ea) {
  const panel = li.querySelector(".emergency-panel");
  if (!panel.hidden) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  panel.innerHTML = '<span class="hint-inline">Loading…</span>';
  try {
    const data = await api(`v1/emergency-access/${ea.id}/vault`);
    const wrapKey = await deriveEmergencyAccessWrapKey(session.x25519PrivateKeyBytes, data.grantor_x25519_public_key);
    const grantorVaultKey = await unwrapKeyBytes(data.wrapped_vault_key_for_grantee, wrapKey);

    panel.innerHTML = "";
    if (!data.ciphers.length) {
      panel.innerHTML = '<span class="hint-inline">This vault is empty.</span>';
      return;
    }
    const listEl = document.createElement("ul");
    listEl.className = "emergency-vault-list";
    for (const cipher of data.ciphers) {
      const itemKey = await unwrapKeyBytes(cipher.wrapped_item_key, grantorVaultKey);
      const item = await decryptJSON(cipher.encrypted_blob, itemKey);
      listEl.appendChild(renderSharedItem(cipher.id, cipher.type, item, itemKey, data.grantor_email));
    }
    panel.appendChild(listEl);
  } catch (err) {
    panel.innerHTML = "";
    panel.textContent = "Couldn't load this vault: " + err.message;
  }
}

// Takeover: the grantee recovers the grantor's vaultKey exactly like the
// view flow above, then picks a NEW master password for the grantor's
// account, derives a fresh wrapKey from it, and re-wraps the SAME
// vaultKey under it — nothing else about the grantor's data changes,
// same reasoning as auth.ChangePassword. The server also signs the
// grantor out of every existing device once this lands.
function wireEmergencyTakeover(li, ea) {
  const panel = li.querySelector(".emergency-panel");
  if (!panel.hidden) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  panel.innerHTML = `
    <p class="takeover-warning">
      This resets ${escapeHTML(ea.grantor_email)}'s master password and signs them out of every device.
      Only do this if you're certain emergency access is warranted.
    </p>
    <label>New master password for ${escapeHTML(ea.grantor_email)}</label>
    <input type="password" class="takeover-password" autocomplete="new-password">
    <label style="margin-top:8px">Confirm new master password</label>
    <input type="password" class="takeover-password-confirm" autocomplete="new-password">
    <p class="takeover-error hint-inline" style="color:var(--danger)" hidden></p>
    <button type="button" class="btn btn-danger btn-block takeover-submit-btn" style="margin-top:10px">Take over account</button>
  `;

  panel.querySelector(".takeover-submit-btn").addEventListener("click", async () => {
    const errorEl = panel.querySelector(".takeover-error");
    errorEl.hidden = true;
    const password = panel.querySelector(".takeover-password").value;
    const confirmPassword = panel.querySelector(".takeover-password-confirm").value;
    if (!password || password !== confirmPassword) {
      errorEl.textContent = "Passwords don't match.";
      errorEl.hidden = false;
      return;
    }
    try {
      const wrapKey = await deriveEmergencyAccessWrapKey(session.x25519PrivateKeyBytes, ea.grantor_x25519_public_key);
      const grantorVaultKey = await unwrapKeyBytes(ea.wrapped_vault_key_for_grantee, wrapKey);

      const kdf = defaultKDFParams();
      const { authKeyB64, wrapKey: newWrapKey } = await deriveKeys(password, kdf);
      const newWrappedVaultKey = await wrapKeyBytes(grantorVaultKey, newWrapKey);

      await api(`v1/emergency-access/${ea.id}/takeover`, {
        method: "POST",
        body: JSON.stringify({ kdf, new_auth_key: authKeyB64, new_wrapped_vault_key: newWrappedVaultKey }),
      });
      panel.innerHTML = '<p class="hint-inline">Done. Tell them their new password through a separate, trusted channel.</p>';
      await renderEmergencyToMe();
    } catch (err) {
      errorEl.textContent = err.message;
      errorEl.hidden = false;
    }
  });
}

// Brief inline feedback next to whatever was clicked, instead of a toast —
// keeps the DOM change scoped to the element the user is already looking
// at. Must reflect whether the copy actually succeeded: navigator.clipboard
// .writeText can be denied (permissions policy, insecure context, browser
// quirk), and silently claiming success when it wasn't would leave someone
// pasting a stale clipboard value without realizing it.
function flashCopied(el, ok) {
  flashMessage(el, ok ? "Copied" : "Copy failed", ok);
}

// General-purpose version of the above for actions that aren't a
// clipboard copy (e.g. alias generation) — same transient-inline-tag
// treatment, just with a message that actually matches what happened.
function flashMessage(el, text, ok) {
  const tag = document.createElement("span");
  tag.className = ok ? "copied-tag" : "copied-tag copied-tag-error";
  tag.textContent = " " + text;
  el.after(tag);
  setTimeout(() => tag.remove(), 1200);
}

function escapeHTML(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Builds the opaque item object per type. The server never inspects this —
// it only sees the type string (for its own validation) and the encrypted
// blob — so these shapes are a purely client-side/UI concern; changing a
// field name here needs no server or schema change.
function buildItemFromForm(type) {
  const name = $("#item-name").value.trim();
  switch (type) {
    case "login":
      return {
        name,
        uri: $("#item-uri").value.trim(),
        username: $("#item-username").value.trim(),
        password: $("#item-password").value,
        totp: $("#item-totp").value.trim(),
        notes: $("#item-notes").value.trim(),
      };
    case "note":
      return { name, notes: $("#note-content").value.trim() };
    case "card":
      return {
        name,
        cardholderName: $("#card-holder").value.trim(),
        brand: $("#card-brand").value,
        number: $("#card-number").value.trim(),
        cvv: $("#card-cvv").value.trim(),
        expMonth: $("#card-exp-month").value.trim(),
        expYear: $("#card-exp-year").value.trim(),
        notes: $("#item-notes").value.trim(),
      };
    case "identity":
      return {
        name,
        firstName: $("#id-first-name").value.trim(),
        lastName: $("#id-last-name").value.trim(),
        email: $("#id-email").value.trim(),
        phone: $("#id-phone").value.trim(),
        address: $("#id-address").value.trim(),
        city: $("#id-city").value.trim(),
        state: $("#id-state").value.trim(),
        postalCode: $("#id-postal").value.trim(),
        country: $("#id-country").value.trim(),
        notes: $("#item-notes").value.trim(),
      };
    case "ssh_key":
      return {
        name,
        keyType: $("#ssh-key-type").value,
        publicKey: $("#ssh-public-key").value.trim(),
        privateKey: $("#ssh-private-key").value.trim(),
        passphrase: $("#ssh-passphrase").value,
        fingerprint: $("#ssh-fingerprint").value.trim(),
        notes: $("#item-notes").value.trim(),
      };
    default:
      throw new Error(`unknown item type: ${type}`);
  }
}

$("#add-item-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const type = $("#item-type").value;
  const item = buildItemFromForm(type);
  const folderIdRaw = $("#item-folder").value;
  // folder_id is a real (unencrypted) column, unlike everything in `item` —
  // the server uses it to group/filter, so it can't live inside the opaque
  // blob. It reveals nothing about a cipher's *contents*, only that two
  // items share a folder, same tradeoff Bitwarden/Vaultwarden both make.
  const folderId = folderIdRaw ? parseInt(folderIdRaw, 10) : null;
  // Editing reuses the existing itemKey (just re-wrapped) rather than
  // rotating it — this is a content edit, not a key-compromise response.
  const itemKey = editingCipher ? editingCipher.itemKey : generateKey();
  const wrappedItemKey = await wrapKeyBytes(itemKey, session.vaultKey);
  const encryptedBlob = await encryptJSON(item, itemKey);
  const body = { type, folder_id: folderId, wrapped_item_key: wrappedItemKey, encrypted_blob: encryptedBlob };
  if (editingCipher) body.id = editingCipher.id;
  await api("v1/ciphers", { method: "POST", body: JSON.stringify(body) });
  closeAddItemModal();
  await refreshItems();
});

$("#logout-btn").addEventListener("click", async () => {
  try {
    await api("v1/auth/logout", { method: "POST" });
  } catch {
    // logging out best-effort even if the request fails
  }
  session.accessToken = null;
  session.refreshToken = null;
  session.vaultKey = null;
  session.x25519PrivateKeyBytes = null;
  session.user = null;
  stopTotpTimer();
  folders = [];
  currentFolderFilter = "all";
  vaultView.hidden = true;
  authView.hidden = false;
  $("#tab-login").click();
});
