// The anonymous recipient side of a Send — deliberately independent of
// app.js/session state (no login, no vaultKey, nothing authenticated).
// Its entire trust boundary is: the decryption key lives ONLY in
// location.hash (never transmitted in any request — that's what makes a
// URL fragment the right place for it), and everything this page shows
// was decrypted right here in the browser. See docs/PROTOCOL.md.
import { fromURLSafeB64, decryptJSON, decryptBytes } from "./crypto.js";

const $ = (sel) => document.querySelector(sel);

function showState(name) {
  for (const el of document.querySelectorAll("[data-state]")) {
    el.hidden = el.dataset.state !== name;
  }
}

function showFatalError(msg) {
  $("#error-text").textContent = msg;
  showState("error");
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false; // clipboard permission denied/unavailable — caller decides how to surface this
  }
}

// The fragment is "<send id>.<url-safe base64 sendKey>" — a dot separator
// is safe because NewOpaqueToken() ids are hex (never contain '.') and
// url-safe base64 doesn't either.
function parseFragment() {
  const hash = location.hash.slice(1);
  const dot = hash.indexOf(".");
  if (dot === -1) return null;
  const id = hash.slice(0, dot);
  const keyB64 = hash.slice(dot + 1);
  if (!id || !keyB64) return null;
  try {
    return { id, sendKey: fromURLSafeB64(keyB64) };
  } catch {
    return null;
  }
}

async function fetchAndShow(id, sendKey, password) {
  let res;
  try {
    res = await fetch(`public/sends/${id}/access`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: password || "" }),
    });
  } catch {
    throw new Error("Couldn't reach the server.");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.error || res.statusText);
    err.status = res.status;
    throw err;
  }

  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    const body = await res.json();
    const { text } = await decryptJSON(body.encrypted_content, sendKey);
    $("#text-output").value = text;
    showState("text");
  } else {
    const encryptedFilenameB64 = res.headers.get("x-encrypted-filename");
    const { name } = await decryptJSON(encryptedFilenameB64, sendKey);
    const encryptedBytes = new Uint8Array(await res.arrayBuffer());
    const plainBytes = await decryptBytes(sendKey, encryptedBytes);

    $("#file-name").textContent = name;
    $("#file-size").textContent = formatBytes(plainBytes.length);
    showState("file");
    // Replace rather than addEventListener: fetchAndShow can run more than
    // once in the same page load (hashchange to a different Send), and a
    // stale closure over a PREVIOUS Send's plainBytes must not linger.
    const freshBtn = $("#download-btn").cloneNode(true);
    $("#download-btn").replaceWith(freshBtn);
    freshBtn.addEventListener("click", () => {
      const blobUrl = URL.createObjectURL(new Blob([plainBytes]));
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = name;
      link.click();
      URL.revokeObjectURL(blobUrl);
    });
  }
}

// Holds the currently-relevant {id, sendKey} for the password-form submit
// handler below, which is attached exactly ONCE (not inside main()) so
// that a fragment-only navigation — pasting a different Send link into a
// tab that already has this page open, which browsers treat as a
// same-document navigation and do NOT reload the script for — doesn't
// stack a second listener on the same persistent <form> element and fire
// the old Send's handler alongside the new one.
let current = null;

function resetUIForNewSend() {
  $("#text-output").value = "";
  $("#file-name").textContent = "";
  $("#file-size").textContent = "";
  $("#send-password").value = "";
  $("#password-error").hidden = true;
  for (const tag of document.querySelectorAll(".copied-tag")) tag.remove();
}

async function main() {
  resetUIForNewSend();
  showState("loading");

  const parsed = parseFragment();
  if (!parsed) {
    current = null;
    showState("invalid");
    return;
  }
  current = parsed;
  const { id, sendKey } = parsed;

  let meta;
  try {
    const res = await fetch(`public/sends/${id}`);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      showFatalError(body.error || "This link doesn't exist or has expired.");
      return;
    }
    meta = await res.json();
  } catch {
    showFatalError("Couldn't reach the server.");
    return;
  }

  if (meta.available_at) {
    $("#unavailable-text").textContent = `This will unlock on ${new Date(meta.available_at).toLocaleString()}.`;
    showState("unavailable");
    return;
  }

  if (!meta.requires_password) {
    try {
      await fetchAndShow(id, sendKey, "");
    } catch (err) {
      showFatalError(err.message);
    }
    return;
  }

  showState("password");
}

$("#password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!current) return;
  const errorEl = $("#password-error");
  errorEl.hidden = true;
  try {
    await fetchAndShow(current.id, current.sendKey, $("#send-password").value);
  } catch (err) {
    errorEl.textContent = err.status === 401 ? "Wrong password." : err.message;
    errorEl.hidden = false;
  }
});

$("#copy-text-btn")?.addEventListener("click", async () => {
  const btn = $("#copy-text-btn");
  const ok = await copyToClipboard($("#text-output").value);
  const tag = document.createElement("span");
  tag.className = ok ? "copied-tag" : "copied-tag copied-tag-error";
  tag.textContent = ok ? "Copied" : "Copy failed";
  btn.after(tag);
  setTimeout(() => tag.remove(), 1500);
});

window.addEventListener("hashchange", main);
main();
