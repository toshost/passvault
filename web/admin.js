// Instance operator settings — gated by PASSVAULT_ADMIN_TOKEN, not a user
// session. Deliberately independent of app.js: this page never touches a
// master password, vaultKey, or anything inside the zero-knowledge
// boundary — SMTP config is server-side operational infrastructure, same
// trust class as the database connection string.
const $ = (sel) => document.querySelector(sel);

let adminToken = null;

async function adminFetch(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + adminToken, ...(opts.headers || {}) },
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

async function loadSettings() {
  const s = await adminFetch("v1/admin/smtp");
  $("#smtp-host").value = s.host || "";
  $("#smtp-port").value = s.port || 587;
  $("#smtp-username").value = s.username || "";
  $("#smtp-password").placeholder = s.has_password ? "Leave blank to keep the saved password" : "No password saved yet";
  $("#smtp-from-address").value = s.from_address || "";
  $("#smtp-from-name").value = s.from_name || "";
  $("#smtp-use-tls").checked = s.use_tls !== false;
}

$("#gate-continue-btn").addEventListener("click", async () => {
  const errorEl = $("#gate-error");
  errorEl.hidden = true;
  const token = $("#admin-token").value.trim();
  if (!token) return;
  adminToken = token;
  try {
    await loadSettings();
    $("#gate-view").hidden = true;
    $("#settings-view").hidden = false;
  } catch (err) {
    adminToken = null;
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#smtp-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#smtp-error");
  const successEl = $("#smtp-success");
  errorEl.hidden = true;
  successEl.hidden = true;
  try {
    await adminFetch("v1/admin/smtp", {
      method: "PUT",
      body: JSON.stringify({
        host: $("#smtp-host").value.trim(),
        port: parseInt($("#smtp-port").value, 10),
        username: $("#smtp-username").value.trim(),
        password: $("#smtp-password").value, // empty = server keeps the existing one
        from_address: $("#smtp-from-address").value.trim(),
        from_name: $("#smtp-from-name").value.trim(),
        use_tls: $("#smtp-use-tls").checked,
      }),
    });
    $("#smtp-password").value = "";
    await loadSettings();
    successEl.textContent = "Saved.";
    successEl.hidden = false;
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#send-test-btn").addEventListener("click", async () => {
  const statusEl = $("#test-status");
  const to = $("#test-email-to").value.trim();
  if (!to) {
    statusEl.textContent = "Enter an address to send the test to.";
    return;
  }
  statusEl.textContent = "Sending…";
  try {
    await adminFetch("v1/admin/smtp/test", { method: "POST", body: JSON.stringify({ to }) });
    statusEl.textContent = "Sent — check the inbox (and spam folder).";
  } catch (err) {
    statusEl.textContent = "Failed: " + err.message;
  }
});
