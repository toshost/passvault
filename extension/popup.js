// Popup UI. Talks to background.js only via chrome.runtime.sendMessage —
// never holds vaultKey or calls the Passvault server itself. See
// background.js's file header for why that split exists.

function sendMessage(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!resp || !resp.ok) return reject(new Error((resp && resp.error) || "extension error"));
      resolve(resp.result);
    });
  });
}

const $ = (sel) => document.querySelector(sel);
const views = ["view-loading", "view-setup", "view-login", "view-2fa", "view-unlocked"];
function showView(id) {
  for (const v of views) $("#" + v).hidden = v !== id;
}

async function activeTabHost() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return null;
  try {
    return new URL(tab.url).hostname;
  } catch {
    return null;
  }
}

async function renderMatches() {
  const host = await activeTabHost();
  $("#unlocked-site").textContent = host || "";
  const list = $("#matches-list");
  list.innerHTML = "";
  if (!host) {
    $("#matches-section").hidden = true;
    $("#no-matches-hint").hidden = false;
    return;
  }
  const { items } = await sendMessage({ type: "PV_GET_MATCHES", host });
  $("#matches-section").hidden = items.length === 0;
  $("#no-matches-hint").hidden = items.length > 0;
  for (const item of items) {
    const row = document.createElement("div");
    row.className = "match";
    row.innerHTML = `
      <div class="match-glyph"></div>
      <div class="match-info">
        <div class="match-name"></div>
        <div class="match-username"></div>
      </div>
      <button class="secondary" type="button">Fill</button>
    `;
    const label = item.name || item.uri;
    row.querySelector(".match-glyph").textContent = (label[0] || "?").toUpperCase();
    row.querySelector(".match-name").textContent = label;
    row.querySelector(".match-username").textContent = item.username;
    row.querySelector("button").addEventListener("click", async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await chrome.tabs.sendMessage(tab.id, { type: "PV_FILL", item });
      window.close();
    });
    list.appendChild(row);
  }
}

async function refresh() {
  showView("view-loading");
  const state = await sendMessage({ type: "PV_GET_STATE" });
  if (!state.configured) {
    showView("view-setup");
    return;
  }
  if (state.locked) {
    showView("view-login");
    return;
  }
  $("#unlocked-email").textContent = state.email;
  $("#unlocked-avatar").textContent = (state.email && state.email[0] || "?").toUpperCase();
  showView("view-unlocked");
  await renderMatches();
}

$("#open-options-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("#open-options-icon-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#login-error");
  errorEl.hidden = true;
  const email = $("#login-email").value.trim();
  const password = $("#login-password").value;
  try {
    const result = await sendMessage({ type: "PV_LOGIN", email, password });
    $("#login-password").value = "";
    if (result.requires2fa) {
      showView("view-2fa");
      $("#twofa-code").focus();
    } else {
      await refresh();
    }
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#twofa-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = $("#twofa-error");
  errorEl.hidden = true;
  const code = $("#twofa-code").value.trim();
  try {
    await sendMessage({ type: "PV_LOGIN_2FA", code });
    $("#twofa-code").value = "";
    await refresh();
  } catch (err) {
    errorEl.textContent = err.message;
    errorEl.hidden = false;
  }
});

$("#lock-btn").addEventListener("click", async () => {
  await sendMessage({ type: "PV_LOCK" });
  await refresh();
});

$("#open-vault-btn").addEventListener("click", async () => {
  const { serverUrl } = await sendMessage({ type: "PV_GET_SERVER_URL" });
  if (serverUrl) chrome.tabs.create({ url: serverUrl });
});

refresh();
