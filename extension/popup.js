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

// Only http(s) tabs have a "site" a credential can belong to — chrome://,
// file://, and extension pages don't, so the popup shouldn't pretend they do.
async function activeTabHost() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return null;
  try {
    const url = new URL(tab.url);
    return /^https?:$/.test(url.protocol) ? url.hostname : null;
  } catch {
    return null;
  }
}

async function renderMatches(host) {
  $("#site-chip").hidden = !host;
  if (host) $("#unlocked-site").textContent = host;
  $("#empty-site-label").textContent = host || "this site";
  const list = $("#matches-list");
  list.innerHTML = "";
  if (!host) {
    $("#matches-section").hidden = true;
    $("#no-matches-hint").hidden = true;
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
      <button type="button">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none"><path d="M5 12h14M13 6l6 6-6 6" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        Fill
      </button>
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

function copyIcon() {
  return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><rect x="8" y="8" width="12" height="12" rx="2" stroke="currentColor" stroke-width="1.7"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" stroke="currentColor" stroke-width="1.7"/></svg>';
}
function checkIcon() {
  return '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="m4 12.5 5 5L20 7" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
}

async function copyToClipboard(btn, text) {
  try {
    await navigator.clipboard.writeText(text || "");
  } catch {
    return;
  }
  btn.classList.add("copied");
  btn.innerHTML = checkIcon();
  setTimeout(() => {
    btn.classList.remove("copied");
    btn.innerHTML = copyIcon();
  }, 1100);
}

let allItems = [];

function renderAllItemsList(filterText) {
  const q = filterText.trim().toLowerCase();
  const filtered = !q
    ? allItems
    : allItems.filter((it) =>
        (it.name || "").toLowerCase().includes(q) ||
        (it.uri || "").toLowerCase().includes(q) ||
        (it.username || "").toLowerCase().includes(q)
      );
  const list = $("#all-items-list");
  list.innerHTML = "";
  $("#no-search-results").hidden = filtered.length > 0;
  for (const item of filtered) {
    const row = document.createElement("div");
    row.className = "item-row";
    row.innerHTML = `
      <div class="match-glyph"></div>
      <div class="match-info">
        <div class="match-name"></div>
        <div class="match-username"></div>
      </div>
      <div class="item-actions">
        <button type="button" class="copy-btn" title="Copy username">${copyIcon()}</button>
        <button type="button" class="copy-btn" title="Copy password">${copyIcon()}</button>
      </div>
    `;
    const label = item.name || item.uri;
    row.querySelector(".match-glyph").textContent = (label[0] || "?").toUpperCase();
    row.querySelector(".match-name").textContent = label;
    row.querySelector(".match-username").textContent = item.username;
    const [copyUserBtn, copyPassBtn] = row.querySelectorAll(".copy-btn");
    copyUserBtn.addEventListener("click", () => copyToClipboard(copyUserBtn, item.username));
    copyPassBtn.addEventListener("click", () => copyToClipboard(copyPassBtn, item.password));
    list.appendChild(row);
  }
}

async function renderAllItems() {
  const { items } = await sendMessage({ type: "PV_GET_ALL_ITEMS" });
  allItems = items;
  $("#all-items-section").hidden = items.length === 0;
  renderAllItemsList($("#items-search").value);
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
  $("#count-chip").hidden = !state.itemCount;
  $("#item-count").textContent = state.itemCount === 1 ? "1 login" : `${state.itemCount} logins`;
  showView("view-unlocked");
  const host = await activeTabHost();
  await Promise.all([renderMatches(host), renderAllItems()]);
}

$("#open-options-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());
$("#open-options-icon-btn").addEventListener("click", () => chrome.runtime.openOptionsPage());

$("#toggle-login-password").addEventListener("click", () => {
  const input = $("#login-password");
  const showing = input.type === "text";
  input.type = showing ? "password" : "text";
  $("#toggle-login-password").setAttribute("title", showing ? "Show password" : "Hide password");
});

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

$("#items-search").addEventListener("input", (e) => renderAllItemsList(e.target.value));

$("#open-vault-btn").addEventListener("click", async () => {
  const { serverUrl } = await sendMessage({ type: "PV_GET_SERVER_URL" });
  if (serverUrl) chrome.tabs.create({ url: serverUrl });
});

refresh();
