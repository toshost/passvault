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
const msgEl = $("#msg");

function showMsg(text, kind) {
  msgEl.textContent = text;
  msgEl.className = "msg " + kind;
  msgEl.hidden = false;
}

(async () => {
  const { serverUrl } = await sendMessage({ type: "PV_GET_SERVER_URL" });
  if (serverUrl) $("#server-url").value = serverUrl;
})();

$("#save-btn").addEventListener("click", async () => {
  msgEl.hidden = true;
  const raw = $("#server-url").value.trim();
  let origin;
  try {
    origin = new URL(raw).origin;
  } catch {
    showMsg("Enter a full URL, including https://", "error");
    return;
  }

  // Must be requested directly inside this click handler — Chrome only
  // honors chrome.permissions.request() as a direct result of a user
  // gesture, which is also why this can't happen automatically on page
  // load even if a URL was already saved from a previous session.
  let granted;
  try {
    granted = await chrome.permissions.request({ origins: [origin + "/*"] });
  } catch (err) {
    showMsg("Permission request failed: " + err.message, "error");
    return;
  }
  if (!granted) {
    showMsg("Permission denied — the extension can't reach your server without it.", "error");
    return;
  }

  try {
    await sendMessage({ type: "PV_SET_SERVER_URL", url: raw });
    showMsg("Saved. You can close this tab and click the Passvault icon to log in.", "ok");
  } catch (err) {
    showMsg(err.message, "error");
  }
});
