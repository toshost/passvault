// Import/export format handling — pure functions only: no DOM, no
// network, no crypto. This module only ever touches PLAINTEXT item data,
// by definition (an import source is plaintext before encryption; an
// export is plaintext after decryption) — that's exactly why it's kept
// entirely separate from crypto.js's trust boundary rather than mixed
// into it. app.js owns turning what this module produces into encrypted
// ciphers, and turning ciphers back into what this module exports.

export const PASSVAULT_EXPORT_FORMAT = "passvault";

// Builds the exportable structure from already-decrypted items. Each
// entry in `items` is { type, folder (name or null), fields: {...} } —
// the same shape every parser below produces, so export and import speak
// exactly one internal dialect regardless of source/destination format.
export function buildPassvaultExport(items) {
  return {
    format: PASSVAULT_EXPORT_FORMAT,
    version: 1,
    exported_at: new Date().toISOString(),
    items: items.map((it) => ({ type: it.type, folder: it.folder || null, ...it.fields })),
  };
}

export function parsePassvaultJSON(text) {
  const data = JSON.parse(text);
  if (data.format !== PASSVAULT_EXPORT_FORMAT || !Array.isArray(data.items)) {
    throw new Error("This doesn't look like a Passvault export file.");
  }
  const items = data.items.map((it) => {
    const { type, folder, ...fields } = it;
    return { type, folder: folder || null, fields };
  });
  return { items, warnings: [] };
}

// Bitwarden's documented individual-vault export schema (JSON): type 1-4
// map to login/note/card/identity; org-only fields (collectionIds etc.)
// are ignored since this app has no org concept. See
// https://bitwarden.com/help/condition-bitwarden-import/ for the format
// this was built against.
const BITWARDEN_TYPE_MAP = { 1: "login", 2: "note", 3: "card", 4: "identity" };

export function parseBitwardenJSON(text) {
  const data = JSON.parse(text);
  // A Passvault export also has a top-level `items` array, so that check
  // alone isn't enough to tell the formats apart — it would otherwise
  // "succeed" here with every item silently skipped (Bitwarden's numeric
  // type 1-4 vs. Passvault's string type), a confusing wrong-format
  // symptom instead of a clear error.
  if (data.format === PASSVAULT_EXPORT_FORMAT) {
    throw new Error("This is a Passvault export file — choose \"Passvault (JSON)\" as the format instead.");
  }
  if (!Array.isArray(data.items) || !data.items.every((it) => typeof it.type === "number")) {
    throw new Error("This doesn't look like a Bitwarden export file.");
  }
  const folderNameById = new Map((data.folders || []).map((f) => [f.id, f.name]));
  const warnings = [];
  const items = [];
  for (const bw of data.items) {
    if (bw.deletedDate) continue; // Bitwarden exports can include trashed items; skip them like the item never existed
    const type = BITWARDEN_TYPE_MAP[bw.type];
    if (!type) {
      warnings.push(`Skipped "${bw.name || "(untitled)"}" — unsupported item type.`);
      continue;
    }
    const folder = bw.folderId ? folderNameById.get(bw.folderId) || null : null;
    const fields = { name: bw.name || "(untitled)", notes: bw.notes || "" };
    if (type === "login") {
      const login = bw.login || {};
      fields.username = login.username || "";
      fields.password = login.password || "";
      fields.totp = login.totp || "";
      fields.uri = (login.uris && login.uris[0] && login.uris[0].uri) || "";
    } else if (type === "card") {
      const card = bw.card || {};
      Object.assign(fields, {
        cardholderName: card.cardholderName || "",
        brand: card.brand || "",
        number: card.number || "",
        cvv: card.code || "",
        expMonth: card.expMonth || "",
        expYear: card.expYear || "",
      });
    } else if (type === "identity") {
      const id = bw.identity || {};
      Object.assign(fields, {
        firstName: id.firstName || "",
        lastName: id.lastName || "",
        email: id.email || "",
        phone: id.phone || "",
        address: [id.address1, id.address2, id.address3].filter(Boolean).join(", "),
        city: id.city || "",
        state: id.state || "",
        postalCode: id.postalCode || "",
        country: id.country || "",
      });
    }
    items.push({ type, folder, fields });
  }
  return { items, warnings };
}

// Minimal RFC-4180-ish CSV parser: quoted fields (embedded commas/
// newlines) and "" as an escaped quote. Enough for the well-behaved
// exports this is actually used to read (Chrome/Google, Bitwarden) — not
// a general-purpose CSV library.
function parseCSV(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        inQuotes = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function hostnameFromURL(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

// Chrome/Google Password Manager's export: header row
// "name,url,username,password,note" (note column not present in every
// Chrome version — treated as optional). Header matching is
// case-insensitive since this isn't Bitwarden's stricter format.
export function parseChromeCSV(text) {
  const rows = parseCSV(text);
  if (!rows.length) throw new Error("Empty file.");
  const header = rows[0].map((h) => h.trim().toLowerCase());
  const col = (name) => header.indexOf(name);
  const nameCol = col("name");
  const urlCol = col("url");
  const userCol = col("username");
  const passCol = col("password");
  const noteCol = col("note");
  if (userCol === -1 || passCol === -1) {
    throw new Error("This doesn't look like a Chrome/Google password export (missing username/password columns).");
  }
  const items = [];
  for (const r of rows.slice(1)) {
    if (!r.length || (r.length === 1 && r[0] === "")) continue;
    const uri = urlCol !== -1 ? r[urlCol] || "" : "";
    const name = (nameCol !== -1 && r[nameCol]) || hostnameFromURL(uri) || "(untitled)";
    items.push({
      type: "login",
      folder: null,
      fields: {
        name,
        uri,
        username: userCol !== -1 ? r[userCol] || "" : "",
        password: passCol !== -1 ? r[passCol] || "" : "",
        totp: "",
        notes: noteCol !== -1 ? r[noteCol] || "" : "",
      },
    });
  }
  return { items, warnings: [] };
}

export const IMPORT_FORMATS = {
  passvault: { label: "Passvault (JSON)", parse: parsePassvaultJSON },
  "bitwarden-json": { label: "Bitwarden (JSON)", parse: parseBitwardenJSON },
  "chrome-csv": { label: "Chrome / Google Password Manager (CSV)", parse: parseChromeCSV },
};
