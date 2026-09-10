# Chrome Web Store listing — draft

Not submitted yet (the extension is still loaded unpacked for development —
see `extension/README.md`). This is reference copy for whenever it is:
copy fields into the [Chrome Web Store Developer
Dashboard](https://chrome.google.com/webstore/devconsole) as-is or adjust to
taste.

## Listing copy

**Name**: Passvault

**Summary** (132 char max — same string as `manifest.json`'s `description`):
> Autofill and save logins for your self-hosted Passvault — zero-knowledge, so the server never sees your master password.

**Category**: Productivity

**Detailed description**:

> Passvault is a free, open-source, self-hosted password manager. This
> extension unlocks your own Passvault server right in the browser and
> autofills your saved logins on other sites — the same zero-knowledge
> design as the web app: your master password and vault key never leave
> your device, encrypted or otherwise.
>
> **What it does**
> - Log in to your self-hosted Passvault instance from the toolbar
> - Autofill saved logins on the sites they belong to
> - Offers to save a new login right after you sign in somewhere
> - Nothing is sent anywhere except the one server you configure
>
> **Requires your own Passvault server.** This extension is a client for
> a self-hosted instance you (or your organization) run — there's no
> Passvault cloud service, and the extension has zero access to any site
> until you explicitly grant it in setup. Get the server at
> [github.com/toshost/passvault](https://github.com/toshost/passvault).
>
> **Zero-knowledge, for real**: the entire client-side crypto trust
> boundary is about 200 lines of code, open source and readable end to
> end. Argon2id key derivation, AES-256-GCM envelope encryption — nothing
> proprietary, nothing to take on faith.
>
> Passkey storage/autofill for other sites, and a Firefox port, are on
> the roadmap but not in this release — see the GitHub repo for current
> status.

**Website**: https://github.com/toshost/passvault

**Support URL**: https://github.com/toshost/passvault/issues

## Permission justifications

Chrome Web Store review requires a plain-language reason for every
requested permission. Use these:

- **`storage`** — Stores the session (access/refresh tokens, unlocked
  vault key, and decrypted login items for autofill matching) in
  `chrome.storage.session` — cleared when the browser closes, never
  written to disk — and stores the user's own configured server URL in
  `chrome.storage.local`.
- **`activeTab`** — Reads the active tab's URL only when the popup is
  opened (a direct user action), to show logins matching that specific
  site and to know which server-permission origin to display in options.
  Never used to read tabs the user hasn't directly interacted with.
- **`optional_host_permissions` (`*://*/*`, requested narrowly per-origin
  at setup time)** — The extension needs to reach the ONE self-hosted
  server URL the user enters in options, which can be any origin since
  Passvault has no fixed cloud domain. Access is requested via
  `chrome.permissions.request()` for that specific origin only, as a
  direct result of the user's own click — never granted broadly or
  silently.
- **Content script on all `http(s)` pages** — Needed to detect login
  forms and offer autofill/save on whatever site the user is actually
  logging into. The content script never contacts the Passvault server
  itself (see `extension/README.md`); it only messages the extension's
  own background worker, which does.

## Screenshots (1280x800 or 640x400, up to 5) — NOT included here

These need to be real captures from a loaded, logged-in extension — a
generated mockup would misrepresent the actual product, so none is
included in this repo. Suggested shots, in order:

1. The unlocked popup showing a matched login for a real site.
2. The options/setup page.
3. The in-page autofill badge next to a password field on a real login form.
4. The "Save this password to Passvault?" prompt after a fresh login.
5. The locked/login state of the popup.

To capture: load the extension unpacked (see `extension/README.md`), log
in, trigger each state, and use your OS's own screenshot tool (macOS:
Cmd+Shift+4) — cropped to just the popup/page content, at or above
640x400.

## Promotional images

- **Small promo tile (440x280)** — `extension/store/small-promo-tile-440x280.png`, included.
- **Marquee tile (1400x560)** — optional (only used if Chrome features
  the listing); not generated, low priority for a first submission.
