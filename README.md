# Passvault

A free, open-source, self-hosted password manager — a Bitwarden / Vaultwarden
/ 1Password alternative you run yourself. Zero-knowledge: the server never
sees your master password or a usable encryption key, only opaque
ciphertext. See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for exactly how, and
[`SECURITY.md`](SECURITY.md) if you find a way to make that claim false.

This is Phase 1: a working server + web app for personal vaults on one
self-hosted instance, including TOTP (both a stored vault item and
account-level 2FA), a password generator and security checker,
attachments, simple item-to-item sharing, passkey device unlock, Send
(including a scheduled-reveal/time-delay mode), emergency access with
real SMTP email, email alias generation (SimpleLogin integration), an
offline-storable account recovery kit, rate limiting on every
guessable-secret endpoint, a recent-activity/audit log view, import/export
(Passvault JSON, Bitwarden JSON, Chrome/Google CSV), an SSH key item
type, installable PWA/offline support (the app shell loads without a
network connection, and an already-unlocked session keeps showing your
vault from a local cache if the connection drops), and a Chromium browser
extension (`extension/`) for login + password autofill/save on other
sites. No full orgs/collections, CLI, mobile app, Firefox support, or
passkey *storage* (saving/autofilling passkeys for other sites — the
extension unlocks that, but the actual WebAuthn-authenticator
implementation isn't built yet) — see [Roadmap](#roadmap).

Licensed [AGPL-3.0](LICENSE) — same license family as Bitwarden and
Vaultwarden. If you run a modified version as a network service, you must
make your changes available to its users.

## Why another one?

Vaultwarden is excellent and this project doesn't try to replace it for
most people — if you just want a lightweight Bitwarden-compatible server
today, use Vaultwarden. Passvault exists as an independent implementation
with its own protocol (not translating Bitwarden's wire format), written to
be small enough to read end-to-end: the entire crypto trust boundary is one
~200-line file (`web/crypto.js`), and the server is a single Go binary with
no framework and only first-party/stdlib crypto dependencies.

## Quickstart

```bash
docker compose -f docker-compose.dev.yml up -d   # local Postgres for development

PASSVAULT_DB_DSN="postgres://passvault:passvault_dev_only@127.0.0.1:55432/passvault?sslmode=disable" \
PASSVAULT_ADMIN_TOKEN="pick-a-dev-only-token" \
PASSVAULT_LISTEN="127.0.0.1:8099" \
go run ./cmd/passvault-server
```

Signups are invite-only by default (same posture as Vaultwarden). Create an
invite with your admin token:

```bash
curl -X POST http://127.0.0.1:8099/v1/admin/invites \
  -H "Authorization: Bearer pick-a-dev-only-token" -H "Content-Type: application/json" -d '{}'
# -> {"invite_token":"..."}
```

Open `http://127.0.0.1:8099/`, paste the token into Sign Up, and create a
vault. (Or set `PASSVAULT_SIGNUPS_ALLOWED=true` to allow open registration —
fine for a private LAN instance, not recommended for anything internet-facing.)

Emergency access needs outbound email to actually notify anyone — set that
up at `http://127.0.0.1:8099/admin.html` (same admin token) rather than an
env var, so it can be configured or changed without a redeploy.

## Deploying

See `install/` for a systemd unit + nginx config for a first-party Go
binary deployment (no Docker needed in production — Postgres via your
distro's package, `passvault-server` as a plain binary behind nginx).
`install/passvault.env.example` documents every environment variable —
SMTP is deliberately not one of them; it's admin-panel-configured, stored
in Postgres.

## Test

```bash
go test ./...
go vet ./...
```

`internal/crypto` has unit tests (Argon2id round-trip, token hashing, blob
validation). The rest is exercised end-to-end via the running app — there's
no mocked-DB integration suite yet; contributions welcome.

## Layout

- `internal/crypto` — server-side Argon2id/AES-GCM/token primitives, no I/O.
- `internal/auth` — session (access/refresh token) issuance, registration,
  login, password change, admin invites, user disable.
- `internal/mailer` — SMTP client for emergency-access and account-security
  notifications; reads its config fresh from Postgres on every send.
- `internal/totp` — RFC 6238 TOTP for account 2FA (login itself) — a
  deliberately separate, server-side concern from a vault item's own
  stored TOTP, which stays entirely client-side (`web/totp.js`).
- `internal/ratelimit` — throttles login, 2FA, account recovery, and
  password-protected Send access, DB-backed so it survives a restart.
- `internal/db` — Postgres schema + migration.
- `internal/api` — HTTP handlers + router (`/v1/*` for authenticated clients,
  `/public/*` for anonymous Send access, `/v1/admin/*` for the instance
  operator).
- `web/` — the reference client: `crypto.js` (the trust boundary — every
  byte of ciphertext is produced here, never on the server), `app.js` (UI
  logic), `send.html`/`send.js` (a deliberately separate, unauthenticated
  page for anonymous Send recipients — no session, no login), `admin.html`/
  `admin.js` (instance operator settings — SMTP — gated by the admin token,
  not a user session), `importexport.js` (Passvault/Bitwarden/Chrome
  format parsers — pure functions, no DOM/network/crypto, since it only
  ever handles plaintext), `vendor/hash-wasm/` (vendored Argon2id WASM,
  the one primitive with no Web Crypto equivalent — everything else is
  native SubtleCrypto), `sw.js`/`manifest.json`/`icons/` (installable PWA:
  offline app-shell caching, no opinion on vault data — see
  `docs/PROTOCOL.md`).
- `extension/` — the Chromium browser extension (Manifest V3): login +
  password autofill/save on other sites. `extension/lib/crypto.js` is a
  generated copy of `web/crypto.js` (see `scripts/sync-extension-libs.sh`),
  not a separate implementation — see `extension/README.md`.
- `cmd/passvault-server/` — the binary.

## Roadmap

0. ~~Protocol spec + data model~~ — see `docs/PROTOCOL.md`.
1. ~~Server + web app, personal vaults~~ — this is where the project is now.
   ~~TOTP, password generator, security check (weak/reused/breach), item
   types (login/note/card/identity/ssh_key), folders, attachments, simple
   one-item sharing (X25519 ECDH), passkey device unlock (WebAuthn PRF),
   Send (one-time anonymous encrypted links, plus scheduled-reveal/
   time-delay), emergency access (view/takeover, with real SMTP
   notifications, admin-panel configured), account 2FA (TOTP + recovery
   codes), email alias generation (SimpleLogin), an offline account
   recovery kit, rate limiting, a recent-activity/audit log view,
   import/export (Passvault JSON, Bitwarden JSON, Chrome/Google CSV), and
   installable PWA/offline support~~.
2. CLI (`passvault-cli`) against the same `/v1` API.
3. Full orgs/collections with role-based access (the current sharing is
   deliberately simple: one item, one recipient, no groups or roles).
4. Bitwarden wire-protocol compatibility as an opt-in second mode, so
   existing official Bitwarden mobile apps can point at a Passvault server
   without Passvault having to ship native apps immediately.
5. Browser extension — ~~Chromium (Manifest V3): self-hosted server setup,
   login, password autofill and save-new-login on other sites~~ (see
   `extension/`). Still open within this item: storing/autofilling
   *passkeys for other sites* (a real WebAuthn/FIDO2 authenticator
   implementation — distinct from today's passkey device-unlock feature,
   and the original reason an extension was needed at all), a Firefox
   port, and a standalone TOTP-authenticator view.
6. Native mobile apps on Passvault's own protocol.

## Contributing

Issues and PRs welcome. If you're touching `internal/crypto`, `internal/auth`,
or `web/crypto.js`, please explain the *why* in the PR description — this is
the one part of the codebase where a "simpler" change can silently weaken
the security guarantee, and reviewers need the reasoning, not just the diff.

## License

[GNU AGPL-3.0](LICENSE).
