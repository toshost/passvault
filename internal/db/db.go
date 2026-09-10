// Package db opens and migrates Passvault's Postgres database. Unlike
// dnsmanager's single-tenant SQLite (internal/db/db.go there), Passvault has
// growing per-user data (items, attachments, audit logs) even for a single
// self-hosted instance, so it starts on Postgres directly rather than
// planning a later migration.
package db

import (
	"database/sql"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Open connects to Postgres (dsn e.g. "postgres://user:pass@host/db") and
// applies the schema. CREATE TABLE IF NOT EXISTS + ALTER ... ADD COLUMN IF
// NOT EXISTS make this safe to run on every boot, same convention as
// dnsmanager's migrate().
func Open(dsn string) (*sql.DB, error) {
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	// Explicit pool bounds rather than Go's unbounded default — without
	// this, a burst of expensive or slow requests (compounded by
	// internal/api's own request-body size cap and server timeouts) could
	// still open an unbounded number of Postgres connections and exhaust
	// it faster than either of those alone would. 25 is comfortable
	// single-instance headroom without needing to be tuned per-deployment.
	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(25)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	if err := sqlDB.Ping(); err != nil {
		return nil, err
	}
	if err := migrate(sqlDB); err != nil {
		return nil, err
	}
	return sqlDB, nil
}

// schema covers personal vaults + attachments (no orgs/collections yet —
// see the roadmap in README.md). One self-hosted instance,
// one flat user table — no tenant/billing concept. Signup is closed by
// default (PASSVAULT_SIGNUPS_ALLOWED=false): the admin generates one-time
// invites (crypto.NewOpaqueToken, same shape as Vaultwarden's own
// invite-only posture) via /v1/admin/invites.
const schema = `
-- One shared sequence for folders+ciphers revision_ts, so GET /v1/sync?since=
-- can return a single strictly-increasing watermark across both kinds
-- instead of racing two independent counters.
CREATE SEQUENCE IF NOT EXISTS revision_seq;

CREATE TABLE IF NOT EXISTS invites (
	token       TEXT PRIMARY KEY,
	email       TEXT, -- optional: locks the invite to one address; NULL = any
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	used_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS users (
	id                          SERIAL PRIMARY KEY,
	email                       TEXT NOT NULL UNIQUE,
	crypto_realm                TEXT NOT NULL DEFAULT 'native', -- native | bwcompat
	kdf_memory_kib              INTEGER NOT NULL,
	kdf_iterations              INTEGER NOT NULL,
	kdf_parallelism             SMALLINT NOT NULL,
	kdf_salt                    TEXT NOT NULL, -- base64, client-generated at signup
	auth_hash                   TEXT NOT NULL, -- crypto.HashAuthKey(authKey) — never a master-password hash
	wrapped_vault_key           TEXT NOT NULL, -- opaque to server
	x25519_public_key           TEXT NOT NULL,
	wrapped_x25519_private_key  TEXT NOT NULL, -- opaque to server
	disabled                    BOOLEAN NOT NULL DEFAULT false, -- admin kill switch; blocks login and revokes nothing implicitly (see auth.DisableUser)
	-- Account 2FA (internal/totp): totp_2fa_secret is server-side, outside
	-- the zero-knowledge boundary on purpose — the server must actively
	-- compute and compare a code on every login, which is impossible if
	-- the secret were only recoverable after a successful login. Same
	-- "operational, not user-data" trust class as smtp_settings.password
	-- (see docs/PROTOCOL.md). Distinct from any TOTP a user stores as a
	-- vault item for OTHER sites, which stays fully client-side.
	totp_2fa_secret             TEXT,
	totp_2fa_enabled            BOOLEAN NOT NULL DEFAULT false,
	-- Replay guard for a verified TOTP code: the highest time-step
	-- counter this account has ever successfully claimed (internal/auth.
	-- ConsumeTOTPStep). A code's ±1-step window is ~90s, during which
	-- totp.Verify alone would accept the SAME correct code more than
	-- once (a second concurrent login, or an attacker racing a captured
	-- code) — this makes claiming a step atomic and one-shot per step,
	-- never the code value itself.
	totp_last_used_step         BIGINT,
	-- Email alias provider integration (see internal/api/email_alias_handlers.go):
	-- the API key stays zero-knowledge at rest, AES-GCM-encrypted under
	-- this account's own vaultKey exactly like everything else opaque in
	-- this schema — it only exists in plaintext transiently, server-side,
	-- for the single request that actually calls the provider's API.
	email_alias_provider        TEXT NOT NULL DEFAULT '', -- '' | 'simplelogin'
	wrapped_email_alias_api_key TEXT,
	-- Account recovery kit (see docs/PROTOCOL.md): a one-time random
	-- recoveryCode, generated client-side and shown to the user exactly
	-- once (print it, store it offline) — never itself sent to or stored
	-- by the server. Two DISTINCT values are HKDF'd from it, mirroring
	-- the master password's own authKey/wrapKey split: recovery_code_hash
	-- is crypto.HashToken(recoveryAuthKey) — cheap, not Argon2id, because
	-- recoveryAuthKey already carries 256 bits of entropy, same reasoning
	-- as recovery_codes.code_hash for 2FA; wrapped_vault_key_for_recovery
	-- is AES-GCM(recoveryWrapKey, vaultKey), opaque to the server exactly
	-- like wrapped_vault_key itself. Creating a new kit overwrites both,
	-- invalidating any previously printed one.
	recovery_code_hash             TEXT,
	wrapped_vault_key_for_recovery  TEXT,
	created_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_2fa_secret TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_2fa_enabled BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_used_step BIGINT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_alias_provider TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS wrapped_email_alias_api_key TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS recovery_code_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS wrapped_vault_key_for_recovery TEXT;

CREATE TABLE IF NOT EXISTS devices (
	id                          SERIAL PRIMARY KEY,
	user_id                     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	label                       TEXT NOT NULL DEFAULT '',
	refresh_token_hash          TEXT NOT NULL UNIQUE,
	-- The hash refresh_token_hash held just before its last rotation —
	-- kept around specifically so Refresh() can tell "a stale/replayed
	-- token" apart from "a token that never existed" (see auth.Refresh).
	-- Not a full history, just one step back: that's all a same-instant
	-- rotation race or a stolen-and-replayed token needs to be detected.
	previous_refresh_token_hash TEXT,
	refresh_expires_at          TIMESTAMPTZ NOT NULL,
	access_token_hash           TEXT NOT NULL,
	access_expires_at           TIMESTAMPTZ NOT NULL,
	last_seen_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
	created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
	revoked_at                  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id) WHERE revoked_at IS NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS previous_refresh_token_hash TEXT;
CREATE INDEX IF NOT EXISTS idx_devices_previous_refresh_token_hash ON devices(previous_refresh_token_hash) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS folders (
	id                  SERIAL PRIMARY KEY,
	user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	wrapped_folder_key  TEXT NOT NULL,
	encrypted_name      TEXT NOT NULL, -- opaque to server
	revision_ts         BIGINT NOT NULL,
	created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_folders_user_rev ON folders(user_id, revision_ts);

CREATE TABLE IF NOT EXISTS ciphers (
	id                SERIAL PRIMARY KEY,
	user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	folder_id         INTEGER REFERENCES folders(id) ON DELETE SET NULL,
	type              TEXT NOT NULL, -- login | note | card | identity | totp | ssh_key
	wrapped_item_key  TEXT NOT NULL,
	encrypted_blob    TEXT NOT NULL, -- opaque to server: name/username/password/TOTP/notes/URIs
	revision_ts       BIGINT NOT NULL,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_ciphers_user_rev ON ciphers(user_id, revision_ts);

-- Simple item sharing (one item, one recipient — not an org/collection
-- model). wrapped_item_key here is NOT wrapped under the recipient's
-- vaultKey like ciphers.wrapped_item_key is under the owner's — it's
-- wrapped via an X25519 ECDH-derived key between owner and recipient (see
-- web/crypto.js's deriveSharedWrapKey and docs/PROTOCOL.md), so only those
-- two people can ever unwrap it, not even this instance's admin.
CREATE TABLE IF NOT EXISTS cipher_shares (
	id                   SERIAL PRIMARY KEY,
	cipher_id            INTEGER NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
	owner_user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	shared_with_user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	wrapped_item_key     TEXT NOT NULL,
	created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (cipher_id, shared_with_user_id)
);
CREATE INDEX IF NOT EXISTS idx_cipher_shares_recipient ON cipher_shares(shared_with_user_id);
CREATE INDEX IF NOT EXISTS idx_cipher_shares_cipher ON cipher_shares(cipher_id);

-- Files are encrypted client-side before upload — the server stores and
-- serves ciphertext bytes verbatim (see internal/api/attachment_handlers.go),
-- same opacity guarantee as encrypted_blob. storage_path is a server-
-- generated random token, never derived from the client-supplied filename
-- (which is itself opaque/encrypted) — no path-traversal surface.
CREATE TABLE IF NOT EXISTS attachments (
	id                      SERIAL PRIMARY KEY,
	cipher_id               INTEGER NOT NULL REFERENCES ciphers(id) ON DELETE CASCADE,
	wrapped_attachment_key  TEXT NOT NULL,
	encrypted_filename      TEXT NOT NULL,
	size_bytes              BIGINT NOT NULL,
	storage_path            TEXT NOT NULL,
	created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id);

-- Bitwarden Send-style one-time/expiring anonymous sharing: id is an
-- opaque unguessable token (like invites.token), not a sequential integer,
-- because anonymous recipients look a Send up with NO authentication at
-- all. Content is encrypted client-side under a random sendKey that is
-- embedded ONLY in the share URL's fragment (web/send.html) — never sent
-- to, or derivable by, the server in any request. wrapped_send_key lets
-- the OWNER's own client re-decrypt content/filename later from "My
-- Sends" (AES-GCM(vaultKey, sendKey)) without needing the one-time URL
-- again; encrypted_label is the owner-visible note, same envelope as
-- folders.encrypted_name. password_hash is an OPTIONAL extra server-side
-- gate (crypto.HashAuthKey reused as a generic Argon2id hash/verify, not
-- actually an authKey here) checked before the server will release
-- encrypted_content/encrypted_filename/file bytes at all — it defends
-- against a leaked or guessed URL (browser history, shoulder-surfing, a
-- referrer leak), not a compromised server, which could already read
-- every other opaque column here too; it never influences sendKey itself.
CREATE TABLE IF NOT EXISTS sends (
	id                  TEXT PRIMARY KEY,
	owner_user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	type                TEXT NOT NULL, -- text | file
	wrapped_send_key    TEXT NOT NULL,
	encrypted_label     TEXT NOT NULL,
	encrypted_content   TEXT, -- text sends only
	encrypted_filename  TEXT, -- file sends only
	storage_path        TEXT, -- file sends only, random on-disk name (see attachments.storage_path)
	size_bytes          BIGINT,
	password_hash       TEXT,
	max_views           INTEGER, -- NULL = unlimited until expiry
	view_count          INTEGER NOT NULL DEFAULT 0,
	expires_at          TIMESTAMPTZ NOT NULL,
	-- NULL = available immediately (the original behavior). When set, the
	-- Send EXISTS and its metadata is visible right away (so a recipient
	-- can see "this unlocks at <time>"), but HandleAccessSend refuses to
	-- release content until now() reaches it — a scheduled-reveal /
	-- dead-man-switch mode, not just a later expiry. Must be before
	-- expires_at (validated at creation) or the Send would be permanently
	-- unreachable.
	available_at        TIMESTAMPTZ,
	created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
	deleted_at          TIMESTAMPTZ -- owner-revoked, or auto-purged on expiry/view-limit
);
ALTER TABLE sends ADD COLUMN IF NOT EXISTS available_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_sends_owner ON sends(owner_user_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sends_expiry ON sends(expires_at) WHERE deleted_at IS NULL;

-- Singleton row (id always 1) holding a per-instance random HMAC key,
-- generated once at first boot (internal/auth.EnsureServerSecret) and
-- reused forever after. The ONLY thing it backs is Prelogin's
-- deterministic fake salt for a nonexistent email (internal/auth.
-- deterministicFakeSalt) — nothing zero-knowledge-relevant depends on
-- it, so losing it (a fresh DB) just resets what fake salts look like,
-- which is harmless. Not reused for anything else so a future need for
-- a "real" server secret never has to reason about this one's blast
-- radius.
CREATE TABLE IF NOT EXISTS server_secrets (
	id       SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	hmac_key TEXT NOT NULL DEFAULT ''
);
INSERT INTO server_secrets (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Singleton row (id always 1) holding the instance operator's SMTP relay
-- config, set from web/admin.html rather than an env var — the whole
-- point is changing it without a redeploy. Password is plaintext at rest:
-- this is server-side operational infrastructure config the server must
-- present verbatim to a mail relay, same trust class as PASSVAULT_DB_DSN,
-- NOT part of the zero-knowledge boundary (nothing here is ever wrapped
-- under a user's vaultKey). See internal/mailer.
CREATE TABLE IF NOT EXISTS smtp_settings (
	id            SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	host          TEXT NOT NULL DEFAULT '',
	port          INTEGER NOT NULL DEFAULT 587,
	username      TEXT NOT NULL DEFAULT '',
	password      TEXT NOT NULL DEFAULT '',
	from_address  TEXT NOT NULL DEFAULT '',
	from_name     TEXT NOT NULL DEFAULT 'Passvault',
	use_tls       BOOLEAN NOT NULL DEFAULT true,
	updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO smtp_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- Bitwarden-style emergency access: a grantor designates a trusted
-- contact who can request read ("view") or full ("takeover") access to
-- the grantor's vault if the grantor doesn't respond within wait_days.
-- wrapped_vault_key_for_grantee is set at CONFIRM time (not invite time)
-- because only the grantor's own already-unlocked client can wrap its own
-- vaultKey — it's an AES-GCM envelope under an X25519-ECDH-derived key
-- between grantor and grantee (web/crypto.js's deriveEmergencyAccessWrapKey,
-- a sibling of deriveSharedWrapKey used for item sharing, with its own
-- distinct HKDF info string so the two features never share derived key
-- material even between the same two users). See docs/PROTOCOL.md.
CREATE TABLE IF NOT EXISTS emergency_access (
	id                             SERIAL PRIMARY KEY,
	grantor_user_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	grantee_user_id                INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	access_type                    TEXT NOT NULL, -- view | takeover
	wait_days                      INTEGER NOT NULL,
	status                         TEXT NOT NULL DEFAULT 'invited', -- invited | accepted | confirmed | requested | granted
	wrapped_vault_key_for_grantee  TEXT,
	requested_at                   TIMESTAMPTZ,
	access_at                      TIMESTAMPTZ, -- requested_at + wait_days; when the sweep auto-grants
	created_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at                     TIMESTAMPTZ NOT NULL DEFAULT now(),
	UNIQUE (grantor_user_id, grantee_user_id)
);
CREATE INDEX IF NOT EXISTS idx_emergency_grantor ON emergency_access(grantor_user_id);
CREATE INDEX IF NOT EXISTS idx_emergency_grantee ON emergency_access(grantee_user_id);
CREATE INDEX IF NOT EXISTS idx_emergency_pending_access ON emergency_access(status, access_at) WHERE status = 'requested';

-- A short-lived bridge between a successful authKey check and a real
-- device token pair, when 2FA is enabled — HandleLogin issues one of
-- these instead of tokens; HandleLoginTOTP exchanges it (plus a valid
-- code) for the real login response. Deleted only on a SUCCESSFUL code
-- (or once expires_at passes) — a wrong code decrements attempts_left
-- instead of burning the whole challenge, so a mistyped digit doesn't
-- force retyping the master password too. attempts_left bounds brute-
-- forcing the 6-digit space within the TTL window in place of a general
-- rate limiter, which this codebase doesn't otherwise have.
CREATE TABLE IF NOT EXISTS pending_logins (
	token_hash    TEXT PRIMARY KEY, -- crypto.HashToken(token) — the raw token is shown to the client exactly once
	user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	device_label  TEXT NOT NULL DEFAULT '',
	attempts_left SMALLINT NOT NULL DEFAULT 10,
	expires_at    TIMESTAMPTZ NOT NULL,
	created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE pending_logins ADD COLUMN IF NOT EXISTS attempts_left SMALLINT NOT NULL DEFAULT 10;

-- The account-recovery equivalent of pending_logins: issued once
-- recovery_code_hash verifies, exchanged (auth.FinishRecovery) for a new
-- master password. Same single-use-on-success, short-TTL shape.
CREATE TABLE IF NOT EXISTS pending_recoveries (
	token_hash TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at TIMESTAMPTZ NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time 2FA recovery codes, issued as a batch whenever 2FA is enabled
-- or explicitly regenerated (which invalidates the previous batch — see
-- auth.RegenerateRecoveryCodes). code_hash uses the cheap crypto.HashToken
-- (SHA-256), not crypto.HashAuthKey's Argon2id round: these are
-- server-generated, already-uniformly-random strings, not low-entropy
-- user-chosen secrets, so there's nothing for an expensive KDF to defend
-- against here (same reasoning as devices.refresh_token_hash).
CREATE TABLE IF NOT EXISTS recovery_codes (
	id          SERIAL PRIMARY KEY,
	user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	code_hash   TEXT NOT NULL,
	used_at     TIMESTAMPTZ,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes(user_id) WHERE used_at IS NULL;

-- Backs internal/ratelimit — throttles guessable-secret endpoints (login,
-- 2FA codes, account recovery, password-protected Send access) that
-- would otherwise have no defense against a script trying values
-- quickly. bucket+identifier namespaces attempts per endpoint and per
-- email/IP/send-id so one flood can't cross-throttle an unrelated
-- resource. Swept hourly (see internal/ratelimit.Sweep) so it never
-- grows unbounded.
CREATE TABLE IF NOT EXISTS rate_limit_attempts (
	id           SERIAL PRIMARY KEY,
	bucket       TEXT NOT NULL,
	identifier   TEXT NOT NULL,
	attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rate_limit_lookup ON rate_limit_attempts(bucket, identifier, attempted_at);

CREATE TABLE IF NOT EXISTS audit_log (
	id          SERIAL PRIMARY KEY,
	user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
	event       TEXT NOT NULL,
	target      TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
`

func migrate(sqlDB *sql.DB) error {
	_, err := sqlDB.Exec(schema)
	return err
}
