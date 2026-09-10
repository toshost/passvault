package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"sync"

	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
)

var (
	dummyAuthHashOnce sync.Once
	dummyAuthHash     string
	dummyAuthHashErr  error
)

// dummyLoginHash lazily computes (once) a validly-shaped but otherwise
// meaningless Argon2id hash, at the same cost parameters HashAuthKey
// always uses — see Login's not-found branch for why.
func dummyLoginHash() (string, error) {
	dummyAuthHashOnce.Do(func() {
		dummyAuthHash, dummyAuthHashErr = vcrypto.HashAuthKey("passvault-dummy-timing-equalizer")
	})
	return dummyAuthHash, dummyAuthHashErr
}

var (
	ErrEmailTaken       = errors.New("email already registered")
	ErrInvalidInvite    = errors.New("invalid or already-used invite")
	ErrInviteWrongEmail = errors.New("this invite was issued for a different email address")
)

// ConsumeInvite atomically marks a one-time admin-issued invite used. If the
// invite was created locked to a specific email, that email must match
// (case-insensitively) or the invite is rejected WITHOUT being consumed —
// anyone who merely learns a locked invite's token (a forwarded email, a
// browser-history entry) must not be able to permanently burn it against
// a different address, denying it to the person it was actually issued
// for. `SELECT ... FOR UPDATE` locks the row for the rest of the
// transaction, which is what still makes this safe against two
// concurrent registrations racing the same valid token: the second
// transaction blocks until the first commits (or rolls back on a
// wrong-email rejection), then re-reads the row's actual current state
// rather than racing it blind.
func ConsumeInvite(db *sql.DB, token, email string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit has succeeded

	var lockedEmail sql.NullString
	var usedAt sql.NullTime
	err = tx.QueryRow(`SELECT email, used_at FROM invites WHERE token = $1 FOR UPDATE`, token).Scan(&lockedEmail, &usedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidInvite
		}
		return err
	}
	if usedAt.Valid {
		return ErrInvalidInvite
	}
	if lockedEmail.Valid && !strings.EqualFold(lockedEmail.String, email) {
		return ErrInviteWrongEmail // tx rolls back — token stays unconsumed
	}
	if _, err := tx.Exec(`UPDATE invites SET used_at = now() WHERE token = $1`, token); err != nil {
		return err
	}
	return tx.Commit()
}

// EnsureServerSecret makes sure a per-instance random HMAC key exists in
// server_secrets, generating one (crypto/rand, 256 bits) the first time
// it's ever called on a given database — called once at startup
// (cmd/passvault-server/main.go), before anything might need it. Safe to
// call on every boot: a key already present is a no-op.
func EnsureServerSecret(db *sql.DB) error {
	var key string
	if err := db.QueryRow(`SELECT hmac_key FROM server_secrets WHERE id = 1`).Scan(&key); err != nil {
		return err
	}
	if key != "" {
		return nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	// The WHERE hmac_key='' guard makes this safe even if called
	// concurrently at cold start: only the first writer's value sticks,
	// everyone else's UPDATE just affects zero rows.
	_, err := db.Exec(`UPDATE server_secrets SET hmac_key = $1 WHERE id = 1 AND hmac_key = ''`,
		base64.StdEncoding.EncodeToString(raw))
	return err
}

// deterministicFakeSalt returns a stable-per-email salt for Prelogin's
// nonexistent-account path — HMAC-SHA256(serverSecret, email), truncated
// to the same 16 bytes a real per-user salt uses. Deterministic (not
// crypto/rand every call) is the whole point: see Prelogin's comment.
// Hashes the email EXACTLY as submitted, no case-folding — `users.email`
// is looked up case-sensitively (no citext, no lower() anywhere in this
// codebase), so this has to match that exactly, or two different-case
// spellings of the same real account's email would get the SAME fake
// salt from each other while the one exact-case spelling that actually
// exists returns a different (real) salt — reintroducing, via casing,
// exactly the kind of oracle this function exists to close.
func deterministicFakeSalt(db *sql.DB, email string) (string, error) {
	var keyB64 string
	if err := db.QueryRow(`SELECT hmac_key FROM server_secrets WHERE id = 1`).Scan(&keyB64); err != nil {
		return "", err
	}
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(email))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16]), nil
}

// Prelogin returns the KDF parameters a client must use to derive authKey
// for the given email — needed before the client can compute anything.
// If the email doesn't match a real account, it returns default
// parameters with a DETERMINISTIC fake salt instead of a freshly random
// one: a real account's salt is stable across repeated calls, so a
// salt that changes every time for an unknown email would itself BE the
// enumeration oracle this function exists to prevent — calling twice and
// diffing the two responses would reveal which case occurred, which is
// exactly the attack a previous version of this function was vulnerable
// to despite the same intent.
func Prelogin(db *sql.DB, email string) (vcrypto.KDFParams, error) {
	row := db.QueryRow(`SELECT kdf_memory_kib, kdf_iterations, kdf_parallelism, kdf_salt FROM users WHERE email = $1`, email)
	var p vcrypto.KDFParams
	err := row.Scan(&p.MemoryKiB, &p.Iterations, &p.Parallelism, &p.SaltB64)
	if err == nil {
		return p, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return vcrypto.KDFParams{}, err
	}
	p, err = vcrypto.DefaultKDFParams()
	if err != nil {
		return vcrypto.KDFParams{}, err
	}
	salt, err := deterministicFakeSalt(db, email)
	if err != nil {
		return vcrypto.KDFParams{}, err
	}
	p.SaltB64 = salt
	return p, nil
}

// RegisterInput is everything the client computes locally at signup. The
// server never sees a master password, wrapKey, vaultKey, or X25519 private
// key — only authKey (which it re-hashes, see crypto.HashAuthKey) and
// already-wrapped/opaque blobs.
type RegisterInput struct {
	Email                   string
	KDF                     vcrypto.KDFParams
	AuthKeyB64              string
	WrappedVaultKey         string
	X25519PublicKey         string
	WrappedX25519PrivateKey string
}

const maxOpaqueBlobBytes = 8192

// Register creates a user on this instance. Whether an invite was required
// to reach here is the caller's decision (see api.Server.signupsAllowed) —
// this function just creates the row.
func Register(db *sql.DB, in RegisterInput) (*models.User, error) {
	for _, blob := range []string{in.WrappedVaultKey, in.WrappedX25519PrivateKey} {
		if err := vcrypto.ValidateOpaqueBlob(blob, maxOpaqueBlobBytes); err != nil {
			return nil, err
		}
	}
	if in.X25519PublicKey == "" || in.AuthKeyB64 == "" || in.KDF.SaltB64 == "" {
		return nil, errors.New("missing required registration field")
	}

	authHash, err := vcrypto.HashAuthKey(in.AuthKeyB64)
	if err != nil {
		return nil, err
	}

	u := &models.User{
		Email:                   in.Email,
		CryptoRealm:             "native",
		KDFMemoryKiB:            in.KDF.MemoryKiB,
		KDFIterations:           in.KDF.Iterations,
		KDFParallelism:          in.KDF.Parallelism,
		KDFSalt:                 in.KDF.SaltB64,
		WrappedVaultKey:         in.WrappedVaultKey,
		X25519PublicKey:         in.X25519PublicKey,
		WrappedX25519PrivateKey: in.WrappedX25519PrivateKey,
	}

	err = db.QueryRow(`
		INSERT INTO users (email, crypto_realm, kdf_memory_kib, kdf_iterations, kdf_parallelism,
			kdf_salt, auth_hash, wrapped_vault_key, x25519_public_key, wrapped_x25519_private_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, created_at`,
		u.Email, u.CryptoRealm, u.KDFMemoryKiB, u.KDFIterations, u.KDFParallelism,
		u.KDFSalt, authHash, u.WrappedVaultKey, u.X25519PublicKey, u.WrappedX25519PrivateKey,
	).Scan(&u.ID, &u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return u, nil
}

// Login verifies a client-submitted authKey against the stored Argon2id
// hash and, only on success, returns the wrapped key material the client
// needs to unlock the vault locally. It never returns AuthHash. A disabled
// account fails the same generic way as a wrong password (see
// ErrInvalidCredentials) — it must not be distinguishable from outside.
func Login(db *sql.DB, email, authKeyB64 string) (*models.User, error) {
	row := db.QueryRow(`
		SELECT u.id, u.email, u.crypto_realm,
		       u.kdf_memory_kib, u.kdf_iterations, u.kdf_parallelism, u.kdf_salt, u.auth_hash,
		       u.wrapped_vault_key, u.x25519_public_key, u.wrapped_x25519_private_key, u.disabled, u.created_at,
		       u.totp_2fa_secret, u.totp_2fa_enabled
		FROM users u
		WHERE u.email = $1`, email)
	var u models.User
	if err := row.Scan(&u.ID, &u.Email, &u.CryptoRealm,
		&u.KDFMemoryKiB, &u.KDFIterations, &u.KDFParallelism, &u.KDFSalt, &u.AuthHash,
		&u.WrappedVaultKey, &u.X25519PublicKey, &u.WrappedX25519PrivateKey, &u.Disabled, &u.CreatedAt,
		&u.TOTP2FASecret, &u.TOTP2FAEnabled); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Run the exact same-cost Argon2id comparison the "wrong
			// password" branch below always pays, against a meaningless
			// precomputed hash, so a nonexistent email takes comparable
			// wall-clock time to a real one — without this, the two
			// branches return the identical ErrInvalidCredentials but at
			// measurably different speeds, letting a timing attacker
			// distinguish "no such account" from "wrong password" despite
			// the shared error being deliberately generic.
			if h, hErr := dummyLoginHash(); hErr == nil {
				vcrypto.VerifyAuthKey(h, authKeyB64)
			}
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}
	if !vcrypto.VerifyAuthKey(u.AuthHash, authKeyB64) || u.Disabled {
		return nil, ErrInvalidCredentials
	}
	u.AuthHash = ""
	return &u, nil
}

// LoadUserByID fetches a user by id with no password check — used by the
// second phase of a 2FA login (HandleLoginTOTP), where auth.Login's
// authKey check already happened in phase one and ConsumePendingLogin is
// what proves this call is entitled to load the account at all.
func LoadUserByID(db *sql.DB, id int64) (*models.User, error) {
	row := db.QueryRow(`
		SELECT u.id, u.email, u.crypto_realm,
		       u.kdf_memory_kib, u.kdf_iterations, u.kdf_parallelism, u.kdf_salt,
		       u.wrapped_vault_key, u.x25519_public_key, u.wrapped_x25519_private_key, u.disabled, u.created_at,
		       u.totp_2fa_secret, u.totp_2fa_enabled
		FROM users u WHERE u.id = $1`, id)
	var u models.User
	if err := row.Scan(&u.ID, &u.Email, &u.CryptoRealm,
		&u.KDFMemoryKiB, &u.KDFIterations, &u.KDFParallelism, &u.KDFSalt,
		&u.WrappedVaultKey, &u.X25519PublicKey, &u.WrappedX25519PrivateKey, &u.Disabled, &u.CreatedAt,
		&u.TOTP2FASecret, &u.TOTP2FAEnabled); err != nil {
		return nil, err
	}
	return &u, nil
}

// VerifyCurrentAuthKey checks a client-submitted authKey against the
// account's CURRENT stored hash — the re-authentication gate for
// credential-changing actions (change password, recovery-kit
// create/replace/remove) that must never be reachable by a bearer token
// alone. UserFromContext doesn't carry AuthHash (userFromAccessToken never
// selects it, so a stolen access token's request context never has it
// sitting in memory either), so this does its own narrow lookup.
func VerifyCurrentAuthKey(db *sql.DB, userID int64, authKeyB64 string) (bool, error) {
	var authHash string
	if err := db.QueryRow(`SELECT auth_hash FROM users WHERE id = $1`, userID).Scan(&authHash); err != nil {
		return false, err
	}
	return vcrypto.VerifyAuthKey(authHash, authKeyB64), nil
}

// ChangePassword atomically swaps AuthHash and the wrapped vault key. It
// never touches ciphers/folders — vaultKey itself doesn't change, only what
// wraps it (see docs/PROTOCOL.md "password change" for why that's safe and
// the entire point of the envelope design).
func ChangePassword(db *sql.DB, userID int64, kdf vcrypto.KDFParams, newAuthKeyB64, newWrappedVaultKey string) error {
	if err := vcrypto.ValidateOpaqueBlob(newWrappedVaultKey, maxOpaqueBlobBytes); err != nil {
		return err
	}
	authHash, err := vcrypto.HashAuthKey(newAuthKeyB64)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
		UPDATE users SET auth_hash=$1, wrapped_vault_key=$2,
			kdf_memory_kib=$3, kdf_iterations=$4, kdf_parallelism=$5, kdf_salt=$6
		WHERE id=$7`,
		authHash, newWrappedVaultKey, kdf.MemoryKiB, kdf.Iterations, kdf.Parallelism, kdf.SaltB64, userID)
	return err
}

// SetUserDisabled is the admin kill switch for one account — a compromised
// or departed user. It doesn't revoke existing devices by itself: combine
// with revoking all of that user's devices if the concern is an
// already-logged-in session, not just future logins.
func SetUserDisabled(db *sql.DB, userID int64, disabled bool) error {
	_, err := db.Exec(`UPDATE users SET disabled = $1 WHERE id = $2`, disabled, userID)
	return err
}

func isUniqueViolation(err error) bool {
	// pgx wraps *pgconn.PgError; string-matching the SQLSTATE avoids an
	// extra import here since this is the only place that needs it.
	return err != nil && (containsCode(err, "23505"))
}

func containsCode(err error, code string) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	if errors.As(err, &s) {
		return s.SQLState() == code
	}
	return false
}
