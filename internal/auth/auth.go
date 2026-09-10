// Package auth issues and verifies Passvault's device access/refresh
// tokens. It never touches a master password or vault key — those are
// entirely client-side (see internal/crypto and docs/PROTOCOL.md). This
// package's job is bearer-token session management only, same shape as
// dnsmanager's internal/auth/auth.go but with a refresh token in addition to
// a short-lived access token, since Passvault clients (extension/mobile/CLI)
// need long-lived unattended sessions without keeping a bearer token that
// never expires.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"net/http"
	"time"

	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
)

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 30 * 24 * time.Hour
)

// ErrInvalidCredentials/ErrUnauthenticated are deliberately generic: a
// disabled account, a wrong password, and a nonexistent account all surface
// the same way, so neither error leaks which case occurred.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUnauthenticated    = errors.New("unauthenticated")
)

type ctxKey string

const userCtxKey ctxKey = "passvault_user"

// Tokens is what a successful login/registration/refresh returns to the
// client. AccessToken is a short-lived bearer credential for /v1/* calls;
// RefreshToken exchanges for a new pair at /v1/auth/refresh. Both are shown
// to the client exactly once — only their hashes are stored (see
// crypto.HashToken).
type Tokens struct {
	AccessToken          string    `json:"access_token"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
	RefreshToken         string    `json:"refresh_token"`
	DeviceID             int64     `json:"device_id"`
}

// IssueDevice creates a new device row with a fresh token pair for an
// already-authenticated user (post password/authKey verification).
func IssueDevice(db *sql.DB, userID int64, label string) (Tokens, error) {
	access, err := vcrypto.NewOpaqueToken()
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := vcrypto.NewOpaqueToken()
	if err != nil {
		return Tokens{}, err
	}
	expiresAt := time.Now().Add(accessTokenTTL)
	refreshExpiresAt := time.Now().Add(refreshTokenTTL)
	var id int64
	err = db.QueryRow(`
		INSERT INTO devices (user_id, label, refresh_token_hash, refresh_expires_at, access_token_hash, access_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		userID, label, vcrypto.HashToken(refresh), refreshExpiresAt, vcrypto.HashToken(access), expiresAt).Scan(&id)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, AccessTokenExpiresAt: expiresAt, RefreshToken: refresh, DeviceID: id}, nil
}

// Refresh rotates a device's token pair. The old refresh token is
// single-use: a replay after rotation is DETECTED (not just rejected) via
// previous_refresh_token_hash — a one-step-back memory of the token this
// device held just before its last rotation — and treated as a
// possible-compromise signal: the device is revoked immediately rather
// than just silently failing the replayed request, since a genuine
// client never legitimately needs to resubmit an already-rotated token.
func Refresh(db *sql.DB, refreshToken string) (Tokens, error) {
	hash := vcrypto.HashToken(refreshToken)
	var deviceID, userID int64
	err := db.QueryRow(`
		SELECT d.id, d.user_id FROM devices d
		WHERE d.refresh_token_hash = $1 AND d.revoked_at IS NULL AND d.refresh_expires_at > now()`,
		hash).Scan(&deviceID, &userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			detectReplayedRefreshToken(db, hash)
			return Tokens{}, ErrUnauthenticated
		}
		return Tokens{}, err
	}
	access, err := vcrypto.NewOpaqueToken()
	if err != nil {
		return Tokens{}, err
	}
	newRefresh, err := vcrypto.NewOpaqueToken()
	if err != nil {
		return Tokens{}, err
	}
	expiresAt := time.Now().Add(accessTokenTTL)
	refreshExpiresAt := time.Now().Add(refreshTokenTTL) // sliding window: each rotation extends the session
	_, err = db.Exec(`
		UPDATE devices SET access_token_hash=$1, access_expires_at=$2,
			previous_refresh_token_hash=refresh_token_hash, refresh_token_hash=$3, refresh_expires_at=$4, last_seen_at=now()
		WHERE id=$5`, vcrypto.HashToken(access), expiresAt, vcrypto.HashToken(newRefresh), refreshExpiresAt, deviceID)
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{AccessToken: access, AccessTokenExpiresAt: expiresAt, RefreshToken: newRefresh, DeviceID: deviceID}, nil
}

// detectReplayedRefreshToken checks whether a refresh-token hash that
// just failed Refresh's primary lookup matches what this device held
// just before its LAST rotation — if so, this isn't just an unknown or
// expired token, it's the legitimate client having already moved past
// it, meaning whoever just submitted it got it from somewhere else.
// Best-effort and silent on no match: an ordinary invalid token is the
// overwhelmingly common case and must not change Refresh's own
// (already-correct) ErrUnauthenticated behavior either way.
func detectReplayedRefreshToken(db *sql.DB, hash string) {
	var deviceID, userID int64
	err := db.QueryRow(`SELECT id, user_id FROM devices WHERE previous_refresh_token_hash = $1 AND revoked_at IS NULL`,
		hash).Scan(&deviceID, &userID)
	if err != nil {
		return
	}
	log.Printf("refresh token replay detected: revoking device %d (user %d) — an already-rotated refresh token was resubmitted", deviceID, userID)
	RevokeDevice(db, userID, deviceID)
}

// RevokeDevice logs a device out. userID scopes the revoke so one user can
// never revoke another's device by guessing an ID.
func RevokeDevice(db *sql.DB, userID, deviceID int64) error {
	_, err := db.Exec(`UPDATE devices SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`,
		deviceID, userID)
	return err
}

// RevokeAllDevices signs a user out everywhere at once — used after an
// emergency-access takeover (internal/api's HandleEmergencyAccessTakeover),
// where the account's master password just changed out from under
// whoever held the old one, so every existing session must stop working
// immediately rather than riding out its access token's remaining TTL.
func RevokeAllDevices(db *sql.DB, userID int64) error {
	_, err := db.Exec(`UPDATE devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

// RevokeAllDevicesExcept signs a user out of every device but one — used
// after a self-service password change (internal/api's
// HandleChangePassword), where the session that just re-proved the
// current password should keep working, but every OTHER already-issued
// token — indistinguishable, from the server's point of view, from one
// that leaked without the password leaking alongside it — must stop
// immediately rather than ride out its remaining TTL.
func RevokeAllDevicesExcept(db *sql.DB, userID, exceptDeviceID int64) error {
	_, err := db.Exec(`UPDATE devices SET revoked_at = now() WHERE user_id = $1 AND id != $2 AND revoked_at IS NULL`,
		userID, exceptDeviceID)
	return err
}

// userFromAccessToken resolves the bearer token on an authenticated request,
// rejecting expired or revoked devices and disabled accounts — this is the
// enforcement point for an admin-disabled user being blocked from both
// reads and writes, not just new logins.
func userFromAccessToken(db *sql.DB, token string) (*models.User, int64, error) {
	hash := vcrypto.HashToken(token)
	row := db.QueryRow(`
		SELECT u.id, u.email, u.crypto_realm, u.totp_2fa_secret, u.totp_2fa_enabled, u.recovery_code_hash, d.id
		FROM devices d
		JOIN users u ON u.id = d.user_id
		WHERE d.access_token_hash = $1 AND d.revoked_at IS NULL
		  AND d.access_expires_at > now() AND u.disabled = false`, hash)
	var u models.User
	var deviceID int64
	if err := row.Scan(&u.ID, &u.Email, &u.CryptoRealm, &u.TOTP2FASecret, &u.TOTP2FAEnabled, &u.RecoveryCodeHash, &deviceID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, ErrUnauthenticated
		}
		return nil, 0, err
	}
	return &u, deviceID, nil
}

// Middleware attaches the authenticated user to the request context from
// the "Authorization: Bearer <access_token>" header, or responds 401.
func Middleware(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerToken(r)
			if token == "" {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			u, deviceID, err := userFromAccessToken(db, token)
			if err != nil {
				http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, u)
			ctx = context.WithValue(ctx, deviceCtxKey, deviceID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type deviceCtxKeyType string

const deviceCtxKey deviceCtxKeyType = "passvault_device"

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

func UserFromContext(ctx context.Context) *models.User {
	u, _ := ctx.Value(userCtxKey).(*models.User)
	return u
}

func DeviceFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(deviceCtxKey).(int64)
	return id
}
