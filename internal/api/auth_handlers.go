package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/ratelimit"
	"github.com/toshost/passvault/internal/totp"
)

func (s *Server) HandlePrelogin(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	ip := clientIP(r)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketPreloginEmail, email, 15) || !ratelimit.Allowed(s.DB, ratelimit.BucketPreloginIP, ip, 40) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketPreloginEmail, email)
	ratelimit.Record(s.DB, ratelimit.BucketPreloginIP, ip)

	params, err := auth.Prelogin(s.DB, email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "prelogin failed")
		return
	}
	writeJSON(w, http.StatusOK, params)
}

type registerRequest struct {
	InviteToken             string            `json:"invite_token"`
	Email                   string            `json:"email"`
	KDF                     vcrypto.KDFParams `json:"kdf"`
	AuthKey                 string            `json:"auth_key"`
	WrappedVaultKey         string            `json:"wrapped_vault_key"`
	X25519PublicKey         string            `json:"x25519_public_key"`
	WrappedX25519PrivateKey string            `json:"wrapped_x25519_private_key"`
}

// HandleRegister requires a valid invite unless the instance operator set
// PASSVAULT_SIGNUPS_ALLOWED=true (Server.SignupsAllowed) — same two modes
// Vaultwarden offers, defaulting closed.
//
// Rate-limited by IP regardless of signup mode: every registration
// triggers a real Argon2id hash (crypto.HashAuthKey) server-side, so with
// open signup enabled this is otherwise a fully public, unauthenticated
// memory/CPU-exhaustion amplifier — a script can trigger the expensive
// hash on every request with no throttle at all.
func (s *Server) HandleRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketRegisterIP, ip, 20) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketRegisterIP, ip)

	var req registerRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}

	if req.InviteToken != "" {
		if err := auth.ConsumeInvite(s.DB, req.InviteToken, req.Email); err != nil {
			if errors.Is(err, auth.ErrInvalidInvite) || errors.Is(err, auth.ErrInviteWrongEmail) {
				writeErr(w, http.StatusForbidden, err.Error())
				return
			}
			writeErr(w, http.StatusInternalServerError, "registration failed")
			return
		}
	} else if !s.SignupsAllowed {
		writeErr(w, http.StatusForbidden, "signups are invite-only on this instance")
		return
	}

	u, err := auth.Register(s.DB, auth.RegisterInput{
		Email:                   req.Email,
		KDF:                     req.KDF,
		AuthKeyB64:              req.AuthKey,
		WrappedVaultKey:         req.WrappedVaultKey,
		X25519PublicKey:         req.X25519PublicKey,
		WrappedX25519PrivateKey: req.WrappedX25519PrivateKey,
	})
	if err != nil {
		if errors.Is(err, auth.ErrEmailTaken) {
			writeErr(w, http.StatusConflict, "email already registered")
			return
		}
		log.Printf("registration failed for %s: %v", req.Email, err)
		writeErr(w, http.StatusBadRequest, "registration failed")
		return
	}

	tokens, err := auth.IssueDevice(s.DB, u.ID, r.Header.Get("X-Device-Label"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "registered but failed to issue session")
		return
	}
	audit(s.DB, &u.ID, "user.registered", u.Email, clientIP(r))
	writeJSON(w, http.StatusCreated, loginResponse{User: u, Tokens: tokens})
}

type loginRequest struct {
	Email   string `json:"email"`
	AuthKey string `json:"auth_key"`
}

type loginResponse struct {
	User   any         `json:"user"`
	Tokens auth.Tokens `json:"tokens"`
}

func (s *Server) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ip := clientIP(r)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketLoginEmail, req.Email, 10) || !ratelimit.Allowed(s.DB, ratelimit.BucketLoginIP, ip, 30) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketLoginEmail, req.Email)
	ratelimit.Record(s.DB, ratelimit.BucketLoginIP, ip)

	u, err := auth.Login(s.DB, req.Email, req.AuthKey)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			audit(s.DB, nil, "user.login_failed", req.Email, clientIP(r))
			writeErr(w, http.StatusUnauthorized, "invalid email or password")
			return
		}
		writeErr(w, http.StatusInternalServerError, "login failed")
		return
	}

	if u.TOTP2FAEnabled {
		// authKey checked out, but the account requires a second factor —
		// hand back a short-lived bridge token instead of real device
		// tokens. HandleLoginTOTP exchanges it (plus a valid code) for the
		// actual login response below.
		challenge, err := auth.IssuePendingLogin(s.DB, u.ID, r.Header.Get("X-Device-Label"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "login failed")
			return
		}
		audit(s.DB, &u.ID, "user.login_2fa_pending", u.Email, clientIP(r))
		writeJSON(w, http.StatusOK, map[string]any{"requires_2fa": true, "login_challenge": challenge})
		return
	}

	tokens, err := auth.IssueDevice(s.DB, u.ID, r.Header.Get("X-Device-Label"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "login failed")
		return
	}
	audit(s.DB, &u.ID, "user.login", u.Email, clientIP(r))
	writeJSON(w, http.StatusOK, loginResponse{User: u, Tokens: tokens})
}

type loginTOTPRequest struct {
	LoginChallenge string `json:"login_challenge"`
	Code           string `json:"code"`
}

// HandleLoginTOTP is the second phase of a 2FA-gated login: exchange a
// pending-login challenge plus a valid TOTP or recovery code for the
// real device token pair. A wrong code burns one of the challenge's
// remaining attempts (RecordFailedPendingLoginAttempt) rather than the
// whole challenge, so a mistyped digit doesn't force the client back to
// retyping the master password — see the pending_logins table comment.
func (s *Server) HandleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var req loginTOTPRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ip := clientIP(r)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketLogin2FAIP, ip, 30) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketLogin2FAIP, ip)

	userID, deviceLabel, err := auth.LookupPendingLogin(s.DB, req.LoginChallenge)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "this login has expired — please log in again")
		return
	}

	u, err := auth.LoadUserByID(s.DB, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "login failed")
		return
	}
	if u.Disabled {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}

	valid := false
	usedRecoveryCode := false
	if u.TOTP2FASecret != nil {
		// VerifyStep + ConsumeTOTPStep, not plain Verify: a login grants
		// real access, so the same correct code must not be usable twice
		// within its own ~90s validity window (see
		// auth.ConsumeTOTPStep's comment).
		if ok, step, _ := totp.VerifyStep(*u.TOTP2FASecret, req.Code, time.Now()); ok {
			if claimed, _ := auth.ConsumeTOTPStep(s.DB, userID, step); claimed {
				valid = true
			}
		}
	}
	if !valid {
		if ok, _ := auth.VerifyRecoveryCode(s.DB, userID, req.Code); ok {
			valid = true
			usedRecoveryCode = true
		}
	}
	if !valid {
		auth.RecordFailedPendingLoginAttempt(s.DB, req.LoginChallenge)
		audit(s.DB, &userID, "user.login_2fa_failed", u.Email, clientIP(r))
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	auth.DeletePendingLogin(s.DB, req.LoginChallenge)

	tokens, err := auth.IssueDevice(s.DB, userID, deviceLabel)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "login failed")
		return
	}
	if usedRecoveryCode {
		audit(s.DB, &userID, "user.login_2fa_recovery_code_used", u.Email, clientIP(r))
		remaining, _ := auth.CountUnusedRecoveryCodes(s.DB, userID)
		notify(s.DB, u.Email, "A recovery code was used to sign in to your Passvault account",
			fmt.Sprintf("A 2FA recovery code was just used to sign in to your account. %d recovery code(s) remain. "+
				"If this wasn't you, your master password may be compromised — change it immediately and regenerate your recovery codes.", remaining))
	}
	audit(s.DB, &userID, "user.login", u.Email, clientIP(r))
	writeJSON(w, http.StatusOK, loginResponse{User: u, Tokens: tokens})
}

func (s *Server) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	tokens, err := auth.Refresh(s.DB, req.RefreshToken)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (s *Server) HandleLogout(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	deviceID := auth.DeviceFromContext(r.Context())
	if u != nil {
		auth.RevokeDevice(s.DB, u.ID, deviceID)
		audit(s.DB, &u.ID, "user.logout", "", clientIP(r))
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type changePasswordRequest struct {
	CurrentAuthKey     string            `json:"current_auth_key"`
	Code               string            `json:"code"` // required only if the account has 2FA enabled
	KDF                vcrypto.KDFParams `json:"kdf"`
	NewAuthKey         string            `json:"new_auth_key"`
	NewWrappedVaultKey string            `json:"new_wrapped_vault_key"`
}

// HandleChangePassword re-wraps the SAME vault key under a new master
// password — it never re-encrypts a single cipher/folder. See
// docs/PROTOCOL.md and auth.ChangePassword for why that's both correct and
// the entire point of the envelope-encryption design.
//
// Re-proving the CURRENT authKey (and a live 2FA code, if enabled) is
// mandatory even though the caller already holds a valid access token: a
// bearer token can leak — an XSS bug, a malicious extension, a logged
// header — without the master password leaking alongside it, and unlike
// most authenticated actions, getting this one wrong can permanently
// destroy the account's ability to ever decrypt its own vault (the
// server never sees the real vaultKey, so it can't tell a legitimate
// re-wrap from an attacker overwriting it with garbage). On success,
// every OTHER device is revoked immediately: the one thing a stolen
// token and a genuine password change can't be told apart on is whether
// other sessions should still be trusted, so they don't get the benefit
// of the doubt.
func (s *Server) HandleChangePassword(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	var req changePasswordRequest
	if err := decode(r, &req); err != nil || req.CurrentAuthKey == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ok, err := auth.VerifyCurrentAuthKey(s.DB, u.ID, req.CurrentAuthKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "change password failed")
		return
	}
	if !ok {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	if u.TOTP2FAEnabled && !s.verifyCurrent2FA(u.ID, u.TOTP2FASecret, req.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := auth.ChangePassword(s.DB, u.ID, req.KDF, req.NewAuthKey, req.NewWrappedVaultKey); err != nil {
		writeErr(w, http.StatusBadRequest, "change password failed")
		return
	}
	if err := auth.RevokeAllDevicesExcept(s.DB, u.ID, auth.DeviceFromContext(r.Context())); err != nil {
		writeErr(w, http.StatusInternalServerError, "change password failed")
		return
	}
	audit(s.DB, &u.ID, "user.password_changed", "", clientIP(r))
	notify(s.DB, u.Email, "Your Passvault master password was changed",
		"Your master password was just changed, and every other device has been signed out. If this wasn't you, contact your Passvault instance administrator immediately.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// audit records an append-only security event. Errors are swallowed, never
// surfaced to the client — a failed audit write must not block the action
// it's recording.
func audit(db *sql.DB, userID *int64, event, target, ip string) {
	db.Exec(`INSERT INTO audit_log (user_id, event, target, ip) VALUES ($1,$2,$3,$4)`,
		userID, event, target, ip)
}
