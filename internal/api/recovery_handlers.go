package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
	"github.com/toshost/passvault/internal/ratelimit"
	"github.com/toshost/passvault/internal/totp"
)

type setRecoveryKitRequest struct {
	CurrentAuthKey             string `json:"current_auth_key"`
	Code                       string `json:"code"` // required only if the account has 2FA enabled
	RecoveryAuthKey            string `json:"recovery_auth_key"`
	WrappedVaultKeyForRecovery string `json:"wrapped_vault_key_for_recovery"`
}

// verifyRecoveryKitReauth re-proves the caller actually knows the current
// master password (and a live 2FA code, if enabled) before touching the
// recovery kit. Required on both create/replace AND delete: this
// endpoint writes the exact credential pair the public
// HandleVerifyRecovery/HandleFinishRecovery flow later accepts as
// sufficient to reset the master password outright, so a bearer token
// alone must never be enough to plant a takeover backdoor here — and a
// hijacked session shouldn't be able to silently destroy the account's
// one real safety net either. Returns false and has already written the
// HTTP response when re-auth fails; callers should return immediately.
func (s *Server) verifyRecoveryKitReauth(w http.ResponseWriter, u *models.User, currentAuthKey, code string) bool {
	if currentAuthKey == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return false
	}
	ok, err := auth.VerifyCurrentAuthKey(s.DB, u.ID, currentAuthKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "request failed")
		return false
	}
	if !ok {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return false
	}
	if u.TOTP2FAEnabled && !s.verifyCurrent2FA(u.ID, u.TOTP2FASecret, code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return false
	}
	return true
}

// HandleSetRecoveryKit creates (or overwrites) the account's recovery
// kit. The recovery CODE itself never reaches this handler — only
// recoveryAuthKey (a value HKDF'd from it, same shape as authKey from a
// master password) and the already-wrapped vault key.
func (s *Server) HandleSetRecoveryKit(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req setRecoveryKitRequest
	if err := decode(r, &req); err != nil || req.RecoveryAuthKey == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedVaultKeyForRecovery, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_vault_key_for_recovery")
		return
	}
	if !s.verifyRecoveryKitReauth(w, u, req.CurrentAuthKey, req.Code) {
		return
	}
	if err := auth.SetRecoveryKit(s.DB, u.ID, req.RecoveryAuthKey, req.WrappedVaultKeyForRecovery); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save recovery kit")
		return
	}
	audit(s.DB, &u.ID, "user.recovery_kit_created", "", clientIP(r))
	notify(s.DB, u.Email, "A new account recovery kit was created",
		"A new Passvault account recovery kit was generated, replacing any previous one. If you didn't do this, change your master password immediately.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) HandleGetRecoveryKitStatus(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	writeJSON(w, http.StatusOK, map[string]bool{"configured": u.RecoveryCodeHash != nil})
}

type deleteRecoveryKitRequest struct {
	CurrentAuthKey string `json:"current_auth_key"`
	Code           string `json:"code"` // required only if the account has 2FA enabled
}

func (s *Server) HandleDeleteRecoveryKit(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req deleteRecoveryKitRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !s.verifyRecoveryKitReauth(w, u, req.CurrentAuthKey, req.Code) {
		return
	}
	if err := auth.ClearRecoveryKit(s.DB, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to remove recovery kit")
		return
	}
	audit(s.DB, &u.ID, "user.recovery_kit_removed", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type verifyRecoveryRequest struct {
	Email           string `json:"email"`
	RecoveryAuthKey string `json:"recovery_auth_key"`
}

// HandleVerifyRecovery is the ONLY thing standing between "I lost my
// password" and "reset anyone's password" — see
// auth.VerifyRecoveryAuthKey. Public/unauthenticated by necessity (the
// whole point is working without a valid session), rate-limited per
// email and per IP like a login attempt.
func (s *Server) HandleVerifyRecovery(w http.ResponseWriter, r *http.Request) {
	var req verifyRecoveryRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ip := clientIP(r)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketRecoveryEmail, req.Email, 10) || !ratelimit.Allowed(s.DB, ratelimit.BucketRecoveryIP, ip, 20) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketRecoveryEmail, req.Email)
	ratelimit.Record(s.DB, ratelimit.BucketRecoveryIP, ip)

	userID, wrapped, err := auth.VerifyRecoveryAuthKey(s.DB, req.Email, req.RecoveryAuthKey)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidRecoveryCode) {
			audit(s.DB, nil, "user.recovery_failed", req.Email, ip)
			writeErr(w, http.StatusUnauthorized, "invalid email or recovery code")
			return
		}
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	challenge, err := auth.IssuePendingRecovery(s.DB, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	recoveringUser, err := auth.LoadUserByID(s.DB, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	audit(s.DB, &userID, "user.recovery_verified", req.Email, ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_challenge":             challenge,
		"wrapped_vault_key_for_recovery": wrapped,
		"requires_2fa":                   recoveringUser.TOTP2FAEnabled,
	})
}

type finishRecoveryRequest struct {
	RecoveryChallenge  string            `json:"recovery_challenge"`
	Code               string            `json:"code"` // required only if the account has 2FA enabled — see below
	KDF                vcrypto.KDFParams `json:"kdf"`
	NewAuthKey         string            `json:"new_auth_key"`
	NewWrappedVaultKey string            `json:"new_wrapped_vault_key"`
}

// HandleFinishRecovery sets a new master password using the SAME
// vaultKey the client recovered via the kit (see auth.ChangePassword's
// docs/PROTOCOL.md rationale — no cipher or folder needs to change).
// Every existing device session is revoked, same as an emergency-access
// takeover: the old password no longer controls the account, so nothing
// that only knew it should keep working. A fresh recovery kit is NOT
// auto-generated — the user must deliberately make a new one from
// settings, so a stale kit doesn't silently keep working after this.
//
// If the account has 2FA enabled, the recovery kit alone is deliberately
// NOT enough — otherwise a stolen printed recovery code would bypass
// 2FA entirely, defeating the point of having it. A TOTP or 2FA-recovery
// code is required too, same acceptance logic as login's second phase
// (someone who genuinely lost everything still has their 2FA recovery
// codes, ideally stored alongside the vault recovery kit — that's the
// "lost everything" path, not a reason to skip this check).
func (s *Server) HandleFinishRecovery(w http.ResponseWriter, r *http.Request) {
	var req finishRecoveryRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.NewWrappedVaultKey, 8192); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid new_wrapped_vault_key")
		return
	}
	userID, err := auth.ConsumePendingRecovery(s.DB, req.RecoveryChallenge)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "this recovery session has expired — start over")
		return
	}

	u, err := auth.LoadUserByID(s.DB, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	if u.TOTP2FAEnabled {
		valid := false
		if u.TOTP2FASecret != nil {
			// VerifyStep + ConsumeTOTPStep: finishing recovery grants a
			// full account reset, so the same correct code must not be
			// replayable within its own ~90s window either.
			if ok, step, _ := totp.VerifyStep(*u.TOTP2FASecret, req.Code, time.Now()); ok {
				if claimed, _ := auth.ConsumeTOTPStep(s.DB, userID, step); claimed {
					valid = true
				}
			}
		}
		if !valid {
			if ok, _ := auth.VerifyRecoveryCode(s.DB, userID, req.Code); ok {
				valid = true
			}
		}
		if !valid {
			audit(s.DB, &userID, "user.recovery_2fa_failed", u.Email, clientIP(r))
			writeErr(w, http.StatusUnauthorized, "invalid code — this account also has 2FA enabled")
			return
		}
	}

	if err := auth.ChangePassword(s.DB, userID, req.KDF, req.NewAuthKey, req.NewWrappedVaultKey); err != nil {
		log.Printf("recovery failed for user %d (change password): %v", userID, err)
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	if err := auth.RevokeAllDevices(s.DB, userID); err != nil {
		log.Printf("recovery failed for user %d (revoke devices): %v", userID, err)
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}

	tokens, err := auth.IssueDevice(s.DB, userID, r.Header.Get("X-Device-Label"))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}

	// Re-load: `u` above was fetched before ChangePassword ran and still
	// carries the OLD wrapped_vault_key — returning it here would send
	// the client back a blob wrapped under the password it just replaced,
	// which its freshly-derived new wrapKey can't decrypt.
	updated, err := auth.LoadUserByID(s.DB, userID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	audit(s.DB, &userID, "user.recovery_completed", "", clientIP(r))
	notify(s.DB, u.Email, "Your Passvault account was recovered",
		"Your master password was just reset using your account recovery kit, and every device has been signed out. "+
			"If this wasn't you, contact your Passvault instance administrator immediately.")
	writeJSON(w, http.StatusOK, loginResponse{User: updated, Tokens: tokens})
}
