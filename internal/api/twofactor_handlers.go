package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/toshost/passvault/internal/auth"
	"github.com/toshost/passvault/internal/ratelimit"
	"github.com/toshost/passvault/internal/totp"
)

// HandleGet2FAStatus tells the settings UI whether to show "enable" or
// "disable", and lets it warn the user when recovery codes are running
// low without ever re-exposing the codes themselves.
func (s *Server) HandleGet2FAStatus(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	remaining, err := auth.CountUnusedRecoveryCodes(s.DB, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load 2FA status")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":                  u.TOTP2FAEnabled,
		"recovery_codes_remaining": remaining,
	})
}

// HandleSetup2FA generates a fresh secret but does NOT persist it — the
// client must round-trip it back to HandleEnable2FA along with a code
// that verifies against it, proving the secret was actually captured by
// a real authenticator before the account starts requiring it.
func (s *Server) HandleSetup2FA(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	secret, err := totp.GenerateSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "setup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":      secret,
		"otpauth_url": totp.OTPAuthURL(secret, u.Email, "Passvault"),
	})
}

type enable2FARequest struct {
	Secret string `json:"secret"`
	Code   string `json:"code"`
}

// HandleEnable2FA verifies the client actually captured the secret
// correctly, then turns 2FA on and issues the one-time recovery codes.
func (s *Server) HandleEnable2FA(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req enable2FARequest
	if err := decode(r, &req); err != nil || req.Secret == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	ok, err := totp.Verify(req.Secret, req.Code, time.Now())
	if err != nil || !ok {
		writeErr(w, http.StatusBadRequest, "that code doesn't match — check your authenticator app and try again")
		return
	}
	if err := auth.EnableTOTP2FA(s.DB, u.ID, req.Secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to enable 2FA")
		return
	}
	codes, err := auth.GenerateRecoveryCodes(s.DB, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "2FA enabled, but failed to generate recovery codes — regenerate them from settings")
		return
	}
	audit(s.DB, &u.ID, "user.2fa_enabled", "", clientIP(r))
	notify(s.DB, u.Email, "Two-factor authentication was enabled on your Passvault account",
		"2FA is now required to log in to your Passvault account. If you didn't do this, someone else may have access to your account — change your master password immediately.")
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

type twoFACodeRequest struct {
	Code string `json:"code"`
}

// verifyCurrent2FA checks a submitted code against the account's live
// secret OR an unused recovery code — the same acceptance logic
// HandleLoginTOTP uses, reused here to gate disabling 2FA, regenerating
// recovery codes, changing the master password, and touching the
// recovery kit, so none of those can happen from a hijacked session
// without re-proving possession of the second factor.
//
// Rate-limited per user (not IP — the caller already holds a valid
// session, so the identity is known and attacker-uncontrolled, unlike
// login's pre-auth 2FA phase): unlike HandleLoginTOTP, which has both an
// IP bucket and the DB-enforced pending_logins.attempts_left, every
// caller of this function used to have NO throttle on the 6-digit code
// space at all — a hijacked session token without the TOTP secret could
// hammer it unthrottled.
func (s *Server) verifyCurrent2FA(userID int64, secret *string, code string) bool {
	identifier := strconv.FormatInt(userID, 10)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketTwoFAVerifyUser, identifier, 10) {
		return false
	}
	ratelimit.Record(s.DB, ratelimit.BucketTwoFAVerifyUser, identifier)
	if secret != nil {
		// VerifyStep + ConsumeTOTPStep, not plain Verify: every caller of
		// this function is gating a real action (disabling 2FA,
		// regenerating recovery codes, changing the master password,
		// touching the recovery kit), so the same correct code must not
		// be replayable within its own ~90s validity window.
		if ok, step, _ := totp.VerifyStep(*secret, code, time.Now()); ok {
			if claimed, _ := auth.ConsumeTOTPStep(s.DB, userID, step); claimed {
				return true
			}
		}
	}
	ok, _ := auth.VerifyRecoveryCode(s.DB, userID, code)
	return ok
}

func (s *Server) HandleDisable2FA(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req twoFACodeRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !u.TOTP2FAEnabled {
		writeErr(w, http.StatusBadRequest, "2FA isn't enabled")
		return
	}
	if !s.verifyCurrent2FA(u.ID, u.TOTP2FASecret, req.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	if err := auth.DisableTOTP2FA(s.DB, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to disable 2FA")
		return
	}
	audit(s.DB, &u.ID, "user.2fa_disabled", "", clientIP(r))
	notify(s.DB, u.Email, "Two-factor authentication was disabled on your Passvault account",
		"2FA is no longer required to log in to your Passvault account. If you didn't do this, change your master password immediately.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) HandleRegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req twoFACodeRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !u.TOTP2FAEnabled {
		writeErr(w, http.StatusBadRequest, "2FA isn't enabled")
		return
	}
	if !s.verifyCurrent2FA(u.ID, u.TOTP2FASecret, req.Code) {
		writeErr(w, http.StatusUnauthorized, "invalid code")
		return
	}
	codes, err := auth.GenerateRecoveryCodes(s.DB, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to regenerate recovery codes")
		return
	}
	audit(s.DB, &u.ID, "user.2fa_recovery_codes_regenerated", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}
