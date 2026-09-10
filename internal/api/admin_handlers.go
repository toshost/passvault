package api

import (
	"crypto/subtle"
	"net/http"

	"github.com/toshost/passvault/internal/auth"
	"github.com/toshost/passvault/internal/mailer"
	"github.com/toshost/passvault/internal/models"
	"github.com/toshost/passvault/internal/ratelimit"
)

// requireAdminToken gates /v1/admin/* — the instance operator's own
// credential (PASSVAULT_ADMIN_TOKEN), same posture as Vaultwarden's
// ADMIN_TOKEN. Never reachable with a user's own session token. The
// comparison itself is constant-time and correctly fails closed if the
// token is unconfigured; the IP-keyed rate limit on top is pure
// defense-in-depth — this endpoint's real security depends on the
// operator choosing a sufficiently long token, not on the limiter — but
// costs nothing.
//
// Only a WRONG guess is recorded (unlike login/2FA's "record every
// attempt" convention elsewhere in this codebase): there's exactly one
// correct value here, so a legitimate, actively-used admin panel making
// many genuine requests in a session never eats into the budget — only
// an attacker actually guessing wrong does.
func (s *Server) requireAdminToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !ratelimit.Allowed(s.DB, ratelimit.BucketAdminTokenIP, ip, 20) {
			writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
			return
		}
		token := bearerTokenFromHeader(r)
		if s.AdminToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.AdminToken)) != 1 {
			ratelimit.Record(s.DB, ratelimit.BucketAdminTokenIP, ip)
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

func bearerTokenFromHeader(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}

type createInviteRequest struct {
	Email string `json:"email,omitempty"` // optional: locks the invite to this address
}

// HandleCreateInvite issues a one-time signup token. The token is returned
// exactly once here — delivering it to the invitee (email, chat, whatever)
// is the operator's job, same as running `bw create` on a self-hosted
// Vaultwarden's admin panel.
func (s *Server) HandleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req createInviteRequest
	decode(r, &req) // empty body is valid — an unrestricted invite
	token, err := auth.CreateInvite(s.DB, req.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to create invite")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"invite_token": token})
}

type setUserDisabledRequest struct {
	Disabled bool `json:"disabled"`
}

// HandleSetUserDisabled is the admin kill switch for a compromised or
// departed account. It blocks both new logins and any already-issued
// access token (auth.userFromAccessToken checks disabled on every request)
// — but existing devices stay listed as active until they naturally expire
// or the admin also revokes them via the user's own device list.
func (s *Server) HandleSetUserDisabled(w http.ResponseWriter, r *http.Request, userID int64) {
	var req setUserDisabledRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := auth.SetUserDisabled(s.DB, userID, req.Disabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleGetSMTPSettings returns the current mail relay config, minus the
// actual password (see models.SMTPSettings).
func (s *Server) HandleGetSMTPSettings(w http.ResponseWriter, r *http.Request) {
	var settings models.SMTPSettings
	var password string
	err := s.DB.QueryRow(`
		SELECT host, port, username, password, from_address, from_name, use_tls, updated_at
		FROM smtp_settings WHERE id=1`).
		Scan(&settings.Host, &settings.Port, &settings.Username, &password,
			&settings.FromAddress, &settings.FromName, &settings.UseTLS, &settings.UpdatedAt)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	settings.HasPassword = password != ""
	writeJSON(w, http.StatusOK, settings)
}

type updateSMTPSettingsRequest struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"` // empty = keep the existing stored password
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name"`
	UseTLS      bool   `json:"use_tls"`
}

// HandleUpdateSMTPSettings upserts the singleton config row. An empty
// Password in the request means "don't change it" — the admin UI never
// gets the real password back to redisplay, so it can't round-trip one
// unless it's actively setting a new value.
func (s *Server) HandleUpdateSMTPSettings(w http.ResponseWriter, r *http.Request) {
	var req updateSMTPSettingsRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Host == "" || req.Port <= 0 || req.Port > 65535 || req.FromAddress == "" {
		writeErr(w, http.StatusBadRequest, "host, a valid port, and from_address are required")
		return
	}
	var err error
	if req.Password == "" {
		_, err = s.DB.Exec(`
			UPDATE smtp_settings SET host=$1, port=$2, username=$3, from_address=$4, from_name=$5, use_tls=$6, updated_at=now()
			WHERE id=1`, req.Host, req.Port, req.Username, req.FromAddress, req.FromName, req.UseTLS)
	} else {
		_, err = s.DB.Exec(`
			UPDATE smtp_settings SET host=$1, port=$2, username=$3, password=$4, from_address=$5, from_name=$6, use_tls=$7, updated_at=now()
			WHERE id=1`, req.Host, req.Port, req.Username, req.Password, req.FromAddress, req.FromName, req.UseTLS)
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type sendTestEmailRequest struct {
	To string `json:"to"`
}

// HandleSendTestEmail sends one email using the CURRENTLY SAVED settings
// (not whatever's in an unsaved form) — the admin UI's flow is save, then
// test, so this deliberately doesn't accept settings inline.
func (s *Server) HandleSendTestEmail(w http.ResponseWriter, r *http.Request) {
	var req sendTestEmailRequest
	if err := decode(r, &req); err != nil || req.To == "" {
		writeErr(w, http.StatusBadRequest, "to is required")
		return
	}
	settings, err := mailer.LoadSettings(s.DB)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SMTP is not configured yet — save settings first")
		return
	}
	if err := mailer.Send(settings, req.To, "Passvault test email",
		"This is a test email from your Passvault instance. If you're reading this, SMTP is configured correctly."); err != nil {
		writeErr(w, http.StatusBadGateway, "send failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
