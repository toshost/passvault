package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
)

// aliasHTTPClient has a short, fixed timeout — this handler blocks on a
// synchronous call to a third-party API inside an HTTP request, and must
// not hang the server if that provider is slow or unreachable.
var aliasHTTPClient = &http.Client{Timeout: 10 * time.Second}

type emailAliasSettingsResponse struct {
	Provider      string `json:"provider"`
	WrappedAPIKey string `json:"wrapped_api_key,omitempty"`
}

// HandleGetEmailAliasSettings returns the opaque wrapped API key
// verbatim (like any other client-encrypted blob) so any of the
// account's logged-in devices can unwrap it with vaultKey and use it —
// this is exactly why it's stored server-side rather than in one
// browser's localStorage.
func (s *Server) HandleGetEmailAliasSettings(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var provider string
	var wrapped *string
	err := s.DB.QueryRow(`SELECT email_alias_provider, wrapped_email_alias_api_key FROM users WHERE id=$1`, u.ID).
		Scan(&provider, &wrapped)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load settings")
		return
	}
	resp := emailAliasSettingsResponse{Provider: provider}
	if wrapped != nil {
		resp.WrappedAPIKey = *wrapped
	}
	writeJSON(w, http.StatusOK, resp)
}

type updateEmailAliasSettingsRequest struct {
	Provider      string `json:"provider"`
	WrappedAPIKey string `json:"wrapped_api_key"`
}

// supportedAliasProviders is deliberately a small allowlist, not
// arbitrary client input — HandleGenerateEmailAlias switches on this
// value to decide which third-party API to call.
var supportedAliasProviders = map[string]bool{"simplelogin": true}

func (s *Server) HandleUpdateEmailAliasSettings(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req updateEmailAliasSettingsRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !supportedAliasProviders[req.Provider] {
		writeErr(w, http.StatusBadRequest, "unsupported provider")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedAPIKey, 4096); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_api_key")
		return
	}
	if _, err := s.DB.Exec(`UPDATE users SET email_alias_provider=$1, wrapped_email_alias_api_key=$2 WHERE id=$3`,
		req.Provider, req.WrappedAPIKey, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to save settings")
		return
	}
	audit(s.DB, &u.ID, "email_alias.configured", req.Provider, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) HandleDeleteEmailAliasSettings(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if _, err := s.DB.Exec(`UPDATE users SET email_alias_provider='', wrapped_email_alias_api_key=NULL WHERE id=$1`, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to remove settings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type generateEmailAliasRequest struct {
	Provider string `json:"provider"`
	APIKey   string `json:"api_key"` // plaintext, decrypted client-side moments before this call — never stored or logged server-side
	Hostname string `json:"hostname,omitempty"`
}

// HandleGenerateEmailAlias is the one place the plaintext third-party API
// key ever exists server-side, and only for the duration of this single
// proxied request — it's read from the request body, used to call the
// provider, and then goes out of scope. Never written to a log line, a
// database row, or anywhere else. This proxy exists purely because
// SimpleLogin's API doesn't set CORS headers permitting a browser to
// call it directly (verified empirically, not assumed) — the key stays
// zero-knowledge AT REST (see users.wrapped_email_alias_api_key), which
// is the property that actually matters; it necessarily can't stay
// zero-knowledge IN TRANSIT for a call only the server can make.
func (s *Server) HandleGenerateEmailAlias(w http.ResponseWriter, r *http.Request) {
	var req generateEmailAliasRequest
	if err := decode(r, &req); err != nil || req.APIKey == "" {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !supportedAliasProviders[req.Provider] {
		writeErr(w, http.StatusBadRequest, "unsupported provider")
		return
	}

	switch req.Provider {
	case "simplelogin":
		email, err := generateSimpleLoginAlias(req.APIKey, req.Hostname)
		if err != nil {
			writeErr(w, http.StatusBadGateway, "alias generation failed: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"email": email})
	default:
		// Unreachable given supportedAliasProviders above, kept as a guard
		// against the two falling out of sync rather than silently
		// returning no response.
		writeErr(w, http.StatusBadRequest, "unsupported provider")
	}
}

// generateSimpleLoginAlias calls SimpleLogin's documented
// POST /api/alias/random/new (see simple-login/app's docs/api.md):
// Authentication header carries the API key, hostname is an optional
// query param used to name the alias sensibly, and a 201 response body
// carries the new alias's email address alongside other fields this
// caller doesn't need.
func generateSimpleLoginAlias(apiKey, hostname string) (string, error) {
	endpoint := "https://app.simplelogin.io/api/alias/random/new"
	if hostname != "" {
		// url.Values.Encode(), not string concatenation: the destination
		// host is hardcoded so this was never SSRF, but an unescaped
		// hostname containing "&" or other query metacharacters could
		// inject additional parameters into the outbound request.
		endpoint += "?" + (url.Values{"hostname": {hostname}}).Encode()
	}
	httpReq, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authentication", apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := aliasHTTPClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if res.StatusCode != http.StatusCreated {
		return "", &aliasProviderError{status: res.StatusCode}
	}
	var parsed struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Email == "" {
		return "", &aliasProviderError{status: res.StatusCode}
	}
	return parsed.Email, nil
}

type aliasProviderError struct{ status int }

func (e *aliasProviderError) Error() string {
	if e.status == http.StatusUnauthorized || e.status == http.StatusForbidden {
		return "the provider rejected this API key"
	}
	return "the provider returned an unexpected response"
}
