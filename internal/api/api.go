package api

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Server holds everything the API handlers need — same shape as
// dnsmanager's internal/api.Server. AdminToken gates /v1/admin/* (invite
// creation, user disable): a static bearer the instance operator sets, same
// pattern as Vaultwarden's ADMIN_TOKEN and toslicense's admin bearer.
// SignupsAllowed mirrors Vaultwarden's SIGNUPS_ALLOWED: false (the default)
// means registration requires a valid invite; true allows open self-signup.
// AttachmentsDir is where encrypted attachment bytes live on local disk
// (see attachment_handlers.go) — never served directly by a static file
// handler, always through the ownership-checked /v1/attachments/{id} route.
// SendsDir is the equivalent for Send file content (see send_handlers.go) —
// kept as its own directory rather than reusing AttachmentsDir so the two
// features' retention/cleanup (Sends expire and get swept; attachments
// don't) can never be confused by an operator inspecting the filesystem.
type Server struct {
	DB             *sql.DB
	AdminToken     string
	SignupsAllowed bool
	AttachmentsDir string
	SendsDir       string
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// setSecurityHeaders applies the two headers every response from this API
// should carry regardless of deployment — reverse-proxy hardening is
// explicitly out of scope for this project (see SECURITY.md), but these
// cost nothing to set from the app itself and don't depend on the
// operator's nginx config being complete. Cache-Control: no-store keeps
// sync/cipher/SMTP-settings responses out of any shared or browser cache;
// X-Content-Type-Options: nosniff stops a browser from ever guessing its
// way into treating a JSON or ciphertext response as executable content.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func parseID(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}

// clientIP resolves the identifier used for every IP-keyed rate limit and
// for audit_log.ip. X-Forwarded-For is only trusted when the connection
// actually arrived from loopback — the documented deployment shape is
// nginx on the same host proxying to PASSVAULT_LISTEN's 127.0.0.1 default
// (see install/nginx-passvault.location) — because otherwise the header
// is entirely client-controlled: nginx's own proxy_set_header APPENDS to
// whatever the client already sent rather than replacing it, so trusting
// the raw header let a client manufacture a brand-new "IP" on every
// request just by varying an arbitrary prefix, silently defeating every
// IP-based rate limit. Once loopback is confirmed, only the right-most
// (nginx-appended) hop is used — that's the one hop nginx itself
// controls, never the client.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if isLoopback(host) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			parts := strings.Split(fwd, ",")
			if last := strings.TrimSpace(parts[len(parts)-1]); last != "" {
				return last
			}
		}
	}
	return host
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
