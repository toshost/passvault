package api

import (
	"net/http"
	"strings"

	"github.com/toshost/passvault/internal/auth"
)

// Routes wires every endpoint (personal vaults + attachments + item
// sharing + Send — orgs/collections and /bwapi/* Bitwarden-compat arrive
// later). Stdlib mux, no third-party router — matches every other
// from-scratch Go panel in the fleet (dnsmanager, toslicense).
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /v1/auth/prelogin", s.HandlePrelogin)
	mux.HandleFunc("POST /v1/auth/register", s.HandleRegister)
	mux.HandleFunc("POST /v1/auth/login", s.HandleLogin)
	mux.HandleFunc("POST /v1/auth/login/2fa", s.HandleLoginTOTP)
	mux.HandleFunc("POST /v1/auth/recovery/verify", s.HandleVerifyRecovery)
	mux.HandleFunc("POST /v1/auth/recovery/finish", s.HandleFinishRecovery)
	mux.HandleFunc("POST /v1/auth/refresh", s.HandleRefresh)

	// Public Send access — deliberately unauthenticated, see
	// send_handlers.go. Namespaced under /public/ rather than /v1/ so it's
	// visually obvious in logs/nginx config which endpoints need no bearer
	// token at all.
	mux.HandleFunc("GET /public/sends/{id}", s.HandleGetSendMeta)
	mux.HandleFunc("POST /public/sends/{id}/access", s.HandleAccessSend)

	// Authenticated (Authorization: Bearer <access_token>)
	authed := auth.Middleware(s.DB)
	mux.Handle("POST /v1/auth/logout", authed(http.HandlerFunc(s.HandleLogout)))
	mux.Handle("POST /v1/auth/change-password", authed(http.HandlerFunc(s.HandleChangePassword)))

	mux.Handle("GET /v1/auth/2fa/status", authed(http.HandlerFunc(s.HandleGet2FAStatus)))
	mux.Handle("GET /v1/auth/recovery-kit/status", authed(http.HandlerFunc(s.HandleGetRecoveryKitStatus)))
	mux.Handle("POST /v1/auth/recovery-kit", authed(http.HandlerFunc(s.HandleSetRecoveryKit)))
	mux.Handle("DELETE /v1/auth/recovery-kit", authed(http.HandlerFunc(s.HandleDeleteRecoveryKit)))
	mux.Handle("POST /v1/auth/2fa/setup", authed(http.HandlerFunc(s.HandleSetup2FA)))
	mux.Handle("POST /v1/auth/2fa/enable", authed(http.HandlerFunc(s.HandleEnable2FA)))
	mux.Handle("POST /v1/auth/2fa/disable", authed(http.HandlerFunc(s.HandleDisable2FA)))
	mux.Handle("POST /v1/auth/2fa/recovery-codes/regenerate", authed(http.HandlerFunc(s.HandleRegenerateRecoveryCodes)))

	mux.Handle("GET /v1/sync", authed(http.HandlerFunc(s.HandleSync)))

	// POST /v1/ciphers doubles as create (no id in body) and update (id set
	// in body) — an upsert, not two endpoints, since the request shape is
	// identical either way and revision_ts already makes both safe to retry.
	mux.Handle("POST /v1/ciphers", authed(http.HandlerFunc(s.HandleUpsertCipher)))
	mux.Handle("DELETE /v1/ciphers/{id}", authed(withID(s.HandleDeleteCipher)))

	mux.Handle("POST /v1/folders", authed(http.HandlerFunc(s.HandleUpsertFolder)))
	mux.Handle("DELETE /v1/folders/{id}", authed(withID(s.HandleDeleteFolder)))

	mux.Handle("POST /v1/ciphers/{id}/attachments", authed(withID(s.HandleUploadAttachment)))
	mux.Handle("GET /v1/ciphers/{id}/attachments", authed(withID(s.HandleListAttachments)))
	mux.Handle("GET /v1/attachments/{id}", authed(withID(s.HandleDownloadAttachment)))
	mux.Handle("DELETE /v1/attachments/{id}", authed(withID(s.HandleDeleteAttachment)))

	mux.Handle("GET /v1/users/lookup", authed(http.HandlerFunc(s.HandleLookupUser)))
	mux.Handle("POST /v1/ciphers/{id}/shares", authed(withID(s.HandleCreateShare)))
	mux.Handle("GET /v1/ciphers/{id}/shares", authed(withID(s.HandleListShares)))
	mux.Handle("DELETE /v1/shares/{id}", authed(withID(s.HandleDeleteShare)))

	mux.Handle("POST /v1/sends", authed(http.HandlerFunc(s.HandleCreateSend)))
	mux.Handle("GET /v1/sends", authed(http.HandlerFunc(s.HandleListSends)))
	mux.Handle("GET /v1/sends/{id}/content", authed(http.HandlerFunc(s.HandleDownloadOwnSendContent)))
	mux.Handle("DELETE /v1/sends/{id}", authed(http.HandlerFunc(s.HandleDeleteSend)))

	mux.Handle("POST /v1/emergency-access", authed(http.HandlerFunc(s.HandleCreateEmergencyAccess)))
	mux.Handle("GET /v1/emergency-access/granted-by-me", authed(http.HandlerFunc(s.HandleListEmergencyAccessGrantedByMe)))
	mux.Handle("GET /v1/emergency-access/granted-to-me", authed(http.HandlerFunc(s.HandleListEmergencyAccessGrantedToMe)))
	mux.Handle("POST /v1/emergency-access/{id}/accept", authed(withID(s.HandleAcceptEmergencyAccess)))
	mux.Handle("POST /v1/emergency-access/{id}/confirm", authed(withID(s.HandleConfirmEmergencyAccess)))
	mux.Handle("POST /v1/emergency-access/{id}/request", authed(withID(s.HandleRequestEmergencyAccess)))
	mux.Handle("POST /v1/emergency-access/{id}/reject", authed(withID(s.HandleRejectEmergencyAccess)))
	mux.Handle("POST /v1/emergency-access/{id}/approve", authed(withID(s.HandleApproveEmergencyAccess)))
	mux.Handle("DELETE /v1/emergency-access/{id}", authed(withID(s.HandleDeleteEmergencyAccess)))
	mux.Handle("GET /v1/emergency-access/{id}/vault", authed(withID(s.HandleEmergencyAccessVault)))
	mux.Handle("POST /v1/emergency-access/{id}/takeover", authed(withID(s.HandleEmergencyAccessTakeover)))

	mux.Handle("GET /v1/settings/email-alias", authed(http.HandlerFunc(s.HandleGetEmailAliasSettings)))
	mux.Handle("PUT /v1/settings/email-alias", authed(http.HandlerFunc(s.HandleUpdateEmailAliasSettings)))
	mux.Handle("DELETE /v1/settings/email-alias", authed(http.HandlerFunc(s.HandleDeleteEmailAliasSettings)))
	mux.Handle("POST /v1/email-alias/generate", authed(http.HandlerFunc(s.HandleGenerateEmailAlias)))

	mux.Handle("GET /v1/devices", authed(http.HandlerFunc(s.HandleListDevices)))
	mux.Handle("DELETE /v1/devices/{id}", authed(withID(s.HandleRevokeDevice)))

	mux.Handle("GET /v1/audit-log", authed(http.HandlerFunc(s.HandleListAuditLog)))

	// Instance admin surface (static PASSVAULT_ADMIN_TOKEN bearer, not a
	// user session — see requireAdminToken).
	mux.HandleFunc("POST /v1/admin/invites", s.requireAdminToken(s.HandleCreateInvite))
	mux.Handle("POST /v1/admin/users/{id}/disabled", s.requireAdminToken(withID(s.HandleSetUserDisabled)))
	mux.HandleFunc("GET /v1/admin/smtp", s.requireAdminToken(s.HandleGetSMTPSettings))
	mux.HandleFunc("PUT /v1/admin/smtp", s.requireAdminToken(s.HandleUpdateSMTPSettings))
	mux.HandleFunc("POST /v1/admin/smtp/test", s.requireAdminToken(s.HandleSendTestEmail))

	return limitRequestBody(mux)
}

// maxRequestBodyBytes caps every JSON request body before it reaches any
// handler — decode() reads via json.NewDecoder(r.Body) with no cap of its
// own, so an unbounded body (especially on unauthenticated endpoints like
// login/register/Send access) would otherwise be buffered into memory in
// full before any field-level size validation in the handler ever runs.
// 1MiB is generous for every JSON body in this API (the largest,
// maxCipherBlobBytes, is 64KiB).
const maxRequestBodyBytes = 1 << 20

// limitRequestBody applies maxRequestBodyBytes to every request EXCEPT
// the two multipart upload routes, which already carry their own larger,
// purpose-built limits (see attachment_handlers.go/send_handlers.go).
// Those can't just be wrapped here too: nesting two http.MaxBytesReaders
// makes the SMALLER one win regardless of read order, which would
// silently break every real attachment/Send-file upload over 1MiB.
func limitRequestBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isMultipartUploadRoute(r) {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

func isMultipartUploadRoute(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}
	return r.URL.Path == "/v1/sends" || strings.HasSuffix(r.URL.Path, "/attachments")
}

func withID(h func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := parseID(r.PathValue("id"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid id")
			return
		}
		h(w, r, id)
	}
}
