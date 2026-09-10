package api

import (
	"net/http"

	"github.com/toshost/passvault/internal/auth"
	"github.com/toshost/passvault/internal/models"
)

// maxAuditLogRows caps a single response — this is a "recent activity"
// view, not a full export; no pagination for v1, matching the security
// view's other lists (weak/reused/compromised passwords are also
// unpaginated).
const maxAuditLogRows = 200

// HandleListAuditLog returns the CALLER's own security-relevant events,
// most recent first — logins, failed logins, password/2FA/recovery-kit
// changes, sharing, Send access, emergency access, and so on. Every
// audit() call site across this codebase already writes only
// machine-safe labels (never plaintext secrets), so returning the raw
// rows verbatim to their own owner is fine — this is deliberately never
// reachable for anyone else's events (WHERE user_id = the caller, not a
// path parameter).
func (s *Server) HandleListAuditLog(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	rows, err := s.DB.Query(`
		SELECT id, event, target, ip, created_at FROM audit_log
		WHERE user_id=$1 ORDER BY created_at DESC LIMIT $2`, u.ID, maxAuditLogRows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to load activity")
		return
	}
	defer rows.Close()
	out := []models.AuditEvent{}
	for rows.Next() {
		var e models.AuditEvent
		if err := rows.Scan(&e.ID, &e.Event, &e.Target, &e.IP, &e.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to load activity")
			return
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, out)
}
