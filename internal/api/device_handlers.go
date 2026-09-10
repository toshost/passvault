package api

import (
	"net/http"
	"time"

	"github.com/toshost/passvault/internal/auth"
)

type deviceView struct {
	ID         int64     `json:"id"`
	Label      string    `json:"label"`
	LastSeenAt time.Time `json:"last_seen_at"`
	CreatedAt  time.Time `json:"created_at"`
	Current    bool      `json:"current"`
}

func (s *Server) HandleListDevices(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	current := auth.DeviceFromContext(r.Context())
	rows, err := s.DB.Query(`
		SELECT id, label, last_seen_at, created_at FROM devices
		WHERE user_id=$1 AND revoked_at IS NULL ORDER BY last_seen_at DESC`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to list devices")
		return
	}
	defer rows.Close()
	var out []deviceView
	for rows.Next() {
		var d deviceView
		if err := rows.Scan(&d.ID, &d.Label, &d.LastSeenAt, &d.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "failed to list devices")
			return
		}
		d.Current = d.ID == current
		out = append(out, d)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) HandleRevokeDevice(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())
	if err := auth.RevokeDevice(s.DB, u.ID, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "revoke failed")
		return
	}
	audit(s.DB, &u.ID, "device.revoked", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
