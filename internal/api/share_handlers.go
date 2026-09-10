package api

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
	"github.com/toshost/passvault/internal/ratelimit"
)

// HandleLookupUser resolves an email to the minimum needed to share an item
// with them: their id and X25519 public key. Nothing else about the
// account is exposed (not disabled status, not join date, nothing) — this
// is the narrowest surface that still lets sharing-by-email work at all;
// any invite/share-by-email feature has this same "does this email have an
// account" tradeoff (Bitwarden's org member invite works the same way).
func (s *Server) HandleLookupUser(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	email := r.URL.Query().Get("email")
	if email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	// Every other identity-guessing endpoint in this API is rate-limited;
	// this one wasn't, despite being reachable by any authenticated user
	// (self-registration may be open) and returning a clean 200/404 split
	// — a scriptable way to enumerate the instance's whole registered
	// user base. Keyed by the CALLER's own id, not IP: the caller is
	// already authenticated, so their identity is the meaningful,
	// attacker-uncontrolled bound here.
	identifier := strconv.FormatInt(u.ID, 10)
	if !ratelimit.Allowed(s.DB, ratelimit.BucketUserLookupUser, identifier, 30) {
		writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
		return
	}
	ratelimit.Record(s.DB, ratelimit.BucketUserLookupUser, identifier)

	var id int64
	var pubKey string
	err := s.DB.QueryRow(`SELECT id, x25519_public_key FROM users WHERE email=$1`, email).Scan(&id, &pubKey)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "no account with that email")
			return
		}
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "x25519_public_key": pubKey})
}

type createShareRequest struct {
	SharedWithUserID int64  `json:"shared_with_user_id"`
	WrappedItemKey   string `json:"wrapped_item_key"`
}

// HandleCreateShare grants (or updates) one recipient's access to one item.
// The caller must already have computed wrapped_item_key client-side via
// ECDH with the recipient's public key — the server never sees, generates,
// or touches an itemKey, same as every other write path here.
func (s *Server) HandleCreateShare(w http.ResponseWriter, r *http.Request, cipherID int64) {
	u := auth.UserFromContext(r.Context())

	var ownerID int64
	err := s.DB.QueryRow(`SELECT user_id FROM ciphers WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, cipherID, u.ID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "item not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "share failed")
		return
	}

	var req createShareRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.SharedWithUserID == u.ID {
		writeErr(w, http.StatusBadRequest, "can't share an item with yourself")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedItemKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_item_key")
		return
	}

	var share models.CipherShare
	err = s.DB.QueryRow(`
		INSERT INTO cipher_shares (cipher_id, owner_user_id, shared_with_user_id, wrapped_item_key)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (cipher_id, shared_with_user_id) DO UPDATE SET wrapped_item_key = EXCLUDED.wrapped_item_key
		RETURNING id, created_at`,
		cipherID, u.ID, req.SharedWithUserID, req.WrappedItemKey,
	).Scan(&share.ID, &share.CreatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			writeErr(w, http.StatusBadRequest, "no such user")
			return
		}
		writeErr(w, http.StatusInternalServerError, "share failed")
		return
	}
	share.CipherID = cipherID
	share.OwnerUserID = u.ID
	share.SharedWithUserID = req.SharedWithUserID
	share.WrappedItemKey = req.WrappedItemKey
	audit(s.DB, &u.ID, "cipher.shared", "", clientIP(r))
	writeJSON(w, http.StatusCreated, share)
}

type shareView struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

// HandleListShares is owner-only — who an item is shared with is not
// itself secret content, but it's still scoped to the owner, same as the
// rest of an item's metadata.
func (s *Server) HandleListShares(w http.ResponseWriter, r *http.Request, cipherID int64) {
	u := auth.UserFromContext(r.Context())
	var ownerID int64
	err := s.DB.QueryRow(`SELECT user_id FROM ciphers WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, cipherID, u.ID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "item not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	rows, err := s.DB.Query(`
		SELECT cs.id, u.email FROM cipher_shares cs
		JOIN users u ON u.id = cs.shared_with_user_id
		WHERE cs.cipher_id=$1 ORDER BY cs.created_at`, cipherID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()
	out := []shareView{}
	for rows.Next() {
		var sv shareView
		if err := rows.Scan(&sv.ID, &sv.Email); err != nil {
			writeErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		out = append(out, sv)
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleDeleteShare revokes one recipient's access. A hard delete, unlike
// ciphers/folders' soft-delete pattern — shares aren't sync'd incrementally
// (see HandleSync), so there's no "tombstone" a recipient's client needs to
// see; they just stop getting the item back on their next sync.
func (s *Server) HandleDeleteShare(w http.ResponseWriter, r *http.Request, shareID int64) {
	u := auth.UserFromContext(r.Context())
	res, err := s.DB.Exec(`DELETE FROM cipher_shares WHERE id=$1 AND owner_user_id=$2`, shareID, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "unshare failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "share not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func isForeignKeyViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	if errors.As(err, &s) {
		return s.SQLState() == "23503"
	}
	return false
}
