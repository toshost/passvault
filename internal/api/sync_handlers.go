package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/toshost/passvault/internal/auth"
)

// HandleSync returns every folder/cipher (including soft-deleted ones, so
// clients can purge them locally) with revision_ts > since. since=0 (or
// omitted) is a full sync. This is the only read path clients need — no
// separate "list ciphers" endpoint, matching Bitwarden's own sync-first
// design, which the future Bitwarden-compat realm's /api/sync also expects.
func (s *Server) HandleSync(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)

	folderRows, err := s.DB.Query(`
		SELECT id, user_id, wrapped_folder_key, encrypted_name, revision_ts, created_at, updated_at, deleted_at
		FROM folders WHERE user_id=$1 AND revision_ts > $2 ORDER BY revision_ts`, u.ID, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sync failed")
		return
	}
	folders, err := scanFolders(folderRows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sync failed")
		return
	}

	cipherRows, err := s.DB.Query(`
		SELECT id, user_id, folder_id, type, wrapped_item_key, encrypted_blob, revision_ts, created_at, updated_at, deleted_at
		FROM ciphers WHERE user_id=$1 AND revision_ts > $2 ORDER BY revision_ts`, u.ID, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sync failed")
		return
	}
	ciphers, err := scanCiphers(cipherRows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sync failed")
		return
	}

	// Items shared with this user, not owned by them. Deliberately NOT
	// part of the revision_ts delta-sync scheme above (owner_id doesn't
	// change, and there simply aren't many of these for a "simple sharing"
	// feature) — every sync call returns the full current set, so a
	// revoked share disappears on the next sync with no tombstone needed.
	sharedRows, err := s.DB.Query(`
		SELECT c.id, c.type, c.encrypted_blob, cs.wrapped_item_key, u.email, u.x25519_public_key, c.updated_at
		FROM cipher_shares cs
		JOIN ciphers c ON c.id = cs.cipher_id
		JOIN users u ON u.id = cs.owner_user_id
		WHERE cs.shared_with_user_id = $1 AND c.deleted_at IS NULL
		ORDER BY c.updated_at`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "sync failed")
		return
	}
	defer sharedRows.Close()
	sharedCiphers := []sharedCipherView{}
	for sharedRows.Next() {
		var sc sharedCipherView
		if err := sharedRows.Scan(&sc.ID, &sc.Type, &sc.EncryptedBlob, &sc.WrappedItemKey, &sc.OwnerEmail, &sc.OwnerX25519PublicKey, &sc.UpdatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "sync failed")
			return
		}
		sharedCiphers = append(sharedCiphers, sc)
	}

	maxRev := since
	for _, f := range folders {
		if f.RevisionTS > maxRev {
			maxRev = f.RevisionTS
		}
	}
	for _, c := range ciphers {
		if c.RevisionTS > maxRev {
			maxRev = c.RevisionTS
		}
	}

	resp := struct {
		Folders       any   `json:"folders"`
		Ciphers       any   `json:"ciphers"`
		SharedCiphers any   `json:"shared_ciphers"`
		RevisionTS    int64 `json:"revision_ts"`
	}{Folders: folders, Ciphers: ciphers, SharedCiphers: sharedCiphers, RevisionTS: maxRev}
	writeJSON(w, http.StatusOK, resp)
}

// sharedCipherView is the shape a recipient needs to decrypt an item
// they didn't create: the owner's public key (to redo the ECDH on their
// side) and the share-specific wrapped_item_key (ECDH-wrapped, NOT the
// owner's own vaultKey-wrapped one from the ciphers table).
type sharedCipherView struct {
	ID                   int64     `json:"id"`
	Type                 string    `json:"type"`
	EncryptedBlob        string    `json:"encrypted_blob"`
	WrappedItemKey       string    `json:"wrapped_item_key"`
	OwnerEmail           string    `json:"owner_email"`
	OwnerX25519PublicKey string    `json:"owner_x25519_public_key"`
	UpdatedAt            time.Time `json:"updated_at"`
}
