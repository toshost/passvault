package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
)

const maxCipherBlobBytes = 64 * 1024 // generous for a login/note/card item; attachments are a separate Phase-1+ concern

type upsertCipherRequest struct {
	ID             int64  `json:"id,omitempty"`
	FolderID       *int64 `json:"folder_id,omitempty"`
	Type           string `json:"type"`
	WrappedItemKey string `json:"wrapped_item_key"`
	EncryptedBlob  string `json:"encrypted_blob"`
}

var validCipherTypes = map[string]bool{"login": true, "note": true, "card": true, "identity": true, "totp": true, "ssh_key": true}

func (s *Server) HandleUpsertCipher(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req upsertCipherRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if !validCipherTypes[req.Type] {
		writeErr(w, http.StatusBadRequest, "invalid cipher type")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedItemKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_item_key")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.EncryptedBlob, maxCipherBlobBytes); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid encrypted_blob")
		return
	}
	// A folder reference gets the same ownership check every other
	// cross-resource reference in this codebase already has (shares,
	// attachments) — without it, a client could attach its own cipher to
	// ANOTHER user's folder_id (the FK only requires the row to exist,
	// not to be owned by the caller), and a small sequential folder id
	// would double as an existence oracle: a foreign-but-valid id
	// succeeds, a nonexistent one 400s.
	if req.FolderID != nil {
		var folderID int64
		if err := s.DB.QueryRow(`SELECT id FROM folders WHERE id=$1 AND user_id=$2`, *req.FolderID, u.ID).Scan(&folderID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeErr(w, http.StatusBadRequest, "folder not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
	}

	var c models.Cipher
	if req.ID == 0 {
		err := s.DB.QueryRow(`
			INSERT INTO ciphers (user_id, folder_id, type, wrapped_item_key, encrypted_blob, revision_ts)
			VALUES ($1,$2,$3,$4,$5, nextval('revision_seq'))
			RETURNING id, revision_ts, created_at, updated_at`,
			u.ID, req.FolderID, req.Type, req.WrappedItemKey, req.EncryptedBlob,
		).Scan(&c.ID, &c.RevisionTS, &c.CreatedAt, &c.UpdatedAt)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
	} else {
		// user_id in the WHERE clause is the ownership check: a user can
		// never update another user's cipher by guessing an id.
		res, err := s.DB.Exec(`
			UPDATE ciphers SET folder_id=$1, type=$2, wrapped_item_key=$3, encrypted_blob=$4,
				revision_ts=nextval('revision_seq'), updated_at=now()
			WHERE id=$5 AND user_id=$6 AND deleted_at IS NULL`,
			req.FolderID, req.Type, req.WrappedItemKey, req.EncryptedBlob, req.ID, u.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "update failed")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeErr(w, http.StatusNotFound, "cipher not found")
			return
		}
		c.ID = req.ID
	}
	c.UserID = u.ID
	c.FolderID = req.FolderID
	c.Type = req.Type
	c.WrappedItemKey = req.WrappedItemKey
	c.EncryptedBlob = req.EncryptedBlob
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) HandleDeleteCipher(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())
	res, err := s.DB.Exec(`
		UPDATE ciphers SET deleted_at=now(), revision_ts=nextval('revision_seq')
		WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "cipher not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func scanCiphers(rows *sql.Rows) ([]models.Cipher, error) {
	defer rows.Close()
	var out []models.Cipher
	for rows.Next() {
		var c models.Cipher
		if err := rows.Scan(&c.ID, &c.UserID, &c.FolderID, &c.Type, &c.WrappedItemKey, &c.EncryptedBlob,
			&c.RevisionTS, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
