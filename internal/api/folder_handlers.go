package api

import (
	"database/sql"
	"net/http"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
)

type upsertFolderRequest struct {
	ID               int64  `json:"id,omitempty"`
	WrappedFolderKey string `json:"wrapped_folder_key"`
	EncryptedName    string `json:"encrypted_name"`
}

func (s *Server) HandleUpsertFolder(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	var req upsertFolderRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedFolderKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_folder_key")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.EncryptedName, 2048); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid encrypted_name")
		return
	}

	var f models.Folder
	if req.ID == 0 {
		err := s.DB.QueryRow(`
			INSERT INTO folders (user_id, wrapped_folder_key, encrypted_name, revision_ts)
			VALUES ($1,$2,$3, nextval('revision_seq'))
			RETURNING id, revision_ts, created_at, updated_at`,
			u.ID, req.WrappedFolderKey, req.EncryptedName,
		).Scan(&f.ID, &f.RevisionTS, &f.CreatedAt, &f.UpdatedAt)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
	} else {
		res, err := s.DB.Exec(`
			UPDATE folders SET wrapped_folder_key=$1, encrypted_name=$2,
				revision_ts=nextval('revision_seq'), updated_at=now()
			WHERE id=$3 AND user_id=$4 AND deleted_at IS NULL`,
			req.WrappedFolderKey, req.EncryptedName, req.ID, u.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "update failed")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			writeErr(w, http.StatusNotFound, "folder not found")
			return
		}
		f.ID = req.ID
	}
	f.UserID = u.ID
	f.WrappedFolderKey = req.WrappedFolderKey
	f.EncryptedName = req.EncryptedName
	writeJSON(w, http.StatusOK, f)
}

func (s *Server) HandleDeleteFolder(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())
	// Ciphers in this folder are NOT deleted — they're detached (folder_id
	// set NULL by the FK's ON DELETE SET NULL only applies to a hard
	// delete; here we soft-delete the folder, so do it explicitly).
	tx, err := s.DB.Begin()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		UPDATE folders SET deleted_at=now(), revision_ts=nextval('revision_seq')
		WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "folder not found")
		return
	}
	if _, err := tx.Exec(`
		UPDATE ciphers SET folder_id=NULL, revision_ts=nextval('revision_seq')
		WHERE folder_id=$1 AND user_id=$2`, id, u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func scanFolders(rows *sql.Rows) ([]models.Folder, error) {
	defer rows.Close()
	var out []models.Folder
	for rows.Next() {
		var f models.Folder
		if err := rows.Scan(&f.ID, &f.UserID, &f.WrappedFolderKey, &f.EncryptedName,
			&f.RevisionTS, &f.CreatedAt, &f.UpdatedAt, &f.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
