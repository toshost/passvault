package api

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
)

// maxAttachmentBytes caps a single upload — generous enough for a scanned
// ID or a short PDF, small enough that one user can't fill the disk with a
// single request. Enforced via http.MaxBytesReader, not just a client-side
// promise.
const maxAttachmentBytes = 25 * 1024 * 1024

// HandleUploadAttachment accepts a multipart/form-data POST: the file part
// is already-encrypted ciphertext bytes (the server never sees plaintext
// file content, same as it never sees plaintext for anything else), plus
// form fields wrapped_attachment_key and encrypted_filename (both opaque,
// base64/ciphertext — validated for shape only, never decrypted).
func (s *Server) HandleUploadAttachment(w http.ResponseWriter, r *http.Request, cipherID int64) {
	u := auth.UserFromContext(r.Context())

	var ownerID int64
	err := s.DB.QueryRow(`SELECT user_id FROM ciphers WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL`, cipherID, u.ID).Scan(&ownerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "item not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "upload failed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAttachmentBytes+1<<20) // +1MiB slack for the other form fields
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "file too large or malformed upload (max 25MB)")
		return
	}

	wrappedKey := r.FormValue("wrapped_attachment_key")
	encryptedFilename := r.FormValue("encrypted_filename")
	if err := vcrypto.ValidateOpaqueBlob(wrappedKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_attachment_key")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(encryptedFilename, 2048); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid encrypted_filename")
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing file")
		return
	}
	defer file.Close()

	storagePath, err := vcrypto.NewOpaqueToken() // random on-disk name — never derived from client input
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "upload failed")
		return
	}
	fullPath := filepath.Join(s.AttachmentsDir, storagePath)
	out, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "upload failed")
		return
	}
	size, err := io.Copy(out, file)
	out.Close()
	if err != nil || size > maxAttachmentBytes {
		os.Remove(fullPath)
		writeErr(w, http.StatusBadRequest, "file too large (max 25MB)")
		return
	}

	var a models.Attachment
	err = s.DB.QueryRow(`
		INSERT INTO attachments (cipher_id, wrapped_attachment_key, encrypted_filename, size_bytes, storage_path)
		VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`,
		cipherID, wrappedKey, encryptedFilename, size, storagePath,
	).Scan(&a.ID, &a.CreatedAt)
	if err != nil {
		os.Remove(fullPath)
		writeErr(w, http.StatusInternalServerError, "upload failed")
		return
	}
	a.CipherID = cipherID
	a.WrappedAttachmentKey = wrappedKey
	a.EncryptedFilename = encryptedFilename
	a.SizeBytes = size
	writeJSON(w, http.StatusCreated, a)
}

// HandleListAttachments returns metadata only (never file bytes) for every
// attachment on one item — fetched lazily by the client when an item's
// attachments are actually opened, not bundled into the main /v1/sync
// payload (attachments can be numerous/large-ish relative to the tiny
// cipher/folder rows that sync already carries).
func (s *Server) HandleListAttachments(w http.ResponseWriter, r *http.Request, cipherID int64) {
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
		SELECT id, cipher_id, wrapped_attachment_key, encrypted_filename, size_bytes, created_at
		FROM attachments WHERE cipher_id=$1 ORDER BY created_at`, cipherID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()
	out := []models.Attachment{}
	for rows.Next() {
		var a models.Attachment
		if err := rows.Scan(&a.ID, &a.CipherID, &a.WrappedAttachmentKey, &a.EncryptedFilename, &a.SizeBytes, &a.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleDownloadAttachment streams ciphertext bytes back verbatim — the
// server has no way to decrypt them and doesn't try. Ownership is checked
// by joining through the parent cipher, same as every other per-resource
// handler in this package.
func (s *Server) HandleDownloadAttachment(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())

	var storagePath string
	err := s.DB.QueryRow(`
		SELECT a.storage_path FROM attachments a
		JOIN ciphers c ON c.id = a.cipher_id
		WHERE a.id=$1 AND c.user_id=$2 AND c.deleted_at IS NULL`, id, u.ID).Scan(&storagePath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "attachment not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "download failed")
		return
	}

	f, err := os.Open(filepath.Join(s.AttachmentsDir, storagePath))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "download failed")
		return
	}
	defer f.Close()
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func (s *Server) HandleDeleteAttachment(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())

	var storagePath string
	err := s.DB.QueryRow(`
		SELECT a.storage_path FROM attachments a
		JOIN ciphers c ON c.id = a.cipher_id
		WHERE a.id=$1 AND c.user_id=$2`, id, u.ID).Scan(&storagePath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "attachment not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}

	if _, err := s.DB.Exec(`DELETE FROM attachments WHERE id=$1`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	os.Remove(filepath.Join(s.AttachmentsDir, storagePath)) // best-effort; the DB row is the source of truth
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
