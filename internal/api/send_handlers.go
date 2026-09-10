package api

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/models"
	"github.com/toshost/passvault/internal/ratelimit"
)

// maxSendFileBytes caps a single Send's file content — a separate constant
// from attachments' maxAttachmentBytes even though both are 25MB today,
// since the two features' storage/retention differ (Sends expire and get
// swept; attachments don't) and may want independent limits later.
const maxSendFileBytes = 25 * 1024 * 1024

// maxSendTTL bounds how far in the future expires_at can be set, regardless
// of what a client requests — defense in depth against a client asking for
// an effectively-permanent Send.
const maxSendTTL = 30 * 24 * time.Hour

// HandleCreateSend accepts a multipart/form-data POST (always multipart,
// even for text-only Sends, so one handler covers both types): the server
// never sees plaintext content, a plaintext label, or a usable send key —
// only opaque ciphertext fields plus an optional plaintext `password`,
// which is Argon2id-hashed immediately and never stored or logged (same
// HashAuthKey primitive internal/auth uses for the master-password authKey,
// reused here as a generic Argon2id hash — see the sends table comment in
// internal/db/db.go for why that's a legitimate, independently-scoped
// reuse).
func (s *Server) HandleCreateSend(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, maxSendFileBytes+1<<20) // +1MiB slack for the other form fields
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "content too large or malformed upload (max 25MB)")
		return
	}

	sendType := r.FormValue("type")
	if sendType != "text" && sendType != "file" {
		writeErr(w, http.StatusBadRequest, "type must be \"text\" or \"file\"")
		return
	}
	wrappedSendKey := r.FormValue("wrapped_send_key")
	if err := vcrypto.ValidateOpaqueBlob(wrappedSendKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_send_key")
		return
	}
	encryptedLabel := r.FormValue("encrypted_label")
	if err := vcrypto.ValidateOpaqueBlob(encryptedLabel, 2048); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid encrypted_label")
		return
	}

	expiresInSeconds, err := strconv.ParseInt(r.FormValue("expires_in_seconds"), 10, 64)
	if err != nil || expiresInSeconds <= 0 {
		writeErr(w, http.StatusBadRequest, "invalid expires_in_seconds")
		return
	}
	ttl := time.Duration(expiresInSeconds) * time.Second
	if ttl > maxSendTTL {
		ttl = maxSendTTL
	}
	now := time.Now()
	expiresAt := now.Add(ttl)

	// Optional scheduled-reveal delay: the Send exists and is visible
	// (web/send.js shows "unlocks at <time>") the moment it's created, but
	// HandleAccessSend refuses to release content until this passes — a
	// dead-man-switch / "don't open before Monday" mode, distinct from
	// expires_in_seconds itself. Must land strictly before expiresAt, or
	// the Send would become reachable and expired in the same instant.
	var availableAt *time.Time
	if raw := r.FormValue("available_in_seconds"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			writeErr(w, http.StatusBadRequest, "invalid available_in_seconds")
			return
		}
		delay := time.Duration(n) * time.Second
		if delay >= ttl {
			writeErr(w, http.StatusBadRequest, "available_in_seconds must be before the Send expires")
			return
		}
		at := now.Add(delay)
		availableAt = &at
	}

	var maxViews *int
	if raw := r.FormValue("max_views"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeErr(w, http.StatusBadRequest, "invalid max_views")
			return
		}
		maxViews = &n
	}

	var passwordHash *string
	if pw := r.FormValue("password"); pw != "" {
		hash, err := vcrypto.HashAuthKey(pw)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
		passwordHash = &hash
	}

	var encryptedContent, encryptedFilename, storagePath *string
	var sizeBytes *int64

	if sendType == "text" {
		content := r.FormValue("encrypted_content")
		if err := vcrypto.ValidateOpaqueBlob(content, 512*1024); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid encrypted_content")
			return
		}
		encryptedContent = &content
	} else {
		filename := r.FormValue("encrypted_filename")
		if err := vcrypto.ValidateOpaqueBlob(filename, 2048); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid encrypted_filename")
			return
		}
		encryptedFilename = &filename

		file, _, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "missing file")
			return
		}
		defer file.Close()

		path, err := vcrypto.NewOpaqueToken() // random on-disk name — never derived from client input
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
		fullPath := filepath.Join(s.SendsDir, path)
		out, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "create failed")
			return
		}
		size, err := io.Copy(out, file)
		out.Close()
		if err != nil || size > maxSendFileBytes {
			os.Remove(fullPath)
			writeErr(w, http.StatusBadRequest, "file too large (max 25MB)")
			return
		}
		storagePath = &path
		sizeBytes = &size
	}

	id, err := vcrypto.NewOpaqueToken() // unguessable — this IS the public URL's lookup key, no auth gates it
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}

	var send models.Send
	err = s.DB.QueryRow(`
		INSERT INTO sends (id, owner_user_id, type, wrapped_send_key, encrypted_label,
			encrypted_content, encrypted_filename, storage_path, size_bytes, password_hash, max_views, expires_at, available_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING created_at`,
		id, u.ID, sendType, wrappedSendKey, encryptedLabel,
		encryptedContent, encryptedFilename, storagePath, sizeBytes, passwordHash, maxViews, expiresAt, availableAt,
	).Scan(&send.CreatedAt)
	if err != nil {
		if storagePath != nil {
			os.Remove(filepath.Join(s.SendsDir, *storagePath))
		}
		writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}

	send.ID = id
	send.Type = sendType
	send.WrappedSendKey = wrappedSendKey
	send.EncryptedLabel = encryptedLabel
	send.SizeBytes = sizeBytes
	send.HasPassword = passwordHash != nil
	send.MaxViews = maxViews
	send.ExpiresAt = expiresAt
	send.AvailableAt = availableAt
	audit(s.DB, &u.ID, "send.created", id, clientIP(r))
	writeJSON(w, http.StatusCreated, send)
}

// HandleListSends returns the owner's own Sends, newest first. Includes
// EncryptedContent/EncryptedFilename (opaque, and the owner is the one
// person who can always re-derive sendKey via WrappedSendKey) so "My
// Sends" can offer re-download/re-view without the original one-time URL.
func (s *Server) HandleListSends(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	rows, err := s.DB.Query(`
		SELECT id, type, wrapped_send_key, encrypted_label, encrypted_content, encrypted_filename,
			size_bytes, (password_hash IS NOT NULL) AS has_password, max_views, view_count, expires_at, available_at, created_at
		FROM sends WHERE owner_user_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	defer rows.Close()
	out := []models.Send{}
	for rows.Next() {
		var send models.Send
		if err := rows.Scan(&send.ID, &send.Type, &send.WrappedSendKey, &send.EncryptedLabel,
			&send.EncryptedContent, &send.EncryptedFilename, &send.SizeBytes, &send.HasPassword,
			&send.MaxViews, &send.ViewCount, &send.ExpiresAt, &send.AvailableAt, &send.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "list failed")
			return
		}
		out = append(out, send)
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleDownloadOwnSendContent lets the owner re-fetch a file Send's raw
// ciphertext bytes from within the app (they can already re-derive sendKey
// via WrappedSendKey, so this doesn't grant any new access, just a
// convenient path to the same bytes an anonymous recipient's URL reaches).
func (s *Server) HandleDownloadOwnSendContent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u := auth.UserFromContext(r.Context())

	var storagePath *string
	err := s.DB.QueryRow(`SELECT storage_path FROM sends WHERE id=$1 AND owner_user_id=$2 AND deleted_at IS NULL`,
		id, u.ID).Scan(&storagePath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "send not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "download failed")
		return
	}
	if storagePath == nil {
		writeErr(w, http.StatusBadRequest, "this send has no file content")
		return
	}
	f, err := os.Open(filepath.Join(s.SendsDir, *storagePath))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "download failed")
		return
	}
	defer f.Close()
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

// HandleDeleteSend is how an owner revokes a Send early (e.g. sent to the
// wrong person). Hard delete plus best-effort file removal, same shape as
// HandleDeleteAttachment.
func (s *Server) HandleDeleteSend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u := auth.UserFromContext(r.Context())

	var storagePath *string
	err := s.DB.QueryRow(`SELECT storage_path FROM sends WHERE id=$1 AND owner_user_id=$2`, id, u.ID).Scan(&storagePath)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "send not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if _, err := s.DB.Exec(`DELETE FROM sends WHERE id=$1`, id); err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if storagePath != nil {
		os.Remove(filepath.Join(s.SendsDir, *storagePath)) // best-effort; the DB row is the source of truth
	}
	audit(s.DB, &u.ID, "send.revoked", id, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// sendPublicMeta is what an anonymous visitor sees BEFORE any password
// check — just enough for web/send.js to render "this is a file, enter
// the password" without revealing the label, size beyond what's needed for
// a progress indicator, or anything else about the owner.
type sendPublicMeta struct {
	Type             string     `json:"type"`
	SizeBytes        *int64     `json:"size_bytes,omitempty"`
	RequiresPassword bool       `json:"requires_password"`
	AvailableAt      *time.Time `json:"available_at,omitempty"` // in the future = not yet unlocked; omitted once it's passed
}

// HandleGetSendMeta is public/unauthenticated — deliberately the only
// information released before a required password is supplied. A future
// AvailableAt is included here (not withheld) so web/send.js can show
// "unlocks at <time>" up front rather than making a recipient guess by
// failing an access attempt.
func (s *Server) HandleGetSendMeta(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var meta sendPublicMeta
	var passwordHash *string
	var expiresAt time.Time
	var availableAt *time.Time
	var deletedAt *time.Time
	err := s.DB.QueryRow(`SELECT type, size_bytes, password_hash, expires_at, available_at, deleted_at FROM sends WHERE id=$1`,
		id).Scan(&meta.Type, &meta.SizeBytes, &passwordHash, &expiresAt, &availableAt, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "this link doesn't exist or has expired")
			return
		}
		writeErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if deletedAt != nil || time.Now().After(expiresAt) {
		writeErr(w, http.StatusGone, "this link doesn't exist or has expired")
		return
	}
	meta.RequiresPassword = passwordHash != nil
	if availableAt != nil && time.Now().Before(*availableAt) {
		meta.AvailableAt = availableAt
	}
	writeJSON(w, http.StatusOK, meta)
}

// HandleAccessSend is public/unauthenticated and is the ONE place actual
// ciphertext is released to a recipient. A wrong password does not consume
// a view (checked before the atomic claim below); a correct one does. The
// view-count claim and the not-expired/not-exhausted check happen in a
// single atomic UPDATE...RETURNING so two simultaneous requests against a
// Send with one view remaining can't both succeed — Postgres's row lock
// during the UPDATE serializes them, and the second one's WHERE clause
// simply no longer matches. Exhausting the last allowed view deletes the
// Send (and its file) immediately, matching Bitwarden's "Maximum Access
// Count" burn-after-reading semantics.
func (s *Server) HandleAccessSend(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Password string `json:"password"`
	}
	decode(r, &req) // a body-less request just means "no password" — fine

	var passwordHash *string
	var expiresAt time.Time
	var availableAt *time.Time
	var deletedAt *time.Time
	err := s.DB.QueryRow(`SELECT password_hash, expires_at, available_at, deleted_at FROM sends WHERE id=$1`, id).
		Scan(&passwordHash, &expiresAt, &availableAt, &deletedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "this link doesn't exist or has expired")
			return
		}
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	if deletedAt != nil || time.Now().After(expiresAt) {
		writeErr(w, http.StatusGone, "this link doesn't exist or has expired")
		return
	}
	// Checked before the password, same as expiry/deleted above: no point
	// spending a password-guess attempt (and its rate-limit budget) against
	// content that wouldn't be released yet regardless of whether it's
	// right.
	if availableAt != nil && time.Now().Before(*availableAt) {
		writeErr(w, http.StatusTooEarly, "this hasn't unlocked yet")
		return
	}
	if passwordHash != nil {
		ip := clientIP(r)
		if !ratelimit.Allowed(s.DB, ratelimit.BucketSendAccessIP, ip, 30) || !ratelimit.Allowed(s.DB, ratelimit.BucketSendAccessSend, id, 15) {
			writeErr(w, http.StatusTooManyRequests, "too many attempts — try again later")
			return
		}
		ratelimit.Record(s.DB, ratelimit.BucketSendAccessIP, ip)
		ratelimit.Record(s.DB, ratelimit.BucketSendAccessSend, id)

		audit(s.DB, nil, "send.access_attempt", id, clientIP(r))
		if !vcrypto.VerifyAuthKey(*passwordHash, req.Password) {
			writeErr(w, http.StatusUnauthorized, "wrong password")
			return
		}
	}

	var sendType string
	var encryptedContent, encryptedFilename, storagePath *string
	var maxViews *int
	var viewCount int
	err = s.DB.QueryRow(`
		UPDATE sends SET view_count = view_count + 1
		WHERE id=$1 AND deleted_at IS NULL AND expires_at > now()
		  AND (max_views IS NULL OR view_count < max_views)
		RETURNING type, encrypted_content, encrypted_filename, storage_path, max_views, view_count`,
		id,
	).Scan(&sendType, &encryptedContent, &encryptedFilename, &storagePath, &maxViews, &viewCount)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusGone, "this link doesn't exist or has expired")
			return
		}
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	audit(s.DB, nil, "send.accessed", id, clientIP(r))

	exhausted := maxViews != nil && viewCount >= *maxViews
	if exhausted {
		s.DB.Exec(`UPDATE sends SET deleted_at = now() WHERE id=$1`, id)
	}

	if sendType == "text" {
		writeJSON(w, http.StatusOK, map[string]any{"type": "text", "encrypted_content": encryptedContent})
		return
	}

	// File send: stream ciphertext bytes with the encrypted filename in a
	// header, since a JSON envelope can't carry raw binary cleanly.
	if storagePath == nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	f, err := os.Open(filepath.Join(s.SendsDir, *storagePath))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	defer f.Close()
	setSecurityHeaders(w)
	if encryptedFilename != nil {
		w.Header().Set("X-Encrypted-Filename", *encryptedFilename)
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
	if exhausted {
		os.Remove(filepath.Join(s.SendsDir, *storagePath))
	}
}

// SweepExpiredSends deletes expired/exhausted-but-not-yet-purged Sends
// (both the DB row and any on-disk file). Exhausted-by-view-count Sends
// are already purged eagerly in HandleAccessSend; this catches the ones
// nobody ever revisits — an expired Send that's never accessed again
// would otherwise sit on disk forever. Called from a periodic ticker in
// cmd/passvault-server/main.go; safe to call concurrently with normal
// traffic since it only ever targets rows already past expires_at.
func (s *Server) SweepExpiredSends() {
	rows, err := s.DB.Query(`SELECT id, storage_path FROM sends WHERE deleted_at IS NULL AND expires_at <= now()`)
	if err != nil {
		return
	}
	type expired struct {
		id          string
		storagePath *string
	}
	var toDelete []expired
	for rows.Next() {
		var e expired
		if rows.Scan(&e.id, &e.storagePath) == nil {
			toDelete = append(toDelete, e)
		}
	}
	rows.Close()
	for _, e := range toDelete {
		s.DB.Exec(`UPDATE sends SET deleted_at = now() WHERE id=$1`, e.id)
		if e.storagePath != nil {
			os.Remove(filepath.Join(s.SendsDir, *e.storagePath))
		}
	}
}
