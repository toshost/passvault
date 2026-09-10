package api

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/toshost/passvault/internal/auth"
	vcrypto "github.com/toshost/passvault/internal/crypto"
	"github.com/toshost/passvault/internal/mailer"
	"github.com/toshost/passvault/internal/models"
)

// maxEmergencyWaitDays bounds wait_days regardless of what a client
// requests, same defense-in-depth reasoning as Send's maxSendTTL.
const maxEmergencyWaitDays = 90

// notify sends a best-effort email — a delivery failure here must never
// fail the state transition it's describing (the grantor/grantee can
// still see the new status next time they open the app). Logged, not
// swallowed silently, so an operator with a misconfigured relay has
// somewhere to look.
func notify(db *sql.DB, to, subject, body string) {
	if to == "" {
		return
	}
	settings, err := mailer.LoadSettings(db)
	if err != nil {
		return // SMTP not configured — nothing to do, not an error condition worth logging repeatedly
	}
	if err := mailer.Send(settings, to, subject, body); err != nil {
		log.Printf("emergency access notification to %s failed: %v", to, err)
	}
}

type createEmergencyAccessRequest struct {
	GranteeEmail string `json:"grantee_email"`
	AccessType   string `json:"access_type"` // view | takeover
	WaitDays     int    `json:"wait_days"`
}

// HandleCreateEmergencyAccess is the grantor inviting a trusted contact.
// No key material is exchanged yet — that happens at confirm time, once
// the grantee has accepted and the grantor's own client can compute the
// ECDH wrap (see the emergency_access table comment).
func (s *Server) HandleCreateEmergencyAccess(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())

	var req createEmergencyAccessRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.AccessType != "view" && req.AccessType != "takeover" {
		writeErr(w, http.StatusBadRequest, "access_type must be \"view\" or \"takeover\"")
		return
	}
	if req.WaitDays < 0 {
		writeErr(w, http.StatusBadRequest, "wait_days must be >= 0")
		return
	}
	if req.WaitDays > maxEmergencyWaitDays {
		req.WaitDays = maxEmergencyWaitDays
	}

	var granteeID int64
	err := s.DB.QueryRow(`SELECT id FROM users WHERE email=$1`, req.GranteeEmail).Scan(&granteeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "no account with that email")
			return
		}
		writeErr(w, http.StatusInternalServerError, "invite failed")
		return
	}
	if granteeID == u.ID {
		writeErr(w, http.StatusBadRequest, "can't designate yourself as your own emergency contact")
		return
	}

	var ea models.EmergencyAccess
	err = s.DB.QueryRow(`
		INSERT INTO emergency_access (grantor_user_id, grantee_user_id, access_type, wait_days)
		VALUES ($1,$2,$3,$4) RETURNING id, created_at, updated_at`,
		u.ID, granteeID, req.AccessType, req.WaitDays,
	).Scan(&ea.ID, &ea.CreatedAt, &ea.UpdatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			writeErr(w, http.StatusConflict, "you've already invited this person")
			return
		}
		writeErr(w, http.StatusInternalServerError, "invite failed")
		return
	}

	audit(s.DB, &u.ID, "emergency_access.invited", req.GranteeEmail, clientIP(r))
	notify(s.DB, req.GranteeEmail, "You've been invited as a Passvault emergency contact",
		u.Email+" has invited you to be their emergency access contact on Passvault. Log in to your Passvault account to accept or decline.")

	ea.GrantorUserID = u.ID
	ea.GranteeUserID = granteeID
	ea.AccessType = req.AccessType
	ea.WaitDays = req.WaitDays
	ea.Status = "invited"
	writeJSON(w, http.StatusCreated, ea)
}

const emergencyAccessListSelect = `
	SELECT ea.id, ea.grantor_user_id, go.email, go.x25519_public_key,
		ea.grantee_user_id, ge.email, ge.x25519_public_key,
		ea.access_type, ea.wait_days, ea.status, ea.wrapped_vault_key_for_grantee,
		ea.requested_at, ea.access_at, ea.created_at, ea.updated_at
	FROM emergency_access ea
	JOIN users go ON go.id = ea.grantor_user_id
	JOIN users ge ON ge.id = ea.grantee_user_id`

func scanEmergencyAccessRows(rows *sql.Rows) ([]models.EmergencyAccess, error) {
	defer rows.Close()
	out := []models.EmergencyAccess{}
	for rows.Next() {
		var ea models.EmergencyAccess
		if err := rows.Scan(&ea.ID, &ea.GrantorUserID, &ea.GrantorEmail, &ea.GrantorX25519PublicKey,
			&ea.GranteeUserID, &ea.GranteeEmail, &ea.GranteeX25519PublicKey,
			&ea.AccessType, &ea.WaitDays, &ea.Status, &ea.WrappedVaultKeyForGrantee,
			&ea.RequestedAt, &ea.AccessAt, &ea.CreatedAt, &ea.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, ea)
	}
	return out, rows.Err()
}

// HandleListEmergencyAccessGrantedByMe is the grantor's view: the
// contacts THEY have designated, at every stage of the state machine.
func (s *Server) HandleListEmergencyAccessGrantedByMe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	rows, err := s.DB.Query(emergencyAccessListSelect+` WHERE ea.grantor_user_id=$1 ORDER BY ea.created_at DESC`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out, err := scanEmergencyAccessRows(rows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// HandleListEmergencyAccessGrantedToMe is the grantee's view: the
// accounts THEY are a trusted contact for.
func (s *Server) HandleListEmergencyAccessGrantedToMe(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	rows, err := s.DB.Query(emergencyAccessListSelect+` WHERE ea.grantee_user_id=$1 ORDER BY ea.created_at DESC`, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	out, err := scanEmergencyAccessRows(rows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// transitionEmergencyAccess is the shared shape behind every status
// change below: load the row scoped to whichever side the caller must be
// on, check the current status is the one expected, apply the update,
// notify the other party. Centralizing this means every transition gets
// the same ownership/status guard instead of six handlers each
// re-deriving it slightly differently.
func (s *Server) transitionEmergencyAccess(
	w http.ResponseWriter, r *http.Request, id int64, callerIsGrantor bool, fromStatus string,
	apply func(ea *models.EmergencyAccess) (setClause string, args []any, err error),
) (*models.EmergencyAccess, bool) {
	u := auth.UserFromContext(r.Context())
	col := "grantee_user_id"
	if callerIsGrantor {
		col = "grantor_user_id"
	}

	rows, err := s.DB.Query(emergencyAccessListSelect+` WHERE ea.id=$1 AND ea.`+col+`=$2`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return nil, false
	}
	list, err := scanEmergencyAccessRows(rows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return nil, false
	}
	if len(list) == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return nil, false
	}
	ea := list[0]
	if ea.Status != fromStatus {
		writeErr(w, http.StatusConflict, "this request is no longer in the expected state (status: "+ea.Status+")")
		return nil, false
	}

	setClause, args, err := apply(&ea)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return nil, false
	}
	args = append(args, id)
	if _, err := s.DB.Exec(`UPDATE emergency_access SET `+setClause+`, updated_at=now() WHERE id=$`+strconv.Itoa(len(args)), args...); err != nil {
		writeErr(w, http.StatusInternalServerError, "update failed")
		return nil, false
	}
	return &ea, true
}

// HandleAcceptEmergencyAccess: the grantee agrees to be a trust contact.
// Still no key material — that's the grantor's confirm step next.
func (s *Server) HandleAcceptEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	ea, ok := s.transitionEmergencyAccess(w, r, id, false, "invited",
		func(ea *models.EmergencyAccess) (string, []any, error) {
			return "status='accepted'", nil, nil
		})
	if !ok {
		return
	}
	notify(s.DB, ea.GrantorEmail, "Your emergency contact accepted",
		ea.GranteeEmail+" accepted your invitation to be your Passvault emergency contact. Log in and confirm to finish setting this up.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type confirmEmergencyAccessRequest struct {
	WrappedVaultKeyForGrantee string `json:"wrapped_vault_key_for_grantee"`
}

// HandleConfirmEmergencyAccess: the grantor uploads their vaultKey
// wrapped under the ECDH-derived key shared with the grantee. This is
// the ONLY step that ever touches key material for this feature, and it
// can only happen on the grantor's own already-unlocked client.
func (s *Server) HandleConfirmEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	var req confirmEmergencyAccessRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.WrappedVaultKeyForGrantee, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid wrapped_vault_key_for_grantee")
		return
	}

	ea, ok := s.transitionEmergencyAccess(w, r, id, true, "accepted",
		func(ea *models.EmergencyAccess) (string, []any, error) {
			return "status='confirmed', wrapped_vault_key_for_grantee=$1", []any{req.WrappedVaultKeyForGrantee}, nil
		})
	if !ok {
		return
	}
	audit(s.DB, &ea.GrantorUserID, "emergency_access.confirmed", ea.GranteeEmail, clientIP(r))
	notify(s.DB, ea.GranteeEmail, "Your Passvault emergency access was confirmed",
		ea.GrantorEmail+" confirmed you as their emergency contact. You can request access from the Emergency Access section if you ever need it.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleRequestEmergencyAccess: the grantee starts the waiting-period
// clock. If the grantor doesn't reject within wait_days, SweepEmergencyAccessGrants
// auto-grants it.
func (s *Server) HandleRequestEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	ea, ok := s.transitionEmergencyAccess(w, r, id, false, "confirmed",
		func(ea *models.EmergencyAccess) (string, []any, error) {
			accessAt := time.Now().Add(time.Duration(ea.WaitDays) * 24 * time.Hour)
			return "status='requested', requested_at=now(), access_at=$1", []any{accessAt}, nil
		})
	if !ok {
		return
	}
	audit(s.DB, &ea.GranteeUserID, "emergency_access.requested", ea.GrantorEmail, clientIP(r))
	waitNote := "Access will be granted automatically almost immediately"
	if ea.WaitDays > 0 {
		waitNote = "If you don't reject this within " + strconv.Itoa(ea.WaitDays) + " day(s), access will be granted automatically"
	}
	notify(s.DB, ea.GrantorEmail, "Emergency access requested on your Passvault account",
		ea.GranteeEmail+" has requested emergency access to your vault. "+waitNote+
			" — log in to Passvault to approve or reject it now.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleRejectEmergencyAccess: the grantor cancels a pending request —
// back to "confirmed" (the relationship stays intact, just not currently
// requested), not deleted.
func (s *Server) HandleRejectEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	ea, ok := s.transitionEmergencyAccess(w, r, id, true, "requested",
		func(ea *models.EmergencyAccess) (string, []any, error) {
			return "status='confirmed', requested_at=NULL, access_at=NULL", nil, nil
		})
	if !ok {
		return
	}
	audit(s.DB, &ea.GrantorUserID, "emergency_access.rejected", ea.GranteeEmail, clientIP(r))
	notify(s.DB, ea.GranteeEmail, "Your emergency access request was rejected",
		ea.GrantorEmail+" rejected your emergency access request.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleApproveEmergencyAccess: the grantor grants access immediately
// instead of waiting out the remainder of wait_days.
func (s *Server) HandleApproveEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	ea, ok := s.transitionEmergencyAccess(w, r, id, true, "requested",
		func(ea *models.EmergencyAccess) (string, []any, error) {
			return "status='granted'", nil, nil
		})
	if !ok {
		return
	}
	audit(s.DB, &ea.GrantorUserID, "emergency_access.approved", ea.GranteeEmail, clientIP(r))
	notify(s.DB, ea.GranteeEmail, "Your Passvault emergency access was approved",
		ea.GrantorEmail+" approved your emergency access request early. You can now access their vault from the Emergency Access section.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleDeleteEmergencyAccess: either side can end the relationship at
// any point in the state machine — the grantor revoking trust, or the
// grantee stepping down as a contact.
func (s *Server) HandleDeleteEmergencyAccess(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())
	res, err := s.DB.Exec(`DELETE FROM emergency_access WHERE id=$1 AND (grantor_user_id=$2 OR grantee_user_id=$2)`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	audit(s.DB, &u.ID, "emergency_access.removed", "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// HandleEmergencyAccessVault is the "view" access type's payload: the
// grantor's current folders/ciphers, shaped like a one-shot GET /v1/sync
// for the grantee, plus the wrapped key and grantor pubkey the grantee's
// client needs to actually decrypt any of it (the same ECDH-redo pattern
// as item sharing's shared_ciphers).
func (s *Server) HandleEmergencyAccessVault(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())

	rows, err := s.DB.Query(emergencyAccessListSelect+` WHERE ea.id=$1 AND ea.grantee_user_id=$2`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	list, err := scanEmergencyAccessRows(rows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	if len(list) == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ea := list[0]
	if ea.Status != "granted" {
		writeErr(w, http.StatusForbidden, "access has not been granted (status: "+ea.Status+")")
		return
	}
	if ea.AccessType != "view" {
		writeErr(w, http.StatusBadRequest, "this grant is \"takeover\" type — use the takeover endpoint instead")
		return
	}

	folderRows, err := s.DB.Query(`
		SELECT id, user_id, wrapped_folder_key, encrypted_name, revision_ts, created_at, updated_at, deleted_at
		FROM folders WHERE user_id=$1 AND deleted_at IS NULL`, ea.GrantorUserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	folders, err := scanFolders(folderRows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	cipherRows, err := s.DB.Query(`
		SELECT id, user_id, folder_id, type, wrapped_item_key, encrypted_blob, revision_ts, created_at, updated_at, deleted_at
		FROM ciphers WHERE user_id=$1 AND deleted_at IS NULL`, ea.GrantorUserID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}
	ciphers, err := scanCiphers(cipherRows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "access failed")
		return
	}

	audit(s.DB, &u.ID, "emergency_access.vault_viewed", ea.GrantorEmail, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"grantor_email":                 ea.GrantorEmail,
		"grantor_x25519_public_key":     ea.GrantorX25519PublicKey,
		"wrapped_vault_key_for_grantee": ea.WrappedVaultKeyForGrantee,
		"folders":                       folders,
		"ciphers":                       ciphers,
	})
}

type emergencyTakeoverRequest struct {
	KDF                vcrypto.KDFParams `json:"kdf"`
	NewAuthKey         string            `json:"new_auth_key"`
	NewWrappedVaultKey string            `json:"new_wrapped_vault_key"`
}

// HandleEmergencyAccessTakeover resets the GRANTOR's login password. The
// grantee's client has already: unwrapped the grantor's vaultKey via
// wrapped_vault_key_for_grantee + ECDH, generated a brand new wrapKey
// from a password the grantee chooses, and re-wrapped the SAME vaultKey
// under it (see auth.ChangePassword's docs/PROTOCOL.md rationale — the
// only reason this doesn't need to touch a single cipher/folder). Every
// existing device session for the grantor is revoked, since their
// password — and therefore anyone who only knew the old one — no longer
// controls the account.
func (s *Server) HandleEmergencyAccessTakeover(w http.ResponseWriter, r *http.Request, id int64) {
	u := auth.UserFromContext(r.Context())

	var req emergencyTakeoverRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := vcrypto.ValidateOpaqueBlob(req.NewWrappedVaultKey, 1024); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid new_wrapped_vault_key")
		return
	}

	rows, err := s.DB.Query(emergencyAccessListSelect+` WHERE ea.id=$1 AND ea.grantee_user_id=$2`, id, u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "takeover failed")
		return
	}
	list, err := scanEmergencyAccessRows(rows)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "takeover failed")
		return
	}
	if len(list) == 0 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	ea := list[0]
	if ea.Status != "granted" {
		writeErr(w, http.StatusForbidden, "access has not been granted (status: "+ea.Status+")")
		return
	}
	if ea.AccessType != "takeover" {
		writeErr(w, http.StatusBadRequest, "this grant is \"view\" type — it doesn't allow a takeover")
		return
	}

	if err := auth.ChangePassword(s.DB, ea.GrantorUserID, req.KDF, req.NewAuthKey, req.NewWrappedVaultKey); err != nil {
		log.Printf("emergency access takeover failed for user %d (change password): %v", ea.GrantorUserID, err)
		writeErr(w, http.StatusInternalServerError, "takeover failed")
		return
	}
	if err := auth.RevokeAllDevices(s.DB, ea.GrantorUserID); err != nil {
		log.Printf("emergency access takeover failed for user %d (revoke devices): %v", ea.GrantorUserID, err)
		writeErr(w, http.StatusInternalServerError, "takeover failed")
		return
	}

	audit(s.DB, &u.ID, "emergency_access.takeover", ea.GrantorEmail, clientIP(r))
	notify(s.DB, ea.GrantorEmail, "Your Passvault account was taken over via emergency access",
		ea.GranteeEmail+" performed an emergency access takeover of your account: your master password has been "+
			"reset and every device has been signed out. If this wasn't expected, contact your Passvault instance administrator immediately.")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func isUniqueViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	if errors.As(err, &s) {
		return s.SQLState() == "23505"
	}
	return false
}

// SweepEmergencyAccessGrants auto-grants any request whose wait period
// has elapsed without the grantor rejecting it — called from the same
// periodic ticker as SweepExpiredSends (cmd/passvault-server/main.go).
func (s *Server) SweepEmergencyAccessGrants() {
	rows, err := s.DB.Query(emergencyAccessListSelect + `
		WHERE ea.status='requested' AND ea.access_at <= now()`)
	if err != nil {
		return
	}
	due, err := scanEmergencyAccessRows(rows)
	if err != nil {
		return
	}
	for _, ea := range due {
		if _, err := s.DB.Exec(`UPDATE emergency_access SET status='granted', updated_at=now() WHERE id=$1 AND status='requested'`, ea.ID); err != nil {
			continue
		}
		audit(s.DB, &ea.GrantorUserID, "emergency_access.auto_granted", ea.GranteeEmail, "")
		notify(s.DB, ea.GrantorEmail, "Emergency access was automatically granted",
			ea.GranteeEmail+" now has emergency access to your Passvault account — the waiting period elapsed without a response.")
		notify(s.DB, ea.GranteeEmail, "Your Passvault emergency access is now active",
			"The waiting period for your emergency access request to "+ea.GrantorEmail+"'s account has elapsed. You can now access it from the Emergency Access section.")
	}
}
