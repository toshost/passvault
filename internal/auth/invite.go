package auth

import (
	"database/sql"

	vcrypto "github.com/toshost/passvault/internal/crypto"
)

// CreateInvite generates a one-time signup token. email is optional: when
// set, the invite can only be redeemed by that exact address (see
// ConsumeInvite); when empty, any email may redeem it. Only reachable via
// the admin-token-gated /v1/admin/invites endpoint — same posture as
// Vaultwarden's ADMIN_TOKEN-gated invite flow, which this instance's
// PASSVAULT_ADMIN_TOKEN mirrors.
func CreateInvite(db *sql.DB, email string) (token string, err error) {
	token, err = vcrypto.NewOpaqueToken()
	if err != nil {
		return "", err
	}
	var emailArg any
	if email != "" {
		emailArg = email
	}
	if _, err := db.Exec(`INSERT INTO invites (token, email) VALUES ($1, $2)`, token, emailArg); err != nil {
		return "", err
	}
	return token, nil
}
