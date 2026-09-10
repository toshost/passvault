package auth

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	vcrypto "github.com/toshost/passvault/internal/crypto"
)

const pendingRecoveryTTL = 15 * time.Minute

var ErrInvalidRecoveryCode = errors.New("invalid recovery code")

// SetRecoveryKit stores a freshly generated kit, overwriting any
// previous one — an old printed code stops working the moment a new kit
// is created, so there's never ambiguity about which one is current.
func SetRecoveryKit(db *sql.DB, userID int64, recoveryAuthKeyB64, wrappedVaultKeyForRecovery string) error {
	if err := vcrypto.ValidateOpaqueBlob(wrappedVaultKeyForRecovery, maxOpaqueBlobBytes); err != nil {
		return err
	}
	hash := vcrypto.HashToken(recoveryAuthKeyB64) // cheap hash: recoveryAuthKey already has 256 bits of entropy
	_, err := db.Exec(`UPDATE users SET recovery_code_hash=$1, wrapped_vault_key_for_recovery=$2 WHERE id=$3`,
		hash, wrappedVaultKeyForRecovery, userID)
	return err
}

// ClearRecoveryKit removes it entirely — after this, forgetting the
// master password is unrecoverable again unless a new kit is made or an
// emergency-access trusted contact exists.
func ClearRecoveryKit(db *sql.DB, userID int64) error {
	_, err := db.Exec(`UPDATE users SET recovery_code_hash=NULL, wrapped_vault_key_for_recovery=NULL WHERE id=$1`, userID)
	return err
}

// VerifyRecoveryAuthKey is the gate that keeps "forgot password" from
// being a free-for-all "reset anyone's password" endpoint: only someone
// who can reproduce recoveryAuthKey (i.e. who has the real recovery
// code) gets back the wrapped vault key material at all.
func VerifyRecoveryAuthKey(db *sql.DB, email, recoveryAuthKeyB64 string) (userID int64, wrappedVaultKeyForRecovery string, err error) {
	var storedHash, wrapped *string
	err = db.QueryRow(`SELECT id, recovery_code_hash, wrapped_vault_key_for_recovery FROM users WHERE email=$1`, email).
		Scan(&userID, &storedHash, &wrapped)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrInvalidRecoveryCode
		}
		return 0, "", err
	}
	if storedHash == nil || wrapped == nil {
		return 0, "", ErrInvalidRecoveryCode
	}
	got := vcrypto.HashToken(recoveryAuthKeyB64)
	if subtle.ConstantTimeCompare([]byte(got), []byte(*storedHash)) != 1 {
		return 0, "", ErrInvalidRecoveryCode
	}
	return userID, *wrapped, nil
}

// IssuePendingRecovery bridges a verified recovery code to the "set a
// new master password" step — same shape as IssuePendingLogin, single-
// use, short-lived (15 minutes, longer than a login challenge since the
// user may need a moment to find/type a new password after an "I'm
// locked out" scare).
func IssuePendingRecovery(db *sql.DB, userID int64) (token string, err error) {
	token, err = vcrypto.NewOpaqueToken()
	if err != nil {
		return "", err
	}
	_, err = db.Exec(`INSERT INTO pending_recoveries (token_hash, user_id, expires_at) VALUES ($1,$2,$3)`,
		vcrypto.HashToken(token), userID, time.Now().Add(pendingRecoveryTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConsumePendingRecovery validates and deletes a pending-recovery token
// in one step — unlike a login challenge, there's no "wrong code, try
// again" state to preserve here (VerifyRecoveryAuthKey already happened
// before this token was issued), so single-use-on-read is correct.
func ConsumePendingRecovery(db *sql.DB, token string) (userID int64, err error) {
	err = db.QueryRow(`
		DELETE FROM pending_recoveries WHERE token_hash=$1 AND expires_at > now()
		RETURNING user_id`, vcrypto.HashToken(token)).Scan(&userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrInvalidPendingLogin
		}
		return 0, err
	}
	return userID, nil
}
