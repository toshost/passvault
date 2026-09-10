package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	vcrypto "github.com/toshost/passvault/internal/crypto"
)

const pendingLoginTTL = 5 * time.Minute

var (
	ErrInvalidPendingLogin = errors.New("invalid or expired login")
	ErrInvalidCode         = errors.New("invalid code")
)

// IssuePendingLogin is what HandleLogin hands back instead of real device
// tokens when the account has 2FA enabled — proof the authKey check
// already passed, without yet granting vault access. Short-lived (5
// minutes) and good for up to 10 code attempts within that window (see
// LookupPendingLogin/RecordFailedPendingLoginAttempt) — a mistyped digit
// shouldn't force retyping the master password too, but the attempt
// count still bounds brute-forcing the 6-digit space.
func IssuePendingLogin(db *sql.DB, userID int64, deviceLabel string) (token string, err error) {
	token, err = vcrypto.NewOpaqueToken()
	if err != nil {
		return "", err
	}
	_, err = db.Exec(`INSERT INTO pending_logins (token_hash, user_id, device_label, expires_at) VALUES ($1,$2,$3,$4)`,
		vcrypto.HashToken(token), userID, deviceLabel, time.Now().Add(pendingLoginTTL))
	if err != nil {
		return "", err
	}
	return token, nil
}

// LookupPendingLogin validates a pending-login token WITHOUT consuming
// it — HandleLoginTOTP calls this first to find out which account to
// verify a code against, then either DeletePendingLogin (on a correct
// code) or RecordFailedPendingLoginAttempt (on a wrong one).
func LookupPendingLogin(db *sql.DB, token string) (userID int64, deviceLabel string, err error) {
	err = db.QueryRow(`
		SELECT user_id, device_label FROM pending_logins
		WHERE token_hash=$1 AND expires_at > now() AND attempts_left > 0`, vcrypto.HashToken(token)).
		Scan(&userID, &deviceLabel)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", ErrInvalidPendingLogin
		}
		return 0, "", err
	}
	return userID, deviceLabel, nil
}

// DeletePendingLogin consumes a pending-login token after a successful
// code check — a replay after this fails, same single-use posture as a
// refresh token once it's actually done its job.
func DeletePendingLogin(db *sql.DB, token string) error {
	_, err := db.Exec(`DELETE FROM pending_logins WHERE token_hash=$1`, vcrypto.HashToken(token))
	return err
}

// RecordFailedPendingLoginAttempt burns one of the token's remaining
// attempts after a wrong code — once attempts_left hits 0,
// LookupPendingLogin stops accepting it even though it hasn't expired
// yet, same effect without needing a separate cleanup pass.
func RecordFailedPendingLoginAttempt(db *sql.DB, token string) error {
	_, err := db.Exec(`UPDATE pending_logins SET attempts_left = attempts_left - 1 WHERE token_hash=$1`, vcrypto.HashToken(token))
	return err
}

// EnableTOTP2FA persists a verified secret and flips the account into
// requiring it at every future login. The caller (HandleEnable2FA) must
// already have confirmed the user can produce a valid code for this exact
// secret before calling this — proving they actually captured it, not
// just that the server generated one.
func EnableTOTP2FA(db *sql.DB, userID int64, secret string) error {
	_, err := db.Exec(`UPDATE users SET totp_2fa_secret=$1, totp_2fa_enabled=true WHERE id=$2`, secret, userID)
	return err
}

// DisableTOTP2FA clears the secret entirely, not just the enabled flag —
// re-enabling later always starts from a fresh secret, never resurrects
// an old one that might have leaked.
func DisableTOTP2FA(db *sql.DB, userID int64) error {
	_, err := db.Exec(`UPDATE users SET totp_2fa_secret=NULL, totp_2fa_enabled=false WHERE id=$1`, userID)
	if err != nil {
		return err
	}
	_, err = db.Exec(`DELETE FROM recovery_codes WHERE user_id=$1`, userID)
	return err
}

// GenerateRecoveryCodes deletes any existing codes (used or not — a
// regenerate fully replaces the batch, per the rule that a stale code
// from a previous batch must never keep working) and issues 10 fresh
// ones. The plaintext codes are returned exactly once; only their hashes
// are stored.
func GenerateRecoveryCodes(db *sql.DB, userID int64) ([]string, error) {
	if _, err := db.Exec(`DELETE FROM recovery_codes WHERE user_id=$1`, userID); err != nil {
		return nil, err
	}
	codes := make([]string, 10)
	for i := range codes {
		raw, err := vcrypto.NewOpaqueToken()
		if err != nil {
			return nil, err
		}
		// A 64-char hex token is needlessly long to type by hand during an
		// actual emergency — fold it down to a short, still-high-entropy,
		// human-typeable code (20 hex chars = 80 bits, split for readability).
		short := raw[:20]
		code := fmt.Sprintf("%s-%s-%s-%s", short[0:5], short[5:10], short[10:15], short[15:20])
		codes[i] = code
		if _, err := db.Exec(`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1,$2)`,
			userID, vcrypto.HashToken(code)); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

// VerifyRecoveryCode checks a submitted code against this account's
// unused codes and, on a match, marks that ONE code used (single-use —
// it must never work twice).
func VerifyRecoveryCode(db *sql.DB, userID int64, code string) (bool, error) {
	res, err := db.Exec(`
		UPDATE recovery_codes SET used_at=now()
		WHERE user_id=$1 AND code_hash=$2 AND used_at IS NULL`,
		userID, vcrypto.HashToken(code))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// CountUnusedRecoveryCodes lets the settings UI warn the user when they're
// running low, without ever exposing the codes themselves again.
func CountUnusedRecoveryCodes(db *sql.DB, userID int64) (int, error) {
	var n int
	err := db.QueryRow(`SELECT count(*) FROM recovery_codes WHERE user_id=$1 AND used_at IS NULL`, userID).Scan(&n)
	return n, err
}

// ConsumeTOTPStep atomically claims a time-step counter for userID,
// returning false if that step (or any later one) was already claimed —
// the replay guard for a TOTP code re-submitted within its own ~90s
// validity window (totp.Verify alone has no memory of what it's already
// accepted; see totp.VerifyStep's comment). Only the step NUMBER is ever
// persisted, never the code itself. Monotonic (< not =) so an
// out-of-order retry of an OLDER step within the same skew window is
// rejected too, not just an exact repeat.
func ConsumeTOTPStep(db *sql.DB, userID, step int64) (bool, error) {
	res, err := db.Exec(`
		UPDATE users SET totp_last_used_step = $1
		WHERE id = $2 AND (totp_last_used_step IS NULL OR totp_last_used_step < $1)`,
		step, userID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
