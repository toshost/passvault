// Package ratelimit throttles guessable-secret endpoints (login,
// password-protected Send access, account recovery) that would otherwise
// have no defense against a script trying values quickly. Nothing else
// in this codebase rate-limits anything — Argon2id's own cost helps
// against a stolen-hash offline attack, but does nothing against an
// online attacker just hammering the live endpoint with the credential
// they're guessing.
//
// Buckets are deliberately separate per endpoint+identifier-kind (see the
// Bucket* constants) so, say, hammering one Send's password can't also
// throttle a legitimate login from the same IP, and a login flood
// against one email can't throttle every OTHER account behind the same
// NAT'd IP into total lockout (the per-IP ceiling is looser than the
// per-identity one for exactly that reason).
package ratelimit

import (
	"database/sql"
	"time"
)

const (
	BucketLoginEmail      = "login-email"
	BucketLoginIP         = "login-ip"
	BucketLogin2FAIP      = "login-2fa-ip"
	BucketPreloginEmail   = "prelogin-email"
	BucketPreloginIP      = "prelogin-ip"
	BucketRegisterIP      = "register-ip"
	BucketUserLookupUser  = "user-lookup-user"
	BucketAdminTokenIP    = "admin-token-ip"
	BucketTwoFAVerifyUser = "twofa-verify-user"
	BucketRecoveryEmail   = "recovery-email"
	BucketRecoveryIP      = "recovery-ip"
	BucketSendAccessIP    = "sendaccess-ip"
	BucketSendAccessSend  = "sendaccess-send"
	defaultWindow         = 15 * time.Minute
	sweepOlderThan        = 1 * time.Hour
)

// Allowed reports whether another attempt in this bucket+identifier is
// permitted right now — max attempts within the last 15 minutes. It does
// NOT record the attempt itself; callers record separately (via Record)
// so a caller can choose to only count attempts that actually reach the
// secret-comparison step, not e.g. a malformed request.
func Allowed(db *sql.DB, bucket, identifier string, max int) bool {
	var n int
	err := db.QueryRow(`
		SELECT count(*) FROM rate_limit_attempts
		WHERE bucket=$1 AND identifier=$2 AND attempted_at > now() - $3::interval`,
		bucket, identifier, defaultWindow.String()).Scan(&n)
	if err != nil {
		return true // fail open — a rate-limit outage must never itself become a login outage
	}
	return n < max
}

// Record logs one attempt against a bucket+identifier. Best-effort: a
// failure to record must never block the request it's describing.
func Record(db *sql.DB, bucket, identifier string) {
	db.Exec(`INSERT INTO rate_limit_attempts (bucket, identifier) VALUES ($1,$2)`, bucket, identifier)
}

// Sweep reclaims old rows so the table doesn't grow forever — called
// from the same periodic ticker as the other background sweeps
// (cmd/passvault-server/main.go). Anything older than the longest window
// any bucket actually uses is safe to drop.
func Sweep(db *sql.DB) {
	db.Exec(`DELETE FROM rate_limit_attempts WHERE attempted_at < now() - $1::interval`, sweepOlderThan.String())
}
