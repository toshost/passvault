// Package totp implements RFC 6238 TOTP generation/verification for
// Passvault's own ACCOUNT 2FA (logging into Passvault itself) — a
// deliberately separate, much narrower concern from the TOTP a user
// stores as an opaque vault item for OTHER sites (web/totp.js generates
// those client-side; the server never sees that secret). An account's
// own 2FA secret must live outside the zero-knowledge boundary: the
// server has to actively verify a code on every login, which is
// impossible if the secret is only recoverable after a successful login.
// Fixed to SHA-1/6 digits/30s — the parameters virtually every
// authenticator app (Google Authenticator, Authy, etc.) assumes by
// default — rather than exposing algorithm/digit/period choices the way
// a stored vault-item TOTP does.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"fmt"
	"strings"
	"time"
)

const (
	digits = 6
	period = 30 * time.Second
	// skew tolerates clock drift between the server and the user's phone —
	// one step each side of "now", matching common TOTP implementations.
	skew = 1
)

// GenerateSecret returns a fresh random 20-byte (160-bit) secret,
// base32-encoded without padding — the shape every authenticator app
// expects for manual entry or an otpauth:// URI.
func GenerateSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func code(secretB32 string, counter uint64) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secretB32))
	if err != nil {
		return "", err
	}
	var counterBytes [8]byte
	for i := 7; i >= 0; i-- {
		counterBytes[i] = byte(counter & 0xff)
		counter >>= 8
	}
	mac := hmac.New(sha1.New, key)
	mac.Write(counterBytes[:])
	hash := mac.Sum(nil)

	offset := hash[len(hash)-1] & 0x0f
	binCode := (uint32(hash[offset]&0x7f) << 24) | (uint32(hash[offset+1]) << 16) | (uint32(hash[offset+2]) << 8) | uint32(hash[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, binCode%mod), nil
}

// Verify checks a user-submitted code against secretB32 at the current
// time, tolerating ±1 step of clock drift. Constant-time comparison per
// candidate step — this is server-side verification of a value an
// attacker could otherwise brute-force-probe (6 digits is only 1e6
// possibilities; the real defense is that a wrong code doesn't reveal
// which digit was wrong, and normal rate-limiting on the login endpoint).
//
// This package has no persistence of its own, so Verify alone has no
// replay protection: the same correct code stays valid for its whole
// ±1-step window (~90s) and can be successfully checked more than once
// inside it. Callers that need to guard against that — anywhere a code
// grants something (login, disabling 2FA, recovery) rather than just
// confirming setup — should use VerifyStep and atomically claim the
// returned step number themselves (see internal/auth.ConsumeTOTPStep).
func Verify(secretB32, userCode string, now time.Time) (bool, error) {
	ok, _, err := VerifyStep(secretB32, userCode, now)
	return ok, err
}

// VerifyStep is Verify, but also returns the matched time-step counter
// on success, so a caller can atomically record which step was actually
// used (see Verify's comment).
func VerifyStep(secretB32, userCode string, now time.Time) (ok bool, step int64, err error) {
	if len(userCode) != digits {
		return false, 0, nil
	}
	counter := now.Unix() / int64(period.Seconds())
	for delta := -skew; delta <= skew; delta++ {
		c := counter + int64(delta)
		want, err := code(secretB32, uint64(c))
		if err != nil {
			return false, 0, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(userCode)) == 1 {
			return true, c, nil
		}
	}
	return false, 0, nil
}

// OTPAuthURL builds the standard otpauth:// URI most authenticator apps
// can open directly (as a tappable link when setup happens on the same
// device, since Passvault doesn't vendor a QR-code generator) or decode
// from a QR code if the operator's own UI renders one from this string.
func OTPAuthURL(secretB32, accountEmail, issuer string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, accountEmail, secretB32, issuer, digits, int(period.Seconds()))
}
