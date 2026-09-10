// Package crypto holds the server-side half of Toshost Vault's zero-knowledge
// protocol. The server never sees a master password or a usable vault key —
// it only ever handles authKey (a value already derived client-side from the
// master password) and opaque, client-encrypted blobs. See docs/PROTOCOL.md.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KDFParams are the Argon2id parameters a client must use to derive authKey
// and wrapKey from the user's master password. They mirror Bitwarden's own
// current default rather than the OWASP bare minimum, since we're operating
// in the same threat model. Stored per-user so they can be upgraded later
// without breaking existing accounts.
type KDFParams struct {
	MemoryKiB   uint32 `json:"memory_kib"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	// SaltB64 is a per-user random salt, base64-encoded. Never derived from
	// email — a random salt avoids tying KDF cost to a guessable identifier.
	SaltB64 string `json:"salt"`
}

// DefaultKDFParams generates fresh parameters (with a new random salt) for a
// new account. Memory 64 MiB / iterations 3 / parallelism 4 matches
// Bitwarden's shipped default.
func DefaultKDFParams() (KDFParams, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, err
	}
	return KDFParams{
		MemoryKiB:   64 * 1024,
		Iterations:  3,
		Parallelism: 4,
		SaltB64:     base64.StdEncoding.EncodeToString(salt),
	}, nil
}

// authKeyHashParams is the SERVER-SIDE second Argon2id round applied to the
// authKey a client submits at login/registration. authKey already carries
// ~256 bits of entropy from the client's own Argon2id+HKDF derivation, so
// this round isn't brute-force defense (that's not feasible against 256 bits
// either way) — it's so that a stolen DB row alone is not a usable bearer
// credential; only the client, which knows the master password, can
// reproduce the exact authKey this hash matches.
var authKeyHashParams = struct {
	memory, iterations uint32
	parallelism        uint8
}{memory: 19 * 1024, iterations: 2, parallelism: 1}

// HashAuthKey Argon2id-hashes a client-submitted authKey for storage. The
// returned string is self-describing (params+salt+hash), same shape as a
// standard password hash, so parameters can change across accounts over
// time without a migration.
func HashAuthKey(authKeyB64 string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(authKeyB64), salt,
		authKeyHashParams.iterations, authKeyHashParams.memory, authKeyHashParams.parallelism, 32)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		authKeyHashParams.memory, authKeyHashParams.iterations, authKeyHashParams.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyAuthKey checks a client-submitted authKey against a stored hash from
// HashAuthKey, in constant time.
func VerifyAuthKey(stored, authKeyB64 string) bool {
	var memory, iterations uint32
	var parallelism uint8
	var saltB64, hashB64 string
	n, err := fmt.Sscanf(stored, "argon2id$v=19$m=%d,t=%d,p=%d$", &memory, &iterations, &parallelism)
	if n != 3 || err != nil {
		return false
	}
	parts := strings.Split(stored, "$")
	if len(parts) != 5 {
		return false
	}
	saltB64, hashB64 = parts[3], parts[4]
	salt, err := base64.RawStdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(hashB64)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(authKeyB64), salt, iterations, memory, parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewOpaqueToken returns a random 256-bit token, hex-encoded — used for
// access/refresh tokens and device identifiers. Matches dnsmanager's session
// token convention (internal/auth/auth.go newToken).
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// HashToken SHA-256-hashes an opaque bearer token for storage, so a stolen
// DB row cannot be replayed as a session token directly (same rationale as
// HashAuthKey, cheaper because tokens are already uniformly random).
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ErrInvalidBlob is returned by DecodeClientBlob when a client-submitted
// "opaque ciphertext" field isn't validly shaped. The server never decrypts
// these — it only checks they look like base64 so malformed data doesn't
// get persisted — but must reject obvious garbage early.
var ErrInvalidBlob = errors.New("invalid encrypted blob")

// ValidateOpaqueBlob checks a client-supplied encrypted field is non-empty,
// valid base64, and under a sane size cap. It never inspects plaintext —
// there is none available to the server — this is purely input hygiene.
func ValidateOpaqueBlob(b64 string, maxBytes int) error {
	if b64 == "" {
		return ErrInvalidBlob
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ErrInvalidBlob
	}
	if len(raw) == 0 || len(raw) > maxBytes {
		return ErrInvalidBlob
	}
	return nil
}
