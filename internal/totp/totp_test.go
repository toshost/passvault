package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// TestRFC6238Vector checks against RFC 6238 Appendix B's published test
// table (HMAC-SHA1, key = ASCII "12345678901234567890", T=59s ->
// TOTP=94287082 at 8 digits). This package always truncates to 6 digits,
// which is simply the same binCode taken mod 10^6 instead of mod 10^8 —
// 94287082 mod 1_000_000 = 287082, so that's the expected 6-digit value.
// GenerateSecret always returns base32; the RFC vector's key is raw
// ASCII, so it's base32-encoded here before being fed through code(),
// which base32-decodes it back to the original key bytes.
func TestRFC6238Vector(t *testing.T) {
	secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	got, err := code(secretB32, 1) // T=59s, period=30s -> counter = floor(59/30) = 1
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	if got != "287082" {
		t.Fatalf("code = %q, want %q (RFC 6238 vector 94287082 mod 1e6)", got, "287082")
	}
}

func TestVerifyAcceptsCurrentCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	counter := uint64(now.Unix() / 30)
	c, err := code(secret, counter)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(secret, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Verify rejected the correct current code")
	}
}

func TestVerifyToleratesOneStepClockSkew(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	counter := uint64(now.Unix()/30) + 1 // the NEXT step's code, as if the phone's clock is slightly ahead
	c, err := code(secret, counter)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(secret, c, now)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("Verify rejected a code one step of clock skew away")
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify(secret, "000000", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		// astronomically unlikely to collide, but guard against a flaky test
		// silently passing if it ever does
		t.Fatal("Verify accepted an arbitrary wrong code")
	}
}

func TestVerifyRejectsMalformedLength(t *testing.T) {
	secret, _ := GenerateSecret()
	ok, err := Verify(secret, "12345", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("Verify accepted a code of the wrong length")
	}
}

func TestGenerateSecretUnique(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two generated secrets must not collide")
	}
}
