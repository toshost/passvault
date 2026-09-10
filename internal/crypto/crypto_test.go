package crypto

import "testing"

func TestHashAuthKeyRoundTrip(t *testing.T) {
	hash, err := HashAuthKey("dGVzdC1hdXRoLWtleQ==")
	if err != nil {
		t.Fatalf("HashAuthKey: %v", err)
	}
	if !VerifyAuthKey(hash, "dGVzdC1hdXRoLWtleQ==") {
		t.Fatal("VerifyAuthKey rejected the correct authKey")
	}
	if VerifyAuthKey(hash, "d3Jvbmcta2V5") {
		t.Fatal("VerifyAuthKey accepted a wrong authKey")
	}
}

func TestHashAuthKeySaltsDiffer(t *testing.T) {
	a, err := HashAuthKey("c2FtZS1rZXk=")
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashAuthKey("c2FtZS1rZXk=")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two hashes of the same authKey must differ (random salt)")
	}
	if !VerifyAuthKey(a, "c2FtZS1rZXk=") || !VerifyAuthKey(b, "c2FtZS1rZXk=") {
		t.Fatal("both hashes must still verify")
	}
}

func TestVerifyAuthKeyRejectsMalformedStoredHash(t *testing.T) {
	if VerifyAuthKey("not-a-real-hash", "anything") {
		t.Fatal("malformed stored hash must never verify")
	}
	if VerifyAuthKey("", "anything") {
		t.Fatal("empty stored hash must never verify")
	}
}

func TestDefaultKDFParamsUniqueSalt(t *testing.T) {
	p1, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := DefaultKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if p1.SaltB64 == p2.SaltB64 {
		t.Fatal("two fresh KDF params must not share a salt")
	}
	if p1.MemoryKiB != 64*1024 || p1.Iterations != 3 || p1.Parallelism != 4 {
		t.Fatalf("unexpected default KDF params: %+v", p1)
	}
}

func TestNewOpaqueTokenUnique(t *testing.T) {
	a, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two tokens must not collide")
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Fatalf("expected 64 hex chars, got %d", len(a))
	}
}

func TestHashTokenDeterministicButOneWay(t *testing.T) {
	tok, _ := NewOpaqueToken()
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatal("HashToken must be deterministic for the same input")
	}
	if h1 == tok {
		t.Fatal("HashToken must not return the input unchanged")
	}
}

func TestValidateOpaqueBlob(t *testing.T) {
	if err := ValidateOpaqueBlob("", 1024); err == nil {
		t.Fatal("empty blob must be rejected")
	}
	if err := ValidateOpaqueBlob("not-base64!!!", 1024); err == nil {
		t.Fatal("non-base64 blob must be rejected")
	}
	if err := ValidateOpaqueBlob("AAAA", 1); err == nil {
		t.Fatal("oversized blob must be rejected")
	}
	if err := ValidateOpaqueBlob("aGVsbG8=", 1024); err != nil {
		t.Fatalf("valid small base64 blob rejected: %v", err)
	}
}
