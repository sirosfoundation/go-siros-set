package set

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestNewRecord(t *testing.T) {
	rec := NewRecord("https://r2ps.siros.org", EventKeyGenerate, map[string]any{
		"key_id": "k-1234",
		"alg":    "ES256",
	})

	if rec.Issuer != "https://r2ps.siros.org" {
		t.Errorf("unexpected issuer: %s", rec.Issuer)
	}
	if rec.JTI == "" {
		t.Error("JTI should not be empty")
	}
	if rec.IssuedAt == 0 {
		t.Error("IssuedAt should not be zero")
	}
	if len(rec.Events) != 1 {
		t.Errorf("expected 1 event, got %d", len(rec.Events))
	}
	if _, ok := rec.Events[EventKeyGenerate]; !ok {
		t.Error("expected EventKeyGenerate in events")
	}
}

func TestRecordWithSubjectAndTransaction(t *testing.T) {
	rec := NewRecord("iss", EventKeySign, nil).
		WithSubject("user:alice").
		WithTransaction("tx-5678")

	if rec.Subject != "user:alice" {
		t.Errorf("unexpected subject: %s", rec.Subject)
	}
	if rec.TransactionID != "tx-5678" {
		t.Errorf("unexpected transaction ID: %s", rec.TransactionID)
	}
}

func TestSignAndParse(t *testing.T) {
	// Generate ephemeral ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := NewSigner(key, "ES256", "test-key-1")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	rec := NewRecord("https://test.siros.org", EventKeyGenerate, map[string]any{
		"key_id": "k-1",
	}).WithSubject("user:bob")

	compact, err := rec.Sign(signer)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if compact == "" {
		t.Fatal("compact serialization should not be empty")
	}

	// Verify and parse
	parsed, err := Parse(compact, &key.PublicKey)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed.Issuer != rec.Issuer {
		t.Errorf("issuer mismatch: got %s, want %s", parsed.Issuer, rec.Issuer)
	}
	if parsed.JTI != rec.JTI {
		t.Errorf("JTI mismatch: got %s, want %s", parsed.JTI, rec.JTI)
	}
	if parsed.Subject != "user:bob" {
		t.Errorf("subject mismatch: got %s", parsed.Subject)
	}
	if _, ok := parsed.Events[EventKeyGenerate]; !ok {
		t.Error("expected EventKeyGenerate in parsed events")
	}
}

func TestParseInvalidSignature(t *testing.T) {
	// Generate two different keys
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, _ := NewSigner(key1, "ES256", "k1")
	rec := NewRecord("iss", EventKeySign, nil)
	compact, _ := rec.Sign(signer)

	// Verify with wrong key should fail
	_, err := Parse(compact, &key2.PublicKey)
	if err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}
