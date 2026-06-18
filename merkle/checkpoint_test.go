package merkle

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-siros-set/store"
)

func TestCheckpointer(t *testing.T) {
	ctx := context.Background()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("sth+jwt"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	s := store.NewMemory()
	cp := NewCheckpointer(s, signer, &key.PublicKey)

	// No entries yet
	sth, err := cp.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint empty: %v", err)
	}
	if sth != nil {
		t.Error("expected nil STH for empty store")
	}

	// Add some entries
	for i := 0; i < 3; i++ {
		_, _ = s.Append(ctx, "record-"+string(rune('0'+i)))
	}

	sth, err = cp.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	if sth == nil {
		t.Fatal("expected non-nil STH")
	}
	if sth.TreeSize != 3 {
		t.Errorf("expected tree size 3, got %d", sth.TreeSize)
	}
	if sth.RootHash == [32]byte{} {
		t.Error("expected non-zero root hash")
	}

	// Verify the STH signature
	if err := sth.Verify(&key.PublicKey); err != nil {
		t.Fatalf("verify STH: %v", err)
	}

	// Checkpoint again with no new entries should return same STH
	sth2, err := cp.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint again: %v", err)
	}
	if sth2.TreeSize != sth.TreeSize {
		t.Errorf("expected same tree size, got %d", sth2.TreeSize)
	}

	// Add more entries and checkpoint again
	_, _ = s.Append(ctx, "record-3")
	sth3, err := cp.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("checkpoint 3: %v", err)
	}
	if sth3.TreeSize != 4 {
		t.Errorf("expected tree size 4, got %d", sth3.TreeSize)
	}
	if sth3.RootHash == sth.RootHash {
		t.Error("root hash should change with new entries")
	}

	// Inclusion proof
	proof, err := cp.InclusionProof(0)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	if len(proof) == 0 {
		t.Error("expected non-empty inclusion proof")
	}
}
