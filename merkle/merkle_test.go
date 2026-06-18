package merkle

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

func TestLeafHash(t *testing.T) {
	h1 := LeafHash([]byte("hello"))
	h2 := LeafHash([]byte("hello"))
	h3 := LeafHash([]byte("world"))

	if h1 != h2 {
		t.Error("same input should produce same hash")
	}
	if h1 == h3 {
		t.Error("different input should produce different hash")
	}
}

func TestNodeHash(t *testing.T) {
	left := LeafHash([]byte("a"))
	right := LeafHash([]byte("b"))

	h1 := NodeHash(left, right)
	h2 := NodeHash(right, left)

	if h1 == h2 {
		t.Error("NodeHash should not be commutative")
	}
}

func TestTreeSingleLeaf(t *testing.T) {
	tree := NewTree()
	leaf := LeafHash([]byte("only"))
	tree.AddLeaf(leaf)

	if tree.Size() != 1 {
		t.Errorf("expected size 1, got %d", tree.Size())
	}
	if tree.RootHash() != leaf {
		t.Error("single-leaf root should equal the leaf")
	}
}

func TestTreeMultipleLeaves(t *testing.T) {
	tree := NewTree()
	l0 := LeafHash([]byte("a"))
	l1 := LeafHash([]byte("b"))
	l2 := LeafHash([]byte("c"))
	l3 := LeafHash([]byte("d"))

	tree.AddLeaf(l0)
	tree.AddLeaf(l1)
	tree.AddLeaf(l2)
	tree.AddLeaf(l3)

	root := tree.RootHash()

	// Manually compute expected root
	n01 := NodeHash(l0, l1)
	n23 := NodeHash(l2, l3)
	expected := NodeHash(n01, n23)

	if root != expected {
		t.Errorf("root mismatch:\n  got:  %x\n  want: %x", root, expected)
	}
}

func TestTreeEmptyRoot(t *testing.T) {
	tree := NewTree()
	root := tree.RootHash()
	if root != [32]byte{} {
		t.Error("empty tree should have zero root")
	}
}

func TestInclusionProofAndVerify(t *testing.T) {
	tree := NewTree()
	leaves := make([][32]byte, 4)
	for i := range leaves {
		leaves[i] = LeafHash([]byte{byte(i)})
		tree.AddLeaf(leaves[i])
	}

	root := tree.RootHash()

	for i := uint64(0); i < 4; i++ {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("inclusion proof for index %d: %v", i, err)
		}

		if !VerifyInclusion(leaves[i], i, 4, proof, root) {
			t.Errorf("inclusion proof verification failed for index %d", i)
		}
	}
}

func TestInclusionProofOutOfRange(t *testing.T) {
	tree := NewTree()
	tree.AddLeaf(LeafHash([]byte("x")))

	_, err := tree.InclusionProof(5)
	if err != ErrIndexOutOfRange {
		t.Errorf("expected ErrIndexOutOfRange, got %v", err)
	}
}

func TestTreeHeadSignAndVerify(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("sth+jwt"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	tree := NewTree()
	tree.AddLeaf(LeafHash([]byte("record-0")))
	tree.AddLeaf(LeafHash([]byte("record-1")))

	th := &TreeHead{
		TreeSize: tree.Size(),
		RootHash: tree.RootHash(),
	}

	sth, err := th.Sign(signer)
	if err != nil {
		t.Fatalf("sign tree head: %v", err)
	}

	if err := sth.Verify(&key.PublicKey); err != nil {
		t.Fatalf("verify tree head: %v", err)
	}

	// Verify with wrong key should fail
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := sth.Verify(&key2.PublicKey); err == nil {
		t.Error("expected verification to fail with wrong key")
	}
}

func TestConsistencyProof(t *testing.T) {
	tree := NewTree()
	for i := 0; i < 4; i++ {
		tree.AddLeaf(LeafHash([]byte{byte(i)}))
	}

	proof, err := tree.ConsistencyProof(2)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}

	if len(proof) == 0 {
		t.Error("expected non-empty consistency proof")
	}
}
