// Package merkle implements a Merkle tree over the SET audit log with
// Signed Tree Heads (STH) following the RFC 9162 model.
//
// Design:
//   - Nodes write signed SET records independently (zero coordination)
//   - A background checkpointer periodically reads new entries, extends the
//     Merkle tree, and signs a new tree head via HSM
//   - Consistency proofs prove the append-only property between two tree heads
//   - Inclusion proofs prove a specific record is in the tree
package merkle

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Hash computes SHA-256 of data.
func Hash(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// LeafHash computes the RFC 6962 leaf hash: SHA-256(0x00 || data).
func LeafHash(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NodeHash computes the RFC 6962 interior node hash: SHA-256(0x01 || left || right).
func NodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// TreeHead is a Signed Tree Head — a commitment to the current state of the log.
type TreeHead struct {
	TreeSize  uint64    `json:"tree_size"`
	RootHash  [32]byte  `json:"root_hash"`
	Timestamp time.Time `json:"timestamp"`
}

// SignedTreeHead is a TreeHead with a JWS signature.
type SignedTreeHead struct {
	TreeHead
	Signature string `json:"signature"` // compact JWS
}

// Sign produces a SignedTreeHead by JWS-signing the tree head.
func (th *TreeHead) Sign(signer jose.Signer) (*SignedTreeHead, error) {
	payload, err := json.Marshal(th)
	if err != nil {
		return nil, fmt.Errorf("merkle: marshal tree head: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("merkle: sign tree head: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("merkle: compact serialize: %w", err)
	}

	return &SignedTreeHead{
		TreeHead:  *th,
		Signature: compact,
	}, nil
}

// Verify checks the JWS signature on a SignedTreeHead.
func (sth *SignedTreeHead) Verify(key crypto.PublicKey) error {
	jws, err := jose.ParseSigned(sth.Signature, []jose.SignatureAlgorithm{
		jose.ES256,
		jose.ES384,
		jose.PS256,
		jose.EdDSA,
	})
	if err != nil {
		return fmt.Errorf("merkle: parse STH signature: %w", err)
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return fmt.Errorf("merkle: verify STH signature: %w", err)
	}

	var th TreeHead
	if err := json.Unmarshal(payload, &th); err != nil {
		return fmt.Errorf("merkle: unmarshal STH payload: %w", err)
	}

	if th.TreeSize != sth.TreeSize || th.RootHash != sth.RootHash {
		return fmt.Errorf("merkle: STH payload does not match header")
	}

	return nil
}
