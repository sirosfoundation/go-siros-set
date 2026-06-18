package merkle

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-siros-set/store"
)

// Checkpointer periodically reads new entries from the store, extends
// the Merkle tree, and signs a new tree head.
type Checkpointer struct {
	store  store.Store
	tree   *Tree
	signer jose.Signer
	pubKey crypto.PublicKey

	// lastCheckpoint is the tree size at the last signed tree head.
	lastCheckpoint uint64

	// latestSTH is the most recent signed tree head.
	latestSTH *SignedTreeHead
}

// NewCheckpointer creates a checkpointer backed by the given store and signer.
func NewCheckpointer(s store.Store, signer jose.Signer, pubKey crypto.PublicKey) *Checkpointer {
	return &Checkpointer{
		store:  s,
		tree:   NewTree(),
		signer: signer,
		pubKey: pubKey,
	}
}

// Checkpoint reads all new entries since the last checkpoint, extends
// the Merkle tree, and signs a new tree head. Returns the new STH.
func (c *Checkpointer) Checkpoint(ctx context.Context) (*SignedTreeHead, error) {
	size, err := c.store.Size(ctx)
	if err != nil {
		return nil, fmt.Errorf("checkpointer: get size: %w", err)
	}

	if size == c.lastCheckpoint {
		return c.latestSTH, nil // No new entries
	}

	// Read new entries
	entries, err := c.store.Range(ctx, c.lastCheckpoint, size)
	if err != nil {
		return nil, fmt.Errorf("checkpointer: range [%d, %d): %w", c.lastCheckpoint, size, err)
	}

	// Add leaves to the Merkle tree
	for _, e := range entries {
		leaf := LeafHash([]byte(e.JWS))
		c.tree.AddLeaf(leaf)
	}

	// Compute and sign tree head
	th := &TreeHead{
		TreeSize:  c.tree.Size(),
		RootHash:  c.tree.RootHash(),
		Timestamp: time.Now().UTC(),
	}

	sth, err := th.Sign(c.signer)
	if err != nil {
		return nil, fmt.Errorf("checkpointer: sign tree head: %w", err)
	}

	c.lastCheckpoint = size
	c.latestSTH = sth
	return sth, nil
}

// LatestSTH returns the most recent signed tree head, or nil if no
// checkpoint has been performed yet.
func (c *Checkpointer) LatestSTH() *SignedTreeHead {
	return c.latestSTH
}

// InclusionProof returns an inclusion proof for the entry at the given index.
func (c *Checkpointer) InclusionProof(index uint64) ([][32]byte, error) {
	return c.tree.InclusionProof(index)
}

// ConsistencyProof returns a consistency proof between oldSize and the
// current tree size.
func (c *Checkpointer) ConsistencyProof(oldSize uint64) ([][32]byte, error) {
	return c.tree.ConsistencyProof(oldSize)
}
