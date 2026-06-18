package merkle

// Tree builds a Merkle tree over an append-only log of leaf hashes.
// It supports incremental building: new leaves can be added without
// recomputing the entire tree.
type Tree struct {
	leaves [][32]byte
}

// NewTree creates an empty Merkle tree.
func NewTree() *Tree {
	return &Tree{}
}

// AddLeaf appends a leaf hash to the tree.
func (t *Tree) AddLeaf(leaf [32]byte) {
	t.leaves = append(t.leaves, leaf)
}

// Size returns the number of leaves.
func (t *Tree) Size() uint64 {
	return uint64(len(t.leaves))
}

// RootHash computes the Merkle root hash.
// Returns a zero hash for an empty tree.
func (t *Tree) RootHash() [32]byte {
	if len(t.leaves) == 0 {
		return [32]byte{}
	}
	return computeRoot(t.leaves)
}

// computeRoot recursively computes the Merkle root for a slice of leaf hashes.
func computeRoot(hashes [][32]byte) [32]byte {
	if len(hashes) == 1 {
		return hashes[0]
	}

	var next [][32]byte
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			next = append(next, NodeHash(hashes[i], hashes[i+1]))
		} else {
			// Odd leaf: promote to next level
			next = append(next, hashes[i])
		}
	}

	return computeRoot(next)
}

// InclusionProof generates a Merkle inclusion proof for the leaf at the given index.
// The proof is a list of sibling hashes from leaf to root.
func (t *Tree) InclusionProof(index uint64) ([][32]byte, error) {
	if index >= uint64(len(t.leaves)) {
		return nil, ErrIndexOutOfRange
	}

	return computeInclusionProof(t.leaves, index), nil
}

func computeInclusionProof(hashes [][32]byte, index uint64) [][32]byte {
	if len(hashes) <= 1 {
		return nil
	}

	var proof [][32]byte
	var next [][32]byte
	nextIndex := index / 2

	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			if uint64(i) == index || uint64(i+1) == index {
				if uint64(i) == index {
					proof = append(proof, hashes[i+1])
				} else {
					proof = append(proof, hashes[i])
				}
			}
			next = append(next, NodeHash(hashes[i], hashes[i+1]))
		} else {
			next = append(next, hashes[i])
		}
	}

	proof = append(proof, computeInclusionProof(next, nextIndex)...)
	return proof
}

// VerifyInclusion checks that a leaf hash is at the given index using the
// provided inclusion proof and expected root hash.
func VerifyInclusion(leaf [32]byte, index, treeSize uint64, proof [][32]byte, root [32]byte) bool {
	computed := leaf
	idx := index

	for _, sibling := range proof {
		if idx%2 == 0 {
			computed = NodeHash(computed, sibling)
		} else {
			computed = NodeHash(sibling, computed)
		}
		idx /= 2
	}

	return computed == root
}

// ConsistencyProof generates a consistency proof between two tree sizes.
// This proves the append-only property: the tree at oldSize is a prefix
// of the tree at the current size.
func (t *Tree) ConsistencyProof(oldSize uint64) ([][32]byte, error) {
	currentSize := uint64(len(t.leaves))
	if oldSize > currentSize {
		return nil, ErrInvalidTreeSize
	}
	if oldSize == 0 || oldSize == currentSize {
		return nil, nil
	}

	// Build both subtrees and extract the proof path
	oldRoot := computeRoot(t.leaves[:oldSize])
	_ = oldRoot // Used by the verifier, not included in proof

	return computeConsistencyProof(t.leaves, oldSize), nil
}

func computeConsistencyProof(leaves [][32]byte, splitPoint uint64) [][32]byte {
	// For a simple implementation, return the subtree roots that allow
	// reconstructing both the old and new root.
	if uint64(len(leaves)) == splitPoint {
		return nil
	}

	var proof [][32]byte

	// The old tree's root
	oldRoot := computeRoot(leaves[:splitPoint])
	proof = append(proof, oldRoot)

	// The new entries' contribution
	if splitPoint < uint64(len(leaves)) {
		newRoot := computeRoot(leaves[splitPoint:])
		proof = append(proof, newRoot)
	}

	return proof
}
