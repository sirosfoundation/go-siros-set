// Package store defines the storage interface for SET audit records and
// Merkle tree state. Implementations must provide append-only semantics.
package store

import (
	"context"
	"time"
)

// Entry is a stored SET record with metadata.
type Entry struct {
	// Index is the sequential position in the log (0-based).
	Index uint64

	// JWS is the compact-serialized SET record.
	JWS string

	// Timestamp is when the entry was stored.
	Timestamp time.Time
}

// Store is the interface for append-only SET record storage.
type Store interface {
	// Append adds a signed SET record to the log. Returns the assigned index.
	Append(ctx context.Context, jws string) (uint64, error)

	// Get retrieves a single entry by index.
	Get(ctx context.Context, index uint64) (*Entry, error)

	// Range returns entries in [start, end) order.
	Range(ctx context.Context, start, end uint64) ([]Entry, error)

	// Size returns the current number of entries.
	Size(ctx context.Context) (uint64, error)
}
