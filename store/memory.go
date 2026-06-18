package store

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Memory is an in-memory append-only store for testing and development.
type Memory struct {
	mu      sync.RWMutex
	entries []Entry
}

// NewMemory creates a new in-memory store.
func NewMemory() *Memory {
	return &Memory{}
}

func (m *Memory) Append(_ context.Context, jws string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx := uint64(len(m.entries))
	m.entries = append(m.entries, Entry{
		Index:     idx,
		JWS:       jws,
		Timestamp: time.Now().UTC(),
	})
	return idx, nil
}

func (m *Memory) Get(_ context.Context, index uint64) (*Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if index >= uint64(len(m.entries)) {
		return nil, fmt.Errorf("store: index %d out of range (size=%d)", index, len(m.entries))
	}
	e := m.entries[index]
	return &e, nil
}

func (m *Memory) Range(_ context.Context, start, end uint64) ([]Entry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	size := uint64(len(m.entries))
	if start >= size {
		return nil, nil
	}
	if end > size {
		end = size
	}
	if start >= end {
		return nil, nil
	}

	result := make([]Entry, end-start)
	copy(result, m.entries[start:end])
	return result, nil
}

func (m *Memory) Size(_ context.Context) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return uint64(len(m.entries)), nil
}
