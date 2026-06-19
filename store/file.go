package store

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"time"
)

// File is an append-only store backed by a local file.
// Each line is one compact JWS record. The file can be read by
// set-checkpoint or shipped to a central aggregator.
//
// Thread-safe for concurrent Append calls within a single process.
// Not suitable for multi-process writers to the same file.
type File struct {
	mu      sync.RWMutex
	path    string
	entries []Entry
}

// NewFile creates a file-backed store. If the file exists, existing
// records are loaded. If not, the file is created.
func NewFile(path string) (*File, error) {
	f := &File{path: path}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

// load reads existing records from the file.
func (f *File) load() error {
	file, err := os.OpenFile(f.path, os.O_RDONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("store: open %s: %w", f.path, err)
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	var idx uint64
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		f.entries = append(f.entries, Entry{
			Index:     idx,
			JWS:       line,
			Timestamp: time.Time{}, // unknown for loaded entries
		})
		idx++
	}
	return scanner.Err()
}

// Append adds a JWS record to the file and the in-memory index.
func (f *File) Append(_ context.Context, jws string) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	file, err := os.OpenFile(f.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return 0, fmt.Errorf("store: append %s: %w", f.path, err)
	}
	defer func() { _ = file.Close() }()

	if _, err := fmt.Fprintln(file, jws); err != nil {
		return 0, fmt.Errorf("store: write: %w", err)
	}

	idx := uint64(len(f.entries))
	f.entries = append(f.entries, Entry{
		Index:     idx,
		JWS:       jws,
		Timestamp: time.Now().UTC(),
	})
	return idx, nil
}

// Get returns the entry at the given index.
func (f *File) Get(_ context.Context, index uint64) (*Entry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if index >= uint64(len(f.entries)) {
		return nil, fmt.Errorf("store: index %d out of range (size %d)", index, len(f.entries))
	}
	e := f.entries[index]
	return &e, nil
}

// Range returns entries in [start, end).
func (f *File) Range(_ context.Context, start, end uint64) ([]Entry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	size := uint64(len(f.entries))
	if start > size {
		start = size
	}
	if end > size {
		end = size
	}
	if start >= end {
		return nil, nil
	}
	result := make([]Entry, end-start)
	copy(result, f.entries[start:end])
	return result, nil
}

// Size returns the number of stored entries.
func (f *File) Size(_ context.Context) (uint64, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return uint64(len(f.entries)), nil
}

// Path returns the file path.
func (f *File) Path() string {
	return f.path
}
