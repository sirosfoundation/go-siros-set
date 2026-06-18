package store

import (
	"context"
	"testing"
)

func TestMemoryAppendAndGet(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	idx, err := s.Append(ctx, "jws-record-0")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx != 0 {
		t.Errorf("expected index 0, got %d", idx)
	}

	idx, err = s.Append(ctx, "jws-record-1")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if idx != 1 {
		t.Errorf("expected index 1, got %d", idx)
	}

	entry, err := s.Get(ctx, 0)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if entry.JWS != "jws-record-0" {
		t.Errorf("unexpected JWS: %s", entry.JWS)
	}
	if entry.Index != 0 {
		t.Errorf("unexpected index: %d", entry.Index)
	}
}

func TestMemoryGetOutOfRange(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	_, err := s.Get(ctx, 0)
	if err == nil {
		t.Error("expected error for empty store")
	}
}

func TestMemoryRange(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	for i := 0; i < 5; i++ {
		_, _ = s.Append(ctx, "record")
	}

	entries, err := s.Range(ctx, 1, 4)
	if err != nil {
		t.Fatalf("range: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Index != 1 {
		t.Errorf("expected first entry index 1, got %d", entries[0].Index)
	}
}

func TestMemorySize(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()

	size, _ := s.Size(ctx)
	if size != 0 {
		t.Errorf("expected size 0, got %d", size)
	}

	_, _ = s.Append(ctx, "a")
	_, _ = s.Append(ctx, "b")

	size, _ = s.Size(ctx)
	if size != 2 {
		t.Errorf("expected size 2, got %d", size)
	}
}
