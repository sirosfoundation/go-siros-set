// Package emit provides a lightweight SET record emitter that writes signed
// audit records through Go's standard log/slog package.
//
// SET records are emitted as structured slog entries with type="secevent",
// mixed into the service's normal log stream. Any log pipeline can filter
// on the "type" field to extract SET records for aggregation.
//
// Example slog/JSON output:
//
//	{"time":"...","level":"INFO","msg":"secevent","type":"secevent","jws":"eyJ...","event":"urn:siros:audit:key:sign","iss":"https://r2ps.siros.org"}
//
// The "jws" field is self-contained: a compact JWS that can be independently
// verified with the emitter's public key. The outer fields are hints for
// log routing — they are NOT trusted for verification.
//
// Extraction in common pipelines:
//
//	jq:       select(.type == "secevent") | .jws
//	fluentd:  <filter> @type grep regexp1 type secevent </filter>
//	Loki:     {app="r2ps"} | json | type="secevent"
//	grep:     grep '"type":"secevent"'
package emit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-siros-set/set"
)

// DefaultBlockSize is the number of records per block in the hash chain.
// After this many records the block sequence number resets to zero,
// marking a block boundary for the Level-2 Merkle tree.
const DefaultBlockSize uint64 = 100

// Emitter signs SET records and writes them as structured slog entries.
// It maintains a SHA-256 hash chain: each record carries the hash of
// the previous compact JWS, providing per-node tamper evidence without
// any external coordination.
type Emitter struct {
	logger    *slog.Logger
	signer    jose.Signer
	issuer    string
	blockSize uint64

	// Hash chain state (protected by mu)
	mu       sync.Mutex
	prevHash string // hex SHA-256 of previous compact JWS; "" at chain start
	blockSeq uint64 // 0-based position within current block
}

// Option configures an Emitter.
type Option func(*Emitter)

// WithLogger sets a custom slog.Logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(e *Emitter) {
		e.logger = l
	}
}

// WithBlockSize sets the number of records per block. The block
// sequence number resets to zero after this many records, creating a
// block boundary. Set to 0 to disable block boundaries.
func WithBlockSize(n uint64) Option {
	return func(e *Emitter) {
		e.blockSize = n
	}
}

// New creates an Emitter that signs records and logs them via slog.
// The hash chain starts with prev="" and block sequence 0.
func New(issuer string, signer jose.Signer, opts ...Option) *Emitter {
	e := &Emitter{
		signer:    signer,
		issuer:    issuer,
		blockSize: DefaultBlockSize,
	}
	for _, opt := range opts {
		opt(e)
	}
	if e.logger == nil {
		e.logger = slog.Default()
	}
	return e
}

// Emit creates, signs, and logs a SET record.
// eventData may be nil for events with no additional data.
func (e *Emitter) Emit(eventURI set.EventURI, eventData map[string]any) error {
	rec := set.NewRecord(e.issuer, eventURI, eventData)
	return e.EmitRecord(rec)
}

// EmitWithSubject creates, signs, and logs a SET record with a subject.
func (e *Emitter) EmitWithSubject(eventURI set.EventURI, subject string, eventData map[string]any) error {
	rec := set.NewRecord(e.issuer, eventURI, eventData).WithSubject(subject)
	return e.EmitRecord(rec)
}

// EmitRecord signs and logs a pre-built SET record.
// The record's Prev and BlockSeq fields are set by the emitter to
// maintain the hash chain — callers should not set them.
func (e *Emitter) EmitRecord(rec *set.Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Stamp chain fields before signing
	rec.Prev = e.prevHash
	rec.BlockSeq = e.blockSeq

	compact, err := rec.Sign(e.signer)
	if err != nil {
		return fmt.Errorf("emit: sign: %w", err)
	}

	// Advance chain state
	h := sha256.Sum256([]byte(compact))
	e.prevHash = hex.EncodeToString(h[:])
	e.blockSeq++
	if e.blockSize > 0 && e.blockSeq >= e.blockSize {
		e.blockSeq = 0
	}

	// Extract the first event URI for the log line hint
	var eventHint string
	for uri := range rec.Events {
		eventHint = string(uri)
		break
	}

	attrs := []any{
		"type", "secevent",
		"jws", compact,
		"event", eventHint,
		"iss", rec.Issuer,
		"bseq", rec.BlockSeq,
	}
	if rec.Prev != "" {
		attrs = append(attrs, "prev", rec.Prev)
	}

	e.logger.Info("secevent", attrs...)
	return nil
}
