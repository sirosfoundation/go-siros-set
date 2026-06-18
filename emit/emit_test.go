package emit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/sirosfoundation/go-siros-set/set"
)

func testEmitter(t *testing.T, buf *bytes.Buffer, opts ...Option) (*Emitter, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := set.NewSigner(key, "ES256", "test-key")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(buf, nil))
	allOpts := append([]Option{WithLogger(logger)}, opts...)
	e := New("https://test.siros.org", signer, allOpts...)
	return e, key
}

func TestEmit(t *testing.T) {
	var buf bytes.Buffer
	e, key := testEmitter(t, &buf)

	err := e.Emit(set.EventKeySign, map[string]any{"key_id": "k-1"})
	if err != nil {
		t.Fatal(err)
	}

	output := buf.String()
	if !strings.HasSuffix(output, "\n") {
		t.Error("expected trailing newline")
	}

	var line map[string]any
	if err := json.Unmarshal([]byte(output), &line); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if line["type"] != "secevent" {
		t.Errorf("type = %q, want secevent", line["type"])
	}
	if line["iss"] != "https://test.siros.org" {
		t.Errorf("iss = %q, want https://test.siros.org", line["iss"])
	}
	if line["event"] != string(set.EventKeySign) {
		t.Errorf("event = %q, want %s", line["event"], set.EventKeySign)
	}
	jws, ok := line["jws"].(string)
	if !ok || jws == "" {
		t.Error("jws is empty")
	}
	if line["msg"] != "secevent" {
		t.Errorf("msg = %q, want secevent", line["msg"])
	}

	// First record should have bseq=0 (omitted from slog as numeric 0)
	// and no prev (chain start)
	if _, hasPrev := line["prev"]; hasPrev {
		t.Errorf("first record should not have prev, got %v", line["prev"])
	}

	// Verify the JWS is independently verifiable
	rec, err := set.Parse(jws, &key.PublicKey)
	if err != nil {
		t.Fatalf("verify JWS: %v", err)
	}
	if rec.Issuer != "https://test.siros.org" {
		t.Errorf("rec.Issuer = %q, want https://test.siros.org", rec.Issuer)
	}
	if rec.Prev != "" {
		t.Errorf("first record prev = %q, want empty", rec.Prev)
	}
}

func TestEmitWithSubject(t *testing.T) {
	var buf bytes.Buffer
	e, key := testEmitter(t, &buf)

	err := e.EmitWithSubject(set.EventWKAIssued, "client:alice", map[string]any{"wka_id": "w-1"})
	if err != nil {
		t.Fatal(err)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rec, err := set.Parse(line["jws"].(string), &key.PublicKey)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rec.Subject != "client:alice" {
		t.Errorf("subject = %q, want client:alice", rec.Subject)
	}
}

func TestEmitMultipleLines(t *testing.T) {
	var buf bytes.Buffer
	e, _ := testEmitter(t, &buf)

	for i := 0; i < 5; i++ {
		if err := e.Emit(set.EventStartup, nil); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 5 {
		t.Errorf("got %d lines, want 5", len(lines))
	}

	for i, raw := range lines {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if line["type"] != "secevent" {
			t.Errorf("line %d: type = %q", i, line["type"])
		}
	}
}

func TestHashChain(t *testing.T) {
	var buf bytes.Buffer
	e, key := testEmitter(t, &buf)

	for i := 0; i < 3; i++ {
		if err := e.Emit(set.EventKeySign, nil); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(lines))
	}

	var prevJWS string
	for i, raw := range lines {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line %d: unmarshal: %v", i, err)
		}

		jws := line["jws"].(string)
		rec, err := set.Parse(jws, &key.PublicKey)
		if err != nil {
			t.Fatalf("line %d: parse: %v", i, err)
		}

		if i == 0 {
			if rec.Prev != "" {
				t.Errorf("line 0: prev = %q, want empty", rec.Prev)
			}
		} else {
			h := sha256.Sum256([]byte(prevJWS))
			want := hex.EncodeToString(h[:])
			if rec.Prev != want {
				t.Errorf("line %d: prev = %q, want %q", i, rec.Prev, want)
			}
		}

		if rec.BlockSeq != uint64(i) {
			t.Errorf("line %d: bseq = %d, want %d", i, rec.BlockSeq, i)
		}

		prevJWS = jws
	}
}

func TestBlockBoundary(t *testing.T) {
	var buf bytes.Buffer
	e, key := testEmitter(t, &buf, WithBlockSize(3))

	for i := 0; i < 5; i++ {
		if err := e.Emit(set.EventStartup, nil); err != nil {
			t.Fatal(err)
		}
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	wantBseq := []uint64{0, 1, 2, 0, 1}

	for i, raw := range lines {
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		rec, err := set.Parse(line["jws"].(string), &key.PublicKey)
		if err != nil {
			t.Fatalf("line %d: parse: %v", i, err)
		}
		if rec.BlockSeq != wantBseq[i] {
			t.Errorf("line %d: bseq = %d, want %d", i, rec.BlockSeq, wantBseq[i])
		}
	}
}
