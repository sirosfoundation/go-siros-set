# go-siros-set

[![CI](https://github.com/sirosfoundation/go-siros-set/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/go-siros-set/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/go-siros-set)](https://goreportcard.com/report/github.com/sirosfoundation/go-siros-set)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/go-siros-set/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/go-siros-set)
[![License: BSD-2-Clause](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](LICENSE)

Go library for tamper-evident audit logging using Security Event Tokens
(RFC 8417) with hash-chain linking and Merkle tree completeness proofs.

Implements the FAU_STG_EXT (WSCA-FAU-02) Common Criteria requirement
for the SIROS ID ecosystem.

## Architecture

```
┌─ Service nodes (r2ps, etc.) ──────────────────────────────┐
│  emit.New(issuer, signer)                                 │
│  emit.Emit(eventURI, data) → sign → slog JSON line       │
│  Each record carries prev=SHA-256(previous JWS) + bseq    │
│  ─── Level 1: hash chain (local, per-node) ───            │
└───────────────────────────────────────────────────────────┘
                         │  stdout / journald
                         ▼
┌─ set-checkpoint (single writer) ──────────────────────────┐
│  stdin → extract JWS → store.Append()                     │
│  Every N records: merkle.Tree.AddLeaf() → Sign(TreeHead)  │
│  Signing via PEM key file or HSM (PKCS#11 / pkcs11pool)   │
│  ─── Level 2: Merkle tree (global, checkpointer) ───      │
└───────────────────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `set` | SET (RFC 8417) record types with hash-chain fields (`prev`, `bseq`), JWS signing/verification |
| `emit` | Slog-based emitter with hash-chain state and configurable block boundaries |
| `store` | Append-only storage interface + file-backed and in-memory implementations |
| `merkle` | Merkle tree, inclusion/consistency proofs, signed tree heads, checkpointer |
| `cmd/set-checkpoint` | CLI tool: reads log streams, extracts SETs, builds Merkle tree, signs tree heads |

## Usage

### Emitting audit records (service side)

```go
import (
    "github.com/sirosfoundation/go-siros-set/emit"
    "github.com/sirosfoundation/go-siros-set/set"
)

// Create an emitter (hash chain starts automatically)
signer, _ := set.NewSigner(key, jose.ES256, "audit-key-1")
e := emit.New("https://r2ps.siros.org", signer)

// Emit audit records — each carries prev=SHA-256(previous JWS)
e.Emit(set.EventKeySign, map[string]any{"key_id": "k-1234"})
e.EmitWithSubject(set.EventWKAIssued, "client:alice", map[string]any{"wka_id": "w-1"})
```

Output (mixed into normal slog JSON):

```json
{"time":"...","level":"INFO","msg":"secevent","type":"secevent","jws":"eyJ...","event":"urn:siros:audit:key:sign","iss":"https://r2ps.siros.org","bseq":0}
{"time":"...","level":"INFO","msg":"secevent","type":"secevent","jws":"eyJ...","event":"urn:siros:audit:wka:issued","iss":"https://r2ps.siros.org","bseq":1,"prev":"a1b2c3..."}
```

### Checkpointing (aggregator side)

```bash
# PEM key
kubectl logs -f deploy/r2ps | set-checkpoint \
  -key sth-key.pem -store /var/lib/set/r2ps.log -batch 100

# HSM via PKCS#11
journalctl -u r2ps -f -o json | set-checkpoint \
  -hsm-module /usr/lib/softhsm/libsofthsm2.so \
  -hsm-token siros-sth -hsm-pin "$PIN" -hsm-key sth-signing \
  -store /var/lib/set/r2ps.log
```

### Verifying records

```go
import "github.com/sirosfoundation/go-siros-set/set"

rec, err := set.Parse(compactJWS, &publicKey)
// rec.Prev  = SHA-256 hex of previous JWS (empty string at chain start)
// rec.BlockSeq = position within current block (resets every N records)
```

## License

BSD-2-Clause — see [LICENSE](LICENSE).
