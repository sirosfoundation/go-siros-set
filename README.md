# go-siros-set

Go library for tamper-evident audit logging using Security Event Tokens (RFC 8417) and Merkle tree completeness proofs.

Implements the FAU_STG_EXT Common Criteria requirement for the SIROS ID ecosystem.

## Architecture

```
┌─ Service nodes (r2ps, etc.) ──────────────┐
│  set.NewRecord() → rec.Sign(signer) → JWS │
│  store.Append(ctx, jws)                    │
└────────────────────────────────────────────┘
                    │
                    ▼
┌─ Checkpointer (single writer) ────────────┐
│  store.Range(last, current)                │
│  merkle.Tree.AddLeaf() for each entry      │
│  TreeHead.Sign(signer) → SignedTreeHead    │
└────────────────────────────────────────────┘
```

## Packages

| Package | Description |
|---------|-------------|
| `set` | SET (RFC 8417) record types, JWS signing/verification |
| `store` | Append-only storage interface + in-memory implementation |
| `merkle` | Merkle tree, inclusion/consistency proofs, signed tree heads, checkpointer |

## Usage

```go
import (
    "github.com/sirosfoundation/go-siros-set/set"
    "github.com/sirosfoundation/go-siros-set/store"
    "github.com/sirosfoundation/go-siros-set/merkle"
)

// Create a signer (HSM-backed in production)
signer, _ := set.NewSigner(key, jose.ES256, "audit-key-1")

// Emit an audit record
rec := set.NewRecord("https://r2ps.siros.org", set.EventKeySign, map[string]any{
    "key_id": "k-1234",
}).WithSubject("client:alice").WithTransaction("tx-5678")

jws, _ := rec.Sign(signer)

// Store it
s := store.NewMemory()  // or store.NewMongoDB(...)
idx, _ := s.Append(ctx, jws)

// Periodic checkpointing
cp := merkle.NewCheckpointer(s, sthSigner, &pubKey)
sth, _ := cp.Checkpoint(ctx)
// sth.Signature is the JWS-signed tree head
```

## License

BSD-2-Clause
