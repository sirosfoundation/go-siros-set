// Command set-checkpoint reads log lines from stdin, extracts SET records
// (type=secevent), appends them to a local file store, and periodically
// produces signed Merkle tree heads.
//
// Usage (PEM key):
//
//	kubectl logs -f deploy/r2ps | set-checkpoint -key sth-key.pem -store /var/lib/set/r2ps.log
//
// Usage (HSM via PKCS#11):
//
//	journalctl -u r2ps -f -o json | set-checkpoint \
//	  -hsm-module /usr/lib/softhsm/libsofthsm2.so \
//	  -hsm-token siros-sth -hsm-pin 1234 -hsm-key sth-signing \
//	  -store /var/lib/set/r2ps.log
//
// The tool reads JSON lines from stdin, filters for type=secevent,
// and feeds the JWS values into the Merkle tree. A signed tree head
// is written to stdout after each batch (when stdin pauses or EOF).
//
// The -store flag specifies a local file for durable append-only storage.
// Without it, records are kept in memory only (useful for testing/piping).
package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/go-jose/go-jose/v4"

	"github.com/sirosfoundation/go-cryptoutil/pkcs11pool"
	"github.com/sirosfoundation/go-siros-set/emit"
	"github.com/sirosfoundation/go-siros-set/merkle"
	"github.com/sirosfoundation/go-siros-set/set"
	"github.com/sirosfoundation/go-siros-set/store"
)

func main() {
	// Key source: PEM file
	keyFile := flag.String("key", "", "PEM-encoded private key for signing tree heads")

	// Key source: PKCS#11 / HSM
	hsmModule := flag.String("hsm-module", "", "Path to PKCS#11 module (.so)")
	hsmToken := flag.String("hsm-token", "", "PKCS#11 token label (alternative to slot)")
	hsmSlot := flag.Uint("hsm-slot", 0, "PKCS#11 slot ID (used if -hsm-token is empty)")
	hsmPIN := flag.String("hsm-pin", "", "PKCS#11 user PIN")
	hsmKey := flag.String("hsm-key", "", "PKCS#11 key label for STH signing")
	hsmPoolSize := flag.Int("hsm-pool-size", 4, "Number of concurrent PKCS#11 sessions")

	storeFile := flag.String("store", "", "Path to append-only log file (default: in-memory)")
	batchSize := flag.Int("batch", 100, "Emit a signed tree head every N records (0 = only at EOF)")
	genKey := flag.Bool("genkey", false, "Generate a new Ed25519 key pair and exit")
	flag.Parse()

	if *genKey {
		generateKey()
		return
	}

	var (
		signer jose.Signer
		pubKey crypto.PublicKey
		closer func() // cleanup for HSM pool
	)

	switch {
	case *hsmModule != "":
		var err error
		signer, pubKey, closer, err = initHSM(*hsmModule, *hsmToken, uint(*hsmSlot), *hsmPIN, *hsmKey, *hsmPoolSize)
		if err != nil {
			log.Fatalf("set-checkpoint: HSM init: %v", err)
		}
		defer closer()

	case *keyFile != "":
		privKey, pub, alg, err := loadKey(*keyFile)
		if err != nil {
			log.Fatalf("set-checkpoint: load key: %v", err)
		}
		pubKey = pub
		signer, err = set.NewSigner(privKey, alg, "sth")
		if err != nil {
			log.Fatalf("set-checkpoint: create signer: %v", err)
		}

	default:
		log.Fatal("set-checkpoint: -key or -hsm-module is required (use -genkey to create a PEM key)")
	}

	var s store.Store
	if *storeFile != "" {
		fs, err := store.NewFile(*storeFile)
		if err != nil {
			log.Fatalf("set-checkpoint: open store: %v", err)
		}
		s = fs
	} else {
		s = store.NewMemory()
	}

	cp := merkle.NewCheckpointer(s, signer, pubKey)
	ctx := context.Background()

	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer for long JWS lines
	scanner.Buffer(make([]byte, 0, 256*1024), 256*1024)

	count := 0
	total := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		jws, ok := emit.ExtractJWS(line)
		if !ok {
			continue // skip non-secevent lines
		}

		if _, err := s.Append(ctx, jws); err != nil {
			log.Printf("set-checkpoint: append: %v", err)
			continue
		}
		count++
		total++

		if *batchSize > 0 && count >= *batchSize {
			if err := checkpoint(cp, ctx); err != nil {
				log.Printf("set-checkpoint: checkpoint: %v", err)
			}
			count = 0
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("set-checkpoint: stdin: %v", err)
	}

	// Final checkpoint at EOF
	if count > 0 {
		if err := checkpoint(cp, ctx); err != nil {
			log.Printf("set-checkpoint: final checkpoint: %v", err)
		}
	}

	log.Printf("set-checkpoint: processed %d SET records", total)
}

func checkpoint(cp *merkle.Checkpointer, ctx context.Context) error {
	sth, err := cp.Checkpoint(ctx)
	if err != nil {
		return err
	}
	if sth == nil {
		return nil
	}

	out := struct {
		TreeSize  uint64 `json:"tree_size"`
		RootHash  string `json:"root_hash"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	}{
		TreeSize:  sth.TreeSize,
		RootHash:  fmt.Sprintf("%x", sth.RootHash),
		Timestamp: sth.Timestamp.Format("2006-01-02T15:04:05Z"),
		Signature: sth.Signature,
	}

	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(out)
}

// initHSM creates a PKCS#11 session pool and returns a jose.Signer backed
// by the HSM key, the corresponding public key, and a cleanup function.
func initHSM(module, token string, slot uint, pin, keyLabel string, poolSize int) (jose.Signer, crypto.PublicKey, func(), error) {
	if keyLabel == "" {
		return nil, nil, nil, fmt.Errorf("-hsm-key is required with -hsm-module")
	}

	pool, err := pkcs11pool.New(pkcs11pool.Config{
		ModulePath: module,
		TokenLabel: token,
		SlotID:     slot,
		PIN:        pin,
		PoolSize:   poolSize,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open PKCS#11 pool: %w", err)
	}

	hsmSigner, err := pkcs11pool.NewSigner(pool, pkcs11pool.KeyByLabel(keyLabel))
	if err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("create PKCS#11 signer for %q: %w", keyLabel, err)
	}

	alg := jose.SignatureAlgorithm(hsmSigner.Algorithm())
	pubKey := hsmSigner.Public()

	signer, err := set.NewSigner(hsmSigner, alg, "sth")
	if err != nil {
		pool.Close()
		return nil, nil, nil, fmt.Errorf("create JWS signer: %w", err)
	}

	return signer, pubKey, func() { pool.Close() }, nil
}

func loadKey(path string) (crypto.Signer, crypto.PublicKey, jose.SignatureAlgorithm, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", fmt.Errorf("read %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, "", fmt.Errorf("no PEM block in %s", path)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse key: %w", err)
	}

	switch k := key.(type) {
	case ed25519.PrivateKey:
		return k, k.Public(), jose.EdDSA, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return k, &k.PublicKey, jose.ES256, nil
		case elliptic.P384():
			return k, &k.PublicKey, jose.ES384, nil
		default:
			return nil, nil, "", fmt.Errorf("unsupported EC curve: %v", k.Curve.Params().Name)
		}
	default:
		return nil, nil, "", fmt.Errorf("unsupported key type: %T", key)
	}
}

func generateKey() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	if err := pem.Encode(os.Stdout, block); err != nil {
		log.Fatalf("encode PEM: %v", err)
	}

	pub := priv.Public().(ed25519.PublicKey)
	derPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatalf("marshal public key: %v", err)
	}

	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: derPub}
	if err := pem.Encode(os.Stderr, pubBlock); err != nil {
		log.Fatalf("encode public PEM: %v", err)
	}

	fmt.Fprintln(os.Stderr, "# Private key written to stdout, public key above")
}
