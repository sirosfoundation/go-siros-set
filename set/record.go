package set

import (
	"crypto"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
)

// EventURI identifies the type of audit event.
type EventURI string

// Standard SIROS audit event URIs.
const (
	EventKeyGenerate      EventURI = "urn:siros:audit:key:generate"
	EventKeySign          EventURI = "urn:siros:audit:key:sign"
	EventKeyAgree         EventURI = "urn:siros:audit:key:agree"
	EventKeyDelete        EventURI = "urn:siros:audit:key:delete"
	EventWKAIssued        EventURI = "urn:siros:audit:wka:issued"
	EventWIAIssued        EventURI = "urn:siros:audit:wia:issued"
	EventWIRevoked        EventURI = "urn:siros:audit:wi:revoked"
	EventWISuspended      EventURI = "urn:siros:audit:wi:suspended"
	Event2FARegistered    EventURI = "urn:siros:audit:2fa:registered"
	Event2FAAuthenticated EventURI = "urn:siros:audit:2fa:authenticated"
	Event2FAChanged       EventURI = "urn:siros:audit:2fa:changed"
	Event2FAFailed        EventURI = "urn:siros:audit:2fa:failed"
	EventWICreated        EventURI = "urn:siros:audit:wi:created"
	EventWIDeactivated    EventURI = "urn:siros:audit:wi:deactivated"
	EventAdminAccess      EventURI = "urn:siros:audit:admin:access"
	EventConfigChange     EventURI = "urn:siros:audit:config:change"
	EventTenantCreated    EventURI = "urn:siros:audit:tenant:created"
	EventTenantUpdated    EventURI = "urn:siros:audit:tenant:updated"
	EventTenantDeleted    EventURI = "urn:siros:audit:tenant:deleted"
	EventUserAdded        EventURI = "urn:siros:audit:user:added"
	EventUserRemoved      EventURI = "urn:siros:audit:user:removed"
	EventUserSuspended    EventURI = "urn:siros:audit:user:suspended"
	EventUserDeleted      EventURI = "urn:siros:audit:user:deleted"
	EventIssuerCreated    EventURI = "urn:siros:audit:issuer:created"
	EventIssuerUpdated    EventURI = "urn:siros:audit:issuer:updated"
	EventIssuerDeleted    EventURI = "urn:siros:audit:issuer:deleted"
	EventVerifierCreated  EventURI = "urn:siros:audit:verifier:created"
	EventVerifierUpdated  EventURI = "urn:siros:audit:verifier:updated"
	EventVerifierDeleted  EventURI = "urn:siros:audit:verifier:deleted"
	EventInviteCreated    EventURI = "urn:siros:audit:invite:created"
	EventInviteUpdated    EventURI = "urn:siros:audit:invite:updated"
	EventInviteDeleted    EventURI = "urn:siros:audit:invite:deleted"
	EventR2PSStatusChange EventURI = "urn:siros:audit:r2ps:status:change"
	EventStartup          EventURI = "urn:siros:audit:system:startup"
	EventShutdown         EventURI = "urn:siros:audit:system:shutdown"
)

// Record is a Security Event Token (RFC 8417) payload.
type Record struct {
	// Standard JWT claims
	Issuer   string `json:"iss"`
	IssuedAt int64  `json:"iat"`
	JTI      string `json:"jti"`

	// SET-specific claims
	Subject       string `json:"sub,omitempty"`
	TransactionID string `json:"txn,omitempty"`
	TimeOfEvent   int64  `json:"toe,omitempty"`

	// Hash chain claims
	Prev     string `json:"prev,omitempty"` // SHA-256(previous JWS), hex; empty = chain start
	BlockSeq uint64 `json:"bseq,omitempty"` // 0-based position within current block

	// Events map: event URI → event-specific data
	Events map[EventURI]map[string]any `json:"events"`
}

// NewRecord creates a new SET audit record.
func NewRecord(issuer string, eventURI EventURI, eventData map[string]any) *Record {
	now := time.Now().UTC()
	return &Record{
		Issuer:      issuer,
		IssuedAt:    now.Unix(),
		JTI:         uuid.New().String(),
		TimeOfEvent: now.Unix(),
		Events: map[EventURI]map[string]any{
			eventURI: eventData,
		},
	}
}

// WithSubject sets the subject claim.
func (r *Record) WithSubject(sub string) *Record {
	r.Subject = sub
	return r
}

// WithTransaction sets the transaction ID claim.
func (r *Record) WithTransaction(txn string) *Record {
	r.TransactionID = txn
	return r
}

// Sign serializes the record as a compact JWS (typ: secevent+jwt).
func (r *Record) Sign(signer jose.Signer) (string, error) {
	payload, err := json.Marshal(r)
	if err != nil {
		return "", fmt.Errorf("set: marshal record: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("set: sign record: %w", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("set: compact serialize: %w", err)
	}

	return compact, nil
}

// Parse verifies and parses a compact JWS SET record.
func Parse(compact string, key crypto.PublicKey) (*Record, error) {
	jws, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{
		jose.ES256,
		jose.ES384,
		jose.PS256,
		jose.EdDSA,
	})
	if err != nil {
		return nil, fmt.Errorf("set: parse JWS: %w", err)
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("set: verify signature: %w", err)
	}

	var rec Record
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, fmt.Errorf("set: unmarshal payload: %w", err)
	}

	return &rec, nil
}

// NewSigner creates a jose.Signer for SET records using the given key.
func NewSigner(key crypto.Signer, alg jose.SignatureAlgorithm, keyID string) (jose.Signer, error) {
	opts := (&jose.SignerOptions{}).
		WithType("secevent+jwt").
		WithHeader(jose.HeaderKey("kid"), keyID)

	return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
}
