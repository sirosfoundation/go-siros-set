// Package set implements Security Event Tokens (RFC 8417) for tamper-evident
// audit logging. Each audit record is a signed JWS (typ: secevent+jwt) with
// events keyed under the urn:siros:audit:* namespace.
//
// This package is designed for the SIROS ID ecosystem's FAU_STG_EXT Common
// Criteria requirement: each record must be individually HSM-signed and
// stored in a tamper-evident append-only log with Merkle tree completeness
// proofs.
package set
