package emit

import (
	"encoding/json"
	"fmt"
)

// ExtractJWS extracts the compact JWS from a JSON log line if it is
// a secevent record. Returns ("", false) for non-secevent lines.
// This is used by the checkpointer to filter SET records from a mixed
// log stream.
func ExtractJWS(line []byte) (string, bool) {
	var obj struct {
		Type string `json:"type"`
		JWS  string `json:"jws"`
	}
	if err := json.Unmarshal(line, &obj); err != nil {
		return "", false
	}
	if obj.Type != "secevent" || obj.JWS == "" {
		return "", false
	}
	return obj.JWS, true
}

// MustExtractJWS is like ExtractJWS but returns an error instead of (string, bool).
func MustExtractJWS(line []byte) (string, error) {
	jws, ok := ExtractJWS(line)
	if !ok {
		return "", fmt.Errorf("emit: not a secevent line")
	}
	return jws, nil
}
