package jwtx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// ParseUnverified decodes the payload of a JWT into dst WITHOUT verifying the signature, the
// expiry or any other claim. dst is a pointer to a struct or map (json.Unmarshal rules).
//
// It is for tokens issued by a third party that the caller received over TLS straight from the
// issuer and cannot verify (no key), for example to read the user id of an upstream session.
// NEVER use it for an authentication or authorization decision: use Verifier for that.
func ParseUnverified(token string, dst any) error {
	if dst == nil {
		return errors.New("jwtx: ParseUnverified needs a destination")
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return fmt.Errorf("jwtx: malformed JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return fmt.Errorf("jwtx: decode JWT payload: %w", err)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("jwtx: unmarshal JWT payload: %w", err)
	}
	return nil
}
