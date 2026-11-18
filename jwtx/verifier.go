package jwtx

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken wraps every verdict against the token itself (bad signature, expired, wrong
// audience, ...). Anything else returned by Verify is an infrastructure error.
var ErrInvalidToken = errors.New("jwtx: invalid token")

// VerifierConfig configures a Verifier.
type VerifierConfig struct {
	// Issuer the token must have been issued by (required).
	Issuer string
	// Audience the token must have been issued for (required): one of the aud values.
	Audience string
	// Keys resolves the signing keys (required).
	Keys KeySet
	// Leeway tolerated for exp, nbf and iat (default 30 seconds).
	Leeway time.Duration
	// OptionalJTI accepts tokens without a jti (external identity providers). Default false.
	OptionalJTI bool
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Verifier verifies RS256 and ES256 tokens. The algorithm is pinned: "none", HS* and any
// other algorithm are rejected, and the key type must match the algorithm.
type Verifier struct {
	cfg    VerifierConfig
	parser *jwt.Parser
}

// NewVerifier validates the config.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("jwtx: issuer is required")
	}
	if cfg.Audience == "" {
		return nil, errors.New("jwtx: audience is required")
	}
	if cfg.Keys == nil {
		return nil, errors.New("jwtx: key set is required")
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(cfg.Leeway),
		jwt.WithTimeFunc(cfg.Now),
	}
	return &Verifier{cfg: cfg, parser: jwt.NewParser(opts...)}, nil
}

// Verify checks signature, issuer, audience, expiry and jti. Errors that match
// ErrInvalidToken are verdicts on the token; ErrKeysUnavailable (and other errors) mean the
// check could not be made.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	claims := &Claims{}
	tok, err := v.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("missing kid")
		}
		pub, err := v.cfg.Keys.Key(ctx, kid)
		if err != nil {
			return nil, err
		}
		switch t.Method.Alg() {
		case "RS256":
			if k, ok := pub.(*rsa.PublicKey); ok {
				return k, nil
			}
		case "ES256":
			if k, ok := pub.(*ecdsa.PublicKey); ok {
				return k, nil
			}
		}
		return nil, errors.New("key type does not match the algorithm")
	})
	if err != nil {
		if errors.Is(err, ErrKeysUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !tok.Valid {
		return nil, ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrInvalidToken)
	}
	if claims.ID == "" && !v.cfg.OptionalJTI {
		return nil, fmt.Errorf("%w: missing jti", ErrInvalidToken)
	}
	return claims, nil
}
