package jwtx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Signer signs tokens with one private key (RS256 for RSA, ES256 for ECDSA P-256).
type Signer struct {
	kid    string
	method jwt.SigningMethod
	key    crypto.Signer
}

// NewSigner returns a Signer for an *rsa.PrivateKey (2048 bits or more) or an
// *ecdsa.PrivateKey on P-256. The kid is written to the header of every token.
func NewSigner(key crypto.Signer, kid string) (*Signer, error) {
	if kid == "" {
		return nil, errors.New("jwtx: kid is required")
	}
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("jwtx: rsa key must be at least 2048 bits")
		}
		return &Signer{kid: kid, method: jwt.SigningMethodRS256, key: k}, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("jwtx: ecdsa key must be on P-256")
		}
		return &Signer{kid: kid, method: jwt.SigningMethodES256, key: k}, nil
	default:
		return nil, fmt.Errorf("jwtx: unsupported key type %T", key)
	}
}

// ParsePrivateKeyPEM reads an RSA or ECDSA private key in PKCS#8, PKCS#1 or SEC1 PEM form.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("jwtx: no PEM block found")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := k.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("jwtx: unsupported key type %T", k)
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("jwtx: cannot parse private key")
}

// KeyID returns the kid.
func (s *Signer) KeyID() string { return s.kid }

// Alg returns the JWS algorithm name (RS256 or ES256).
func (s *Signer) Alg() string { return s.method.Alg() }

// Public returns the public key.
func (s *Signer) Public() crypto.PublicKey { return s.key.Public() }

// Sign signs the claims. The caller sets every claim (iss, aud, exp, jti, ...).
func (s *Signer) Sign(c *Claims) (string, error) {
	t := jwt.NewWithClaims(s.method, c)
	t.Header["kid"] = s.kid
	return t.SignedString(s.key)
}
