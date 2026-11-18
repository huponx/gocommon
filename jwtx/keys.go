package jwtx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sort"
	"sync"
	"time"
)

// ErrKeysUnavailable means the signing keys could not be loaded (network, bad document). It is
// an infrastructure error, not a verdict on the token.
var ErrKeysUnavailable = errors.New("jwtx: signing keys unavailable")

// ErrUnknownKey means the kid is not part of the key set.
var ErrUnknownKey = errors.New("jwtx: unknown key id")

// KeySet resolves the public key of a kid.
type KeySet interface {
	Key(ctx context.Context, kid string) (crypto.PublicKey, error)
}

// StaticKeySet is a fixed set of public keys.
type StaticKeySet map[string]crypto.PublicKey

// Key implements KeySet.
func (s StaticKeySet) Key(_ context.Context, kid string) (crypto.PublicKey, error) {
	if k, ok := s[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// MarshalJWKS builds the JWKS document of the public keys (sorted by kid).
func MarshalJWKS(keys map[string]crypto.PublicKey) ([]byte, error) {
	kids := make([]string, 0, len(keys))
	for kid := range keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	doc := jwksDoc{Keys: make([]jwk, 0, len(kids))}
	for _, kid := range kids {
		switch k := keys[kid].(type) {
		case *rsa.PublicKey:
			doc.Keys = append(doc.Keys, jwk{
				Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
				N: b64(k.N.Bytes()), E: b64(big.NewInt(int64(k.E)).Bytes()),
			})
		case *ecdsa.PublicKey:
			if k.Curve != elliptic.P256() {
				return nil, fmt.Errorf("jwtx: key %s: only P-256 is supported", kid)
			}
			doc.Keys = append(doc.Keys, jwk{
				Kty: "EC", Kid: kid, Use: "sig", Alg: "ES256", Crv: "P-256",
				X: b64(pad32(k.X)), Y: b64(pad32(k.Y)),
			})
		default:
			return nil, fmt.Errorf("jwtx: key %s: unsupported type %T", kid, keys[kid])
		}
	}
	return json.Marshal(doc)
}

// ParseJWKS reads a JWKS document. Keys of other types or without a kid are skipped.
func ParseJWKS(data []byte) (map[string]crypto.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("jwtx: parse jwks: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := unb64(k.N)
			e, err2 := unb64(k.E)
			if err1 != nil || err2 != nil || len(n) < 256 {
				continue // 2048 bits minimum
			}
			ev := new(big.Int).SetBytes(e)
			if !ev.IsInt64() || ev.Int64() < 3 || ev.Int64() > 1<<31-1 {
				continue
			}
			out[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev.Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := unb64(k.X)
			y, err2 := unb64(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			out[k.Kid] = pub
		}
	}
	return out, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	if len(b) >= 32 {
		return b
	}
	return append(make([]byte, 32-len(b)), b...)
}

// RemoteKeySetConfig configures a RemoteKeySet.
type RemoteKeySetConfig struct {
	// URL of the JWKS document (required).
	URL string
	// HTTPClient used to fetch it (default: 5 second timeout).
	HTTPClient *http.Client
	// TTL is how long a fetched set is used before it is refreshed (default 10 minutes). A
	// failed refresh keeps serving the previous set (stale-if-error) until StaleFor.
	TTL time.Duration
	// StaleFor is how long a stale set may be served when refreshing fails (default 24 hours).
	StaleFor time.Duration
	// MinRefresh is the minimum time between two fetches, also for unknown kids (default 30s).
	MinRefresh time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// RemoteKeySet loads a JWKS from a URL and caches it. An unknown kid triggers one refresh
// (limited by MinRefresh) so a key rotation is picked up without a restart.
type RemoteKeySet struct {
	cfg RemoteKeySetConfig

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time // last successful fetch
	triedAt   time.Time // last fetch attempt
}

// NewRemoteKeySet validates the config and returns the set. Nothing is fetched yet.
func NewRemoteKeySet(cfg RemoteKeySetConfig) (*RemoteKeySet, error) {
	if cfg.URL == "" {
		return nil, errors.New("jwtx: jwks url is required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.StaleFor <= 0 {
		cfg.StaleFor = 24 * time.Hour
	}
	if cfg.MinRefresh <= 0 {
		cfg.MinRefresh = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &RemoteKeySet{cfg: cfg}, nil
}

// Key implements KeySet.
func (r *RemoteKeySet) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()

	expired := r.keys == nil || now.Sub(r.fetchedAt) >= r.cfg.TTL
	if !expired {
		if k, ok := r.keys[kid]; ok {
			return k, nil
		}
	}
	// Refresh when the set is missing, expired, or the kid is unknown (rotation).
	if r.keys == nil || now.Sub(r.triedAt) >= r.cfg.MinRefresh {
		r.triedAt = now
		if err := r.fetch(ctx); err != nil {
			if r.keys == nil || now.Sub(r.fetchedAt) >= r.cfg.StaleFor {
				return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
			}
		}
	}
	if r.keys == nil {
		return nil, ErrKeysUnavailable
	}
	if k, ok := r.keys[kid]; ok {
		return k, nil
	}
	return nil, ErrUnknownKey
}

func (r *RemoteKeySet) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.cfg.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: unexpected status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("jwks: no usable key")
	}
	r.keys = keys
	r.fetchedAt = r.cfg.Now()
	return nil
}
