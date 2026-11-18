package jwtx

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "bill"
)

var now = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func claims() *Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    testIssuer,
			Subject:   "user-1",
			Audience:  jwt.ClaimStrings{testAudience},
			ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-1",
		},
		Scope: "bill.read bill.write",
		Roles: []string{"viewer"},
	}
}

func verifier(t *testing.T, keys KeySet, mut ...func(*VerifierConfig)) *Verifier {
	t.Helper()
	cfg := VerifierConfig{Issuer: testIssuer, Audience: testAudience, Keys: keys, Now: func() time.Time { return now }}
	for _, m := range mut {
		m(&cfg)
	}
	v, err := NewVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for name, key := range map[string]crypto.Signer{"es256": ecKey(t), "rs256": rsaKey(t)} {
		t.Run(name, func(t *testing.T) {
			s, err := NewSigner(key, "k1")
			if err != nil {
				t.Fatal(err)
			}
			c := claims()
			c.Act = &Actor{Subject: "gatekeeper", ClientID: "gatekeeper", Act: &Actor{Subject: "other"}}
			c.AMR = []string{"pwd", "otp"}
			raw, err := s.Sign(c)
			if err != nil {
				t.Fatal(err)
			}
			v := verifier(t, StaticKeySet{"k1": s.Public()})
			got, err := v.Verify(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			if got.Subject != "user-1" || got.ID != "jti-1" || !got.HasScope("bill.write") || !got.HasRole("viewer") || !got.HasAMR("otp") {
				t.Fatalf("claims %+v", got)
			}
			if got.Act.Depth() != 2 || got.Act.Subject != "gatekeeper" {
				t.Fatalf("act %+v", got.Act)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	key := ecKey(t)
	s, _ := NewSigner(key, "k1")
	good := StaticKeySet{"k1": s.Public()}

	sign := func(mut func(*Claims)) string {
		c := claims()
		mut(c)
		raw, err := s.Sign(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	cases := map[string]string{
		"expired":        sign(func(c *Claims) { c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour)) }),
		"no exp":         sign(func(c *Claims) { c.ExpiresAt = nil }),
		"wrong audience": sign(func(c *Claims) { c.Audience = jwt.ClaimStrings{"courier"} }),
		"wrong issuer":   sign(func(c *Claims) { c.Issuer = "https://evil.example.com" }),
		"no jti":         sign(func(c *Claims) { c.ID = "" }),
		"no sub":         sign(func(c *Claims) { c.Subject = "" }),
		"not yet valid":  sign(func(c *Claims) { c.NotBefore = jwt.NewNumericDate(now.Add(time.Hour)) }),
		"garbage":        "not.a.jwt",
	}

	// alg none
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"k1"}`))
	body, _ := json.Marshal(claims())
	cases["alg none"] = hdr + "." + base64.RawURLEncoding.EncodeToString(body) + "."

	// HS256 signed with the PEM of the public key (classic algorithm confusion)
	der, _ := x509.MarshalPKIXPublicKey(s.Public())
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	hsHdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"k1"}`))
	signing := hsHdr + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, pemKey)
	mac.Write([]byte(signing))
	cases["hs256 confusion"] = signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// signed by another key under the same kid
	other, _ := NewSigner(ecKey(t), "k1")
	raw, _ := other.Sign(claims())
	cases["wrong key"] = raw

	// missing kid
	tk := jwt.NewWithClaims(jwt.SigningMethodES256, claims())
	cases["no kid"], _ = tk.SignedString(key)

	// unknown kid
	unknown, _ := NewSigner(key, "k2")
	cases["unknown kid"], _ = unknown.Sign(claims())

	// RS256 token against an EC key registered under the kid
	rs, _ := NewSigner(rsaKey(t), "k1")
	cases["key type mismatch"], _ = rs.Sign(claims())

	v := verifier(t, good)
	for name, raw := range cases {
		_, err := v.Verify(context.Background(), raw)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: want ErrInvalidToken, got %v", name, err)
		}
	}
}

func TestVerifyOptionalJTIAndLeeway(t *testing.T) {
	s, _ := NewSigner(ecKey(t), "k1")
	c := claims()
	c.ID = ""
	c.ExpiresAt = jwt.NewNumericDate(now.Add(-10 * time.Second)) // inside the 30s leeway
	raw, _ := s.Sign(c)
	keys := StaticKeySet{"k1": s.Public()}
	if _, err := verifier(t, keys).Verify(context.Background(), raw); err == nil {
		t.Fatal("missing jti accepted by default")
	}
	if _, err := verifier(t, keys, func(c *VerifierConfig) { c.OptionalJTI = true }).Verify(context.Background(), raw); err != nil {
		t.Fatalf("optional jti + leeway: %v", err)
	}
	c.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Minute))
	raw, _ = s.Sign(c)
	if _, err := verifier(t, keys, func(c *VerifierConfig) { c.OptionalJTI = true }).Verify(context.Background(), raw); err == nil {
		t.Fatal("expired beyond leeway accepted")
	}
}

func TestJWKSRoundTrip(t *testing.T) {
	ec := ecKey(t)
	rs := rsaKey(t)
	doc, err := MarshalJWKS(map[string]crypto.PublicKey{"ec": &ec.PublicKey, "rs": &rs.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("keys %d", len(keys))
	}
	if !keys["ec"].(*ecdsa.PublicKey).Equal(&ec.PublicKey) || !keys["rs"].(*rsa.PublicKey).Equal(&rs.PublicKey) {
		t.Fatal("keys changed in the round trip")
	}
	// unsupported entries are skipped, not fatal
	extra := `{"keys":[{"kty":"oct","kid":"x","k":"AAAA"},{"kty":"RSA","kid":"short","n":"AQAB","e":"AQAB"}]}`
	got, err := ParseJWKS([]byte(extra))
	if err != nil || len(got) != 0 {
		t.Fatalf("skip: %v %v", got, err)
	}
}

func TestRemoteKeySetRotationAndStale(t *testing.T) {
	k1, k2 := ecKey(t), ecKey(t)
	var current atomic.Value
	var fetches, fail atomic.Int32
	set := func(m map[string]crypto.PublicKey) {
		doc, _ := MarshalJWKS(m)
		current.Store(doc)
	}
	set(map[string]crypto.PublicKey{"k1": &k1.PublicKey})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		if fail.Load() == 1 {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(current.Load().([]byte))
	}))
	defer srv.Close()

	clock := now
	ks, err := NewRemoteKeySet(RemoteKeySetConfig{URL: srv.URL, TTL: time.Minute, MinRefresh: 10 * time.Second, StaleFor: time.Hour, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := ks.Key(ctx, "k1"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "k1"); err != nil || fetches.Load() != 1 {
		t.Fatalf("cache: fetches=%d err=%v", fetches.Load(), err)
	}

	// rotation: k2 appears, unknown kid triggers one refresh once MinRefresh passed
	set(map[string]crypto.PublicKey{"k1": &k1.PublicKey, "k2": &k2.PublicKey})
	if _, err := ks.Key(ctx, "k2"); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("refresh is rate limited, want unknown key, got %v", err)
	}
	clock = clock.Add(11 * time.Second)
	if _, err := ks.Key(ctx, "k2"); err != nil {
		t.Fatalf("rotated key: %v", err)
	}

	// a kid that never exists does not hammer the endpoint
	before := fetches.Load()
	for i := 0; i < 20; i++ {
		_, _ = ks.Key(ctx, "nope")
	}
	if fetches.Load() > before+1 {
		t.Fatalf("unknown kid fetched %d times", fetches.Load()-before)
	}

	// stale-if-error: expired set, endpoint down
	fail.Store(1)
	clock = clock.Add(2 * time.Minute)
	if _, err := ks.Key(ctx, "k1"); err != nil {
		t.Fatalf("stale set must still serve: %v", err)
	}
	// beyond StaleFor: unavailable
	clock = clock.Add(2 * time.Hour)
	if _, err := ks.Key(ctx, "k1"); !errors.Is(err, ErrKeysUnavailable) {
		t.Fatalf("want ErrKeysUnavailable, got %v", err)
	}
}

func TestRemoteKeySetDownFromTheStart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 503) }))
	defer srv.Close()
	ks, _ := NewRemoteKeySet(RemoteKeySetConfig{URL: srv.URL})
	s, _ := NewSigner(ecKey(t), "k1")
	raw, _ := s.Sign(claims())
	_, err := verifier(t, ks).Verify(context.Background(), raw)
	if !errors.Is(err, ErrKeysUnavailable) || errors.Is(err, ErrInvalidToken) {
		t.Fatalf("infra error must not look like an invalid token: %v", err)
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	ec := ecKey(t)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	pk, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner(pk, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKeyPEM([]byte("nope")); err == nil {
		t.Fatal("garbage accepted")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := NewSigner(small, "k"); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Fatalf("small rsa key: %v", err)
	}
	if _, err := NewSigner(ec, ""); err == nil {
		t.Fatal("empty kid accepted")
	}
}
