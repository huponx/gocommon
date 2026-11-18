package oidcclient

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/huponx/gocommon/jwtx"
)

type fake struct {
	srv      *httptest.Server
	signer   *jwtx.Signer
	nonce    string // put in the next id token
	grantErr string
	revoked  []string
}

func newFake(t *testing.T) *fake {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := jwtx.NewSigner(k, "k1")
	f := &fake{signer: s}
	mux := http.NewServeMux()
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	base := f.srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Provider{
			Issuer: base, AuthorizationEndpoint: base + "/authorize", TokenEndpoint: base + "/token",
			JWKSURI: base + "/jwks", RevocationEndpoint: base + "/revoke", EndSessionEndpoint: base + "/logout",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		doc, _ := jwtx.MarshalJWKS(map[string]crypto.PublicKey{"k1": s.Public()})
		_, _ = w.Write(doc)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if id, sec, ok := r.BasicAuth(); !ok || id != "gatekeeper" || sec != "s3cret" {
			w.WriteHeader(401)
			return
		}
		if f.grantErr != "" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"` + f.grantErr + `"}`))
			return
		}
		access := "access-1"
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": access, "refresh_token": "refresh-1", "expires_in": 300, "token_type": "Bearer",
			"id_token": f.mint(jwtx.TypeID, func(c *jwtx.Claims) { c.Nonce = f.nonce; c.AtHash = AtHash(access) }),
		})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.revoked = append(f.revoked, r.PostForm.Get("token"))
	})
	return f
}

func (f *fake) mint(typ string, mut func(*jwtx.Claims)) string {
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: f.srv.URL, Subject: "user-1", Audience: jwt.ClaimStrings{"gatekeeper"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()), ID: "j1",
		},
		Type: typ,
	}
	mut(c)
	raw, err := f.signer.Sign(c)
	if err != nil {
		panic(err)
	}
	return raw
}

func (f *fake) client(t *testing.T) *Client {
	t.Helper()
	c, err := Discover(context.Background(), Config{
		Issuer: f.srv.URL, ClientID: "gatekeeper", ClientSecret: "s3cret", RedirectURL: "https://app.example.com/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAuthURLHasPKCEStateNonce(t *testing.T) {
	c := newFake(t).client(t)
	raw, req, err := c.AuthURL(AuthURLOptions{ACRValues: "mfa", MaxAge: 60})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") != Challenge(req.Verifier) || q.Get("state") != req.State || q.Get("nonce") != req.Nonce ||
		q.Get("acr_values") != "mfa" || q.Get("max_age") != "60" || q.Get("client_id") != "gatekeeper" {
		t.Fatalf("query %v", q)
	}
	if req.State == req.Nonce || len(req.Verifier) < 43 {
		t.Fatalf("weak values %+v", req)
	}
}

func TestPKCEVector(t *testing.T) { // RFC 7636 appendix B
	if got := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %s", got)
	}
}

func TestExchange(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	_, req, _ := c.AuthURL(AuthURLOptions{})

	f.nonce = req.Nonce
	tok, err := c.Exchange(context.Background(), "code", req)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "access-1" || tok.RefreshToken != "refresh-1" || tok.ID.Subject != "user-1" {
		t.Fatalf("%+v", tok)
	}

	f.nonce = "other"
	if _, err := c.Exchange(context.Background(), "code", req); err == nil {
		t.Fatal("nonce mismatch accepted")
	}

	f.grantErr = "invalid_grant"
	if _, err := c.Exchange(context.Background(), "code", req); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("want ErrInvalidGrant, got %v", err)
	}
}

func TestDiscoveryIssuerMustMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"issuer":"https://evil.example.com","authorization_endpoint":"a","token_endpoint":"t","jwks_uri":"j"}`))
	}))
	defer srv.Close()
	_, err := Discover(context.Background(), Config{Issuer: srv.URL, ClientID: "a", ClientSecret: "b", RedirectURL: "c"})
	if err == nil {
		t.Fatal("issuer mismatch accepted")
	}
}

func TestVerifyLogoutToken(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	event := map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}

	good := f.mint(jwtx.TypeLogout, func(c *jwtx.Claims) { c.Events = event; c.SessionID = "sid-1" })
	if lt, err := c.VerifyLogoutToken(context.Background(), good); err != nil || lt.SessionID != "sid-1" {
		t.Fatalf("%v", err)
	}
	bad := map[string]string{
		"no event":   f.mint(jwtx.TypeLogout, func(c *jwtx.Claims) { c.SessionID = "s" }),
		"nonce":      f.mint(jwtx.TypeLogout, func(c *jwtx.Claims) { c.Events = event; c.SessionID = "s"; c.Nonce = "n" }),
		"id token":   f.mint(jwtx.TypeID, func(c *jwtx.Claims) { c.Events = event; c.SessionID = "s" }),
		"no sub/sid": f.mint(jwtx.TypeLogout, func(c *jwtx.Claims) { c.Events = event; c.Subject = "" }),
	}
	for name, raw := range bad {
		if _, err := c.VerifyLogoutToken(context.Background(), raw); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestRevokeAndEndSession(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	if err := c.Revoke(context.Background(), "refresh-1", "refresh_token"); err != nil || len(f.revoked) != 1 {
		t.Fatalf("%v %v", err, f.revoked)
	}
	raw, err := c.EndSessionURL("idt", "https://app.example.com/", "st")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	if u.Query().Get("id_token_hint") != "idt" || u.Query().Get("post_logout_redirect_uri") != "https://app.example.com/" {
		t.Fatalf("%s", raw)
	}
}
