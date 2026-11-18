package grpcserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/requestctx"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

const (
	tIssuer   = "https://auth.example.com"
	tAudience = "bill"
)

func jwtFixture(t *testing.T) (*jwtx.Signer, *jwtx.Verifier) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwtx.NewSigner(k, "k1")
	if err != nil {
		t.Fatal(err)
	}
	v, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: tIssuer, Audience: tAudience, Keys: jwtx.StaticKeySet{"k1": s.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

func accessToken(t *testing.T, s *jwtx.Signer, mut func(*jwtx.Claims)) string {
	t.Helper()
	c := &jwtx.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: tIssuer, Subject: "user-1", Audience: jwt.ClaimStrings{tAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()), ID: "jti-1",
		},
		Type: jwtx.TypeAccess, Perms: []string{"bill:read"},
	}
	if mut != nil {
		mut(c)
	}
	raw, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func jwtBearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(MDAuthorization, "Bearer "+token))
}

func TestJWTAuth(t *testing.T) {
	s, v := jwtFixture(t)
	fn := JWTAuth(v)

	ctx, err := fn(jwtBearerCtx(accessToken(t, s, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p := authn.FromContext(ctx)
	if p == nil || p.Subject != "user-1" || p.TokenID != "jti-1" || !p.Can("bill:read") {
		t.Fatalf("principal %+v", p)
	}

	for name, ctx := range map[string]context.Context{
		"missing":    context.Background(),
		"garbage":    jwtBearerCtx("nope"),
		"id token":   jwtBearerCtx(accessToken(t, s, func(c *jwtx.Claims) { c.Type = jwtx.TypeID })),
		"no typ":     jwtBearerCtx(accessToken(t, s, func(c *jwtx.Claims) { c.Type = "" })),
		"wrong aud":  jwtBearerCtx(accessToken(t, s, func(c *jwtx.Claims) { c.Audience = jwt.ClaimStrings{"dict"} })),
		"logout tok": jwtBearerCtx(accessToken(t, s, func(c *jwtx.Claims) { c.Type = jwtx.TypeLogout })),
	} {
		if _, err := fn(ctx); apperror.From(err).Code != codes.Unauthenticated {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestJWTAuthOverridesForgedUserID(t *testing.T) {
	s, v := jwtFixture(t)
	md := metadata.Pairs(MDAuthorization, "Bearer "+accessToken(t, s, nil), "user-id", "admin")
	ctx, err := JWTAuth(v)(metadata.NewIncomingContext(context.Background(), md))
	if err != nil {
		t.Fatal(err)
	}
	ctx = requestctx.HydrateIncoming(ctx)
	if got := requestctx.From(ctx).UserID; got != "user-1" {
		t.Fatalf("user id %q, want the token subject", got)
	}
}

func TestAnyAuth(t *testing.T) {
	ok := func(ctx context.Context) (context.Context, error) { return WithCaller(ctx, "sa"), nil }
	unauth := func(context.Context) (context.Context, error) { return nil, apperror.Unauthenticated("no") }
	denied := func(context.Context) (context.Context, error) { return nil, apperror.PermissionDenied("no") }
	unavailable := func(context.Context) (context.Context, error) { return nil, apperror.Unavailable("down") }

	ctx, err := AnyAuth(unauth, ok)(context.Background())
	if err != nil || CallerFromContext(ctx) != "sa" {
		t.Fatalf("second wins: %v", err)
	}
	if _, err := AnyAuth(unauth, unauth)(context.Background()); apperror.From(err).Code != codes.Unauthenticated {
		t.Fatalf("all unauth: %v", err)
	}
	if _, err := AnyAuth(unauth, denied)(context.Background()); apperror.From(err).Code != codes.PermissionDenied {
		t.Fatalf("denied beats unauth: %v", err)
	}
	if _, err := AnyAuth(unauth, unavailable)(context.Background()); apperror.From(err).Code != codes.Unavailable {
		t.Fatalf("unavailable beats unauth: %v", err)
	}
	if _, err := AnyAuth()(context.Background()); apperror.From(err).Code != codes.Unauthenticated {
		t.Fatalf("no funcs must refuse: %v", err)
	}
}

func TestCheckMethod(t *testing.T) {
	perms := map[string]string{
		"/svc/Read":   "bill:read",
		"/svc/Any":    Public,
		"/svc/Admin":  "bill:admin",
		"/svc/Empty":  "",
		"/svc/Stream": "bill:*",
	}
	withPerms := func(p ...string) context.Context {
		return authn.WithPrincipal(context.Background(), &authn.Principal{Subject: "u", Perms: p})
	}
	cases := []struct {
		name   string
		ctx    context.Context
		method string
		want   codes.Code
	}{
		{"allowed", withPerms("bill:read"), "/svc/Read", codes.OK},
		{"wildcard", withPerms("*:read"), "/svc/Read", codes.OK},
		{"missing perm", withPerms("bill:write"), "/svc/Read", codes.PermissionDenied},
		{"no perms", withPerms(), "/svc/Read", codes.PermissionDenied},
		{"public", withPerms(), "/svc/Any", codes.OK},
		{"unmapped method denied", withPerms("*"), "/svc/New", codes.PermissionDenied},
		{"empty requirement denied", withPerms("*"), "/svc/Empty", codes.PermissionDenied},
		{"admin", withPerms("bill:read"), "/svc/Admin", codes.PermissionDenied},
		{"health open", context.Background(), "/grpc.health.v1.Health/Check", codes.OK},
		{"kube caller trusted", WithCaller(context.Background(), "system:serviceaccount:a:b"), "/svc/Read", codes.OK},
		{"kube caller still denied on unmapped", WithCaller(context.Background(), "x"), "/svc/New", codes.PermissionDenied},
		{"no identity", context.Background(), "/svc/Read", codes.Unauthenticated},
	}
	for _, c := range cases {
		err := checkMethod(c.ctx, perms, c.method)
		got := codes.OK
		if err != nil {
			got = apperror.From(err).Code
		}
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if err := checkMethod(context.Background(), nil, "/svc/Anything"); err != nil {
		t.Errorf("no map configured must not enforce: %v", err)
	}
}
