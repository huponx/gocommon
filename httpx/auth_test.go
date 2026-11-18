package httpx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/jwtx"
)

func authRouter(t *testing.T) (*gin.Engine, func(perms ...string) string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, _ := jwtx.NewSigner(k, "k1")
	v, err := jwtx.NewVerifier(jwtx.VerifierConfig{Issuer: "iss", Audience: "bill", Keys: jwtx.StaticKeySet{"k1": s.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	r := gin.New()
	r.Use(JWTAuth(v))
	r.GET("/read", RequirePermission("bill:read"), func(c *gin.Context) {
		c.String(200, authn.FromContext(c.Request.Context()).Subject)
	})
	r.GET("/none", RequirePermission(), func(c *gin.Context) { c.Status(200) })
	mint := func(perms ...string) string {
		raw, err := s.Sign(&jwtx.Claims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "iss", Subject: "u1", Audience: jwt.ClaimStrings{"bill"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)), IssuedAt: jwt.NewNumericDate(time.Now()), ID: "j"},
			Type: jwtx.TypeAccess, Perms: perms,
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	return r, mint
}

func get(r *gin.Engine, path, auth string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestJWTAuthAndRequirePermission(t *testing.T) {
	r, mint := authRouter(t)
	cases := []struct {
		name, path, auth string
		want             int
	}{
		{"no token", "/read", "", 401},
		{"garbage", "/read", "Bearer nope", 401},
		{"wrong scheme", "/read", "Basic abc", 401},
		{"ok", "/read", "Bearer " + mint("bill:read"), 200},
		{"lowercase scheme", "/read", "bearer " + mint("bill:*"), 200},
		{"missing permission", "/read", "Bearer " + mint("bill:write"), 403},
		{"no requirement refuses", "/none", "Bearer " + mint("*"), 403},
	}
	for _, c := range cases {
		if w := get(r, c.path, c.auth); w.Code != c.want {
			t.Errorf("%s: %d want %d (%s)", c.name, w.Code, c.want, w.Body.String())
		}
	}
	if w := get(r, "/read", ""); w.Header().Get("WWW-Authenticate") == "" {
		t.Error("401 needs WWW-Authenticate")
	}
}
