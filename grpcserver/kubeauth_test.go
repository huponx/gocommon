package grpcserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huponx/gocommon/apperror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

const testSubject = "system:serviceaccount:billing:billing-api"

type fakeAPI struct {
	srv   *httptest.Server
	calls atomic.Int32
	// reply decides the answer for a token
	reply func(token string, audiences []string) (status int, body any)
	// ownToken is the last bearer the API server saw (courier's own ServiceAccount token)
	ownToken atomic.Value
}

func newFakeAPI(t *testing.T, reply func(token string, audiences []string) (int, any)) *fakeAPI {
	t.Helper()
	f := &fakeAPI{reply: reply}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		f.ownToken.Store(r.Header.Get("Authorization"))
		if r.Method != http.MethodPost || r.URL.Path != tokenReviewPath {
			http.NotFound(w, r)
			return
		}
		var req tokenReviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		code, body := f.reply(req.Spec.Token, req.Spec.Audiences)
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func review(authenticated bool, user string, audiences ...string) map[string]any {
	return map[string]any{"status": map[string]any{
		"authenticated": authenticated,
		"audiences":     audiences,
		"user":          map[string]any{"username": user},
	}}
}

func newAuth(t *testing.T, api *fakeAPI, mutate func(*KubeAuthConfig)) AuthFunc {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("own-sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := KubeAuthConfig{
		Audience:        "courier",
		AllowedSubjects: []string{testSubject},
		APIURL:          api.srv.URL,
		TokenPath:       tokenPath,
		HTTPClient:      api.srv.Client(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	fn, err := KubeAuth(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fn
}

func bearerCtx(token string) context.Context {
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(MDAuthorization, "Bearer "+token))
}

func codeOf(err error) codes.Code { return apperror.From(err).Code }

func TestKubeAuthAccepts(t *testing.T) {
	api := newFakeAPI(t, func(token string, aud []string) (int, any) {
		if token != "caller-token" || len(aud) != 1 || aud[0] != "courier" {
			return http.StatusOK, review(false, "")
		}
		return http.StatusCreated, review(true, testSubject, "courier")
	})
	fn := newAuth(t, api, nil)
	ctx, err := fn(bearerCtx("caller-token"))
	if err != nil {
		t.Fatal(err)
	}
	if got := CallerFromContext(ctx); got != testSubject {
		t.Fatalf("caller %q", got)
	}
	if got := api.ownToken.Load(); got != "Bearer own-sa-token" {
		t.Fatalf("API server saw %v, want courier's own token without the newline", got)
	}
}

func TestKubeAuthMissingToken(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 200, review(true, testSubject, "courier") })
	fn := newAuth(t, api, nil)
	_, err := fn(context.Background())
	if codeOf(err) != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
	if api.calls.Load() != 0 {
		t.Fatal("no token must not reach the API server")
	}
}

func TestKubeAuthRejectedToken(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(false, "") })
	_, err := newAuth(t, api, nil)(bearerCtx("bad"))
	if codeOf(err) != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthWrongAudienceInAnswer(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "other") })
	_, err := newAuth(t, api, nil)(bearerCtx("t"))
	if codeOf(err) != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthSubjectNotAllowed(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) {
		return 201, review(true, "system:serviceaccount:evil:thing", "courier")
	})
	_, err := newAuth(t, api, nil)(bearerCtx("t"))
	if codeOf(err) != codes.PermissionDenied {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthEmptyAllowedListRejectsEveryone(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "courier") })
	fn := newAuth(t, api, func(c *KubeAuthConfig) { c.AllowedSubjects = nil })
	if _, err := fn(bearerCtx("t")); codeOf(err) != codes.PermissionDenied {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthAPIErrorFailsClosed(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return http.StatusForbidden, map[string]any{} })
	_, err := newAuth(t, api, nil)(bearerCtx("t"))
	if codeOf(err) != codes.Unavailable {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthAPIUnreachableFailsClosed(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "courier") })
	fn := newAuth(t, api, nil)
	api.srv.Close()
	if _, err := fn(bearerCtx("t")); codeOf(err) != codes.Unavailable {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthOwnTokenMissingFailsClosed(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "courier") })
	fn := newAuth(t, api, func(c *KubeAuthConfig) { c.TokenPath = filepath.Join(t.TempDir(), "absent") })
	if _, err := fn(bearerCtx("t")); codeOf(err) != codes.Unavailable {
		t.Fatalf("code %v", err)
	}
}

func TestKubeAuthCacheHitAndExpiry(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "courier") })
	now := time.Unix(1_000_000, 0)
	fn := newAuth(t, api, func(c *KubeAuthConfig) {
		c.CacheTTL = time.Minute
		c.Now = func() time.Time { return now }
	})
	for i := 0; i < 3; i++ {
		if _, err := fn(bearerCtx("same")); err != nil {
			t.Fatal(err)
		}
	}
	if got := api.calls.Load(); got != 1 {
		t.Fatalf("cache hit should make one upstream call, got %d", got)
	}
	if _, err := fn(bearerCtx("other")); err != nil {
		t.Fatal(err)
	}
	if got := api.calls.Load(); got != 2 {
		t.Fatalf("another token is another call, got %d", got)
	}
	now = now.Add(2 * time.Minute)
	if _, err := fn(bearerCtx("same")); err != nil {
		t.Fatal(err)
	}
	if got := api.calls.Load(); got != 3 {
		t.Fatalf("expired entry must be reviewed again, got %d", got)
	}
}

func TestKubeAuthCacheDoesNotKeepRejections(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(false, "") })
	fn := newAuth(t, api, nil)
	for i := 0; i < 2; i++ {
		if _, err := fn(bearerCtx("bad")); err == nil {
			t.Fatal("expected error")
		}
	}
	if got := api.calls.Load(); got != 2 {
		t.Fatalf("rejections are not cached, got %d calls", got)
	}
}

func fakeJWT(exp time.Time) string {
	payload, _ := json.Marshal(map[string]any{"exp": exp.Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(payload) + ".s"
}

func TestKubeAuthCacheCappedByTokenExpiry(t *testing.T) {
	api := newFakeAPI(t, func(string, []string) (int, any) { return 201, review(true, testSubject, "courier") })
	now := time.Unix(1_000_000, 0)
	fn := newAuth(t, api, func(c *KubeAuthConfig) {
		c.CacheTTL = time.Hour
		c.Now = func() time.Time { return now }
	})
	token := fakeJWT(now.Add(30 * time.Second))
	if _, err := fn(bearerCtx(token)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(31 * time.Second) // token expired, long before CacheTTL
	if _, err := fn(bearerCtx(token)); err != nil {
		t.Fatal(err)
	}
	if got := api.calls.Load(); got != 2 {
		t.Fatalf("an expired token must not be served from the cache, got %d calls", got)
	}
}

func TestKubeAuthRequiresAudience(t *testing.T) {
	if _, err := KubeAuth(KubeAuthConfig{HTTPClient: http.DefaultClient}); err == nil {
		t.Fatal("expected error")
	}
}

func TestKubeAuthMissingClusterCA(t *testing.T) {
	_, err := KubeAuth(KubeAuthConfig{Audience: "courier", CAPath: filepath.Join(t.TempDir(), "absent")})
	if err == nil {
		t.Fatal("expected error when the cluster CA cannot be read")
	}
}

func TestWithKubeAuthPanicsOnInvalidConfig(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	WithKubeAuth(KubeAuthConfig{})
}

func TestWithKubeAuthSetsAuth(t *testing.T) {
	o := defaultOptions()
	WithKubeAuth(KubeAuthConfig{Audience: "courier", HTTPClient: http.DefaultClient})(&o)
	if o.auth == nil {
		t.Fatal("expected auth")
	}
}

func TestDefaultAPIURL(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if got := defaultAPIURL(); got != "https://kubernetes.default.svc" {
		t.Fatal(got)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "6443")
	if got := defaultAPIURL(); got != "https://10.0.0.1:6443" {
		t.Fatal(got)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "fd00::1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	if got := defaultAPIURL(); got != "https://[fd00::1]:443" {
		t.Fatal(got)
	}
}

func TestTokenExpiry(t *testing.T) {
	exp := time.Unix(2_000_000, 0)
	if got, ok := tokenExpiry(fakeJWT(exp)); !ok || !got.Equal(exp) {
		t.Fatalf("%v %v", got, ok)
	}
	for _, bad := range []string{"", "a.b", "a.!!!.c", fmt.Sprintf("a.%s.c", base64.RawURLEncoding.EncodeToString([]byte("{}")))} {
		if _, ok := tokenExpiry(bad); ok {
			t.Fatalf("%q should have no expiry", bad)
		}
	}
}

func TestCallerFromContextEmpty(t *testing.T) {
	if CallerFromContext(context.Background()) != "" {
		t.Fatal("expected empty")
	}
	if got := CallerFromContext(WithCaller(context.Background(), "x")); got != "x" {
		t.Fatal(got)
	}
}
