package grpcserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/huponx/gocommon/apperror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

const (
	defaultSATokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultSACAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultCacheTTL    = 60 * time.Second
	maxCacheEntries    = 4096
	tokenReviewPath    = "/apis/authentication.k8s.io/v1/tokenreviews"
)

// KubeAuthConfig configures ServiceAccount token authentication.
//
// The caller sends a projected ServiceAccount token (audience Audience) as
// "authorization: Bearer <token>". The server asks the Kubernetes API server to
// review it (TokenReview) with its own ServiceAccount, which therefore needs the
// ClusterRole system:auth-delegator, and accepts it only when the audience matches
// and the user (system:serviceaccount:<namespace>:<name>) is in AllowedSubjects.
type KubeAuthConfig struct {
	// Audience the token must have been issued for (required).
	Audience string
	// AllowedSubjects are the accepted usernames, for example
	// "system:serviceaccount:billing:billing-api". An empty list rejects every caller.
	AllowedSubjects []string
	// CacheTTL is how long an accepted token is remembered (default 60s). It is capped by
	// the expiry of the token when that can be read.
	CacheTTL time.Duration

	// APIURL is the API server base URL. Default: https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT,
	// else https://kubernetes.default.svc.
	APIURL string
	// TokenPath is the ServiceAccount token of this process (default: the in-cluster path).
	TokenPath string
	// CAPath is the cluster CA used to reach the API server (default: the in-cluster path).
	CAPath string
	// HTTPClient overrides the client (tests); CAPath is ignored when it is set.
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

type callerKey struct{}

// CallerFromContext returns the authenticated caller (the Kubernetes username) put in
// the context by KubeAuth, or "" when the request was not authenticated that way.
func CallerFromContext(ctx context.Context) string {
	s, _ := ctx.Value(callerKey{}).(string)
	return s
}

// WithCaller returns a context that carries the caller name.
func WithCaller(ctx context.Context, caller string) context.Context {
	return context.WithValue(ctx, callerKey{}, caller)
}

// WithKubeAuth enables ServiceAccount token authentication. It panics when the
// configuration is invalid so the process cannot start unprotected.
func WithKubeAuth(cfg KubeAuthConfig) Option {
	fn, err := KubeAuth(cfg)
	if err != nil {
		panic("grpcserver: WithKubeAuth: " + err.Error())
	}
	return WithAuth(fn)
}

// KubeAuth returns an AuthFunc that verifies ServiceAccount tokens, see KubeAuthConfig.
func KubeAuth(cfg KubeAuthConfig) (AuthFunc, error) {
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	if cfg.Audience == "" {
		return nil, errors.New("audience is required")
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = defaultCacheTTL
	}
	if cfg.TokenPath == "" {
		cfg.TokenPath = defaultSATokenPath
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL()
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	if cfg.HTTPClient == nil {
		client, err := inClusterClient(cfg.CAPath)
		if err != nil {
			return nil, err
		}
		cfg.HTTPClient = client
	}
	allowed := make(map[string]struct{}, len(cfg.AllowedSubjects))
	for _, s := range cfg.AllowedSubjects {
		if s = strings.TrimSpace(s); s != "" {
			allowed[s] = struct{}{}
		}
	}
	k := &kubeAuth{cfg: cfg, allowed: allowed, cache: map[[32]byte]cacheEntry{}}
	return k.authenticate, nil
}

type cacheEntry struct {
	caller  string
	expires time.Time
}

type kubeAuth struct {
	cfg     KubeAuthConfig
	allowed map[string]struct{}

	mu    sync.Mutex
	cache map[[32]byte]cacheEntry
}

func (k *kubeAuth) authenticate(ctx context.Context) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	token := bearerFromMD(md)
	if token == "" {
		return ctx, apperror.Unauthenticated("unauthenticated")
	}
	key := sha256.Sum256([]byte(token))
	now := k.cfg.Now()

	if caller, ok := k.cached(key, now); ok {
		return WithCaller(ctx, caller), nil
	}

	user, err := k.review(ctx, token)
	if err != nil {
		return ctx, err
	}
	if _, ok := k.allowed[user]; !ok {
		return ctx, apperror.PermissionDenied("caller is not allowed")
	}

	ttl := k.cfg.CacheTTL
	if exp, ok := tokenExpiry(token); ok {
		if left := exp.Sub(now); left < ttl {
			ttl = left
		}
	}
	if ttl > 0 {
		k.store(key, cacheEntry{caller: user, expires: now.Add(ttl)}, now)
	}
	return WithCaller(ctx, user), nil
}

func (k *kubeAuth) cached(key [32]byte, now time.Time) (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.cache[key]
	if !ok {
		return "", false
	}
	if !now.Before(e.expires) {
		delete(k.cache, key)
		return "", false
	}
	return e.caller, true
}

func (k *kubeAuth) store(key [32]byte, e cacheEntry, now time.Time) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.cache) >= maxCacheEntries {
		for h, old := range k.cache {
			if !now.Before(old.expires) {
				delete(k.cache, h)
			}
		}
		if len(k.cache) >= maxCacheEntries {
			k.cache = map[[32]byte]cacheEntry{}
		}
	}
	k.cache[key] = e
}

type tokenReviewRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Token     string   `json:"token"`
		Audiences []string `json:"audiences"`
	} `json:"spec"`
}

type tokenReviewResponse struct {
	Status struct {
		Authenticated bool     `json:"authenticated"`
		Audiences     []string `json:"audiences"`
		Error         string   `json:"error"`
		User          struct {
			Username string `json:"username"`
		} `json:"user"`
	} `json:"status"`
}

// review asks the API server who the token belongs to. Transport and API errors fail
// closed with Unavailable; a rejected token is Unauthenticated.
func (k *kubeAuth) review(ctx context.Context, token string) (string, error) {
	own, err := os.ReadFile(k.cfg.TokenPath)
	if err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", fmt.Errorf("read service account token: %w", err))
	}

	var body tokenReviewRequest
	body.APIVersion = "authentication.k8s.io/v1"
	body.Kind = "TokenReview"
	body.Spec.Token = token
	body.Spec.Audiences = []string{k.cfg.Audience}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.cfg.APIURL+tokenReviewPath, bytes.NewReader(payload))
	if err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))

	resp, err := k.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", fmt.Errorf("token review: %w", err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", fmt.Errorf("token review: %w", err))
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable",
			fmt.Errorf("token review: API server answered %d", resp.StatusCode))
	}
	var out tokenReviewResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", apperror.Wrap(codes.Unavailable, "authentication unavailable", fmt.Errorf("token review: %w", err))
	}
	if !out.Status.Authenticated || out.Status.User.Username == "" {
		return "", apperror.Unauthenticated("unauthenticated")
	}
	if !containsString(out.Status.Audiences, k.cfg.Audience) {
		return "", apperror.Unauthenticated("unauthenticated")
	}
	return out.Status.User.Username, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// tokenExpiry reads the exp claim of a JWT WITHOUT verifying it. It is only used to cap
// the cache lifetime; the token itself was already accepted by the API server.
func tokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0), true
}

func defaultAPIURL() string {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return "https://kubernetes.default.svc"
	}
	if strings.Contains(host, ":") { // IPv6
		host = "[" + host + "]"
	}
	if port == "" {
		port = "443"
	}
	return "https://" + host + ":" + port
}

func inClusterClient(caPath string) (*http.Client, error) {
	if caPath == "" {
		caPath = defaultSACAPath
	}
	pem, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA %s: %w", caPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("cluster CA %s has no certificate", caPath)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}
