// Package tokenexchange is the client of the identity token endpoint for service to service
// calls: client credentials (the service acts as itself) and RFC 8693 token exchange (the
// service acts on behalf of a user, the new token has another audience and an "act" claim).
//
// Tokens are cached until shortly before they expire; concurrent requests for the same token
// share one call.
package tokenexchange

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"crypto/sha256"
	"encoding/hex"
)

const (
	grantClientCredentials = "client_credentials"
	grantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess        = "urn:ietf:params:oauth:token-type:access_token"
)

// ErrDenied means identity refused the request (invalid client, exchange not allowed by the
// policy, invalid subject token). It is not worth retrying.
var ErrDenied = errors.New("tokenexchange: denied")

// ErrUnavailable means identity could not be reached or failed.
var ErrUnavailable = errors.New("tokenexchange: identity unavailable")

// Config configures a Client.
type Config struct {
	// TokenURL is the token endpoint of identity, for example http://identity:8080/oauth2/token.
	TokenURL string
	// ClientID and ClientSecret authenticate this service (client_secret_basic).
	ClientID     string
	ClientSecret string
	// HTTPClient used for the calls (default: 5 second timeout).
	HTTPClient *http.Client
	// EarlyExpiry is how long before the expiry a cached token is dropped (default 15 seconds).
	EarlyExpiry time.Duration
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Client requests and caches tokens.
type Client struct {
	cfg Config

	mu    sync.Mutex
	cache map[string]cached
	locks map[string]*sync.Mutex
}

type cached struct {
	token   string
	expires time.Time
}

// New validates the config.
func New(cfg Config) (*Client, error) {
	if cfg.TokenURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("tokenexchange: token url, client id and client secret are required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.EarlyExpiry <= 0 {
		cfg.EarlyExpiry = 15 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Client{cfg: cfg, cache: map[string]cached{}, locks: map[string]*sync.Mutex{}}, nil
}

// ServiceToken returns a token of this service (grant client_credentials) for the audience.
func (c *Client) ServiceToken(ctx context.Context, audience string) (string, error) {
	if audience == "" {
		return "", errors.New("tokenexchange: audience is required")
	}
	form := url.Values{"grant_type": {grantClientCredentials}, "audience": {audience}}
	return c.get(ctx, "cc|"+audience, form)
}

// ExchangeToken trades the subject token (the access token of the user, issued for this
// service) for a token of the same user for the audience. identity allows it only when a
// policy lets this client exchange for that audience; the new token has a short life, an
// "act" claim naming this service, and no refresh token.
func (c *Client) ExchangeToken(ctx context.Context, subjectToken, audience string, scopes ...string) (string, error) {
	if subjectToken == "" || audience == "" {
		return "", errors.New("tokenexchange: subject token and audience are required")
	}
	sort.Strings(scopes)
	scope := strings.Join(scopes, " ")
	form := url.Values{
		"grant_type":           {grantTokenExchange},
		"subject_token":        {subjectToken},
		"subject_token_type":   {tokenTypeAccess},
		"requested_token_type": {tokenTypeAccess},
		"audience":             {audience},
	}
	if scope != "" {
		form.Set("scope", scope)
	}
	sum := sha256.Sum256([]byte(subjectToken))
	return c.get(ctx, "tx|"+hex.EncodeToString(sum[:])+"|"+audience+"|"+scope, form)
}

func (c *Client) get(ctx context.Context, key string, form url.Values) (string, error) {
	if tok, ok := c.lookup(key); ok {
		return tok, nil
	}
	// one request per key at a time, the others reuse its result
	lock := c.keyLock(key)
	lock.Lock()
	defer lock.Unlock()
	if tok, ok := c.lookup(key); ok {
		return tok, nil
	}

	tok, ttl, err := c.request(ctx, form)
	if err != nil {
		return "", err
	}
	if ttl > c.cfg.EarlyExpiry {
		c.mu.Lock()
		c.sweep()
		c.cache[key] = cached{token: tok, expires: c.cfg.Now().Add(ttl - c.cfg.EarlyExpiry)}
		c.mu.Unlock()
	}
	return tok, nil
}

func (c *Client) lookup(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || !c.cfg.Now().Before(e.expires) {
		return "", false
	}
	return e.token, true
}

func (c *Client) keyLock(key string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	l, ok := c.locks[key]
	if !ok {
		l = &sync.Mutex{}
		c.locks[key] = l
	}
	return l
}

// sweep drops expired entries (and their locks) once the cache grows; callers hold c.mu.
func (c *Client) sweep() {
	if len(c.cache) < 1024 {
		return
	}
	now := c.cfg.Now()
	for k, e := range c.cache {
		if !now.Before(e.expires) {
			delete(c.cache, k)
			delete(c.locks, k)
		}
	}
	if len(c.cache) >= 4096 { // everything is still fresh: start over rather than grow
		c.cache = map[string]cached{}
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func (c *Client) request(ctx context.Context, form url.Values) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))

	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)

	switch {
	case resp.StatusCode == http.StatusOK && tr.AccessToken != "":
		return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return "", 0, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	default:
		return "", 0, fmt.Errorf("%w: %s %s", ErrDenied, tr.Error, tr.Description)
	}
}
