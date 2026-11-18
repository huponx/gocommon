// Package oidcclient is the relying party side of OpenID Connect for confidential clients
// (gatekeeper, the BFF): authorization code flow with PKCE, ID token validation, refresh,
// revocation, RP-initiated logout and back-channel logout tokens.
package oidcclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/huponx/gocommon/jwtx"
)

// Provider is the discovery document of the issuer.
type Provider struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// Config configures a Client.
type Config struct {
	// Issuer URL of identity (required); discovery is read from <issuer>/.well-known/openid-configuration.
	Issuer string
	// ClientID, ClientSecret and RedirectURL of this application (required).
	ClientID     string
	ClientSecret string
	RedirectURL  string
	// Scopes requested (default: openid profile email offline_access).
	Scopes []string
	// HTTPClient used for every call (default: 5 second timeout).
	HTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Client talks to one OpenID provider.
type Client struct {
	cfg      Config
	provider Provider
	idv      *jwtx.Verifier
	keys     *jwtx.RemoteKeySet
}

// Discover reads the discovery document and returns a Client. The issuer in the document must
// equal the configured one, otherwise a rogue server could impersonate it.
func Discover(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidcclient: issuer, client id, client secret and redirect url are required")
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Client{cfg: cfg}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidcclient: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidcclient: discovery: status %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&c.provider); err != nil {
		return nil, fmt.Errorf("oidcclient: discovery: %w", err)
	}
	p := c.provider
	if p.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("oidcclient: discovery issuer %q does not match %q", p.Issuer, cfg.Issuer)
	}
	if p.AuthorizationEndpoint == "" || p.TokenEndpoint == "" || p.JWKSURI == "" {
		return nil, errors.New("oidcclient: discovery document is incomplete")
	}

	c.keys, err = jwtx.NewRemoteKeySet(jwtx.RemoteKeySetConfig{URL: p.JWKSURI, HTTPClient: cfg.HTTPClient, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	c.idv, err = jwtx.NewVerifier(jwtx.VerifierConfig{
		Issuer: cfg.Issuer, Audience: cfg.ClientID, Keys: c.keys, Now: cfg.Now,
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Provider returns the discovery document.
func (c *Client) Provider() Provider { return c.provider }

// AuthRequest is what the application must remember between the redirect and the callback
// (in a short lived, signed or server side store bound to the browser).
type AuthRequest struct {
	State, Nonce, Verifier string
}

// AuthURLOptions refine an authorization request.
type AuthURLOptions struct {
	// Prompt is "none", "login", "consent" or "" (default).
	Prompt string
	// MaxAge forces re-authentication when the session is older (seconds, 0 = unset).
	MaxAge int
	// ACRValues requests a level, for example "mfa".
	ACRValues string
	// LoginHint pre-fills the user name.
	LoginHint string
}

// AuthURL builds the authorization URL (code flow, PKCE S256) with a fresh state, nonce and
// code verifier.
func (c *Client) AuthURL(opt AuthURLOptions) (string, AuthRequest, error) {
	req := AuthRequest{State: RandomString(24), Nonce: RandomString(24), Verifier: RandomString(48)}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.cfg.ClientID},
		"redirect_uri":          {c.cfg.RedirectURL},
		"scope":                 {strings.Join(c.cfg.Scopes, " ")},
		"state":                 {req.State},
		"nonce":                 {req.Nonce},
		"code_challenge":        {Challenge(req.Verifier)},
		"code_challenge_method": {"S256"},
	}
	if opt.Prompt != "" {
		q.Set("prompt", opt.Prompt)
	}
	if opt.MaxAge > 0 {
		q.Set("max_age", fmt.Sprint(opt.MaxAge))
	}
	if opt.ACRValues != "" {
		q.Set("acr_values", opt.ACRValues)
	}
	if opt.LoginHint != "" {
		q.Set("login_hint", opt.LoginHint)
	}
	u, err := url.Parse(c.provider.AuthorizationEndpoint)
	if err != nil {
		return "", req, err
	}
	u.RawQuery = q.Encode()
	return u.String(), req, nil
}

// Tokens is the result of a code exchange or a refresh.
type Tokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
	Scope        string
	// ID are the verified claims of the ID token (nil when none was returned).
	ID *jwtx.Claims
}

// Exchange trades the authorization code for tokens and verifies the ID token: signature,
// issuer, audience, expiry, nonce.
func (c *Client) Exchange(ctx context.Context, code string, req AuthRequest) (*Tokens, error) {
	t, err := c.token(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.cfg.RedirectURL},
		"code_verifier": {req.Verifier},
	})
	if err != nil {
		return nil, err
	}
	if t.IDToken == "" {
		return nil, errors.New("oidcclient: no id_token in the response")
	}
	id, err := c.VerifyIDToken(ctx, t.IDToken)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(id.Nonce), []byte(req.Nonce)) != 1 || req.Nonce == "" {
		return nil, errors.New("oidcclient: nonce mismatch")
	}
	if id.AtHash != "" && id.AtHash != AtHash(t.AccessToken) {
		return nil, errors.New("oidcclient: at_hash mismatch")
	}
	t.ID = id
	return t, nil
}

// Refresh trades a refresh token for new tokens. Refresh tokens rotate: store the new one.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Tokens, error) {
	t, err := c.token(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return nil, err
	}
	if t.IDToken != "" {
		if t.ID, err = c.VerifyIDToken(ctx, t.IDToken); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// VerifyIDToken verifies an ID token of this client (no nonce check).
func (c *Client) VerifyIDToken(ctx context.Context, raw string) (*jwtx.Claims, error) {
	id, err := c.idv.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if id.Type != jwtx.TypeID {
		return nil, fmt.Errorf("%w: not an id token", jwtx.ErrInvalidToken)
	}
	return id, nil
}

// VerifyLogoutToken verifies an OpenID back-channel logout token: signature, issuer,
// audience, the logout event, and no nonce. It returns the subject and the session to end;
// at least one of them is set. The caller must also remember the jti to refuse a replay.
func (c *Client) VerifyLogoutToken(ctx context.Context, raw string) (*jwtx.Claims, error) {
	lt, err := c.idv.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}
	if lt.Type != jwtx.TypeLogout {
		return nil, fmt.Errorf("%w: not a logout token", jwtx.ErrInvalidToken)
	}
	if _, ok := lt.Events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		return nil, fmt.Errorf("%w: missing logout event", jwtx.ErrInvalidToken)
	}
	if lt.Nonce != "" {
		return nil, fmt.Errorf("%w: logout token has a nonce", jwtx.ErrInvalidToken)
	}
	if lt.SessionID == "" && lt.Subject == "" {
		return nil, fmt.Errorf("%w: no sub or sid", jwtx.ErrInvalidToken)
	}
	return lt, nil
}

// Revoke revokes a token (RFC 7009). hint is "refresh_token" or "access_token".
func (c *Client) Revoke(ctx context.Context, token, hint string) error {
	if c.provider.RevocationEndpoint == "" {
		return errors.New("oidcclient: provider has no revocation endpoint")
	}
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	resp, err := c.post(ctx, c.provider.RevocationEndpoint, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("oidcclient: revoke: status %d", resp.StatusCode)
	}
	return nil
}

// EndSessionURL builds the RP-initiated logout URL (idTokenHint may be empty).
func (c *Client) EndSessionURL(idTokenHint, postLogoutRedirect, state string) (string, error) {
	if c.provider.EndSessionEndpoint == "" {
		return "", errors.New("oidcclient: provider has no end session endpoint")
	}
	u, err := url.Parse(c.provider.EndSessionEndpoint)
	if err != nil {
		return "", err
	}
	q := url.Values{"client_id": {c.cfg.ClientID}}
	if idTokenHint != "" {
		q.Set("id_token_hint", idTokenHint)
	}
	if postLogoutRedirect != "" {
		q.Set("post_logout_redirect_uri", postLogoutRedirect)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// ErrInvalidGrant means the code or refresh token was refused (expired, used, revoked).
var ErrInvalidGrant = errors.New("oidcclient: invalid grant")

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

func (c *Client) token(ctx context.Context, form url.Values) (*Tokens, error) {
	resp, err := c.post(ctx, c.provider.TokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var tr tokenResponse
	_ = json.Unmarshal(body, &tr)
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		if tr.Error == "invalid_grant" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, tr.Description)
		}
		return nil, fmt.Errorf("oidcclient: token endpoint: status %d %s", resp.StatusCode, tr.Error)
	}
	return &Tokens{
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		IDToken:      tr.IDToken,
		Scope:        tr.Scope,
		ExpiresAt:    c.cfg.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
	}, nil
}

func (c *Client) post(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(c.cfg.ClientID), url.QueryEscape(c.cfg.ClientSecret))
	return c.cfg.HTTPClient.Do(req)
}

// RandomString returns n random bytes, base64url encoded.
func RandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oidcclient: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge is the PKCE S256 code challenge of a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AtHash is the OIDC at_hash of an access token (left half of the SHA-256, base64url).
func AtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}
