// Package authn carries the authenticated caller (Principal) through a context. It is
// transport neutral: grpcserver and httpx both fill it from a verified JWT.
package authn

import (
	"context"
	"strings"

	"github.com/huponx/gocommon/authz"
	"github.com/huponx/gocommon/jwtx"
)

// Principal is the verified identity of the caller.
type Principal struct {
	// Subject is the user or service the token was issued for.
	Subject string
	// ClientID is the OAuth client the token was issued to.
	ClientID string
	// TokenID is the jti of the access token.
	TokenID string
	// SessionID is the identity session (sid) the token belongs to, if any.
	SessionID string
	Roles     []string
	Scopes    []string
	// Perms are the permissions granted on this service's audience.
	Perms []string
	AMR   []string
	// Actor is the party acting on behalf of the subject (token exchange), nil for a direct call.
	Actor *jwtx.Actor
	// Claims are the verified claims.
	Claims *jwtx.Claims
	// Raw is the compact token. It is the subject token of a token exchange when this service
	// calls another one on behalf of the caller. Never log it.
	Raw string
}

// FromClaims builds the principal of verified claims.
func FromClaims(c *jwtx.Claims) *Principal {
	client := c.ClientID
	if client == "" {
		client = c.AZP
	}
	return &Principal{
		Subject:   c.Subject,
		ClientID:  client,
		TokenID:   c.ID,
		SessionID: c.SessionID,
		Roles:     c.Roles,
		Scopes:    c.Scopes(),
		Perms:     c.Perms,
		AMR:       c.AMR,
		Actor:     c.Act,
		Claims:    c,
	}
}

// Can reports whether the principal holds the permission.
func (p *Principal) Can(perm string) bool {
	return p != nil && authz.Allowed(p.Perms, perm)
}

// HasScope reports whether the token carries the scope.
func (p *Principal) HasScope(scope string) bool {
	if p == nil {
		return false
	}
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole reports whether the principal has the role.
func (p *Principal) HasRole(role string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsService reports whether the token is a service token (client credentials): the subject is
// the client itself.
func (p *Principal) IsService() bool {
	return p != nil && p.Subject != "" && p.Subject == p.ClientID
}

// ActorChain renders the delegation chain "gatekeeper>billing" (most recent first), or "".
func (p *Principal) ActorChain() string {
	if p == nil || p.Actor == nil {
		return ""
	}
	var parts []string
	for a := p.Actor; a != nil; a = a.Act {
		parts = append(parts, a.Subject)
	}
	return strings.Join(parts, ">")
}

type ctxKey struct{}

// WithPrincipal returns a context that carries the principal.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// FromContext returns the principal, or nil when the request was not authenticated by a JWT.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}
