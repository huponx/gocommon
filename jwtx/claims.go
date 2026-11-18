// Package jwtx signs and verifies the JWTs of the platform (access, ID and logout tokens):
// RS256 or ES256 only, a kid in the header, a jti in the claims, JWKS for key distribution.
package jwtx

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Actor is the party acting on behalf of the subject (RFC 8693 "act" claim). Nested actors
// record a chain of delegations, the outermost is the most recent one.
type Actor struct {
	Subject  string `json:"sub"`
	ClientID string `json:"client_id,omitempty"`
	Act      *Actor `json:"act,omitempty"`
}

// Depth is the number of delegations in the chain (0 for a nil actor).
func (a *Actor) Depth() int {
	n := 0
	for ; a != nil; a = a.Act {
		n++
	}
	return n
}

// Claims are the claims used by the platform on top of the registered ones (iss, sub, aud,
// exp, nbf, iat, jti).
type Claims struct {
	jwt.RegisteredClaims

	Scope string   `json:"scope,omitempty"`
	Roles []string `json:"roles,omitempty"`
	// Perms are the permissions ("resource:action", wildcards allowed) the roles grant on the
	// audience of the token. Identity flattens them so services need no role table.
	Perms     []string `json:"perms,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	AZP       string   `json:"azp,omitempty"`
	Type      string   `json:"typ,omitempty"` // access, id, logout
	Nonce     string   `json:"nonce,omitempty"`
	Act       *Actor   `json:"act,omitempty"`
	AMR       []string `json:"amr,omitempty"`
	ACR       string   `json:"acr,omitempty"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	SessionID string   `json:"sid,omitempty"`
	AtHash    string   `json:"at_hash,omitempty"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	// Events is the "events" claim of a back-channel logout token.
	Events map[string]any `json:"events,omitempty"`
}

// Token types of the "typ" claim.
const (
	TypeAccess = "access"
	TypeID     = "id"
	TypeLogout = "logout"
)

// Scopes splits the space separated scope claim.
func (c *Claims) Scopes() []string {
	return strings.Fields(c.Scope)
}

// HasScope reports whether the token carries the scope.
func (c *Claims) HasScope(scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// HasRole reports whether the token carries the role.
func (c *Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasAMR reports whether the authentication methods include the method (for example "otp").
func (c *Claims) HasAMR(method string) bool {
	for _, m := range c.AMR {
		if m == method {
			return true
		}
	}
	return false
}
