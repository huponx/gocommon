package grpcserver

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/huponx/gocommon/apperror"
	"google.golang.org/grpc/metadata"
)

const MDAuthorization = "authorization"

// BearerToken verifies incoming metadata authorization: Bearer <token>.
func BearerToken(expected string) AuthFunc {
	expected = strings.TrimSpace(expected)
	return func(ctx context.Context) (context.Context, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		if !secureEqual(bearerFromMD(md), expected) {
			return ctx, apperror.Unauthenticated("unauthenticated")
		}
		return ctx, nil
	}
}

// WithBearerAuth enables Bearer auth. Panics if token is empty so the
// process cannot start unprotected.
func WithBearerAuth(token string) Option {
	token = strings.TrimSpace(token)
	if token == "" {
		panic("grpcserver: WithBearerAuth requires a non-empty token")
	}
	return WithAuth(BearerToken(token))
}

// WithOptionalBearerAuth enables Bearer auth when token is non-empty;
// otherwise leaves the server unauthenticated.
func WithOptionalBearerAuth(token string) Option {
	token = strings.TrimSpace(token)
	if token == "" {
		return func(*options) {}
	}
	return WithAuth(BearerToken(token))
}

func bearerFromMD(md metadata.MD) string {
	if md == nil {
		return ""
	}
	vals := md.Get(MDAuthorization)
	if len(vals) == 0 {
		return ""
	}
	scheme, rest, ok := strings.Cut(strings.TrimSpace(vals[0]), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

func secureEqual(got, expected string) bool {
	if expected == "" {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1 {
		return true
	}
	return false
}
