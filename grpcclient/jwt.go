package grpcclient

import (
	"context"
	"errors"

	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/tokenexchange"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenProvider is satisfied by *tokenexchange.Client.
type TokenProvider interface {
	// ServiceToken is a token of this service for the audience (client credentials).
	ServiceToken(ctx context.Context, audience string) (string, error)
	// ExchangeToken is a token of the user of subjectToken for the audience (RFC 8693).
	ExchangeToken(ctx context.Context, subjectToken, audience string, scopes ...string) (string, error)
}

// ctxToken returns the token to send for a call, "" to send nothing.
type ctxToken func(ctx context.Context) (string, error)

// WithServiceToken authenticates every call as this service: a client credentials token for
// the audience of the callee (the service name registered in identity). Use it for jobs and
// calls that are not made on behalf of a user.
func WithServiceToken(p TokenProvider, audience string) Option {
	return func(o *options) {
		o.ctxToken = func(ctx context.Context) (string, error) {
			return p.ServiceToken(ctx, audience)
		}
	}
}

// WithTokenExchange authenticates every call on behalf of the user of the request: when the
// context carries an authenticated principal (authn.FromContext, filled by the server
// interceptor or by gatekeeper) its token is exchanged for a token for the audience of the
// callee; the callee sees the user as subject and this service in the "act" claim. Without a
// principal (a background job) it falls back to the service's own token.
func WithTokenExchange(p TokenProvider, audience string) Option {
	return func(o *options) {
		o.ctxToken = func(ctx context.Context) (string, error) {
			if pr := authn.FromContext(ctx); pr != nil && pr.Raw != "" {
				return p.ExchangeToken(ctx, pr.Raw, audience)
			}
			return p.ServiceToken(ctx, audience)
		}
	}
}

func tokenError(err error) error {
	switch {
	case errors.Is(err, tokenexchange.ErrDenied):
		return status.Error(codes.PermissionDenied, "token request denied")
	default:
		return status.Error(codes.Unavailable, "token unavailable")
	}
}

func unaryCtxToken(src ctxToken) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if src == nil {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		token, err := src(ctx)
		if err != nil {
			return tokenError(err)
		}
		return invoker(appendBearer(ctx, token), method, req, reply, cc, opts...)
	}
}

func streamCtxToken(src ctxToken) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if src == nil {
			return streamer(ctx, desc, cc, method, opts...)
		}
		token, err := src(ctx)
		if err != nil {
			return nil, tokenError(err)
		}
		return streamer(appendBearer(ctx, token), desc, cc, method, opts...)
	}
}
