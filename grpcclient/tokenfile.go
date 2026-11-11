package grpcclient

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// tokenFile reads a token from a file and re-reads it when the file changes. It is meant
// for a projected ServiceAccount token: the kubelet rotates the file before it expires.
type tokenFile struct {
	path string

	mu      sync.Mutex
	token   string
	modTime time.Time
	size    int64
}

func newTokenFile(path string) *tokenFile {
	return &tokenFile{path: path}
}

// Token returns the current token. The file is stat-ed on every call (cheap) and only
// read when its modification time or size changed.
func (f *tokenFile) Token() (string, error) {
	st, err := os.Stat(f.path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.token != "" && st.ModTime().Equal(f.modTime) && st.Size() == f.size {
		return f.token, nil
	}
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", f.path)
	}
	f.token, f.modTime, f.size = tok, st.ModTime(), st.Size()
	return tok, nil
}

// tokenSource returns the token to send; an empty token with a nil error means "send nothing".
type tokenSource func() (string, error)

func (o options) tokenSource() tokenSource {
	if o.bearerTokenFile != "" {
		return newTokenFile(o.bearerTokenFile).Token
	}
	token := o.bearerToken
	return func() (string, error) { return token, nil }
}

func unaryBearerSource(src tokenSource) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		token, err := src()
		if err != nil {
			return status.Error(codes.Unavailable, err.Error())
		}
		return invoker(appendBearer(ctx, token), method, req, reply, cc, opts...)
	}
}

func streamBearerSource(src tokenSource) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		token, err := src()
		if err != nil {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		return streamer(appendBearer(ctx, token), desc, cc, method, opts...)
	}
}

// WithBearerTokenFile attaches authorization: Bearer <contents of the file> to every call
// when the caller has not already set that metadata key. The file is re-read when it
// changes, so a rotated projected ServiceAccount token is picked up without a restart.
// A missing or empty file fails the call with codes.Unavailable instead of sending the
// request unauthenticated. It takes precedence over WithBearerToken; an empty path is a no-op.
func WithBearerTokenFile(path string) Option {
	return func(o *options) {
		o.bearerTokenFile = strings.TrimSpace(path)
	}
}
