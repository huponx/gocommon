package grpcclient

import (
	"crypto/tls"
	"strings"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type options struct {
	logger          *zap.Logger
	timeout         time.Duration
	insecure        bool
	tlsConfig       *tls.Config
	block           bool
	maxRecvMsgSize  int
	maxSendMsgSize  int
	keepalive       keepalive.ClientParameters
	bearerToken     string
	bearerTokenFile string
	extra           []grpc.DialOption
}

func defaultOptions() options {
	return options{
		logger:         zap.NewNop(),
		timeout:        5 * time.Second,
		insecure:       true,
		maxRecvMsgSize: 8 * 1024 * 1024,
		maxSendMsgSize: 8 * 1024 * 1024,
		keepalive: keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		},
	}
}

type Option func(*options)

func WithLogger(log *zap.Logger) Option {
	return func(o *options) {
		if log != nil {
			o.logger = log
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		o.timeout = d
	}
}

func WithInsecure(insecure bool) Option {
	return func(o *options) {
		o.insecure = insecure
	}
}

func WithTLS(cfg *tls.Config) Option {
	return func(o *options) {
		o.tlsConfig = cfg
		o.insecure = false
	}
}

func WithBlock(block bool) Option {
	return func(o *options) {
		o.block = block
	}
}

func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(o *options) {
		o.extra = append(o.extra, opts...)
	}
}

// WithBearerToken attaches authorization: Bearer <token> when the caller
// has not already set that metadata key. An empty token is a no-op.
func WithBearerToken(token string) Option {
	return func(o *options) {
		o.bearerToken = strings.TrimSpace(token)
	}
}
