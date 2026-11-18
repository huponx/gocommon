package grpcserver

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type AuthFunc func(ctx context.Context) (context.Context, error)

type options struct {
	logger           *zap.Logger
	auth             AuthFunc
	methodPerms      map[string]string
	enableReflection bool
	enableHealth     bool
	maxRecvMsgSize   int
	maxSendMsgSize   int
	keepalive        keepalive.ServerParameters
	extra            []grpc.ServerOption
}

func defaultOptions() options {
	return options{
		logger:         zap.NewNop(),
		enableHealth:   true,
		maxRecvMsgSize: 8 * 1024 * 1024,
		maxSendMsgSize: 8 * 1024 * 1024,
		keepalive: keepalive.ServerParameters{
			MaxConnectionIdle: 15 * time.Minute,
			Time:              5 * time.Minute,
			Timeout:           20 * time.Second,
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

func WithAuth(fn AuthFunc) Option {
	return func(o *options) {
		o.auth = fn
	}
}

func WithReflection(enable bool) Option {
	return func(o *options) {
		o.enableReflection = enable
	}
}

func WithHealth(enable bool) Option {
	return func(o *options) {
		o.enableHealth = enable
	}
}

func WithMaxMsgSize(recv, send int) Option {
	return func(o *options) {
		if recv > 0 {
			o.maxRecvMsgSize = recv
		}
		if send > 0 {
			o.maxSendMsgSize = send
		}
	}
}

func WithServerOptions(opts ...grpc.ServerOption) Option {
	return func(o *options) {
		o.extra = append(o.extra, opts...)
	}
}
