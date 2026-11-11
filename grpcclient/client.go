package grpcclient

import (
	"context"
	"crypto/tls"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func Dial(ctx context.Context, target string, opts ...Option) (*grpc.ClientConn, error) {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	src := o.tokenSource()
	unary := []grpc.UnaryClientInterceptor{
		unaryRequestContext(),
		unaryBearerSource(src),
		unaryTimeout(o.timeout),
		unaryLogging(o.logger),
	}
	stream := []grpc.StreamClientInterceptor{
		streamRequestContext(),
		streamBearerSource(src),
		streamLogging(o.logger),
	}

	dialOpts := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unary...),
		grpc.WithChainStreamInterceptor(stream...),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(o.maxRecvMsgSize),
			grpc.MaxCallSendMsgSize(o.maxSendMsgSize),
		),
		grpc.WithKeepaliveParams(o.keepalive),
		grpc.WithTransportCredentials(transportCreds(o)),
	}
	dialOpts = append(dialOpts, o.extra...)

	conn, err := grpc.NewClient(target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	if o.block {
		conn.Connect()
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return nil, fmt.Errorf("dial %s: %w", target, ctx.Err())
		default:
		}
	}
	return conn, nil
}

func transportCreds(o options) credentials.TransportCredentials {
	if o.insecure {
		return insecure.NewCredentials()
	}
	cfg := o.tlsConfig
	if cfg == nil {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return credentials.NewTLS(cfg)
}
