package grpcclient

import (
	"context"
	"time"

	"github.com/huponx/gocommon/logging"
	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const mdAuthorization = "authorization"

func appendBearer(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	md, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		md = md.Copy()
	} else {
		md = metadata.MD{}
	}
	if len(md.Get(mdAuthorization)) > 0 {
		return ctx
	}
	md.Set(mdAuthorization, "Bearer "+token)
	return metadata.NewOutgoingContext(ctx, md)
}

func unaryRequestContext() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(requestctx.AppendOutgoing(ctx), method, req, reply, cc, opts...)
	}
}

func streamRequestContext() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(requestctx.AppendOutgoing(ctx), desc, cc, method, opts...)
	}
}

func unaryTimeout(d time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if d > 0 {
			if _, ok := ctx.Deadline(); !ok {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, d)
				defer cancel()
			}
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// Stream RPCs keep the caller deadline; a default timeout here would cancel
// the stream as soon as the interceptor returns.

func unaryLogging(base *zap.Logger) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = logging.WithCtx(ctx, base)
		start := time.Now()
		err := invoker(ctx, method, req, reply, cc, opts...)
		st, _ := status.FromError(err)
		logging.FromCtx(ctx).Info("grpc client request",
			zap.String("grpc.method", method),
			zap.String("grpc.code", st.Code().String()),
			zap.Duration("latency", time.Since(start)),
		)
		return err
	}
}

func streamLogging(base *zap.Logger) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = logging.WithCtx(ctx, base)
		start := time.Now()
		stream, err := streamer(ctx, desc, cc, method, opts...)
		st, _ := status.FromError(err)
		logging.FromCtx(ctx).Info("grpc client stream",
			zap.String("grpc.method", method),
			zap.String("grpc.code", st.Code().String()),
			zap.Duration("latency", time.Since(start)),
		)
		return stream, err
	}
}
