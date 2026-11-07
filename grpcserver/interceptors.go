package grpcserver

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/huponx/gocommon/logging"
	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func unaryRequestContext() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(requestctx.HydrateIncoming(ctx), req)
	}
}

func streamRequestContext() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return handler(srv, &wrappedServerStream{
			ServerStream: ss,
			ctx:          requestctx.HydrateIncoming(ss.Context()),
		})
	}
}

const healthMethodPrefix = "/grpc.health.v1.Health/"

func isHealthMethod(method string) bool {
	return len(method) >= len(healthMethodPrefix) && method[:len(healthMethodPrefix)] == healthMethodPrefix
}

func unaryAuth(auth AuthFunc) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if auth == nil || isHealthMethod(info.FullMethod) {
			return handler(ctx, req)
		}
		ctx, err := auth(ctx)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func streamAuth(auth AuthFunc) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if auth == nil || isHealthMethod(info.FullMethod) {
			return handler(srv, ss)
		}
		ctx, err := auth(ss.Context())
		if err != nil {
			return err
		}
		return handler(srv, &wrappedServerStream{ServerStream: ss, ctx: ctx})
	}
}

func unaryLogging(base *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = logging.WithCtx(ctx, base)
		start := time.Now()
		resp, err := handler(ctx, req)
		st, _ := status.FromError(err)
		logging.FromCtx(ctx).Info("grpc request",
			zap.String("grpc.method", info.FullMethod),
			zap.String("grpc.code", st.Code().String()),
			zap.Duration("latency", time.Since(start)),
		)
		return resp, err
	}
}

func streamLogging(base *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := logging.WithCtx(ss.Context(), base)
		wrapped := &wrappedServerStream{ServerStream: ss, ctx: ctx}
		start := time.Now()
		err := handler(srv, wrapped)
		st, _ := status.FromError(err)
		logging.FromCtx(ctx).Info("grpc stream",
			zap.String("grpc.method", info.FullMethod),
			zap.String("grpc.code", st.Code().String()),
			zap.Duration("latency", time.Since(start)),
		)
		return err
	}
}

func unaryRecovery() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.FromCtx(ctx).Error("grpc panic",
					zap.String("grpc.method", info.FullMethod),
					zap.Any("panic", rec),
					zap.ByteString("stack", debug.Stack()),
				)
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

func streamRecovery() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.FromCtx(ss.Context()).Error("grpc stream panic",
					zap.String("grpc.method", info.FullMethod),
					zap.Any("panic", rec),
					zap.ByteString("stack", debug.Stack()),
				)
				err = status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(srv, ss)
	}
}

type wrappedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedServerStream) Context() context.Context {
	return w.ctx
}
