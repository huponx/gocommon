package grpcserver

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
)

type Server struct {
	GRPC   *grpc.Server
	Health *health.Server
}

func New(opts ...Option) *Server {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}

	// Method permissions are deny by default; the services the server registers itself are
	// opened to any authenticated caller (reflection only exists when explicitly enabled).
	if o.methodPerms != nil {
		if o.enableReflection {
			o.methodPerms["/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"] = Public
			o.methodPerms["/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"] = Public
		}
		if o.enableHealth {
			o.methodPerms["/grpc.health.v1.Health/Check"] = Public
			o.methodPerms["/grpc.health.v1.Health/Watch"] = Public
		}
	}

	unary := []grpc.UnaryServerInterceptor{
		unaryRecovery(),
		unaryRequestContext(),
		unaryAuth(o.auth),
		unaryLogging(o.logger),
		unaryMethodPerms(o.methodPerms),
	}
	stream := []grpc.StreamServerInterceptor{
		streamRecovery(),
		streamRequestContext(),
		streamAuth(o.auth),
		streamLogging(o.logger),
		streamMethodPerms(o.methodPerms),
	}

	serverOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unary...),
		grpc.ChainStreamInterceptor(stream...),
		grpc.MaxRecvMsgSize(o.maxRecvMsgSize),
		grpc.MaxSendMsgSize(o.maxSendMsgSize),
		grpc.KeepaliveParams(o.keepalive),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             o.keepalive.Time / 2,
			PermitWithoutStream: true,
		}),
	}
	serverOpts = append(serverOpts, o.extra...)

	s := &Server{GRPC: grpc.NewServer(serverOpts...)}
	if o.enableHealth {
		s.Health = health.NewServer()
		healthpb.RegisterHealthServer(s.GRPC, s.Health)
		s.Health.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	}
	if o.enableReflection {
		reflection.Register(s.GRPC)
	}
	return s
}

func (s *Server) SetServing(service string, serving bool) {
	if s.Health == nil {
		return
	}
	status := healthpb.HealthCheckResponse_SERVING
	if !serving {
		status = healthpb.HealthCheckResponse_NOT_SERVING
	}
	s.Health.SetServingStatus(service, status)
}

func (s *Server) Stop(ctx context.Context) {
	if s.Health != nil {
		s.Health.Shutdown()
	}
	done := make(chan struct{})
	go func() {
		s.GRPC.GracefulStop()
		close(done)
	}()
	select {
	case <-ctx.Done():
		s.GRPC.Stop()
	case <-done:
	}
}
