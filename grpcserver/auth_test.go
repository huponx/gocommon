package grpcserver

import (
	"context"
	"testing"

	"github.com/huponx/gocommon/apperror"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

func TestBearerTokenMatch(t *testing.T) {
	fn := BearerToken("s3cret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(MDAuthorization, "Bearer s3cret"))
	if _, err := fn(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBearerTokenCaseInsensitiveScheme(t *testing.T) {
	fn := BearerToken("s3cret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(MDAuthorization, "bearer s3cret"))
	if _, err := fn(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBearerTokenMissing(t *testing.T) {
	fn := BearerToken("s3cret")
	_, err := fn(context.Background())
	if apperror.From(err).Code != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
}

func TestBearerTokenWrong(t *testing.T) {
	fn := BearerToken("s3cret")
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(MDAuthorization, "Bearer other"))
	_, err := fn(ctx)
	if apperror.From(err).Code != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
}

func TestWithBearerAuthPanicsOnEmpty(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	WithBearerAuth("  ")
}

func TestWithOptionalBearerAuthEmptyIsNoop(t *testing.T) {
	o := defaultOptions()
	WithOptionalBearerAuth("")(&o)
	if o.auth != nil {
		t.Fatal("expected no auth")
	}
}

func TestHealthSkipsAuth(t *testing.T) {
	fn := BearerToken("s3cret")
	called := false
	interceptor := unaryAuth(fn)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/grpc.health.v1.Health/Check",
	}, func(ctx context.Context, req any) (any, error) {
		called = true
		return nil, nil
	})
	if err != nil || !called {
		t.Fatalf("health should skip auth: called=%v err=%v", called, err)
	}
}

func TestUnaryAuthRejectsAppMethod(t *testing.T) {
	fn := BearerToken("s3cret")
	interceptor := unaryAuth(fn)
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/courier.v1.CourierService/SendNotification",
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not run")
		return nil, nil
	})
	if apperror.From(err).Code != codes.Unauthenticated {
		t.Fatalf("code %v", err)
	}
}
