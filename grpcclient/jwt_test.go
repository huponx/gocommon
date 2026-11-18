package grpcclient

import (
	"context"
	"errors"
	"testing"

	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/tokenexchange"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeProvider struct {
	service, exchange  string
	err                error
	gotSubject, gotAud string
}

func (f *fakeProvider) ServiceToken(_ context.Context, aud string) (string, error) {
	f.gotAud = aud
	return f.service, f.err
}

func (f *fakeProvider) ExchangeToken(_ context.Context, subject, aud string, _ ...string) (string, error) {
	f.gotSubject, f.gotAud = subject, aud
	return f.exchange, f.err
}

func sentAuth(t *testing.T, o options, ctx context.Context) (string, error) {
	t.Helper()
	var got string
	err := unaryCtxToken(o.ctxToken)(ctx, "/svc/M", nil, nil, nil, func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, _ := metadata.FromOutgoingContext(ctx)
		if v := md.Get("authorization"); len(v) > 0 {
			got = v[0]
		}
		return nil
	})
	return got, err
}

func TestWithServiceToken(t *testing.T) {
	p := &fakeProvider{service: "svc-token"}
	var o options
	WithServiceToken(p, "courier")(&o)
	got, err := sentAuth(t, o, context.Background())
	if err != nil || got != "Bearer svc-token" || p.gotAud != "courier" {
		t.Fatalf("%q %v aud=%q", got, err, p.gotAud)
	}
}

func TestWithTokenExchangeUsesCallerToken(t *testing.T) {
	p := &fakeProvider{service: "svc-token", exchange: "ex-token"}
	var o options
	WithTokenExchange(p, "bill")(&o)

	ctx := authn.WithPrincipal(context.Background(), &authn.Principal{Subject: "u", Raw: "user-token"})
	got, err := sentAuth(t, o, ctx)
	if err != nil || got != "Bearer ex-token" || p.gotSubject != "user-token" || p.gotAud != "bill" {
		t.Fatalf("%q %v %+v", got, err, p)
	}

	// no principal: the service speaks for itself
	got, err = sentAuth(t, o, context.Background())
	if err != nil || got != "Bearer svc-token" {
		t.Fatalf("fallback %q %v", got, err)
	}
}

func TestCallerAuthorizationIsKept(t *testing.T) {
	p := &fakeProvider{service: "svc-token"}
	var o options
	WithServiceToken(p, "x")(&o)
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer mine")
	got, _ := sentAuth(t, o, ctx)
	if got != "Bearer mine" {
		t.Fatalf("got %q", got)
	}
}

func TestTokenErrorsFailTheCall(t *testing.T) {
	var o options
	WithServiceToken(&fakeProvider{err: tokenexchange.ErrDenied}, "x")(&o)
	if _, err := sentAuth(t, o, context.Background()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("denied: %v", err)
	}
	WithServiceToken(&fakeProvider{err: errors.New("boom")}, "x")(&o)
	if _, err := sentAuth(t, o, context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("unavailable: %v", err)
	}
}
