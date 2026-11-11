package grpcclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func writeToken(t *testing.T, path, token string, mod time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
}

func TestTokenFileReloadsOnChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	base := time.Unix(1_000_000, 0)
	writeToken(t, path, "one\n", base)
	f := newTokenFile(path)
	if got, err := f.Token(); err != nil || got != "one" {
		t.Fatalf("%q %v", got, err)
	}
	writeToken(t, path, "two-longer", base.Add(time.Minute))
	if got, err := f.Token(); err != nil || got != "two-longer" {
		t.Fatalf("rotated token not picked up: %q %v", got, err)
	}
}

func TestTokenFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := newTokenFile(filepath.Join(dir, "absent")).Token(); err == nil {
		t.Fatal("expected error for a missing file")
	}
	empty := filepath.Join(dir, "empty")
	writeToken(t, empty, " \n", time.Now())
	if _, err := newTokenFile(empty).Token(); err == nil {
		t.Fatal("expected error for an empty file")
	}
}

func authHeader(ctx context.Context) []string {
	md, _ := metadata.FromOutgoingContext(ctx)
	return md.Get(mdAuthorization)
}

func TestUnaryBearerSourceFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "sa-token", time.Now())
	o := defaultOptions()
	WithBearerTokenFile(path)(&o)
	intercept := unaryBearerSource(o.tokenSource())

	var got []string
	err := intercept(context.Background(), "/svc/M", nil, nil, nil,
		func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			got = authHeader(ctx)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "Bearer sa-token" {
		t.Fatalf("header %v", got)
	}
}

func TestUnaryBearerSourceMissingFileFailsTheCall(t *testing.T) {
	o := defaultOptions()
	WithBearerTokenFile(filepath.Join(t.TempDir(), "absent"))(&o)
	called := false
	err := unaryBearerSource(o.tokenSource())(context.Background(), "/svc/M", nil, nil, nil,
		func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
			called = true
			return nil
		})
	if status.Code(err) != codes.Unavailable || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestBearerSourceStaticTokenAndEmpty(t *testing.T) {
	o := defaultOptions()
	WithBearerToken(" abc ")(&o)
	tok, err := o.tokenSource()()
	if err != nil || tok != "abc" {
		t.Fatalf("%q %v", tok, err)
	}
	empty := defaultOptions().tokenSource()
	if tok, err := empty(); err != nil || tok != "" {
		t.Fatalf("%q %v", tok, err)
	}
}

func TestBearerTokenFileWinsOverStaticToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "from-file", time.Now())
	o := defaultOptions()
	WithBearerToken("static")(&o)
	WithBearerTokenFile(path)(&o)
	if tok, _ := o.tokenSource()(); tok != "from-file" {
		t.Fatal(tok)
	}
}

func TestBearerSourceKeepsExistingHeader(t *testing.T) {
	ctx := metadata.AppendToOutgoingContext(context.Background(), mdAuthorization, "Bearer explicit")
	var got []string
	_ = unaryBearerSource(func() (string, error) { return "other", nil })(ctx, "/svc/M", nil, nil, nil,
		func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			got = authHeader(ctx)
			return nil
		})
	if len(got) != 1 || got[0] != "Bearer explicit" {
		t.Fatalf("header %v", got)
	}
}
