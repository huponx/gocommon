package permsync

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fake struct {
	calls int
	fail  int
	err   error
	last  *identityv1.RegisterPermissionsRequest
}

func (f *fake) RegisterPermissions(_ context.Context, in *identityv1.RegisterPermissionsRequest, _ ...grpc.CallOption) (*identityv1.RegisterPermissionsResponse, error) {
	f.calls++
	f.last = in
	if f.calls <= f.fail {
		return nil, f.err
	}
	return &identityv1.RegisterPermissionsResponse{Inserted: 1}, nil
}

func TestRequestReadsTheFile(t *testing.T) {
	// the identity file declares only identity: names; as "identity" it is a valid request
	req := Request("identity", identityv1.File_identity_v1_permissions_proto)
	if req.Service != "identity" || len(req.Permissions) < 10 || req.Permissions[0].Description == "" {
		t.Errorf("%v", req)
	}
}

func TestRegisterRefusesAForeignName(t *testing.T) {
	f := &fake{}
	if _, err := Register(context.Background(), f, "dictionary", identityv1.File_identity_v1_permissions_proto); err == nil || f.calls != 0 {
		t.Errorf("a service sends only its own namespace: %v, %d calls", err, f.calls)
	}
}

func TestRegisterWithRetrySucceedsAfterFailures(t *testing.T) {
	f := &fake{fail: 1, err: status.Error(codes.Unavailable, "identity is down")}
	err := RegisterWithRetry(context.Background(), zap.NewNop(), f, "identity", 10*time.Second, identityv1.File_identity_v1_permissions_proto)
	if err != nil || f.calls != 2 {
		t.Errorf("%v after %d calls", err, f.calls)
	}
}

func TestRegisterWithRetryGivesUpAfterTheTimeout(t *testing.T) {
	f := &fake{fail: 1 << 30, err: status.Error(codes.Unavailable, "identity is down")}
	start := time.Now()
	err := RegisterWithRetry(context.Background(), zap.NewNop(), f, "identity", 1500*time.Millisecond, identityv1.File_identity_v1_permissions_proto)
	if err == nil || !strings.Contains(err.Error(), "not registered within") || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestRegisterWithRetryDoesNotRetryAnInvalidRequest(t *testing.T) {
	f := &fake{fail: 5, err: status.Error(codes.InvalidArgument, "bad name")}
	if err := RegisterWithRetry(context.Background(), zap.NewNop(), f, "identity", 10*time.Second, identityv1.File_identity_v1_permissions_proto); err == nil || f.calls != 1 {
		t.Errorf("%v after %d calls", err, f.calls)
	}
}
