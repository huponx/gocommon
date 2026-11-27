// Package permsync registers the permissions a service declares in its permissions.proto with identity, which
// keeps the catalog. A service calls Register at start, before it is ready: a changed permission set changes what
// many users may do, so a service that cannot register does not serve (and does not retire anything by omission).
package permsync

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/huponx/gocommon/grpcserver"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// DefaultTimeout is how long RegisterWithRetry tries (PERMISSIONS_SYNC_TIMEOUT of the services).
const DefaultTimeout = 2 * time.Minute

// Registrar is the part of the identity client Register needs.
type Registrar interface {
	RegisterPermissions(ctx context.Context, in *identityv1.RegisterPermissionsRequest, opts ...grpc.CallOption) (*identityv1.RegisterPermissionsResponse, error)
}

// Request builds the RegisterPermissions request of a service from the `authz.v1.permissions` option of the files.
func Request(service string, files ...protoreflect.FileDescriptor) *identityv1.RegisterPermissionsRequest {
	req := &identityv1.RegisterPermissionsRequest{Service: service}
	for _, d := range grpcserver.DeclaredPermissions(files...) {
		req.Permissions = append(req.Permissions, &identityv1.PermissionDeclaration{Name: d.Name, Description: d.Description, RenamedFrom: d.RenamedFrom})
	}
	return req
}

// Register sends the permissions once.
func Register(ctx context.Context, c Registrar, service string, files ...protoreflect.FileDescriptor) (*identityv1.RegisterPermissionsResponse, error) {
	req := Request(service, files...)
	for _, p := range req.Permissions {
		if !strings.HasPrefix(p.Name, service+":") {
			return nil, fmt.Errorf("permsync: %q is outside the namespace %q", p.Name, service+":")
		}
	}
	return c.RegisterPermissions(ctx, req)
}

// RegisterWithRetry calls Register with a growing pause (1s up to 15s) until it succeeds or timeout passes
// (0: DefaultTimeout), then returns the last error: the caller exits non-zero. A refusal that retrying cannot fix
// (the request itself is invalid) returns at once.
func RegisterWithRetry(ctx context.Context, log *zap.Logger, c Registrar, service string, timeout time.Duration, files ...protoreflect.FileDescriptor) error {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pause := time.Second
	for attempt := 1; ; attempt++ {
		res, err := Register(ctx, c, service, files...)
		if err == nil {
			log.Info("permissions registered", zap.String("service", service), zap.Int("declared", len(Request(service, files...).Permissions)),
				zap.Int32("inserted", res.GetInserted()), zap.Int32("updated", res.GetUpdated()), zap.Int32("renamed", res.GetRenamed()),
				zap.Int32("retired", res.GetRetired()), zap.Int32("deleted", res.GetDeleted()))
			return nil
		}
		if status.Code(err) == codes.InvalidArgument {
			return fmt.Errorf("permissions of %s refused by identity: %w", service, err)
		}
		if ctx.Err() != nil {
			return fmt.Errorf("permissions of %s not registered within %s: %w", service, timeout, errors.Join(err, ctx.Err()))
		}
		log.Warn("permission registration failed, retrying", zap.String("service", service), zap.Int("attempt", attempt), zap.Duration("in", pause), zap.Error(err))
		select {
		case <-time.After(pause):
		case <-ctx.Done():
			return fmt.Errorf("permissions of %s not registered within %s: %w", service, timeout, errors.Join(err, ctx.Err()))
		}
		if pause *= 2; pause > 15*time.Second {
			pause = 15 * time.Second
		}
	}
}
