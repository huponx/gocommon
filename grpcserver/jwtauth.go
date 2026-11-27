package grpcserver

import (
	"context"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/authz"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// JWTAuth returns an AuthFunc that verifies "authorization: Bearer <jwt>" with the verifier
// (issuer, audience, signature, expiry, jti) and puts the Principal in the context
// (authn.FromContext).
func JWTAuth(v *jwtx.Verifier) AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		token := bearerFromMD(md)
		if token == "" {
			return ctx, apperror.Unauthenticated("unauthenticated")
		}
		p, err := authn.Verify(ctx, v, token)
		if err != nil {
			return ctx, err
		}
		// The verified subject replaces any user-id the caller sent in metadata.
		return authn.WithPrincipal(requestctx.SetUserID(ctx, p.Subject), p), nil
	}
}

// WithJWTAuth enables JWT authentication.
func WithJWTAuth(v *jwtx.Verifier) Option { return WithAuth(JWTAuth(v)) }

// AnyAuth accepts a request when any of the AuthFuncs accepts it, trying them in order
// (put the cheap local ones first, for example JWTAuth before KubeAuth). When none accepts,
// the first error that is not Unauthenticated wins (PermissionDenied, Unavailable), else
// Unauthenticated.
func AnyAuth(fns ...AuthFunc) AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		var first error
		for _, fn := range fns {
			out, err := fn(ctx)
			if err == nil {
				return out, nil
			}
			if first == nil || (status.Code(first) == codes.Unauthenticated && status.Code(err) != codes.Unauthenticated) {
				first = err
			}
		}
		if first == nil {
			first = apperror.Unauthenticated("unauthenticated")
		}
		return ctx, first
	}
}

// Rule says who may call a method. Any: the caller needs at least one of the permissions. All: the caller needs
// every one. Public: any authenticated caller. An empty Rule never allows, so a method with no decision stays closed.
type Rule struct {
	Any    []string
	All    []string
	Public bool
}

// PublicRule is the Rule of a method that needs a signed-in caller and no permission.
var PublicRule = Rule{Public: true}

// Allows reports whether a caller holding perms (authz wildcards apply) passes the rule. The three parts are
// exclusive in the protos; if several are set here every set one must pass.
func (r Rule) Allows(perms []string) bool {
	if !r.Public && len(r.Any) == 0 && len(r.All) == 0 {
		return false
	}
	if len(r.Any) > 0 {
		ok := false
		for _, name := range r.Any {
			if authz.Allowed(perms, name) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.All) > 0 && !authz.AllowedAll(perms, r.All...) {
		return false
	}
	return true
}

// WithMethodPermissions enables authorization by method. The map key is the full method
// ("/identity.v1.IdentityService/GetUser"), the value the Rule of the method (see PermissionsFromProto, which reads
// it from the proto). It is deny by default: a method that is not in the map, or whose Rule is empty, is refused,
// so a new RPC stays closed until someone decides who may call it. Health checks are always open.
//
// Who is checked:
//   - a caller authenticated by JWT must pass the Rule (authz wildcards apply);
//   - a caller authenticated only by KubeAuth (no Principal) is trusted, its allow list is
//     its authorization.
func WithMethodPermissions(perms map[string]Rule) Option {
	cp := make(map[string]Rule, len(perms))
	for m, r := range perms {
		cp[m] = r
	}
	return func(o *options) { o.methodPerms = cp }
}

// checkMethod is the decision of WithMethodPermissions.
func checkMethod(ctx context.Context, perms map[string]Rule, method string) error {
	if perms == nil || isHealthMethod(method) {
		return nil
	}
	rule, ok := perms[method]
	if !ok || (!rule.Public && len(rule.Any) == 0 && len(rule.All) == 0) {
		return apperror.PermissionDenied("permission denied")
	}
	p := authn.FromContext(ctx)
	if p == nil {
		if CallerFromContext(ctx) != "" {
			return nil
		}
		return apperror.Unauthenticated("unauthenticated")
	}
	if rule.Allows(p.Perms) {
		return nil
	}
	return apperror.PermissionDenied("permission denied")
}

// principalFields are the log fields of the authenticated principal.
func principalFields(ctx context.Context) []zap.Field {
	p := authn.FromContext(ctx)
	if p == nil {
		return nil
	}
	fs := []zap.Field{zap.String("sub", p.Subject), zap.String("jti", p.TokenID)}
	if p.ClientID != "" {
		fs = append(fs, zap.String("client_id", p.ClientID))
	}
	if a := p.ActorChain(); a != "" {
		fs = append(fs, zap.String("act", a))
	}
	return fs
}
