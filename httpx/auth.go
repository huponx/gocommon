package httpx

import (
	"context"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/authn"
	"github.com/huponx/gocommon/jwtx"
	"github.com/huponx/gocommon/logging"
	"github.com/huponx/gocommon/requestctx"
	"go.uber.org/zap"
)

// BearerToken returns the token of "Authorization: Bearer <token>", or "".
func BearerToken(c *gin.Context) string {
	h := c.GetHeader("Authorization")
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	return strings.TrimSpace(h[7:])
}

// JWTAuth verifies the bearer access token and puts the Principal in the request context
// (authn.FromContext). A missing or invalid token ends the request with 401, a key set that
// cannot be loaded with 502.
func JWTAuth(v *jwtx.Verifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := BearerToken(c)
		if token == "" {
			c.Header("WWW-Authenticate", `Bearer realm="api"`)
			apperror.WriteHTTP(c, apperror.Unauthenticated("unauthenticated"))
			c.Abort()
			return
		}
		p, err := authn.Verify(c.Request.Context(), v, token)
		if err != nil {
			if apperror.From(err).HTTPStatus() == 401 {
				c.Header("WWW-Authenticate", `Bearer realm="api", error="invalid_token"`)
			}
			apperror.WriteHTTP(c, err)
			c.Abort()
			return
		}
		SetPrincipal(c, p)
		c.Next()
	}
}

// SetPrincipal stores an already authenticated principal (for example one restored from a
// BFF session) in the request context and tags the request logger with it.
func SetPrincipal(c *gin.Context, p *authn.Principal) {
	ctx := authn.WithPrincipal(requestctx.SetUserID(c.Request.Context(), p.Subject), p)
	ctx = principalLogger(ctx, p)
	c.Request = c.Request.WithContext(ctx)
}

func principalLogger(ctx context.Context, p *authn.Principal) context.Context {
	fields := []zap.Field{zap.String("sub", p.Subject)}
	if p.TokenID != "" {
		fields = append(fields, zap.String("jti", p.TokenID))
	}
	if p.ClientID != "" {
		fields = append(fields, zap.String("client_id", p.ClientID))
	}
	return logging.WithCtx(ctx, logging.FromCtx(ctx).With(fields...))
}

// RequirePermission allows the request only when the principal holds every permission
// (authz wildcards apply). Use it after JWTAuth; without a principal it answers 401.
func RequirePermission(perms ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		p := authn.FromContext(c.Request.Context())
		if p == nil {
			apperror.WriteHTTP(c, apperror.Unauthenticated("unauthenticated"))
			c.Abort()
			return
		}
		if len(perms) == 0 {
			apperror.WriteHTTP(c, apperror.PermissionDenied("permission denied"))
			c.Abort()
			return
		}
		for _, perm := range perms {
			if !p.Can(perm) {
				apperror.WriteHTTP(c, apperror.PermissionDenied("permission denied"))
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
