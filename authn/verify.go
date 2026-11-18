package authn

import (
	"context"
	"errors"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/gocommon/jwtx"
	"google.golang.org/grpc/codes"
)

// Verify checks a raw access token and returns its principal. It fails closed:
//   - a token that is not valid, or not an access token: Unauthenticated
//   - keys that cannot be loaded: Unavailable (the caller should retry, not re-login)
//
// The reason of an Unauthenticated error is never sent to the client.
func Verify(ctx context.Context, v *jwtx.Verifier, raw string) (*Principal, error) {
	claims, err := v.Verify(ctx, raw)
	if err != nil {
		if errors.Is(err, jwtx.ErrInvalidToken) {
			return nil, apperror.Wrap(codes.Unauthenticated, "unauthenticated", err)
		}
		return nil, apperror.Wrap(codes.Unavailable, "authentication unavailable", err)
	}
	if claims.Type != jwtx.TypeAccess {
		return nil, apperror.Unauthenticated("unauthenticated")
	}
	p := FromClaims(claims)
	p.Raw = raw
	return p, nil
}
