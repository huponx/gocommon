// Package pagination holds the building blocks of token (keyset) pagination for List calls: the page
// size rules and the opaque page token that carries the key of the last item of a page.
package pagination

import (
	"encoding/base64"
	"strings"

	"github.com/huponx/gocommon/apperror"
)

const (
	// DefaultSize is the page size used when the caller sends none.
	DefaultSize = 50
	// MaxSize is the largest page size a caller gets; a bigger request is capped, not rejected.
	MaxSize = 200
	// tokenSep separates the parts of a composite key inside a page token (it never occurs in a key).
	tokenSep = "\x00"
)

// Size applies DefaultSize and MaxSize to the page_size of a List call.
func Size(n int32) (int, error) { return SizeWith(n, DefaultSize, MaxSize) }

// SizeWith is Size with the default and the maximum of the caller's choice.
func SizeWith(n int32, def, maxSize int) (int, error) {
	switch {
	case n < 0:
		return 0, apperror.InvalidArgument("page_size must not be negative")
	case n == 0:
		return def, nil
	case int(n) > maxSize:
		return maxSize, nil
	}
	return int(n), nil
}

// Encode turns the key of the last item of a page (one part, or several for a composite key) into the opaque
// token the caller sends back to get the next page.
func Encode(parts ...string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Join(parts, tokenSep)))
}

// Decode is the inverse of Encode and returns n parts; an empty token (the first page) gives n empty parts.
// A token that is not valid base64 or has another number of parts is an InvalidArgument error.
func Decode(token string, n int) ([]string, error) {
	out := make([]string, n)
	if token == "" {
		return out, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, apperror.InvalidArgument("invalid page_token")
	}
	parts := strings.Split(string(b), tokenSep)
	if len(parts) != n {
		return nil, apperror.InvalidArgument("invalid page_token")
	}
	return parts, nil
}
