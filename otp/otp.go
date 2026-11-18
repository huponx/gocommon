// Package otp generates and checks time-based one-time passwords (TOTP, RFC 6238) with
// HMAC-SHA1, 6 digits and a 30 second step: what every authenticator app and most upstream
// login APIs expect.
package otp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default, the only algorithm every authenticator app supports
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the step of a code in seconds.
	Period = 30
)

// DecodeSecret decodes a base32 secret (case, spaces and padding are ignored).
func DecodeSecret(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	s = strings.TrimRight(s, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("otp: decode secret: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("otp: empty secret")
	}
	return key, nil
}

// Code returns the code of the step (unix time / Period) for the raw key.
func Code(key []byte, step int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// dynamic truncation (RFC 4226 section 5.4)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	var mod uint32 = 1
	for i := 0; i < Digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", Digits, bin%mod)
}

// Generate returns the code of the base32 secret at time t.
func Generate(secret string, t time.Time) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	return Code(key, t.Unix()/Period), nil
}

// Validate reports whether code is the code of the base32 secret at time t, accepting
// `skew` steps before and after (clock drift). The comparison is constant time.
func Validate(secret, code string, t time.Time, skew int) (bool, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return false, err
	}
	step := t.Unix() / Period
	ok := 0
	for d := -int64(skew); d <= int64(skew); d++ {
		ok |= subtle.ConstantTimeCompare([]byte(Code(key, step+d)), []byte(strings.TrimSpace(code)))
	}
	return ok == 1, nil
}
