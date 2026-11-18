package otp

import (
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890"; the 6 digit codes are the last
// 6 digits of the 8 digit test vectors.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestGenerateRFC6238(t *testing.T) {
	for unix, want := range map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	} {
		got, err := Generate(rfcSecret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %q err %v, want %q", unix, got, err, want)
		}
	}
}

func TestSecretFormats(t *testing.T) {
	at := time.Unix(59, 0)
	for _, s := range []string{
		rfcSecret,
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
		rfcSecret + "====",
	} {
		if got, err := Generate(s, at); err != nil || got != "287082" {
			t.Errorf("%q: got %q err %v", s, got, err)
		}
	}
	if _, err := Generate("not base32 !", at); err == nil {
		t.Error("invalid secret: expected an error")
	}
	if _, err := Generate("", at); err == nil {
		t.Error("empty secret: expected an error")
	}
}

func TestValidate(t *testing.T) {
	at := time.Unix(1111111109, 0)
	if ok, _ := Validate(rfcSecret, "081804", at, 0); !ok {
		t.Error("current code rejected")
	}
	if ok, _ := Validate(rfcSecret, "050471", at, 0); ok {
		t.Error("next step accepted without skew")
	}
	if ok, _ := Validate(rfcSecret, "050471", at, 1); !ok {
		t.Error("next step rejected with skew 1")
	}
	if ok, _ := Validate(rfcSecret, "000000", at, 1); ok {
		t.Error("wrong code accepted")
	}
}
