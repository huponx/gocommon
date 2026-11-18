package jwtx

import (
	"encoding/base64"
	"testing"
)

func fakeToken(payload string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(payload)) + ".sig"
}

func TestParseUnverified(t *testing.T) {
	var got struct {
		UserID string `json:"userId"`
	}
	if err := ParseUnverified(fakeToken(`{"userId":"u-1"}`), &got); err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u-1" {
		t.Fatalf("userId = %q", got.UserID)
	}

	m := map[string]any{}
	if err := ParseUnverified(fakeToken(`{"a":1}`), &m); err != nil || m["a"] != float64(1) {
		t.Fatalf("map = %v, err = %v", m, err)
	}
}

func TestParseUnverifiedErrors(t *testing.T) {
	var v map[string]any
	for name, tok := range map[string]string{
		"parts":   "a.b",
		"base64":  "a.!!!.c",
		"json":    fakeToken(`not json`),
		"emptyin": "",
	} {
		if err := ParseUnverified(tok, &v); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := ParseUnverified(fakeToken(`{}`), nil); err == nil {
		t.Error("nil destination: expected an error")
	}
}
