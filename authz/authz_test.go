package authz

import (
	"encoding/json"
	"os"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		granted, required string
		want              bool
	}{
		{"bill:read", "bill:read", true},
		{"bill:read", "bill:write", false},
		{"bill:*", "bill:write", true},
		{"bill:*", "bill:invoice:write", true}, // trailing * covers the rest
		{"bill:*", "bill", false},
		{"bill:*", "dict:write", false},
		{"*:read", "dict:read", true},
		{"*:read", "dict:write", false},
		{"*:read", "dict:invoice:read", false}, // middle * is one segment
		{"identity:*:read", "identity:user:read", true},
		{"identity:*:read", "identity:read", false},
		{"identity:*:read", "identity:user:write", false},
		{"identity:user:*", "identity:user:write", true},
		{"identity:user:*", "identity:role:write", false},
		{"*", "x:y", true},
		{"*", "x", true},
		{"*:*", "x:y", true},
		{"bill", "bill:read", false},
		{"bill:read", "bill", false},
		{"bill:read", "bill:read:extra", false},
		{"bi*:read", "bill:read", false},
		{"*", "", false},
		{"*", "a:*", false}, // a requirement is concrete
	}
	for _, c := range cases {
		if got := Match(c.granted, c.required); got != c.want {
			t.Errorf("Match(%q,%q)=%v want %v", c.granted, c.required, got, c.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	if Allowed([]string{"*:*", "*"}, "") {
		t.Error("empty requirement must not be allowed")
	}
	if Allowed(nil, "a:b") {
		t.Error("no grants")
	}
	if !Allowed([]string{"x:y", "a:*"}, "a:b") {
		t.Error("second grant")
	}
	if !AllowedAll([]string{"a:*"}, "a:b", "a:c") || AllowedAll([]string{"a:b"}, "a:b", "a:c") || AllowedAll([]string{"*"}) {
		t.Error("AllowedAll")
	}
}

func TestValid(t *testing.T) {
	for _, ok := range []string{"*", "a:b", "a:*", "identity:*:read", "a.b-c_d:e"} {
		if !Valid(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "a:", ":a", "a::b", "A:b", "a b:c", "a*:b"} {
		if Valid(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

// The vectors are shared with web/packages/auth-client (permissions.test.ts): both matchers must agree.
func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/match_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Match []struct {
			Granted, Required string
			Want              bool
		} `json:"match"`
		Allowed []struct {
			Granted  []string
			Required string
			Want     bool
		} `json:"allowed"`
		AllowedAll []struct {
			Granted  []string
			Required []string
			Want     bool
		} `json:"allowedAll"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Match) == 0 || len(v.Allowed) == 0 || len(v.AllowedAll) == 0 {
		t.Fatal("the vector file is empty")
	}
	for _, c := range v.Match {
		if got := Match(c.Granted, c.Required); got != c.Want {
			t.Errorf("Match(%q,%q)=%v want %v", c.Granted, c.Required, got, c.Want)
		}
	}
	for _, c := range v.Allowed {
		if got := Allowed(c.Granted, c.Required); got != c.Want {
			t.Errorf("Allowed(%v,%q)=%v want %v", c.Granted, c.Required, got, c.Want)
		}
	}
	for _, c := range v.AllowedAll {
		if got := AllowedAll(c.Granted, c.Required...); got != c.Want {
			t.Errorf("AllowedAll(%v,%v)=%v want %v", c.Granted, c.Required, got, c.Want)
		}
	}
}
