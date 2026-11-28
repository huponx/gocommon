package netsafe

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
)

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "192.168.0.1": false, "172.16.0.1": false, "169.254.169.254": false, "::1": false,
		"0.0.0.0": false, "0.1.2.3": false, "100.64.0.1": false, "100.100.100.200": false, "198.18.0.5": false, "192.0.0.8": false,
		"240.0.0.1": false, "255.255.255.255": false, "64:ff9b::a00:1": false, "fe80::1": false, "fc00::1": false, "224.0.0.1": false,
	} {
		if got := Public(net.ParseIP(ip)); got != want {
			t.Errorf("Public(%s) = %v", ip, got)
		}
	}
}

func TestRefusal(t *testing.T) {
	if !IsRefused(fmt.Errorf("dial: %s is not a public address", "10.0.0.1")) || IsRefused(errors.New("timeout")) || IsRefused(nil) {
		t.Fatal("IsRefused")
	}
}

func TestScrubRemovesTheURLFromAnHTTPError(t *testing.T) {
	secret := "https://api.telegram.org/bot123456:SECRET-TOKEN/sendMessage"
	err := &url.Error{Op: "Post", URL: secret, Err: errors.New("dial tcp: lookup api.telegram.org: no such host")}
	got := Scrub(err)
	if strings.Contains(got.Error(), "SECRET-TOKEN") || strings.Contains(got.Error(), "telegram.org/bot") {
		t.Fatalf("the token is still in %q", got)
	}
	if !strings.Contains(got.Error(), "no such host") || !strings.Contains(got.Error(), "Post") {
		t.Fatalf("the cause must stay: %q", got)
	}
	other := errors.New("boom")
	if Scrub(other) != other || Scrub(nil) != nil {
		t.Fatal("another error is returned as it is")
	}
}

func TestSafeLink(t *testing.T) {
	for link, ok := range map[string]bool{
		"/users/1": true, "/": true, "https://admin.example.com/users/1": true, "http://localhost:3002/users/1": true,
		"javascript:alert(1)": false, "JaVaScRiPt:alert(1)": false, "data:text/html,x": false, "//evil.example/x": false, "/\\evil.example": false,
		"https:///nohost": false, "ftp://x.example": false, "/a b": false, "/a\nb": false, "": false, "users/1": false,
	} {
		if SafeLink(link) != ok {
			t.Errorf("SafeLink(%q) = %v", link, !ok)
		}
	}
}
