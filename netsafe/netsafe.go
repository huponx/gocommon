// Package netsafe is what a service needs when it calls, or shows, an address somebody else chose (a webhook of an
// administrator, the push endpoint of a browser, a link in a notification): an HTTP client that connects to public
// addresses only, so nobody can aim the service at the cluster; the removal of the URL from the error of a call; and the
// check of a link before it becomes an href.
package netsafe

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// notPublic lists the ranges that are not the public internet and that net.IP does not know about: carrier grade NAT
// (some clouds keep their metadata service there), "this network", protocol assignments, benchmarking, reserved, and
// the NAT64 prefix (it can embed a private IPv4 address).
var notPublic = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "100::/64", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// Public reports whether the address belongs to the public internet.
func Public(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, n := range notPublic {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// Client returns an HTTP client that does not follow redirects and, unless allowPrivate, refuses to connect to a
// private address. The check is on the connected IP, after the name was resolved, so a name that points inside is
// refused too (and a change of the DNS answer between a check and the connection cannot get around it).
func Client(timeout time.Duration, allowPrivate bool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if !allowPrivate {
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || !Public(ip) {
				return fmt.Errorf("%s is not a public address", host)
			}
			return nil
		}
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     &http.Transport{DialContext: dialer.DialContext, Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Scrub removes the address from the error of an HTTP call: Go puts the URL in it, and the URL of the Telegram API holds
// the token of the bot, the URL of a Slack webhook is itself the secret. The result is safe to store in a log of
// deliveries and to log.
func Scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// SafeLink accepts what a notification, a redirect or a menu may open: a path of the app ("/users/1", not "//host") or
// an http(s) URL with a host. Any other scheme ("javascript:", "data:") would run in the page that shows the link.
func SafeLink(l string) bool {
	if strings.ContainsAny(l, "\r\n\t ") {
		return false
	}
	if strings.HasPrefix(l, "/") {
		return !strings.HasPrefix(l, "//") && !strings.HasPrefix(l, "/\\")
	}
	u, err := url.Parse(l)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// IsRefused reports whether err is the refusal of a private address (final: retrying cannot make it public).
func IsRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), "is not a public address")
}
