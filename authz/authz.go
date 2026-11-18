// Package authz matches permissions made of colon separated segments, for example
// "invoice:read" or "identity:user:write".
//
// A granted permission may use "*" as a segment:
//   - "*" alone grants everything;
//   - a "*" in the middle matches exactly one segment ("identity:*:read" matches
//     "identity:user:read" but not "identity:read");
//   - a trailing "*" matches one or more segments ("identity:*" matches "identity:read" and
//     "identity:user:write").
//
// A required permission is always concrete (no "*").
package authz

import "strings"

// Match reports whether the granted permission covers the required one.
func Match(granted, required string) bool {
	if required == "" || strings.Contains(required, "*") {
		return false
	}
	if granted == "*" || granted == required {
		return true
	}
	gs := strings.Split(granted, ":")
	rs := strings.Split(required, ":")
	for i, g := range gs {
		last := i == len(gs)-1
		if last && g == "*" {
			return len(rs) > i // one or more segments left
		}
		if i >= len(rs) {
			return false
		}
		if g != "*" && g != rs[i] {
			return false
		}
	}
	return len(gs) == len(rs)
}

// Valid reports whether s is a well formed granted permission: "*" or non empty segments of
// [a-z0-9_.-] or "*".
func Valid(s string) bool {
	if s == "*" {
		return true
	}
	for _, seg := range strings.Split(s, ":") {
		if seg == "" {
			return false
		}
		if seg == "*" {
			continue
		}
		for _, r := range seg {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.' || r == '-') {
				return false
			}
		}
	}
	return true
}

// Allowed reports whether any granted permission covers the required one. An empty required
// permission is never allowed (a missing requirement must not open a door).
func Allowed(granted []string, required string) bool {
	for _, g := range granted {
		if Match(g, required) {
			return true
		}
	}
	return false
}

// AllowedAll reports whether every required permission is covered.
func AllowedAll(granted []string, required ...string) bool {
	if len(required) == 0 {
		return false
	}
	for _, r := range required {
		if !Allowed(granted, r) {
			return false
		}
	}
	return true
}
