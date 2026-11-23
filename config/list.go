package config

import (
	"strings"
)

// Lines flattens a list read from the environment (`envSeparator:","` already splits on commas)
// into its entries. An entry may also be separated by a new line, so a deployment can write one
// entry per line in a YAML block scalar (`|-`) instead of one long comma separated string.
// Entries are trimmed, empty ones dropped; spaces inside an entry are kept ("Admin Portal=https://...").
func Lines(items []string) []string {
	var out []string
	for _, item := range items {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

// Fields is Lines for values that never contain white space (URLs, origins, hosts): entries are
// also separated by spaces and tabs.
func Fields(items []string) []string {
	var out []string
	for _, item := range items {
		out = append(out, strings.FieldsFunc(item, func(r rune) bool { return r == ',' })...)
	}
	var fields []string
	for _, e := range out {
		fields = append(fields, strings.Fields(e)...)
	}
	return fields
}
