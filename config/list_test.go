package config

import (
	"reflect"
	"testing"
)

func TestLines(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"comma list already split", []string{"a=1", "b=2"}, []string{"a=1", "b=2"}},
		{"block scalar", []string{"Admin Portal=https://a|https://a/logo.svg\nDict=https://d\n"}, []string{"Admin Portal=https://a|https://a/logo.svg", "Dict=https://d"}},
		{"mixed, windows line ends, blanks", []string{" a ,b\r\n\r\n c\n", "", "  "}, []string{"a", "b", "c"}},
		{"spaces inside an entry are kept", []string{"Admin Portal=https://a"}, []string{"Admin Portal=https://a"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Lines(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Lines(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFields(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"one per item", []string{"https://a", "https://b"}, []string{"https://a", "https://b"}},
		{"block scalar", []string{"https://a\nhttps://b\n"}, []string{"https://a", "https://b"}},
		{"spaces and commas", []string{"https://a https://b,https://c\t https://d"}, []string{"https://a", "https://b", "https://c", "https://d"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Fields(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Fields(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
