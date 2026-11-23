package pagination

import (
	"reflect"
	"testing"
)

func TestSize(t *testing.T) {
	for in, want := range map[int32]int{0: 50, 1: 1, 200: 200, 1000: 200} {
		got, err := Size(in)
		if err != nil || got != want {
			t.Errorf("Size(%d) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := Size(-1); err == nil {
		t.Error("a negative page_size must be rejected")
	}
	if got, _ := SizeWith(0, 10, 20); got != 10 {
		t.Errorf("SizeWith default = %d", got)
	}
	if got, _ := SizeWith(99, 10, 20); got != 20 {
		t.Errorf("SizeWith max = %d", got)
	}
}

func TestToken(t *testing.T) {
	first, err := Decode("", 2)
	if err != nil || !reflect.DeepEqual(first, []string{"", ""}) {
		t.Fatalf("first page = %v, %v", first, err)
	}
	got, err := Decode(Encode("web", "https://api"), 2)
	if err != nil || !reflect.DeepEqual(got, []string{"web", "https://api"}) {
		t.Fatalf("round trip = %v, %v", got, err)
	}
	if _, err := Decode(Encode("only-one"), 2); err == nil {
		t.Error("a token with the wrong number of parts must be rejected")
	}
	if _, err := Decode("!!not base64!!", 1); err == nil {
		t.Error("garbage must be rejected")
	}
}
