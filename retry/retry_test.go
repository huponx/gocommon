package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

var fast = Config{MaxAttempts: 3, InitialWait: time.Millisecond, MaxWait: 2 * time.Millisecond, Multiplier: 2}

func TestDoSucceedsAfterRetries(t *testing.T) {
	calls := 0
	err := Do(context.Background(), fast, func() error {
		calls++
		if calls < 3 {
			return errors.New("boom")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}

func TestDoReturnsLastError(t *testing.T) {
	calls := 0
	want := errors.New("last")
	err := Do(context.Background(), fast, func() error { calls++; return want })
	if !errors.Is(err, want) || calls != 3 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}

func TestDoStopsOnContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Config{MaxAttempts: 5, InitialWait: time.Hour, MaxWait: time.Hour, Multiplier: 1}
	calls := 0
	err := Do(ctx, cfg, func() error { calls++; cancel(); return errors.New("x") })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls = %d, err = %v", calls, err)
	}
}
