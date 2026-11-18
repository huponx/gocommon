// Package retry runs an operation again with exponential backoff and jitter.
package retry

import (
	"context"
	"math/rand/v2"
	"time"
)

// Config controls the backoff.
type Config struct {
	MaxAttempts int           // total attempts (1 = no retry)
	InitialWait time.Duration // wait before the second attempt
	MaxWait     time.Duration // cap on the wait between two attempts
	Multiplier  float64       // growth factor of the wait (for example 2.0)
	Jitter      float64       // fraction of the wait added at random (0 to 1)
}

// Default is 5 attempts, 1s growing to a 16s cap, times 2, 20% jitter.
var Default = Config{
	MaxAttempts: 5,
	InitialWait: time.Second,
	MaxWait:     16 * time.Second,
	Multiplier:  2.0,
	Jitter:      0.2,
}

// Do calls fn until it returns nil, ctx is done or MaxAttempts is exhausted. It returns the
// last error of fn, or ctx.Err() when the context ended while waiting.
func Do(ctx context.Context, cfg Config, fn func() error) error {
	wait := cfg.InitialWait
	var err error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		if attempt == cfg.MaxAttempts {
			break
		}
		timer := time.NewTimer(addJitter(wait, cfg.Jitter))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		wait = scale(wait, cfg.Multiplier, cfg.MaxWait)
	}
	return err
}

func scale(d time.Duration, factor float64, limit time.Duration) time.Duration {
	next := time.Duration(float64(d) * factor)
	if limit > 0 && next > limit {
		return limit
	}
	return next
}

func addJitter(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	return d + time.Duration(float64(d)*jitter*rand.Float64())
}
