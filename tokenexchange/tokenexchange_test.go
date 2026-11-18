package tokenexchange

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func server(t *testing.T, calls *atomic.Int32, h func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	return newClient(t, srv.URL, time.Now)
}

func newClient(t *testing.T, url string, now func() time.Time) *Client {
	t.Helper()
	c, err := New(Config{TokenURL: url, ClientID: "gatekeeper", ClientSecret: "s3cret", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func ok(w http.ResponseWriter, token string, expires int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"` + token + `","token_type":"Bearer","expires_in":` + itoa(expires) + `}`))
}

func itoa(i int) string {
	b := []byte{}
	if i == 0 {
		return "0"
	}
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestServiceTokenRequestAndCache(t *testing.T) {
	var calls atomic.Int32
	c := server(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		id, secret, hasAuth := r.BasicAuth()
		if !hasAuth || id != "gatekeeper" || secret != "s3cret" {
			t.Errorf("client auth %q %q %v", id, secret, hasAuth)
		}
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("audience") != "courier" {
			t.Errorf("form %v", r.PostForm)
		}
		ok(w, "tok-courier", 300)
	})
	for i := 0; i < 3; i++ {
		got, err := c.ServiceToken(context.Background(), "courier")
		if err != nil || got != "tok-courier" {
			t.Fatalf("%q %v", got, err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cache: %d calls", calls.Load())
	}
}

func TestExchangeRequestAndCacheKey(t *testing.T) {
	var calls atomic.Int32
	c := server(t, &calls, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f := r.PostForm
		if f.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			f.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" ||
			(f.Get("audience") != "bill" && f.Get("audience") != "dict") {
			t.Errorf("form %v", f)
		}
		ok(w, "tok-"+f.Get("subject_token"), 120)
	})
	ctx := context.Background()
	a, _ := c.ExchangeToken(ctx, "user-a", "bill")
	b, _ := c.ExchangeToken(ctx, "user-b", "bill")
	a2, _ := c.ExchangeToken(ctx, "user-a", "bill")
	if a != "tok-user-a" || b != "tok-user-b" || a2 != a {
		t.Fatalf("tokens %q %q %q", a, b, a2)
	}
	if calls.Load() != 2 {
		t.Fatalf("one call per subject, got %d", calls.Load())
	}
	// another audience or scope is another token
	_, _ = c.ExchangeToken(ctx, "user-a", "dict")
	_, _ = c.ExchangeToken(ctx, "user-a", "bill", "bill.read")
	if calls.Load() != 4 {
		t.Fatalf("audience/scope in the key, got %d", calls.Load())
	}
}

func TestCacheExpiresEarly(t *testing.T) {
	var calls atomic.Int32
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		ok(w, "t", 60)
	}))
	defer srv.Close()
	c := newClient(t, srv.URL, func() time.Time { return now })
	_, _ = c.ServiceToken(context.Background(), "x")
	now = now.Add(40 * time.Second) // 60s life, refreshed 15s early
	_, _ = c.ServiceToken(context.Background(), "x")
	if calls.Load() != 1 {
		t.Fatal("still fresh")
	}
	now = now.Add(10 * time.Second)
	_, _ = c.ServiceToken(context.Background(), "x")
	if calls.Load() != 2 {
		t.Fatal("must refresh before expiry")
	}
}

func TestShortLivedTokenNotCached(t *testing.T) {
	var calls atomic.Int32
	c := server(t, &calls, func(w http.ResponseWriter, _ *http.Request) { ok(w, "t", 10) })
	_, _ = c.ServiceToken(context.Background(), "x")
	_, _ = c.ServiceToken(context.Background(), "x")
	if calls.Load() != 2 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestConcurrentRequestsShareOneCall(t *testing.T) {
	var calls atomic.Int32
	c := server(t, &calls, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		ok(w, "t", 300)
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ServiceToken(context.Background(), "x"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestErrors(t *testing.T) {
	var calls atomic.Int32
	status := http.StatusBadRequest
	c := server(t, &calls, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"access_denied","error_description":"exchange not allowed"}`))
	})
	if _, err := c.ExchangeToken(context.Background(), "u", "bill"); !errors.Is(err, ErrDenied) {
		t.Fatalf("4xx must be denied: %v", err)
	}
	status = http.StatusServiceUnavailable
	if _, err := c.ServiceToken(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("5xx must be unavailable: %v", err)
	}
	down := newClient(t, "http://127.0.0.1:1/token", time.Now)
	if _, err := down.ServiceToken(context.Background(), "x"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("network error must be unavailable: %v", err)
	}
	if _, err := c.ServiceToken(context.Background(), ""); err == nil {
		t.Fatal("empty audience accepted")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}
