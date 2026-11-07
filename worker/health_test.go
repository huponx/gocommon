package worker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/huponx/gocommon/healthz"
)

func TestHealthLive(t *testing.T) {
	h := NewHealth("")
	w := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHealthReadyCheckFails(t *testing.T) {
	h := NewHealth("", healthz.Check{
		Name: "db",
		Fn:   func(context.Context) error { return errors.New("dial") },
	})
	w := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}

func TestHealthNotReadyWhileDraining(t *testing.T) {
	h := NewHealth("")
	h.SetReady(false)
	w := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", w.Code)
	}
	var body healthReport
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Checks["ready"] != "draining" {
		t.Fatalf("body %+v", body)
	}
}

func TestHealthReadyOK(t *testing.T) {
	h := NewHealth("", healthz.Check{
		Name: "queue",
		Fn:   func(context.Context) error { return nil },
	})
	w := httptest.NewRecorder()
	h.srv.Handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
}
