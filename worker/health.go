package worker

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/huponx/gocommon/healthz"
)

type healthReport struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

// Health is an optional stdlib /healthz + /readyz server for K8s probes.
// Call SetReady(false) when the process starts draining so readiness fails
// before in-flight jobs finish.
type Health struct {
	srv    *http.Server
	ready  atomic.Bool
	checks []healthz.Check
}

func NewHealth(addr string, checks ...healthz.Check) *Health {
	h := &Health{checks: checks}
	h.ready.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", h.live)
	mux.HandleFunc("/readyz", h.readyz)
	h.srv = &http.Server{Addr: addr, Handler: mux}
	return h
}

func (h *Health) ListenAndServe() error {
	err := h.srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func (h *Health) Shutdown(ctx context.Context) error {
	return h.srv.Shutdown(ctx)
}

func (h *Health) SetReady(ready bool) {
	h.ready.Store(ready)
}

func (h *Health) live(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, healthReport{Status: "ok"})
}

func (h *Health) readyz(w http.ResponseWriter, r *http.Request) {
	if !h.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, healthReport{
			Status: "unavailable",
			Checks: map[string]string{"ready": "draining"},
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	results := map[string]string{}
	ok := true
	for _, check := range h.checks {
		if err := check.Fn(ctx); err != nil {
			ok = false
			results[check.Name] = err.Error()
			continue
		}
		results[check.Name] = "ok"
	}
	status := http.StatusOK
	body := healthReport{Status: "ok", Checks: results}
	if !ok {
		status = http.StatusServiceUnavailable
		body.Status = "unavailable"
	}
	writeJSON(w, status, body)
}

func writeJSON(w http.ResponseWriter, status int, body healthReport) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
